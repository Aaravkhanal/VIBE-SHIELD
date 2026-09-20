import { chromium } from 'playwright';
import { createFinding } from '../utils/finding.js';

/**
 * Parallel, rate-limit-aware Crawler with JS API discovery.
 *
 * Improvements over v1:
 *   - Worker-pool based parallel crawling (configurable concurrency)
 *   - Intercepts all fetch()/XHR network requests for API discovery
 *   - Detects 429/503 rate limiting and backs off automatically
 */
export class Crawler {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;

        // State
        this.visited = new Set();
        this.surfaces = [];
        this.apiEndpoints = [];
        this.forms = [];
        this.consoleErrors = [];
        this.failedRequests = [];

        // Config
        this.maxPages = config.crawler?.max_pages || 50;
        this.maxDepth = config.crawler?.max_depth || 5;
        this.timeout = config.crawler?.timeout || 30000;
        this.concurrency = config.crawler?.concurrency || 4;
        this.baseUrl = null;

        // Rate limiting state
        this._rateLimitHits = 0;
        this._backoffMs = 0;
        this._rateLimited = false;
    }

    /**
     * Main crawl entry point. Returns a SurfaceInventory.
     * Uses a worker-pool pattern for parallel crawling.
     *
     * @param {string} targetUrl - URL to crawl
     * @param {object} [authState] - Playwright storageState for authenticated crawling
     * @param {string[]} [seedLinks] - Additional URLs to crawl (e.g., from post-login page)
     */
    async crawl(targetUrl, authState = null, seedLinks = []) {
        let urlStr = (targetUrl || '').trim();
        if (urlStr && !/^https?:\/\//i.test(urlStr)) {
            urlStr = 'https://' + urlStr;
        }
        this.baseUrl = new URL(urlStr);

        let browser;
        try {
            browser = await chromium.launch({ headless: true });
        } catch (err) {
            if (err.message.includes("Executable doesn't exist") || err.message.includes('playwright install')) {
                this.logger?.warn?.('Chromium not found — attempting automatic install...');
                const { execSync } = await import('child_process');
                try {
                    execSync('npx playwright install chromium', { stdio: 'inherit', timeout: 120000 });
                    browser = await chromium.launch({ headless: true });
                } catch {
                    throw new Error(
                        'Playwright Chromium is not installed. Run:\n\n' +
                        '    npx playwright install chromium\n\n' +
                        'Then re-run your vibe-shield command.'
                    );
                }
            } else {
                throw err;
            }
        }

        const contextOptions = {
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        };

        if (authState) {
            contextOptions.storageState = authState;
        }

        const context = await browser.newContext(contextOptions);

        try {
            // Build initial queue: target URL + seed links
            const queue = [{ url: urlStr, depth: 0 }];
            for (const link of seedLinks) {
                if (this._isSameOrigin(link)) {
                    queue.push({ url: link, depth: 0 });
                }
            }

            // Run parallel workers that drain the queue
            await this._runParallelCrawl(context, queue);
        } finally {
            await browser.close();
        }

        const inventory = {
            baseUrl: targetUrl,
            pages: this.surfaces,
            apiEndpoints: this.apiEndpoints,
            forms: this.forms,
            totalPages: this.surfaces.length,
            totalApis: this.apiEndpoints.length,
            totalForms: this.forms.length,
            crawledAt: new Date().toISOString(),
            authenticated: !!authState,
        };

        this.logger?.info?.(
            `Crawl complete: ${inventory.totalPages} pages, ${inventory.totalApis} APIs, ` +
            `${inventory.totalForms} forms${authState ? ' (authenticated)' : ''} ` +
            `[concurrency=${this.concurrency}]`
        );
        return inventory;
    }

    // ── Parallel Worker Pool ──────────────────────────────

    /**
     * Spawns N workers that consume URLs from a shared queue.
     * Workers stop when the queue is empty AND no other worker is active.
     */
    async _runParallelCrawl(context, queue) {
        let activeWorkers = 0;
        let queueIndex = 0;
        const effectiveConcurrency = Math.min(this.concurrency, 8);

        const self = this;

        return new Promise((resolve) => {
            function tryDequeue() {
                // Abort if rate limited too many times
                if (self._rateLimitHits >= 5) {
                    self.logger?.warn?.('[VIBE-SHIELD-CRAWL] Too many rate limit responses — aborting crawl with partial results');
                    if (activeWorkers === 0) resolve();
                    return;
                }

                while (activeWorkers < effectiveConcurrency && queueIndex < queue.length) {
                    if (self.visited.size >= self.maxPages) break;

                    const item = queue[queueIndex++];
                    const normalizedUrl = self._normalizeUrl(item.url);

                    // Skip already visited or off-origin
                    if (self.visited.has(normalizedUrl) || !self._isSameOrigin(item.url)) {
                        continue;
                    }
                    if (item.depth > self.maxDepth) continue;

                    self.visited.add(normalizedUrl);
                    activeWorkers++;

                    // Crawl this page in a worker
                    self._crawlPage(context, item.url, item.depth)
                        .then((discoveredLinks) => {
                            // Enqueue discovered links
                            for (const link of discoveredLinks) {
                                if (self.visited.size + (queue.length - queueIndex) >= self.maxPages * 2) break;
                                queue.push({ url: link, depth: item.depth + 1 });
                            }
                        })
                        .catch((err) => {
                            self.logger?.debug?.(`Worker error: ${err.message}`);
                        })
                        .finally(() => {
                            activeWorkers--;
                            // Try to pick up more work
                            if (activeWorkers === 0 && queueIndex >= queue.length) {
                                resolve();
                            } else {
                                tryDequeue();
                            }
                        });
                }

                // If no workers active and nothing left, resolve
                if (activeWorkers === 0 && queueIndex >= queue.length) {
                    resolve();
                }
            }

            tryDequeue();
        });
    }

    // ── Single Page Crawler ──────────────────────────────

    /**
     * Crawls a single page. Returns an array of discovered link URLs.
     */
    async _crawlPage(context, url, depth) {
        const normalizedUrl = this._normalizeUrl(url);

        // Rate limit backoff
        if (this._backoffMs > 0) {
            this.logger?.debug?.(`Rate limit backoff: waiting ${this._backoffMs}ms`);
            await new Promise(r => setTimeout(r, this._backoffMs));
        }

        const page = await context.newPage();
        const pageData = {
            url: normalizedUrl,
            type: 'page',
            status: null,
            title: '',
            links: [],
            forms: [],
            consoleErrors: [],
            failedRequests: [],
            loadTime: 0,
        };

        const consoleMessages = [];
        const failedReqs = [];
        const discoveredLinks = [];

        // ── Monitor console ──
        page.on('console', msg => {
            if (msg.type() === 'error') {
                consoleMessages.push({
                    type: msg.type(),
                    text: msg.text(),
                    url: normalizedUrl,
                });
            }
        });

        page.on('pageerror', error => {
            consoleMessages.push({
                type: 'exception',
                text: error.message,
                url: normalizedUrl,
            });
        });

        page.on('requestfailed', request => {
            failedReqs.push({
                url: request.url(),
                method: request.method(),
                failure: request.failure()?.errorText || 'Unknown',
                page: normalizedUrl,
            });
        });

        // ── JS API Discovery: Intercept ALL network requests ──
        page.on('response', response => {
            try {
                const reqUrl = response.url();
                const method = response.request().method();
                const status = response.status();
                const contentType = response.headers()['content-type'] || '';
                const resourceType = response.request().resourceType();

                // Rate limit detection
                if (status === 429 || status === 503) {
                    this._handleRateLimit(status, reqUrl);
                } else if (status >= 200 && status < 400) {
                    this._resetRateLimit();
                }

                // Discover API endpoints — expanded detection
                if (this._isSameOrigin(reqUrl) && this._isApiRequest(reqUrl, contentType, resourceType, method)) {
                    const apiKey = `${method}::${this._stripQueryParams(reqUrl)}`;
                    const existing = this.apiEndpoints.find(e => `${e.method}::${this._stripQueryParams(e.url)}` === apiKey);
                    if (!existing) {
                        const hasAuthHeader = !!(
                            response.request().headers()['authorization'] ||
                            response.request().headers()['x-api-key'] ||
                            response.request().headers()['x-auth-token']
                        );
                        this.apiEndpoints.push({
                            url: reqUrl,
                            method,
                            status,
                            contentType,
                            authenticated: hasAuthHeader,
                            discoveredVia: 'network-intercept',
                        });
                    }
                }
            } catch {
                // Ignore response parsing errors
            }
        });

        try {
            const startTime = Date.now();
            const response = await page.goto(url, {
                waitUntil: 'networkidle',
                timeout: this.timeout,
            });
            pageData.loadTime = Date.now() - startTime;
            pageData.status = response?.status() || null;
            pageData.title = await page.title();

            // Rate limit check on main page response
            if (pageData.status === 429 || pageData.status === 503) {
                this._handleRateLimit(pageData.status, normalizedUrl);
            }

            // Extract links
            const links = await page.evaluate(() => {
                const anchors = Array.from(document.querySelectorAll('a[href]'));
                return anchors.map(a => a.href).filter(href => href && !href.startsWith('javascript:'));
            });
            pageData.links = [...new Set(links)];
            discoveredLinks.push(...pageData.links);

            // Extract forms (with CSRF token detection for downstream)
            const pageForms = await page.evaluate(() => {
                return Array.from(document.querySelectorAll('form')).map((form, idx) => {
                    const fields = Array.from(form.querySelectorAll('input, select, textarea')).map(field => ({
                        tag: field.tagName.toLowerCase(),
                        type: field.type || field.tagName.toLowerCase(),
                        name: field.name || field.id || `field-${idx}`,
                        required: field.required,
                        placeholder: field.placeholder || '',
                        pattern: field.pattern || '',
                        minLength: field.minLength > 0 ? field.minLength : null,
                        maxLength: field.maxLength > 0 ? field.maxLength : null,
                        value: field.type === 'hidden' ? field.value : undefined,
                    }));

                    // Check for CSRF meta tags
                    const csrfMeta = document.querySelector(
                        'meta[name="csrf-token"], meta[name="_csrf"], meta[name="csrf-param"]'
                    );

                    return {
                        action: form.action || window.location.href,
                        method: (form.method || 'get').toUpperCase(),
                        id: form.id || `form-${idx}`,
                        fields,
                        hasSubmitButton: !!form.querySelector('button[type="submit"], input[type="submit"]'),
                        hasCsrfToken: fields.some(f =>
                            ['_csrf', 'csrf_token', '_token', 'authenticity_token', '__RequestVerificationToken', 'csrfmiddlewaretoken']
                                .includes(f.name?.toLowerCase())
                        ),
                        hasCsrfMeta: !!csrfMeta,
                    };
                });
            });

            for (const form of pageForms) {
                form.page = normalizedUrl;
                this.forms.push(form);
            }
            pageData.forms = pageForms;

            pageData.consoleErrors = consoleMessages;
            pageData.failedRequests = failedReqs;

            this.consoleErrors.push(...consoleMessages);
            this.failedRequests.push(...failedReqs);
            this.surfaces.push(pageData);

            this.logger?.debug?.(
                `Crawled: ${normalizedUrl} (${pageData.status}) - ` +
                `${links.length} links, ${pageForms.length} forms [depth=${depth}]`
            );
        } catch (err) {
            pageData.status = 'error';
            pageData.error = err.message;
            this.surfaces.push(pageData);
            this.logger?.warn?.(`Failed to crawl ${normalizedUrl}: ${err.message}`);
        } finally {
            await page.close();
        }

        return discoveredLinks;
    }

    // ── Rate Limiting ────────────────────────────────────

    _handleRateLimit(status, url) {
        this._rateLimitHits++;
        const delays = [2000, 5000, 10000, 15000, 20000];
        this._backoffMs = delays[Math.min(this._rateLimitHits - 1, delays.length - 1)];

        this.logger?.warn?.(
            `[VIBE-SHIELD-CRAWL] Rate limited (${status}) on ${url} — ` +
            `backing off ${this._backoffMs}ms (hit #${this._rateLimitHits})`
        );

        // Reduce concurrency on repeated rate limits
        if (this._rateLimitHits >= 3 && this.concurrency > 1) {
            this.concurrency = 1;
            this.logger?.warn?.('[VIBE-SHIELD-CRAWL] Reduced concurrency to 1 due to rate limiting');
        }
    }

    _resetRateLimit() {
        if (this._rateLimitHits > 0) {
            this._rateLimitHits = Math.max(0, this._rateLimitHits - 1);
            if (this._rateLimitHits === 0) {
                this._backoffMs = 0;
            }
        }
    }

    // ── API Detection ────────────────────────────────────

    /**
     * Determine if a network request is an API call.
     * Expanded from v1: detects JSON, API paths, fetch/XHR, GraphQL.
     */
    _isApiRequest(url, contentType, resourceType, method) {
        // JSON responses are always API calls
        if (contentType.includes('application/json')) return true;

        // GraphQL endpoint
        if (url.includes('/graphql')) return true;

        // Common API path patterns
        const apiPatterns = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/_api/', '/wp-json/'];
        if (apiPatterns.some(p => url.includes(p))) return true;

        // fetch/XHR requests that aren't standard page resources
        if (resourceType === 'fetch' || resourceType === 'xhr') {
            // Exclude static assets
            const staticExts = ['.js', '.css', '.png', '.jpg', '.svg', '.woff', '.woff2', '.ico'];
            const urlPath = new URL(url).pathname;
            if (!staticExts.some(ext => urlPath.endsWith(ext))) return true;
        }

        // Non-GET requests to same origin are likely API calls
        if (method !== 'GET' && method !== 'OPTIONS') return true;

        return false;
    }

    // ── URL Helpers ──────────────────────────────────────

    _normalizeUrl(url) {
        try {
            const u = new URL(url);
            u.hash = '';
            let normalized = u.toString();
            if (normalized.endsWith('/') && u.pathname !== '/') {
                normalized = normalized.slice(0, -1);
            }
            return normalized;
        } catch {
            return url;
        }
    }

    _stripQueryParams(url) {
        try {
            const u = new URL(url);
            return `${u.origin}${u.pathname}`;
        } catch {
            return url;
        }
    }

    _isSameOrigin(url) {
        try {
            const u = new URL(url);
            return u.origin === this.baseUrl.origin;
        } catch {
            return false;
        }
    }
}

export default Crawler;
