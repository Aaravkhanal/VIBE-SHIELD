import { chromium } from 'playwright';
import { createFinding } from '../../utils/finding.js';

/**
 * Secret Detector — Scans pages, JS files, and responses for leaked secrets.
 * Detects API keys, tokens, hardcoded credentials, .env exposure, source maps, and debug endpoints.
 */
export class SecretDetector {
    constructor(logger) {
        this.logger = logger;
        this.findings = [];
        this.checkedUrls = new Set();
    }

    // Regex patterns for common secret formats
    static PATTERNS = [
        { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
        { name: 'AWS Secret Key', regex: /(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: 'critical' },
        { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high' },
        { name: 'Stripe Live Key', regex: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'critical' },
        { name: 'Stripe Publishable Key', regex: /pk_live_[0-9a-zA-Z]{24,}/g, severity: 'medium' },
        { name: 'Stripe Test Key', regex: /sk_test_[0-9a-zA-Z]{24,}/g, severity: 'low' },
        { name: 'GitHub Token', regex: /gh[ps]_[A-Za-z0-9_]{36,}/g, severity: 'critical' },
        { name: 'GitHub OAuth', regex: /gho_[A-Za-z0-9_]{36,}/g, severity: 'high' },
        { name: 'Twilio API Key', regex: /SK[0-9a-fA-F]{32}/g, severity: 'high' },
        { name: 'SendGrid API Key', regex: /SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}/g, severity: 'high' },
        { name: 'Slack Token', regex: /xox[baprs]-[0-9a-zA-Z\-]{10,}/g, severity: 'high' },
        { name: 'Slack Webhook', regex: /hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g, severity: 'medium' },
        { name: 'Firebase Key', regex: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g, severity: 'high' },
        { name: 'Private Key', regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
        { name: 'JWT Token', regex: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g, severity: 'medium' },
        { name: 'Generic API Key', regex: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]([^'"]{8,})['"/]/gi, severity: 'medium' },
        { name: 'Generic Secret', regex: /(?:secret|password|passwd|pwd|token)\s*[=:]\s*['"]([^'"]{8,})['"/]/gi, severity: 'medium' },
        { name: 'Database URL', regex: /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"<>]+/gi, severity: 'critical' },
        { name: 'Bearer Token in Code', regex: /['"](Bearer\s+[A-Za-z0-9\-._~+/]+=*)['"]/g, severity: 'high' },
    ];

    // Common sensitive file paths to probe
    static SENSITIVE_PATHS = [
        { path: '/.env', desc: 'Environment variables file' },
        { path: '/.env.local', desc: 'Local environment file' },
        { path: '/.env.production', desc: 'Production environment file' },
        { path: '/.env.development', desc: 'Development environment file' },
        { path: '/.git/config', desc: 'Git configuration' },
        { path: '/.git/HEAD', desc: 'Git HEAD reference' },
        { path: '/wp-config.php', desc: 'WordPress configuration' },
        { path: '/config.json', desc: 'Configuration file' },
        { path: '/config.yaml', desc: 'Configuration file' },
        { path: '/config.yml', desc: 'Configuration file' },
        { path: '/.DS_Store', desc: 'macOS directory metadata' },
        { path: '/debug', desc: 'Debug endpoint' },
        { path: '/_debug', desc: 'Debug endpoint' },
        { path: '/graphiql', desc: 'GraphQL IDE (should not be public)' },
        { path: '/graphql', desc: 'GraphQL endpoint' },
        { path: '/__debug', desc: 'Debug endpoint' },
        { path: '/phpinfo.php', desc: 'PHP info page' },
        { path: '/server-status', desc: 'Apache server status' },
        { path: '/elmah.axd', desc: '.NET error log' },
        { path: '/actuator', desc: 'Spring Boot actuator' },
        { path: '/actuator/env', desc: 'Spring Boot environment' },
    ];

    /**
     * Run secret detection on all crawled surfaces.
     */
    async detect(surfaceInventory) {
        // 1. Scan page sources for secrets
        await this._scanPageSources(surfaceInventory);

        // 2. Probe for sensitive file exposure
        await this._probeSensitivePaths(surfaceInventory.baseUrl);

        // 3. Check for source map exposure
        await this._checkSourceMaps(surfaceInventory);

        this.logger?.info?.(`Secret detector found ${this.findings.length} issues`);
        return this.findings;
    }

    /**
     * Scan page HTML and inline JS for secret patterns.
     */
    async _scanPageSources(surfaceInventory) {
        const browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({ ignoreHTTPSErrors: true });

        for (const page of surfaceInventory.pages) {
            if (typeof page.status !== 'number' || page.status >= 400) continue;
            if (this.checkedUrls.has(page.url)) continue;
            this.checkedUrls.add(page.url);

            try {
                const browserPage = await context.newPage();
                await browserPage.goto(page.url, { waitUntil: 'networkidle', timeout: 15000 });

                // Get the full page source
                const source = await browserPage.content();

                // Get all inline and external script contents
                const scripts = await browserPage.evaluate(() => {
                    const scriptEls = Array.from(document.querySelectorAll('script'));
                    return scriptEls.map(s => ({
                        src: s.src || null,
                        content: s.textContent || '',
                    }));
                });

                // Scan page source
                this._scanText(source, page.url, 'page source');

                // Scan inline scripts
                for (const script of scripts) {
                    if (script.content) {
                        this._scanText(script.content, page.url, 'inline script');
                    }
                }

                // Scan external JS files
                for (const script of scripts) {
                    if (script.src && !this.checkedUrls.has(script.src)) {
                        this.checkedUrls.add(script.src);
                        try {
                            const resp = await fetch(script.src, { signal: AbortSignal.timeout(5000) });
                            if (resp.ok) {
                                const jsContent = await resp.text();
                                this._scanText(jsContent, script.src, 'external JavaScript');
                            }
                        } catch {
                            // Best effort
                        }
                    }
                }

                await browserPage.close();
            } catch (err) {
                this.logger?.debug?.(`Secret scan failed for ${page.url}: ${err.message}`);
            }
        }

        await browser.close();
    }

    /**
     * Scan a text block for secret patterns.
     */
    _scanText(text, url, context) {
        for (const pattern of SecretDetector.PATTERNS) {
            const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
            let match;

            while ((match = regex.exec(text)) !== null) {
                const secretValue = match[1] || match[0];
                const maskedValue = this._maskSecret(secretValue);

                // Skip obvious false positives
                if (this._isFalsePositive(secretValue, pattern.name)) continue;

                this.findings.push(createFinding({
                    module: 'security',
                    title: `Exposed ${pattern.name}: ${maskedValue}`,
                    severity: pattern.severity,
                    affected_surface: url,
                    description: `A ${pattern.name} was found in the ${context} at ${url}. Exposed secrets can be exploited by attackers to gain unauthorized access to services, data, and infrastructure.\n\nDetected value: ${maskedValue}`,
                    reproduction: [
                        `1. Navigate to ${url}`,
                        `2. View the ${context}`,
                        `3. Search for the pattern matching ${pattern.name}`,
                        `4. Found: ${maskedValue}`,
                    ],
                    evidence: JSON.stringify({ pattern: pattern.name, maskedValue, location: context }),
                    remediation: `Immediately rotate this ${pattern.name}. Remove it from client-side code and store in server-side environment variables or a secrets manager. Never commit secrets to version control.`,
                    references: ['https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'],
                }));
            }
        }
    }

    /**
     * Probe known sensitive file paths.
     */
    async _probeSensitivePaths(baseUrl) {
        // Step 1: Fingerprint the SPA shell by fetching the homepage
        let spaFingerprint = null;
        try {
            const homeResp = await fetch(baseUrl, {
                method: 'GET',
                redirect: 'follow',
                signal: AbortSignal.timeout(5000),
            });
            if (homeResp.ok) {
                const homeBody = await homeResp.text();
                // Extract a fingerprint: title + first 200 chars of body structure
                const titleMatch = homeBody.match(/<title[^>]*>(.*?)<\/title>/i);
                spaFingerprint = {
                    title: titleMatch?.[1] || '',
                    length: homeBody.length,
                    body: homeBody,
                };
            }
        } catch { /* ignore */ }

        for (const { path, desc } of SecretDetector.SENSITIVE_PATHS) {
            const url = new URL(path, baseUrl).toString();

            try {
                const resp = await fetch(url, {
                    method: 'GET',
                    redirect: 'follow',
                    signal: AbortSignal.timeout(5000),
                });

                if (resp.ok && resp.status === 200) {
                    const contentType = resp.headers.get('content-type') || '';
                    const body = await resp.text();

                    // Filter out obviously empty responses
                    if (body.trim().length < 5) continue;

                    // ── SPA catch-all detection ──
                    // If the response is HTML and matches the homepage fingerprint, it's a SPA catch-all
                    if (contentType.includes('text/html') || body.match(/<!doctype\s+html/i)) {
                        // Check 1: Same body length as homepage (within 10 bytes)
                        if (spaFingerprint && Math.abs(body.length - spaFingerprint.length) < 10) continue;
                        // Check 2: Contains SPA root mount point (React/Vue/Angular/Next)
                        if (/id=["'](root|app|__next|__nuxt)["']/.test(body)) continue;
                        // Check 3: Body is identical to homepage
                        if (spaFingerprint && body === spaFingerprint.body) continue;
                        // Check 4: Generic HTML page with no path-specific content
                        if (body.includes('<!doctype html') || body.includes('<!DOCTYPE html')) {
                            const pathName = path.replace(/[/._\-]/g, '').toLowerCase();
                            if (!body.toLowerCase().includes(pathName)) continue;
                        }
                    }

                    // ── Content validation ──
                    // Verify the response looks like the expected file type
                    if (!this._isLegitimateFileContent(path, body, contentType)) continue;

                    const isSecret = path.includes('.env') || path.includes('.git') || path.includes('config');
                    const severity = isSecret ? 'critical' : 'high';

                    this.findings.push(createFinding({
                        module: 'security',
                        title: `Sensitive File Accessible: ${path}`,
                        severity,
                        affected_surface: url,
                        description: `The file "${path}" (${desc}) is publicly accessible and returned a ${resp.status} response. This file may contain sensitive configuration, credentials, or repository metadata.\n\nContent-Type: ${contentType}\nResponse length: ${body.length} bytes`,
                        reproduction: [
                            `1. Navigate to ${url}`,
                            `2. File returns HTTP ${resp.status} with ${body.length} bytes`,
                        ],
                        evidence: body.substring(0, 500),
                        remediation: `Block access to "${path}" via web server configuration. Add rules to deny access to dotfiles and sensitive configuration files.`,
                        references: ['https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'],
                    }));
                }
            } catch {
                // Path not accessible — this is fine
            }
        }
    }

    /**
     * Validate that response content actually matches the expected sensitive file type.
     * Catches SPA catch-all where HTML is served for all routes.
     */
    _isLegitimateFileContent(path, body, contentType) {
        const isHTML = contentType.includes('text/html') || /<!doctype\s+html/i.test(body);

        // .env files should contain KEY=VALUE pairs, not HTML
        if (path.includes('.env')) {
            if (isHTML) return false;
            return /^[A-Z_]+=.+/m.test(body); // At least one KEY=VALUE line
        }

        // .git files should not be HTML
        if (path.includes('.git')) {
            if (isHTML) return false;
            if (path.includes('HEAD')) return /^ref:\s/.test(body.trim());
            if (path.includes('config')) return body.includes('[core]') || body.includes('[remote');
            return true;
        }

        // PHP files should contain PHP markers or actual PHP output, not SPA HTML
        if (path.endsWith('.php')) {
            if (isHTML && /id=["'](root|app|__next)["']/.test(body)) return false;
            return true;
        }

        // Config files (json/yaml/yml) should contain structured data, not HTML
        if (path.match(/config\.(json|yaml|yml)$/)) {
            if (isHTML) return false;
            if (path.endsWith('.json')) {
                try { JSON.parse(body); return true; } catch { return false; }
            }
            return true;
        }

        // .DS_Store is binary, should not be HTML
        if (path.includes('.DS_Store')) {
            return !isHTML;
        }

        // Debug/admin endpoints — HTML is OK but SPA shells are not
        if (isHTML && /id=["'](root|app|__next|__nuxt)["']/.test(body)) return false;

        return true;
    }

    /**
     * Check for exposed source maps.
     */
    async _checkSourceMaps(surfaceInventory) {
        const jsUrls = new Set();

        for (const page of surfaceInventory.pages) {
            // Check for source maps in known patterns
            if (page.url.endsWith('.js')) {
                jsUrls.add(page.url + '.map');
            }
        }

        // Also check API-discovered JS files
        for (const api of surfaceInventory.apiEndpoints || []) {
            if (api.url.endsWith('.js')) {
                jsUrls.add(api.url + '.map');
            }
        }

        for (const mapUrl of jsUrls) {
            try {
                const resp = await fetch(mapUrl, { signal: AbortSignal.timeout(5000) });
                if (resp.ok) {
                    this.findings.push(createFinding({
                        module: 'security',
                        title: `Source Map Exposed: ${new URL(mapUrl).pathname}`,
                        severity: 'medium',
                        affected_surface: mapUrl,
                        description: 'A JavaScript source map file is publicly accessible. Source maps contain the original source code, which can reveal business logic, internal API endpoints, and potential vulnerabilities.',
                        reproduction: [
                            `1. Navigate to ${mapUrl}`,
                            '2. Source map file is returned successfully',
                        ],
                        remediation: 'Remove source maps from production builds or restrict access to them via server configuration. Most bundlers have options to disable source map generation for production.',
                    }));
                }
            } catch {
                // Not accessible — fine
            }
        }
    }

    _maskSecret(value) {
        if (!value || value.length < 8) return '****';
        return value.substring(0, 4) + '****' + value.substring(value.length - 4);
    }

    _isFalsePositive(value, patternName) {
        if (!value) return true;
        // Skip very short matches
        if (value.length < 8) return true;
        // Skip placeholder/example values
        const placeholders = ['example', 'test', 'placeholder', 'your_', 'xxx', 'TODO', 'CHANGEME', 'sample'];
        if (placeholders.some(p => value.toLowerCase().includes(p))) return true;
        // Skip if all same character
        if (/^(.)\1+$/.test(value)) return true;

        // ── Enhanced false-positive detection for Generic Secret / Generic API Key ──
        if (patternName === 'Generic Secret' || patternName === 'Generic API Key') {
            // Reject minified JS fragments: high ratio of special chars
            const specialCharRatio = (value.match(/[(){}\[\],;!?@#$%^&*~`<>|\\]/g) || []).length / value.length;
            if (specialCharRatio > 0.15) return true;

            // Reject if it looks like a code expression (contains JS operators)
            if (/[(){}\[\];,]/.test(value) && /[a-z]\(/i.test(value)) return true;

            // Reject common JS code patterns
            if (/\b(function|return|const|var|let|this|window|document|null|undefined|true|false)\b/.test(value)) return true;

            // Reject URL-like values that aren't secrets
            if (/^(https?:\/\/|data:|blob:|javascript:)/i.test(value)) return true;

            // Reject hex color codes
            if (/^#[0-9a-fA-F]{3,8}$/.test(value)) return true;

            // Require minimum entropy for generic matches
            const uniqueChars = new Set(value).size;
            if (uniqueChars < value.length * 0.3) return true;
        }

        return false;
    }
}

export default SecretDetector;
