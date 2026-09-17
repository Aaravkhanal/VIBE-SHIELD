import { createFinding } from '../../utils/finding.js';

/**
 * Header Analyzer — Checks HTTP response headers against security best practices.
 * Tests CSP, HSTS, X-Frame-Options, X-Content-Type-Options, CORS, and information disclosure.
 */
export class HeaderAnalyzer {
    constructor(logger) {
        this.logger = logger;
        this.findings = [];
    }

    /**
     * Analyze headers from all crawled pages.
     */
    async analyze(surfaceInventory) {
        const analyzedOrigins = new Set();

        for (const page of surfaceInventory.pages) {
            if (typeof page.status !== 'number') continue;

            // Only analyze headers once per origin
            const origin = this._getOrigin(page.url);
            if (analyzedOrigins.has(origin)) continue;
            analyzedOrigins.add(origin);

            try {
                const headers = await this._fetchHeaders(page.url);
                if (headers) {
                    this._checkCSP(headers, page.url);
                    this._checkHSTS(headers, page.url);
                    this._checkXFrameOptions(headers, page.url);
                    this._checkXContentTypeOptions(headers, page.url);
                    this._checkReferrerPolicy(headers, page.url);
                    this._checkPermissionsPolicy(headers, page.url);
                    this._checkCORS(headers, page.url);
                    this._checkInfoDisclosure(headers, page.url);
                }
            } catch (err) {
                this.logger?.debug?.(`Header analysis failed for ${page.url}: ${err.message}`);
            }
        }

        this.logger?.info?.(`Header analyzer found ${this.findings.length} issues`);
        return this.findings;
    }

    async _fetchHeaders(url) {
        try {
            const response = await fetch(url, {
                method: 'HEAD',
                redirect: 'follow',
                signal: AbortSignal.timeout(10000),
            });
            const headers = {};
            response.headers.forEach((value, key) => {
                headers[key.toLowerCase()] = value;
            });
            return headers;
        } catch {
            return null;
        }
    }

    _checkCSP(headers, url) {
        const csp = headers['content-security-policy'];

        if (!csp) {
            this.findings.push(createFinding({
                module: 'security',
                title: 'Missing Content-Security-Policy Header',
                severity: 'medium',
                affected_surface: url,
                description: 'No Content-Security-Policy (CSP) header is set. CSP is a critical defense against XSS attacks, clickjacking, and other code injection attacks. Without it, the browser allows all sources of content.',
                reproduction: [
                    `1. Send a HEAD request to ${url}`,
                    '2. Observe the response headers',
                    '3. No Content-Security-Policy header is present',
                ],
                remediation: "Add a Content-Security-Policy header. Start with a restrictive policy like `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';` and refine as needed.",
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
            }));
            return;
        }

        if (csp.includes("'unsafe-inline'") && csp.includes('script-src')) {
            this.findings.push(createFinding({
                module: 'security',
                title: "CSP allows 'unsafe-inline' Scripts",
                severity: 'medium',
                affected_surface: url,
                description: `The Content-Security-Policy allows 'unsafe-inline' in the script-src directive. This significantly weakens XSS protection as inline scripts can still be injected.\n\nCurrent CSP: ${csp}`,
                reproduction: [
                    `1. Check CSP header at ${url}`,
                    `2. CSP contains: ${csp}`,
                    "3. Note 'unsafe-inline' in script-src",
                ],
                remediation: "Remove 'unsafe-inline' from script-src. Use nonces or hashes for legitimate inline scripts instead.",
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src'],
            }));
        }

        if (csp.includes("'unsafe-eval'")) {
            this.findings.push(createFinding({
                module: 'security',
                title: "CSP allows 'unsafe-eval'",
                severity: 'medium',
                affected_surface: url,
                description: `The Content-Security-Policy allows 'unsafe-eval', which permits eval() and similar dynamic code execution. This is a common XSS exploitation vector.\n\nCurrent CSP: ${csp}`,
                reproduction: [
                    `1. Check CSP header at ${url}`,
                    "2. Note 'unsafe-eval' directive present",
                ],
                remediation: "Remove 'unsafe-eval' from CSP. Refactor code to not rely on eval(), new Function(), or setTimeout/setInterval with string arguments.",
            }));
        }
    }

    _checkHSTS(headers, url) {
        if (!url.startsWith('https://')) return;

        const hsts = headers['strict-transport-security'];

        if (!hsts) {
            this.findings.push(createFinding({
                module: 'security',
                title: 'Missing Strict-Transport-Security Header',
                severity: 'medium',
                affected_surface: url,
                description: 'No HSTS header is set for this HTTPS site. Without HSTS, users could be subject to protocol downgrade attacks and cookie hijacking via MITM.',
                reproduction: [
                    `1. Check response headers for ${url}`,
                    '2. No Strict-Transport-Security header present',
                ],
                remediation: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to all HTTPS responses.',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
            }));
            return;
        }

        const maxAgeMatch = hsts.match(/max-age=(\d+)/);
        if (maxAgeMatch && parseInt(maxAgeMatch[1]) < 15768000) {
            this.findings.push(createFinding({
                module: 'security',
                title: 'HSTS max-age Too Low',
                severity: 'low',
                affected_surface: url,
                description: `HSTS max-age is set to ${maxAgeMatch[1]} seconds (${(parseInt(maxAgeMatch[1]) / 86400).toFixed(0)} days). This should be at least 6 months (15768000 seconds) for adequate protection.`,
                reproduction: [
                    `1. HSTS header: ${hsts}`,
                    `2. max-age=${maxAgeMatch[1]} is below the recommended minimum`,
                ],
                remediation: 'Increase HSTS max-age to at least 15768000 (6 months), ideally 31536000 (1 year).',
            }));
        }
    }

    _checkXFrameOptions(headers, url) {
        const xfo = headers['x-frame-options'];
        if (!xfo) {
            this.findings.push(createFinding({
                module: 'security',
                title: 'Missing X-Frame-Options Header',
                severity: 'low',
                affected_surface: url,
                description: 'No X-Frame-Options header is set. The site may be vulnerable to clickjacking attacks where it is embedded in a malicious iframe.',
                reproduction: [
                    `1. Check headers for ${url}`,
                    '2. X-Frame-Options header is missing',
                    '3. Page can be embedded in an iframe on any domain',
                ],
                remediation: "Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`. Alternatively, use CSP's frame-ancestors directive.",
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
            }));
        }
    }

    _checkXContentTypeOptions(headers, url) {
        const xcto = headers['x-content-type-options'];
        if (!xcto || xcto.toLowerCase() !== 'nosniff') {
            this.findings.push(createFinding({
                module: 'security',
                title: 'Missing X-Content-Type-Options: nosniff',
                severity: 'low',
                affected_surface: url,
                description: 'The X-Content-Type-Options header is missing or not set to "nosniff". Browsers may MIME-sniff the content type, potentially executing malicious content uploaded with a non-executable MIME type.',
                reproduction: [
                    `1. Check headers for ${url}`,
                    '2. X-Content-Type-Options is missing or not "nosniff"',
                ],
                remediation: 'Add `X-Content-Type-Options: nosniff` to all responses.',
            }));
        }
    }

    _checkReferrerPolicy(headers, url) {
        const rp = headers['referrer-policy'];
        if (!rp) {
            this.findings.push(createFinding({
                module: 'security',
                title: 'Missing Referrer-Policy Header',
                severity: 'low',
                affected_surface: url,
                description: 'No Referrer-Policy header is set. The browser will use its default policy which may leak sensitive URL paths and query parameters to third parties.',
                reproduction: [
                    `1. Check headers for ${url}`,
                    '2. Referrer-Policy header is missing',
                ],
                remediation: 'Add `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer` to all responses.',
            }));
        } else if (rp.toLowerCase() === 'unsafe-url') {
            this.findings.push(createFinding({
                module: 'security',
                title: 'Referrer-Policy Set to unsafe-url',
                severity: 'medium',
                affected_surface: url,
                description: 'Referrer-Policy is set to "unsafe-url" which sends the full URL (including path and query string) in the Referer header to all origins, potentially leaking sensitive data.',
                reproduction: [
                    `1. Referrer-Policy: ${rp}`,
                    '2. Full URL including query params leaked to third parties',
                ],
                remediation: 'Change Referrer-Policy to "strict-origin-when-cross-origin" or "no-referrer".',
            }));
        }
    }

    _checkPermissionsPolicy(headers, url) {
        const pp = headers['permissions-policy'] || headers['feature-policy'];
        if (!pp) {
            this.findings.push(createFinding({
                module: 'security',
                title: 'Missing Permissions-Policy Header',
                severity: 'info',
                affected_surface: url,
                description: 'No Permissions-Policy (formerly Feature-Policy) header is set. This header controls which browser features and APIs can be used, reducing the attack surface.',
                reproduction: [
                    `1. Check headers for ${url}`,
                    '2. Permissions-Policy header is missing',
                ],
                remediation: 'Add a Permissions-Policy header to restrict unused browser features. Example: `Permissions-Policy: camera=(), microphone=(), geolocation=()`.',
            }));
        }
    }

    _checkCORS(headers, url) {
        const acao = headers['access-control-allow-origin'];
        const acac = headers['access-control-allow-credentials'];

        if (acao === '*' && acac?.toLowerCase() === 'true') {
            this.findings.push(createFinding({
                module: 'security',
                title: 'CORS: Wildcard Origin with Credentials',
                severity: 'high',
                affected_surface: url,
                description: 'The server sets Access-Control-Allow-Origin to "*" with Access-Control-Allow-Credentials: true. This is a dangerous misconfiguration that allows any website to make authenticated cross-origin requests, potentially stealing user data.',
                reproduction: [
                    `1. Send request to ${url} with Origin: https://evil.com`,
                    '2. Response contains: Access-Control-Allow-Origin: *',
                    '3. Response also contains: Access-Control-Allow-Credentials: true',
                ],
                remediation: 'Never use wildcard (*) with credentials. Whitelist specific trusted origins and validate the Origin header dynamically.',
                references: ['https://portswigger.net/web-security/cors'],
            }));
        } else if (acao === '*') {
            this.findings.push(createFinding({
                module: 'security',
                title: 'CORS: Wildcard Allow-Origin',
                severity: 'low',
                affected_surface: url,
                description: 'Access-Control-Allow-Origin is set to "*", allowing any website to read responses. While not directly exploitable without credentials, it may expose public API data to unintended consumers.',
                reproduction: [
                    `1. Check CORS headers for ${url}`,
                    '2. Access-Control-Allow-Origin: * (allows all origins)',
                ],
                remediation: 'If the API is not intended to be fully public, restrict CORS to specific trusted origins.',
            }));
        }
    }

    _checkInfoDisclosure(headers, url) {
        const server = headers['server'];
        const poweredBy = headers['x-powered-by'];

        if (server && /\d/.test(server)) {
            this.findings.push(createFinding({
                module: 'security',
                title: `Server Version Disclosure: ${server}`,
                severity: 'low',
                affected_surface: url,
                description: `The Server header discloses technology and version information: "${server}". Attackers can use this to search for known vulnerabilities specific to this version.`,
                reproduction: [
                    `1. Check Server header for ${url}`,
                    `2. Server: ${server}`,
                ],
                remediation: 'Remove or obfuscate the Server header. Most web servers have configuration options to suppress version information.',
            }));
        }

        if (poweredBy) {
            this.findings.push(createFinding({
                module: 'security',
                title: `X-Powered-By Disclosure: ${poweredBy}`,
                severity: 'low',
                affected_surface: url,
                description: `The X-Powered-By header reveals the backend technology: "${poweredBy}". This aids attackers in fingerprinting and targeting technology-specific exploits.`,
                reproduction: [
                    `1. Check X-Powered-By header for ${url}`,
                    `2. X-Powered-By: ${poweredBy}`,
                ],
                remediation: 'Remove the X-Powered-By header. In Express.js: `app.disable("x-powered-by")`. In PHP: set `expose_php = Off` in php.ini.',
            }));
        }
    }

    _getOrigin(url) {
        try {
            return new URL(url).origin;
        } catch {
            return url;
        }
    }
}

export default HeaderAnalyzer;
