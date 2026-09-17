import { createFinding } from '../../utils/finding.js';

/**
 * APIKeyAuditor — Tests API key management and authentication hygiene.
 *
 * Probes:
 * - API keys in URLs (leaked in logs/referrer)
 * - API keys hardcoded in client JS
 * - Missing rate limiting
 * - Auth bypass (protected endpoints without token)
 * - API versioning issues
 */
export class APIKeyAuditor {
    constructor(logger) {
        this.logger = logger;

        this.KEY_PARAM_NAMES = [
            'api_key', 'apikey', 'key', 'token', 'access_token',
            'auth_token', 'secret', 'api_secret', 'client_secret',
        ];

        this.PROTECTED_ENDPOINTS = [
            '/api/users', '/api/user', '/api/me', '/api/profile',
            '/api/account', '/api/settings', '/api/orders', '/api/data',
            '/api/admin', '/api/dashboard', '/api/v1/users', '/api/v1/me',
            '/api/v2/users', '/api/v2/me',
        ];
    }

    /**
     * Audit API key management.
     */
    async audit(surfaceInventory) {
        const findings = [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        this.logger?.info?.('API Key Auditor: starting tests');

        // 1. Check for API keys in URLs
        const urlKeyFindings = this._checkKeysInURLs(surfaceInventory);
        findings.push(...urlKeyFindings);

        // 2. Check for API keys in JavaScript
        const jsKeyFindings = await this._checkKeysInJS(surfaceInventory);
        findings.push(...jsKeyFindings);

        // 3. Test auth bypass on protected endpoints
        const bypassFindings = await this._testAuthBypass(baseUrl);
        findings.push(...bypassFindings);

        // 4. Test rate limiting
        const rateLimitFindings = await this._testRateLimiting(baseUrl);
        findings.push(...rateLimitFindings);

        this.logger?.info?.(`API Key Auditor: found ${findings.length} issues`);
        return findings;
    }

    /**
     * Check if API keys appear in crawled URLs.
     */
    _checkKeysInURLs(surfaceInventory) {
        const findings = [];
        const pages = surfaceInventory.pages || [];
        const apis = surfaceInventory.apiEndpoints || surfaceInventory.apis || [];

        for (const entry of [...pages, ...apis]) {
            const url = entry.url || entry;
            try {
                const parsed = new URL(url);
                for (const [param, value] of parsed.searchParams) {
                    if (this.KEY_PARAM_NAMES.includes(param.toLowerCase()) && value.length > 8) {
                        findings.push(createFinding({
                            module: 'api',
                            title: 'API Key in URL: Leaked via Query Parameter',
                            severity: 'high',
                            affected_surface: url,
                            description: `API key passed as URL query parameter "${param}". Keys in URLs are logged in server logs, proxy logs, browser history, and shared via the Referer header. This key is effectively public.`,
                            evidence: `Parameter: ${param}=${value.substring(0, 8)}...`,
                            remediation: 'Send API keys in the Authorization header (Bearer token) or a custom header. Never use query parameters for authentication credentials.',
                        }));
                        break;
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    /**
     * Check for hardcoded API keys in client-side JavaScript.
     */
    async _checkKeysInJS(surfaceInventory) {
        const findings = [];
        const pages = surfaceInventory.pages || [];

        for (const page of pages) {
            const url = page.url || page;
            try {
                const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
                if (!response.ok) continue;

                const html = await response.text();

                // Check for API key patterns in inline scripts
                const scriptBlocks = html.match(/<script[^>]*>[\s\S]*?<\/script>/gi) || [];
                for (const block of scriptBlocks) {
                    for (const keyName of this.KEY_PARAM_NAMES) {
                        const patterns = [
                            new RegExp(`['"]?${keyName}['"]?\\s*[:=]\\s*['"]([^'"]{16,})['"]`, 'gi'),
                            new RegExp(`${keyName}\\s*=\\s*['"]([^'"]{16,})['"]`, 'gi'),
                        ];

                        for (const pattern of patterns) {
                            const match = pattern.exec(block);
                            if (match) {
                                findings.push(createFinding({
                                    module: 'api',
                                    title: 'API Key Hardcoded in Client JavaScript',
                                    severity: 'high',
                                    affected_surface: url,
                                    description: `An API key ("${keyName}") is hardcoded in client-side JavaScript. Anyone viewing page source can extract this key and use it to access your API.`,
                                    evidence: `Found: ${keyName} = "${match[1].substring(0, 12)}..."`,
                                    remediation: 'Never hardcode API keys in client-side code. Use server-side proxying, environment variables, or runtime configuration. Use restricted API keys with minimal scopes for any client-side keys.',
                                }));
                                break;
                            }
                        }
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    /**
     * Test if protected endpoints can be accessed without authentication.
     */
    async _testAuthBypass(baseUrl) {
        const findings = [];

        for (const path of this.PROTECTED_ENDPOINTS) {
            try {
                const url = new URL(path, baseUrl).href;
                const response = await fetch(url, {
                    method: 'GET',
                    signal: AbortSignal.timeout(5000),
                    // Deliberately no auth headers
                });

                if (response.ok) {
                    const text = await response.text();
                    // Check if actual data was returned (not just a generic 200)
                    if (text.length > 50 && !this._isGenericResponse(text)) {
                        try {
                            const json = JSON.parse(text);
                            if (json.data || json.users || json.results || json.items ||
                                Array.isArray(json) || json.email || json.name) {
                                findings.push(createFinding({
                                    module: 'api',
                                    title: 'Auth Bypass: Protected Endpoint Accessible',
                                    severity: 'critical',
                                    affected_surface: url,
                                    description: `API endpoint ${path} returns data without any authentication token. An unauthenticated attacker can access this endpoint and retrieve sensitive data.`,
                                    reproduction: [
                                        `1. GET ${url} with no Authorization header`,
                                        `2. Server returns data`,
                                    ],
                                    evidence: `Status: ${response.status}\nResponse length: ${text.length} bytes\nContains structured data`,
                                    remediation: 'Require authentication (JWT, API key, session) on all API endpoints that return user data. Return 401 Unauthorized for unauthenticated requests.',
                                }));
                            }
                        } catch {
                            // Not JSON
                        }
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    /**
     * Test rate limiting on API endpoints.
     */
    async _testRateLimiting(baseUrl) {
        const findings = [];

        // Test login endpoint for rate limiting
        const loginPaths = ['/api/auth/login', '/api/login', '/login', '/auth/login'];

        for (const path of loginPaths) {
            try {
                const url = new URL(path, baseUrl).href;
                let successCount = 0;

                // Fire 20 rapid login attempts
                const attempts = Array.from({ length: 20 }, () =>
                    fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: 'test@test.com', password: 'wrong' }),
                        signal: AbortSignal.timeout(5000),
                    }).then(r => ({ status: r.status, ok: r.status < 500 }))
                        .catch(() => null)
                );

                const results = await Promise.allSettled(attempts);
                const responses = results
                    .filter(r => r.status === 'fulfilled' && r.value)
                    .map(r => r.value);

                const nonRateLimited = responses.filter(r =>
                    r.status !== 429 && r.status !== 503
                ).length;

                if (nonRateLimited >= 18) {
                    findings.push(createFinding({
                        module: 'api',
                        title: 'Missing Rate Limiting on Login',
                        severity: 'high',
                        affected_surface: url,
                        description: `Login endpoint at ${path} accepted ${nonRateLimited}/20 rapid requests without rate limiting (no 429 responses). This enables credential brute-force and stuffing attacks.`,
                        reproduction: [
                            `1. Fire 20 rapid POST requests to ${url}`,
                            `2. ${nonRateLimited} requests accepted (no 429)`,
                        ],
                        evidence: `Rapid attempts: 20\nNon-rate-limited: ${nonRateLimited}\n429 responses: ${responses.length - nonRateLimited}`,
                        remediation: 'Implement rate limiting: max 5 login attempts per minute per IP/account. Return 429 Too Many Requests after threshold. Add exponential backoff and account lockout after repeated failures.',
                    }));
                }
                break; // Only test first found login endpoint
            } catch {
                continue;
            }
        }

        return findings;
    }

    _getBaseUrl(surfaceInventory) {
        const pages = surfaceInventory.pages || [];
        if (pages.length === 0) return null;
        try {
            const parsed = new URL(pages[0].url || pages[0]);
            return `${parsed.protocol}//${parsed.host}`;
        } catch { return null; }
    }

    _isGenericResponse(text) {
        return /not found|404|403|unauthorized|forbidden|error|<!doctype/i.test(text) &&
            text.length < 500;
    }
}

export default APIKeyAuditor;
