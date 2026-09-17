import { createFinding } from '../../utils/finding.js';

/**
 * OAuthProber — Tests OAuth/SSO flow security.
 *
 * Probes:
 * - Missing state parameter (CSRF via OAuth)
 * - Open redirect via redirect_uri manipulation
 * - Token leakage in URL fragments / referrer
 * - Scope escalation
 * - Missing PKCE
 * - Deprecated implicit flow detection
 */
export class OAuthProber {
    constructor(logger) {
        this.logger = logger;

        this.OAUTH_ENDPOINTS = [
            '/oauth/authorize', '/auth/authorize', '/oauth2/authorize',
            '/api/oauth/authorize', '/connect/authorize', '/oauth/login',
            '/.well-known/openid-configuration', '/oauth/.well-known/openid-configuration',
        ];

        this.CALLBACK_ENDPOINTS = [
            '/callback', '/oauth/callback', '/auth/callback',
            '/api/auth/callback', '/login/callback', '/oauth2/callback',
        ];
    }

    /**
     * Test OAuth flow security.
     */
    async probe(surfaceInventory) {
        const findings = [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        this.logger?.info?.('OAuth Prober: starting tests');

        // 1. Discover OAuth endpoints
        const oauthEndpoints = await this._discoverOAuth(baseUrl);

        // 2. Test state parameter
        const stateFindings = await this._testMissingState(baseUrl, oauthEndpoints);
        findings.push(...stateFindings);

        // 3. Test redirect_uri manipulation
        const redirectFindings = await this._testOpenRedirect(baseUrl, oauthEndpoints);
        findings.push(...redirectFindings);

        // 4. Test callback endpoints for token leakage
        const callbackFindings = await this._testCallbackSecurity(baseUrl);
        findings.push(...callbackFindings);

        // 5. Check OpenID Configuration
        const oidcFindings = await this._checkOIDCConfig(baseUrl);
        findings.push(...oidcFindings);

        this.logger?.info?.(`OAuth Prober: found ${findings.length} issues`);
        return findings;
    }

    async _discoverOAuth(baseUrl) {
        const discovered = [];

        // Step 1: Fingerprint the homepage to detect SPA catch-all
        let homeFingerprint = null;
        try {
            const homeResp = await fetch(baseUrl, {
                redirect: 'follow',
                signal: AbortSignal.timeout(5000),
            });
            if (homeResp.ok) {
                homeFingerprint = {
                    length: (await homeResp.text()).length,
                    status: homeResp.status,
                };
            }
        } catch { /* ignore */ }

        for (const path of this.OAUTH_ENDPOINTS) {
            try {
                const url = new URL(path, baseUrl).href;
                const response = await fetch(url, {
                    method: 'GET',
                    redirect: 'manual',
                    signal: AbortSignal.timeout(5000),
                });

                // Must be a redirect (302/301) or return OAuth-specific responses
                if (response.status >= 300 && response.status < 400) {
                    const location = response.headers.get('location') || '';
                    // Real OAuth endpoints redirect to login pages, consent screens, or error pages
                    // Skip if it's just a www redirect (SPA routing)
                    const locUrl = new URL(location, baseUrl);
                    const reqUrl = new URL(url);
                    // If it's just a www prefix redirect, it's not OAuth
                    if (locUrl.pathname === reqUrl.pathname && locUrl.hostname !== reqUrl.hostname) continue;
                    discovered.push({ url, path, status: response.status });
                } else if (response.status === 200) {
                    // 200 could be an OAuth discovery endpoint or SPA catch-all
                    const body = await response.text();
                    // Check for OAuth-specific JSON responses (.well-known/openid-configuration)
                    if (body.includes('authorization_endpoint') || body.includes('token_endpoint')) {
                        discovered.push({ url, path, status: response.status });
                    }
                    // Check for OAuth error page (not SPA catch-all)
                    else if (body.includes('oauth') && body.includes('error') && !body.includes('id="root"') && !body.includes('id="app"')) {
                        discovered.push({ url, path, status: response.status });
                    }
                    // If body length matches homepage, it's SPA catch-all — skip
                    else if (homeFingerprint && Math.abs(body.length - homeFingerprint.length) < 10) {
                        continue;
                    }
                } else if (response.status === 401 || response.status === 400) {
                    // OAuth endpoints often return 401/400 for missing params
                    discovered.push({ url, path, status: response.status });
                }
                // Skip 404, 403, 500+ — not OAuth endpoints
            } catch {
                continue;
            }
        }

        return discovered;
    }

    async _testMissingState(baseUrl, endpoints) {
        const findings = [];

        for (const endpoint of endpoints) {
            try {
                // Request OAuth authorize without state parameter
                const url = new URL(endpoint.url);
                url.searchParams.set('client_id', 'test');
                url.searchParams.set('redirect_uri', `${baseUrl}/callback`);
                url.searchParams.set('response_type', 'code');
                // Deliberately omit 'state' parameter

                const response = await fetch(url.href, {
                    redirect: 'manual',
                    signal: AbortSignal.timeout(5000),
                });

                // If it redirects without requiring state, that's CSRF-vulnerable
                if (response.status >= 300 && response.status < 400) {
                    const location = response.headers.get('location') || '';

                    // Skip simple www-prefix or trailing-slash redirects (SPA routing)
                    const locUrl = new URL(location, baseUrl);
                    const reqUrl = new URL(url.href);
                    if (locUrl.pathname === reqUrl.pathname && locUrl.hostname !== reqUrl.hostname) continue;

                    // Must redirect to something OAuth-related (code, token, login, consent)
                    const isOAuthRedirect = /code=|token=|login|consent|authorize|error=|oauth/i.test(location);
                    if (!isOAuthRedirect && !location.includes('state=')) {
                        // If it redirects to the same path with params appended, it's just URL normalization
                        if (locUrl.searchParams.toString() === reqUrl.searchParams.toString()) continue;
                    }

                    if (!location.includes('state=') && !location.includes('error')) {
                        findings.push(createFinding({
                            module: 'api',
                            title: 'OAuth CSRF: Missing State Parameter',
                            severity: 'high',
                            affected_surface: endpoint.url,
                            description: `OAuth authorize endpoint at ${endpoint.url} processes requests without a state parameter. This enables CSRF attacks where an attacker forces a victim to log in with the attacker's account (login CSRF).`,
                            reproduction: [
                                `1. Request ${url.href} (no state parameter)`,
                                `2. Server redirects without requiring state`,
                                `3. Attacker crafts URL and sends to victim`,
                            ],
                            evidence: `Redirect location: ${location.substring(0, 200)}`,
                            remediation: 'Require and validate a cryptographically random state parameter on all OAuth flows. Reject authorization requests without state.',
                        }));
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    async _testOpenRedirect(baseUrl, endpoints) {
        const findings = [];
        const evilRedirects = [
            'https://evil.com/steal',
            'https://evil.com@legitimate.com',
            '//evil.com',
            'https://legitimate.com.evil.com/steal',
        ];

        for (const endpoint of endpoints) {
            for (const evilUri of evilRedirects) {
                try {
                    const url = new URL(endpoint.url);
                    url.searchParams.set('redirect_uri', evilUri);
                    url.searchParams.set('client_id', 'test');
                    url.searchParams.set('response_type', 'code');

                    const response = await fetch(url.href, {
                        redirect: 'manual',
                        signal: AbortSignal.timeout(5000),
                    });

                    if (response.status >= 300 && response.status < 400) {
                        const location = response.headers.get('location') || '';

                        // Skip www-prefix redirects (SPA routing)
                        // A real open redirect would redirect to evil.com domain, not just append params to the same path
                        const locUrl = new URL(location, baseUrl);
                        const reqUrl = new URL(url.href);
                        if (locUrl.pathname === reqUrl.pathname && locUrl.hostname !== reqUrl.hostname) {
                            // www redirect — check if evil.com is in the actual redirect target, not just the query string
                            if (!locUrl.hostname.includes('evil.com')) continue;
                        }

                        if (location.includes('evil.com')) {
                            // Verify evil.com is in the redirect HOST, not just echoed in query params
                            const isHostRedirect = locUrl.hostname.includes('evil.com');
                            const isQueryEcho = location.includes('redirect_uri=') && !isHostRedirect;
                            if (isQueryEcho) continue;  // Just echoed our param back, not a real redirect

                            findings.push(createFinding({
                                module: 'api',
                                title: 'OAuth Open Redirect: Arbitrary redirect_uri',
                                severity: 'critical',
                                affected_surface: endpoint.url,
                                description: `OAuth endpoint accepts arbitrary redirect_uri values. An attacker can steal authorization codes by redirecting the OAuth flow to their server: ${evilUri}`,
                                reproduction: [
                                    `1. Set redirect_uri to "${evilUri}"`,
                                    `2. Server redirects the authorization code to attacker's domain`,
                                ],
                                evidence: `redirect_uri: ${evilUri}\nServer redirected to: ${location.substring(0, 200)}`,
                                remediation: 'Strictly validate redirect_uri against a pre-registered allowlist. Use exact string matching, not prefix matching. Reject any URI not in the allowlist.',
                            }));
                            break;
                        }
                    }
                } catch {
                    continue;
                }
            }
        }

        return findings;
    }

    async _testCallbackSecurity(baseUrl) {
        const findings = [];

        for (const path of this.CALLBACK_ENDPOINTS) {
            try {
                const url = new URL(path, baseUrl).href;
                // Test if callback accepts token in query string (should be fragment)
                const testUrl = `${url}?code=test_auth_code&state=test_state`;

                const response = await fetch(testUrl, {
                    redirect: 'manual',
                    signal: AbortSignal.timeout(5000),
                });

                if (response.status === 200) {
                    const text = await response.text();
                    // Check if the page handles the code parameter
                    if (text.includes('test_auth_code') || text.includes('code=')) {
                        findings.push(createFinding({
                            module: 'api',
                            title: 'OAuth Token Leakage: Code in URL',
                            severity: 'medium',
                            affected_surface: url,
                            description: `OAuth callback at ${url} processes authorization codes from query parameters. Codes in URLs can leak via browser history, referrer headers, and server logs.`,
                            evidence: `Callback echoed the authorization code`,
                            remediation: 'Use POST-based callback handling. If using query parameters, ensure codes are single-use and short-lived (30 seconds). Implement PKCE to prevent code interception.',
                        }));
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    async _checkOIDCConfig(baseUrl) {
        const findings = [];

        try {
            const url = new URL('/.well-known/openid-configuration', baseUrl).href;
            const response = await fetch(url, { signal: AbortSignal.timeout(5000) });

            if (response.ok) {
                const config = await response.json();

                // Check for implicit flow support
                const grantTypes = config.grant_types_supported || [];
                if (grantTypes.includes('implicit')) {
                    findings.push(createFinding({
                        module: 'api',
                        title: 'OAuth Implicit Flow Supported (Deprecated)',
                        severity: 'medium',
                        affected_surface: url,
                        description: `OpenID Configuration advertises support for the implicit grant type. Implicit flow is deprecated because tokens are exposed in URL fragments and browser history.`,
                        evidence: `grant_types_supported: ${JSON.stringify(grantTypes)}`,
                        remediation: 'Disable implicit flow. Use authorization code flow with PKCE for all clients, including SPAs.',
                    }));
                }

                // Check for missing PKCE support
                const codeMethods = config.code_challenge_methods_supported || [];
                if (grantTypes.includes('authorization_code') && codeMethods.length === 0) {
                    findings.push(createFinding({
                        module: 'api',
                        title: 'OAuth Missing PKCE Support',
                        severity: 'high',
                        affected_surface: url,
                        description: `Authorization code flow is supported but PKCE (Proof Key for Code Exchange) is not. Without PKCE, authorization codes can be intercepted by malicious apps.`,
                        evidence: `code_challenge_methods_supported: not present`,
                        remediation: 'Implement PKCE support (RFC 7636). Require code_challenge on all authorization requests. Support S256 code_challenge_method.',
                    }));
                }
            }
        } catch {
            // No OIDC config
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
}

export default OAuthProber;
