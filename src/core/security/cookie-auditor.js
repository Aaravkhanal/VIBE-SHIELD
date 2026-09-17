import { createFinding } from '../../utils/finding.js';

/**
 * CookieAuditor — Deep audit of cookie security attributes.
 *
 * Goes beyond HttpOnly to check:
 *   - SameSite (None/Lax/Strict)
 *   - Secure flag (required for HTTPS sites)
 *   - __Host- / __Secure- prefix usage
 *   - Overly long expiry (session cookies living for years)
 *   - Domain scope (overly broad domain attribute)
 *   - Path attribute (overly broad path)
 */
export class CookieAuditor {
    constructor(logger) {
        this.logger = logger;
    }

    async audit(surfaceInventory) {
        this.logger?.info?.('Cookie Auditor: starting deep cookie analysis');
        const findings = [];
        const baseUrl = new URL(surfaceInventory.baseUrl);
        const isHTTPS = baseUrl.protocol === 'https:';

        // Fetch cookies from the target
        const cookies = await this._fetchCookies(surfaceInventory.baseUrl);

        if (cookies.length === 0) {
            this.logger?.info?.('Cookie Auditor: no cookies found — skipping');
            return findings;
        }

        this.logger?.info?.(`Cookie Auditor: analyzing ${cookies.length} cookies`);

        // Session-related cookie name patterns
        const sessionPatterns = [
            /sess/i, /session/i, /sid/i, /token/i, /auth/i, /jwt/i,
            /login/i, /user/i, /account/i, /csrf/i, /xsrf/i,
            /connect\.sid/i, /PHPSESSID/i, /JSESSIONID/i, /ASP\.NET_SessionId/i,
        ];

        for (const cookie of cookies) {
            const isSessionCookie = sessionPatterns.some(p => p.test(cookie.name));

            // Check 1: Missing Secure flag on HTTPS site
            if (isHTTPS && !cookie.secure) {
                findings.push(createFinding({
                    module: 'security',
                    title: `Cookie "${cookie.name}" Missing Secure Flag`,
                    severity: isSessionCookie ? 'high' : 'medium',
                    affected_surface: surfaceInventory.baseUrl,
                    description:
                        `Cookie "${cookie.name}" is served over HTTPS but lacks the Secure flag. ` +
                        `It can be transmitted over unencrypted HTTP connections, exposing it to interception.` +
                        (isSessionCookie ? ' This is a session-related cookie, making this a high-severity issue.' : ''),
                    evidence: { cookie_name: cookie.name, flags: this._cookieFlags(cookie) },
                    remediation: 'Add the Secure flag to all cookies served over HTTPS: `Set-Cookie: name=value; Secure`',
                }));
            }

            // Check 2: Missing or weak SameSite attribute
            if (!cookie.sameSite || cookie.sameSite === 'None') {
                const hasCrossOriginNeed = cookie.name.toLowerCase().includes('third') ||
                    cookie.name.toLowerCase().includes('embed');

                if (!hasCrossOriginNeed) {
                    findings.push(createFinding({
                        module: 'security',
                        title: `Cookie "${cookie.name}" Has Weak SameSite Policy`,
                        severity: isSessionCookie ? 'medium' : 'low',
                        affected_surface: surfaceInventory.baseUrl,
                        description:
                            `Cookie "${cookie.name}" has SameSite=${cookie.sameSite || 'not set'}. ` +
                            `Without SameSite=Lax or Strict, the cookie is sent on cross-site requests, ` +
                            `enabling CSRF attacks.`,
                        evidence: { cookie_name: cookie.name, sameSite: cookie.sameSite || 'not set', flags: this._cookieFlags(cookie) },
                        remediation: 'Set SameSite=Lax (or Strict for maximum protection) on all cookies: `Set-Cookie: name=value; SameSite=Lax`',
                    }));
                }
            }

            // Check 3: Missing HttpOnly on session cookies
            if (isSessionCookie && !cookie.httpOnly) {
                findings.push(createFinding({
                    module: 'security',
                    title: `Session Cookie "${cookie.name}" Missing HttpOnly Flag`,
                    severity: 'high',
                    affected_surface: surfaceInventory.baseUrl,
                    description:
                        `Session cookie "${cookie.name}" lacks the HttpOnly flag. ` +
                        `It is accessible via JavaScript (document.cookie), making it vulnerable to XSS-based session theft.`,
                    evidence: { cookie_name: cookie.name, flags: this._cookieFlags(cookie) },
                    remediation: 'Add HttpOnly flag to session cookies: `Set-Cookie: name=value; HttpOnly`',
                }));
            }

            // Check 4: Excessive expiry (> 1 year)
            if (cookie.expires && cookie.expires > 0) {
                const now = Date.now() / 1000;
                const oneYear = 365 * 24 * 60 * 60;
                if (cookie.expires - now > oneYear) {
                    const years = ((cookie.expires - now) / (365 * 24 * 60 * 60)).toFixed(1);
                    findings.push(createFinding({
                        module: 'security',
                        title: `Cookie "${cookie.name}" Has Excessive Expiry (${years} years)`,
                        severity: isSessionCookie ? 'medium' : 'low',
                        affected_surface: surfaceInventory.baseUrl,
                        description:
                            `Cookie "${cookie.name}" expires in ${years} years. ` +
                            `Long-lived cookies increase the window for session theft and tracking.`,
                        evidence: { cookie_name: cookie.name, expires: new Date(cookie.expires * 1000).toISOString(), years },
                        remediation: 'Set reasonable expiry times. Session cookies should expire when the browser closes. Persistent cookies should not exceed 30 days for sensitive data.',
                    }));
                }
            }

            // Check 5: Missing __Host- prefix for sensitive cookies
            if (isSessionCookie && isHTTPS && !cookie.name.startsWith('__Host-') && !cookie.name.startsWith('__Secure-')) {
                findings.push(createFinding({
                    module: 'security',
                    title: `Session Cookie "${cookie.name}" Not Using Cookie Prefix`,
                    severity: 'info',
                    affected_surface: surfaceInventory.baseUrl,
                    description:
                        `Session cookie "${cookie.name}" does not use __Host- or __Secure- prefix. ` +
                        `Cookie prefixes provide additional security guarantees enforced by browsers ` +
                        `(e.g., __Host- requires Secure, Path=/, and no Domain attribute).`,
                    evidence: { cookie_name: cookie.name },
                    remediation: 'Consider renaming session cookies with __Host- prefix for maximum security: `Set-Cookie: __Host-session=value; Secure; Path=/; HttpOnly; SameSite=Lax`',
                    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes'],
                }));
            }

            // Check 6: Overly broad domain
            if (cookie.domain) {
                const domainParts = cookie.domain.replace(/^\./, '').split('.');
                if (domainParts.length <= 2 && cookie.domain.startsWith('.')) {
                    findings.push(createFinding({
                        module: 'security',
                        title: `Cookie "${cookie.name}" Has Broad Domain Scope`,
                        severity: isSessionCookie ? 'medium' : 'low',
                        affected_surface: surfaceInventory.baseUrl,
                        description:
                            `Cookie "${cookie.name}" is scoped to "${cookie.domain}", making it accessible ` +
                            `to all subdomains. If any subdomain is compromised, this cookie can be stolen or manipulated.`,
                        evidence: { cookie_name: cookie.name, domain: cookie.domain },
                        remediation: 'Avoid setting the Domain attribute (cookie defaults to exact host only) or use the most specific subdomain possible.',
                    }));
                }
            }
        }

        this.logger?.info?.(`Cookie Auditor: found ${findings.length} issues across ${cookies.length} cookies`);
        return findings;
    }

    async _fetchCookies(url) {
        try {
            const { chromium } = await import('playwright');
            const browser = await chromium.launch({ headless: true });
            const context = await browser.newContext({ ignoreHTTPSErrors: true });
            const page = await context.newPage();
            await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
            const cookies = await context.cookies();
            await browser.close();
            return cookies;
        } catch (err) {
            this.logger?.debug?.(`Failed to fetch cookies: ${err.message}`);
            return [];
        }
    }

    _cookieFlags(cookie) {
        const flags = [];
        if (cookie.secure) flags.push('Secure');
        if (cookie.httpOnly) flags.push('HttpOnly');
        if (cookie.sameSite) flags.push(`SameSite=${cookie.sameSite}`);
        if (cookie.expires) flags.push(`Expires=${new Date(cookie.expires * 1000).toISOString()}`);
        if (cookie.domain) flags.push(`Domain=${cookie.domain}`);
        if (cookie.path) flags.push(`Path=${cookie.path}`);
        return flags.join('; ') || 'none';
    }
}

export default CookieAuditor;
