import { createFinding } from '../../utils/finding.js';

/**
 * CSRFDetector — Detects missing CSRF protection on state-changing forms.
 *
 * Checks for:
 *   - CSRF token hidden fields (_csrf, csrf_token, _token, authenticity_token, etc.)
 *   - CSRF meta tags in page head
 *   - SameSite cookie attribute (mitigates CSRF partially)
 *   - Only flags POST/PUT/DELETE/PATCH forms (GET forms don't need CSRF)
 */
export class CSRFDetector {
    constructor(logger) {
        this.logger = logger;
    }

    async detect(surfaceInventory) {
        this.logger?.info?.('CSRF Detector: starting analysis');
        const findings = [];

        const forms = surfaceInventory.forms || [];
        const pages = surfaceInventory.pages || [];

        // Check SameSite cookie attribute from page cookies (if available)
        const hasSameSiteCookies = this._checkSameSiteCookies(surfaceInventory);

        // Known CSRF token field names
        const csrfFieldNames = [
            '_csrf', 'csrf_token', 'csrf', '_token', 'authenticity_token',
            '__requestverificationtoken', 'csrfmiddlewaretoken', 'xsrf_token',
            '_xsrf', 'anti-csrf-token', 'antiforgerytoken',
        ];

        // Filter to state-changing forms only
        const stateChangingForms = forms.filter(f =>
            ['POST', 'PUT', 'DELETE', 'PATCH'].includes(f.method)
        );

        if (stateChangingForms.length === 0) {
            this.logger?.info?.('CSRF Detector: no state-changing forms found — skipping');
            return findings;
        }

        for (const form of stateChangingForms) {
            // Check 1: CSRF token in form fields
            const hasCsrfField = form.fields?.some(field =>
                csrfFieldNames.includes(field.name?.toLowerCase()) ||
                field.name?.toLowerCase().includes('csrf') ||
                field.name?.toLowerCase().includes('xsrf')
            ) || form.hasCsrfToken;

            if (hasCsrfField) continue; // Protected

            // Check 2: CSRF meta tag on the page
            if (form.hasCsrfMeta) continue; // Protected via JS-injected tokens

            // Check 3: Is this a login form? (login forms typically don't need CSRF)
            const isLoginForm = form.fields?.some(f =>
                f.type === 'password'
            ) && form.fields?.some(f =>
                ['email', 'username', 'user', 'login'].includes(f.name?.toLowerCase()) ||
                f.type === 'email'
            );
            if (isLoginForm) continue;

            // Determine severity based on SameSite cookies
            const severity = hasSameSiteCookies ? 'low' : 'medium';
            const sameSiteNote = hasSameSiteCookies
                ? ' (partially mitigated by SameSite cookies)'
                : ' and no SameSite cookie protection detected';

            findings.push(createFinding({
                module: 'security',
                title: 'Missing CSRF Protection on State-Changing Form',
                severity,
                affected_surface: form.page || form.action,
                description:
                    `Form "${form.id}" with method ${form.method} at ${form.action} ` +
                    `has no CSRF token${sameSiteNote}. ` +
                    `An attacker could craft a page that submits this form on behalf of an authenticated user.`,
                evidence: {
                    form_id: form.id,
                    form_method: form.method,
                    form_action: form.action,
                    field_names: form.fields?.map(f => f.name) || [],
                    page: form.page,
                },
                remediation:
                    'Add a CSRF token to all state-changing forms. Most frameworks provide built-in CSRF middleware: ' +
                    'Express (csurf), Django (csrf_token), Rails (authenticity_token), Laravel (_token). ' +
                    'Additionally, set SameSite=Strict or SameSite=Lax on session cookies.',
                references: [
                    'https://owasp.org/www-community/attacks/csrf',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
                ],
            }));
        }

        this.logger?.info?.(`CSRF Detector: found ${findings.length} issues`);
        return findings;
    }

    _checkSameSiteCookies(inventory) {
        // Check if any page response headers set SameSite cookies
        // This is a best-effort check from the surface data available
        for (const page of (inventory.pages || [])) {
            if (page.cookies) {
                return page.cookies.some(c =>
                    c.sameSite === 'Strict' || c.sameSite === 'Lax'
                );
            }
        }
        return false;
    }
}

export default CSRFDetector;
