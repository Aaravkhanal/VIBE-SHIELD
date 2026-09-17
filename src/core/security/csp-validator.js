import { createFinding } from '../../utils/finding.js';

/**
 * CSPValidator — Deep Content Security Policy effectiveness analysis.
 *
 * Goes beyond "does CSP exist?" to evaluate:
 *   - unsafe-inline / unsafe-eval in script-src
 *   - Wildcard sources (*.example.com, *)
 *   - data: URI scheme in script/object sources
 *   - Missing important directives (default-src, script-src, object-src)
 *   - Overly permissive connect-src (enables data exfiltration)
 *   - Report-only mode (not enforcing)
 *   - base-uri missing (allows base tag injection)
 *   - form-action missing (allows form hijacking)
 *   - Known CSP bypass hosts (e.g., CDNs with JSONP)
 */
export class CSPValidator {
    constructor(logger) {
        this.logger = logger;
    }

    async validate(surfaceInventory) {
        this.logger?.info?.('CSP Validator: starting deep CSP analysis');
        const findings = [];

        const pages = surfaceInventory.pages || [];
        const checkedOrigins = new Set();

        for (const page of pages) {
            const origin = new URL(page.url).origin;
            if (checkedOrigins.has(origin)) continue;
            checkedOrigins.add(origin);

            try {
                const headers = await this._fetchHeaders(page.url);
                const csp = headers['content-security-policy'];
                const cspRO = headers['content-security-policy-report-only'];

                // Report-only CSP without enforcement
                if (cspRO && !csp) {
                    findings.push(createFinding({
                        module: 'security',
                        title: 'CSP in Report-Only Mode (Not Enforced)',
                        severity: 'medium',
                        affected_surface: page.url,
                        description:
                            'Content-Security-Policy-Report-Only is set but no enforcing CSP exists. ' +
                            'The policy only logs violations without blocking them.',
                        evidence: { csp_report_only: cspRO },
                        remediation: 'Move from Report-Only to enforced CSP once violations are resolved.',
                    }));
                }

                if (!csp) continue;

                const directives = this._parseCSP(csp);

                // Check 1: Missing default-src
                if (!directives['default-src']) {
                    findings.push(createFinding({
                        module: 'security',
                        title: 'CSP Missing default-src Directive',
                        severity: 'medium',
                        affected_surface: page.url,
                        description:
                            'CSP lacks a default-src directive. Without it, any missing specific directive ' +
                            'falls back to allowing everything.',
                        evidence: { csp },
                        remediation: "Add `default-src 'self'` as a baseline.",
                    }));
                }

                // Check 2: Wildcards in critical directives
                const criticalDirectives = ['script-src', 'default-src', 'connect-src', 'object-src'];
                for (const dir of criticalDirectives) {
                    const values = directives[dir] || [];
                    if (values.includes('*')) {
                        findings.push(createFinding({
                            module: 'security',
                            title: `CSP ${dir} Contains Wildcard (*)`,
                            severity: 'high',
                            affected_surface: page.url,
                            description:
                                `The ${dir} directive contains a wildcard (*), allowing resources from any origin. ` +
                                `This effectively disables CSP protection for this resource type.`,
                            evidence: { directive: dir, values, csp },
                            remediation: `Replace * with specific allowed origins in ${dir}.`,
                        }));
                    }
                }

                // Check 3: data: URI in script-src or object-src
                for (const dir of ['script-src', 'default-src', 'object-src']) {
                    const values = directives[dir] || [];
                    if (values.includes('data:')) {
                        findings.push(createFinding({
                            module: 'security',
                            title: `CSP ${dir} Allows data: URIs`,
                            severity: dir === 'script-src' ? 'high' : 'medium',
                            affected_surface: page.url,
                            description:
                                `The ${dir} directive allows data: URIs. ` +
                                `In script-src, this enables XSS via data: URI payloads.`,
                            evidence: { directive: dir, values, csp },
                            remediation: `Remove data: from ${dir} directive.`,
                        }));
                    }
                }

                // Check 4: unsafe-inline in script-src without nonce/hash
                const scriptSrc = directives['script-src'] || directives['default-src'] || [];
                if (scriptSrc.includes("'unsafe-inline'")) {
                    const hasNonce = scriptSrc.some(v => v.startsWith("'nonce-"));
                    const hasHash = scriptSrc.some(v => v.startsWith("'sha256-") || v.startsWith("'sha384-") || v.startsWith("'sha512-"));
                    if (!hasNonce && !hasHash) {
                        findings.push(createFinding({
                            module: 'security',
                            title: "CSP script-src Allows unsafe-inline Without Nonce/Hash",
                            severity: 'high',
                            affected_surface: page.url,
                            description:
                                "CSP allows 'unsafe-inline' in script-src without nonce or hash fallback. " +
                                "This completely defeats XSS protection from CSP.",
                            evidence: { script_src: scriptSrc, csp },
                            remediation: "Remove 'unsafe-inline' and use nonces or hashes for legitimate inline scripts.",
                        }));
                    }
                }

                // Check 5: unsafe-eval
                if (scriptSrc.includes("'unsafe-eval'")) {
                    findings.push(createFinding({
                        module: 'security',
                        title: "CSP Allows unsafe-eval",
                        severity: 'medium',
                        affected_surface: page.url,
                        description:
                            "CSP allows 'unsafe-eval', permitting eval() and dynamic code execution.",
                        evidence: { script_src: scriptSrc, csp },
                        remediation: "Remove 'unsafe-eval' and refactor code to avoid eval().",
                    }));
                }

                // Check 6: Missing object-src (Flash/plugin attacks)
                if (!directives['object-src'] && !directives['default-src']?.includes("'none'")) {
                    findings.push(createFinding({
                        module: 'security',
                        title: "CSP Missing object-src Directive",
                        severity: 'low',
                        affected_surface: page.url,
                        description:
                            "CSP does not restrict object-src. Plugins (Flash, Java) can be embedded.",
                        evidence: { csp },
                        remediation: "Add `object-src 'none'` to CSP.",
                    }));
                }

                // Check 7: Missing base-uri (base tag injection)
                if (!directives['base-uri']) {
                    findings.push(createFinding({
                        module: 'security',
                        title: "CSP Missing base-uri Directive",
                        severity: 'low',
                        affected_surface: page.url,
                        description:
                            "CSP does not restrict base-uri. An attacker who can inject HTML " +
                            "could add a <base> tag to redirect relative URLs to a malicious server.",
                        evidence: { csp },
                        remediation: "Add `base-uri 'self'` or `base-uri 'none'` to CSP.",
                    }));
                }

                // Check 8: Missing form-action (form hijacking)
                if (!directives['form-action']) {
                    findings.push(createFinding({
                        module: 'security',
                        title: "CSP Missing form-action Directive",
                        severity: 'low',
                        affected_surface: page.url,
                        description:
                            "CSP does not restrict form-action. Forms can submit data to any origin.",
                        evidence: { csp },
                        remediation: "Add `form-action 'self'` to restrict form submissions to same origin.",
                    }));
                }

                // Check 9: Known CSP bypass CDNs in script-src
                const bypassDomains = [
                    'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
                    'ajax.googleapis.com', 'accounts.google.com',
                    '*.googleapis.com', '*.gstatic.com',
                ];
                for (const val of scriptSrc) {
                    const match = bypassDomains.find(d => val.includes(d));
                    if (match) {
                        findings.push(createFinding({
                            module: 'security',
                            title: `CSP script-src Includes Known Bypass Host: ${match}`,
                            severity: 'medium',
                            affected_surface: page.url,
                            description:
                                `CSP allows scripts from ${match}, which hosts JSONP endpoints or ` +
                                `user-uploaded files that can be abused to bypass CSP.`,
                            evidence: { bypass_host: match, script_src: scriptSrc },
                            remediation: "Use 'strict-dynamic' with nonces instead of allowlisting CDN domains.",
                            references: ['https://csp-evaluator.withgoogle.com/'],
                        }));
                        break; // One finding per page
                    }
                }

                // Check 10: Overly permissive connect-src
                const connectSrc = directives['connect-src'] || [];
                if (connectSrc.includes('*') || connectSrc.length === 0) {
                    if (directives['default-src']?.includes('*') || (!directives['connect-src'] && !directives['default-src'])) {
                        findings.push(createFinding({
                            module: 'security',
                            title: "CSP Does Not Restrict connect-src (Data Exfiltration Risk)",
                            severity: 'medium',
                            affected_surface: page.url,
                            description:
                                "CSP does not restrict connect-src. XHR/fetch requests can be made to any origin, " +
                                "enabling data exfiltration via XMLHttpRequest or fetch().",
                            evidence: { connect_src: connectSrc, csp },
                            remediation: "Add `connect-src 'self'` with specific API origins.",
                        }));
                    }
                }
            } catch (err) {
                this.logger?.debug?.(`CSP validation failed for ${page.url}: ${err.message}`);
            }
        }

        this.logger?.info?.(`CSP Validator: found ${findings.length} issues`);
        return findings;
    }

    _parseCSP(csp) {
        const directives = {};
        for (const part of csp.split(';')) {
            const trimmed = part.trim();
            if (!trimmed) continue;
            const [name, ...values] = trimmed.split(/\s+/);
            directives[name.toLowerCase()] = values;
        }
        return directives;
    }

    async _fetchHeaders(url) {
        try {
            const response = await fetch(url, {
                method: 'HEAD',
                redirect: 'follow',
                headers: { 'User-Agent': 'VIBE SHIELD-SecurityScanner/1.0' },
                signal: AbortSignal.timeout(10000),
            });
            const headers = {};
            for (const [key, value] of response.headers) {
                headers[key.toLowerCase()] = value;
            }
            return headers;
        } catch {
            return {};
        }
    }
}

export default CSPValidator;
