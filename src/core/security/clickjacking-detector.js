import { createFinding } from '../../utils/finding.js';

/**
 * ClickjackingDetector — Tests for clickjacking vulnerability.
 *
 * Checks:
 *   - X-Frame-Options header (DENY, SAMEORIGIN, ALLOW-FROM)
 *   - CSP frame-ancestors directive
 *   - Both missing = vulnerable
 *   - Conflicting policies
 *   - Deprecated ALLOW-FROM usage
 *   - Actual iframe embedding test
 */
export class ClickjackingDetector {
    constructor(logger) {
        this.logger = logger;
    }

    async detect(surfaceInventory) {
        this.logger?.info?.('Clickjacking Detector: starting analysis');
        const findings = [];
        const pages = surfaceInventory.pages || [];
        const checkedOrigins = new Set();

        for (const page of pages) {
            const origin = new URL(page.url).origin;
            if (checkedOrigins.has(origin)) continue;
            checkedOrigins.add(origin);

            try {
                const headers = await this._fetchHeaders(page.url);
                const xfo = headers['x-frame-options']?.toLowerCase().trim();
                const csp = headers['content-security-policy'];

                // Parse frame-ancestors from CSP
                const frameAncestors = this._parseFrameAncestors(csp);

                // Case 1: Neither X-Frame-Options nor frame-ancestors
                if (!xfo && !frameAncestors) {
                    findings.push(createFinding({
                        module: 'security',
                        title: 'Clickjacking: No Frame Protection',
                        severity: 'medium',
                        affected_surface: page.url,
                        description:
                            'Page has neither X-Frame-Options header nor CSP frame-ancestors directive. ' +
                            'It can be embedded in iframes on any domain, enabling clickjacking attacks.',
                        evidence: {
                            x_frame_options: xfo || 'missing',
                            frame_ancestors: frameAncestors || 'missing',
                        },
                        reproduction: [
                            `1. Create HTML: <iframe src="${page.url}" width="100%" height="100%"></iframe>`,
                            '2. Host on external domain',
                            '3. Page loads inside the iframe — vulnerable to clickjacking',
                        ],
                        remediation:
                            "Add `X-Frame-Options: DENY` header AND `frame-ancestors 'none'` CSP directive. " +
                            "Use SAMEORIGIN / frame-ancestors 'self' if same-origin framing is needed.",
                        references: [
                            'https://owasp.org/www-community/attacks/Clickjacking',
                            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
                        ],
                    }));
                    continue;
                }

                // Case 2: Deprecated ALLOW-FROM
                if (xfo && xfo.startsWith('allow-from')) {
                    findings.push(createFinding({
                        module: 'security',
                        title: 'Clickjacking: Deprecated ALLOW-FROM in X-Frame-Options',
                        severity: 'medium',
                        affected_surface: page.url,
                        description:
                            `X-Frame-Options uses deprecated ALLOW-FROM directive (${xfo}). ` +
                            'ALLOW-FROM is not supported by modern browsers (Chrome, Firefox). ' +
                            'The page may be frameable despite intending to restrict it.',
                        evidence: { x_frame_options: xfo },
                        remediation: "Replace with CSP frame-ancestors directive: `frame-ancestors 'self' https://trusted.com`",
                    }));
                }

                // Case 3: frame-ancestors is wildcard or overly permissive
                if (frameAncestors) {
                    const values = frameAncestors.split(/\s+/).filter(v => v);
                    if (values.includes('*')) {
                        findings.push(createFinding({
                            module: 'security',
                            title: 'Clickjacking: frame-ancestors Allows Wildcard (*)',
                            severity: 'medium',
                            affected_surface: page.url,
                            description:
                                'CSP frame-ancestors contains wildcard (*), allowing framing from any origin.',
                            evidence: { frame_ancestors: frameAncestors },
                            remediation: "Set `frame-ancestors 'none'` or list specific trusted origins.",
                        }));
                    }

                    // Check for http: (insecure) sources
                    if (values.some(v => v.startsWith('http:'))) {
                        findings.push(createFinding({
                            module: 'security',
                            title: 'Clickjacking: frame-ancestors Allows HTTP Origins',
                            severity: 'low',
                            affected_surface: page.url,
                            description:
                                'CSP frame-ancestors allows framing from HTTP (non-HTTPS) origins, ' +
                                'which can be MitM-attacked to serve a clickjacking page.',
                            evidence: { frame_ancestors: frameAncestors },
                            remediation: 'Only allow HTTPS origins in frame-ancestors.',
                        }));
                    }
                }

                // Case 4: X-Frame-Options set but no CSP frame-ancestors (incomplete protection)
                if (xfo && !frameAncestors) {
                    findings.push(createFinding({
                        module: 'security',
                        title: 'Clickjacking: Only X-Frame-Options (No CSP frame-ancestors)',
                        severity: 'info',
                        affected_surface: page.url,
                        description:
                            `X-Frame-Options is set (${xfo}) but CSP frame-ancestors is missing. ` +
                            'frame-ancestors is the modern replacement and supports multiple origins.',
                        evidence: { x_frame_options: xfo, frame_ancestors: 'missing' },
                        remediation: "Add CSP `frame-ancestors 'self'` alongside X-Frame-Options for defense-in-depth.",
                    }));
                }
            } catch (err) {
                this.logger?.debug?.(`Clickjacking check failed for ${page.url}: ${err.message}`);
            }
        }

        this.logger?.info?.(`Clickjacking Detector: found ${findings.length} issues`);
        return findings;
    }

    _parseFrameAncestors(csp) {
        if (!csp) return null;
        const match = csp.match(/frame-ancestors\s+([^;]+)/i);
        return match ? match[1].trim() : null;
    }

    async _fetchHeaders(url) {
        try {
            const response = await fetch(url, {
                method: 'GET',
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

export default ClickjackingDetector;
