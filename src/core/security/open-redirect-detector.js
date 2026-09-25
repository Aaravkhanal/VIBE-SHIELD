import { createFinding } from '../../utils/finding.js';
import { DifferentialEngine } from '../differential-engine.js';

/**
 * OpenRedirectDetector — Probes URL parameters for open redirect vulnerabilities.
 *
 * Checks for redirect-like parameters and tests if they allow
 * navigation to external domains.
 */
export class OpenRedirectDetector {
    constructor(logger, coverageTracker = null) {
        this.logger = logger;
        this.differential = new DifferentialEngine({ logger, coverageTracker });
    }

    async detect(surfaceInventory) {
        this.logger?.info?.('Open Redirect Detector: starting analysis');
        const findings = [];

        const pages = surfaceInventory.pages || [];
        const baseUrl = new URL(surfaceInventory.baseUrl);

        // Redirect parameter names to look for
        const redirectParams = [
            'redirect', 'redirect_url', 'redirect_uri', 'redirectUrl',
            'url', 'next', 'return', 'return_to', 'returnTo', 'return_url',
            'continue', 'dest', 'destination', 'go', 'goto', 'target',
            'rurl', 'redir', 'forward', 'forward_url', 'callback',
            'callback_url', 'fallback', 'checkout_url', 'ref',
        ];

        // Evil domains to test with
        const evilPayloads = [
            'https://evil.com',
            '//evil.com',
            'https://evil.com/%2f..',
            '////evil.com',
            'https://evil.com@' + baseUrl.hostname,
            '/\\evil.com',
        ];

        // Scan all page URLs for redirect parameters
        const testedUrls = new Set();

        for (const page of pages) {
            try {
                const pageUrl = new URL(page.url);
                const params = pageUrl.searchParams;

                for (const [key, value] of params) {
                    if (!redirectParams.includes(key.toLowerCase())) continue;

                    const testKey = `${pageUrl.pathname}::${key}`;
                    if (testedUrls.has(testKey)) continue;
                    testedUrls.add(testKey);

                    // Test each payload
                    for (const payload of evilPayloads) {
                        const testUrl = new URL(page.url);
                        testUrl.searchParams.set(key, payload);

                        try {
                            const differential = await this._testRedirect(page.url, key, payload, baseUrl);
                            const response = differential.aggregates.payload.representative;
                            const location = response?.location;
                            if (differential.confirmed && location && this._isExternalRedirect(location, baseUrl)) {
                                findings.push(createFinding({
                                    module: 'security',
                                    title: 'Open Redirect Vulnerability',
                                    severity: 'medium',
                                    affected_surface: page.url,
                                    description:
                                        `Parameter "${key}" on ${pageUrl.pathname} allows redirect to external domain. ` +
                                        `Payload "${payload}" resulted in redirect to "${location}". ` +
                                        `This can be used for phishing attacks by crafting URLs that appear to come from trusted domain.`,
                                    evidence: {
                                        parameter: key,
                                        original_value: value,
                                        payload,
                                        redirect_location: location,
                                        response_status: response.status,
                                        test_url: testUrl.toString(),
                                        differential: differential.evidence,
                                    },
                                    verification: {
                                        level: 'high_confidence',
                                        reason: 'A controlled redirect parameter produced an external Location header.',
                                        method: 'http-redirect-differential',
                                        proof: {
                                            originalRequest: { method: 'GET', url: page.url, parameter: key, value },
                                            mutatedRequest: { method: 'GET', url: testUrl.toString(), parameter: key, payload },
                                            baselineResponse: differential.evidence.baseline,
                                            vulnerableResponse: { status: response.status, location },
                                            responseDifference: { externalRedirectIntroduced: true, destination: location, differential: differential.evidence.comparisons },
                                            reproductionCommand: `curl -i ${JSON.stringify(testUrl.toString())}`,
                                            accountRole: 'anonymous',
                                        },
                                    },
                                    reproduction: [
                                        `Open: ${testUrl.toString()}`,
                                        `Observe redirect to: ${location}`,
                                    ],
                                    remediation:
                                        'Validate redirect URLs server-side. Use an allowlist of permitted redirect domains. ' +
                                        'Alternatively, use relative paths only for redirects and reject any URL starting with ' +
                                        'http://, https://, or //.',
                                    references: [
                                        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect',
                                        'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
                                    ],
                                }));
                                // One finding per parameter is enough
                                break;
                            }
                        } catch {
                            // Network error — skip this payload
                        }
                    }
                }
            } catch {
                // Invalid URL — skip
            }
        }

        // Also check for redirect links on pages (links that go to /redirect?url= etc.)
        for (const page of pages) {
            for (const link of (page.links || [])) {
                try {
                    const linkUrl = new URL(link);
                    if (linkUrl.origin !== baseUrl.origin) continue;

                    const params = linkUrl.searchParams;
                    for (const [key] of params) {
                        if (!redirectParams.includes(key.toLowerCase())) continue;

                        const testKey = `${linkUrl.pathname}::${key}`;
                        if (testedUrls.has(testKey)) continue;
                        testedUrls.add(testKey);

                        // Quick test with one payload
                        const testUrl = new URL(link);
                        testUrl.searchParams.set(key, 'https://evil.com');

                        try {
                            const differential = await this._testRedirect(link, key, 'https://evil.com', baseUrl);
                            const response = differential.aggregates.payload.representative;
                            const location = response?.location;
                            if (differential.confirmed && location && this._isExternalRedirect(location, baseUrl)) {
                                findings.push(createFinding({
                                    module: 'security',
                                    title: 'Open Redirect via Link Parameter',
                                    severity: 'medium',
                                    affected_surface: link,
                                    description:
                                        `Redirect parameter "${key}" on ${linkUrl.pathname} allows external redirect. ` +
                                        `Found in link on page ${page.url}.`,
                                    evidence: {
                                        parameter: key,
                                        redirect_location: location,
                                        found_on_page: page.url,
                                        test_url: testUrl.toString(),
                                        differential: differential.evidence,
                                    },
                                    verification: {
                                        level: 'high_confidence',
                                        reason: 'A controlled link mutation produced an external Location header.',
                                        method: 'http-redirect-differential',
                                        proof: {
                                            originalRequest: { method: 'GET', url: link },
                                            mutatedRequest: { method: 'GET', url: testUrl.toString(), parameter: key, payload: 'https://evil.com' },
                                            baselineResponse: differential.evidence.baseline,
                                            vulnerableResponse: { status: response.status, location },
                                            responseDifference: { externalRedirectIntroduced: true, destination: location, differential: differential.evidence.comparisons },
                                            reproductionCommand: `curl -i ${JSON.stringify(testUrl.toString())}`,
                                            accountRole: 'anonymous',
                                        },
                                    },
                                    remediation:
                                        'Validate redirect URLs server-side with an allowlist of permitted domains.',
                                    references: [
                                        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect',
                                    ],
                                }));
                            }
                        } catch {
                            // Skip
                        }
                    }
                } catch {
                    // Invalid URL
                }
            }
        }

        this.logger?.info?.(`Open Redirect Detector: found ${findings.length} issues`);
        return findings;
    }

    _isExternalRedirect(location, baseUrl) {
        try {
            // Handle protocol-relative URLs
            if (location.startsWith('//')) {
                location = 'https:' + location;
            }

            // Handle absolute URLs
            if (location.startsWith('http://') || location.startsWith('https://')) {
                const redirectUrl = new URL(location);
                return redirectUrl.hostname !== baseUrl.hostname &&
                    !redirectUrl.hostname.endsWith('.' + baseUrl.hostname);
            }

            // Relative URLs are safe
            return false;
        } catch {
            return false;
        }
    }

    async _testRedirect(originalUrl, parameter, payload, baseUrl) {
        const baselineUrl = new URL(originalUrl);
        const controlUrl = new URL(originalUrl);
        controlUrl.searchParams.set(parameter, '/.vibe-shield-redirect-control');
        const payloadUrl = new URL(originalUrl);
        payloadUrl.searchParams.set(parameter, payload);
        const request = url => ({
            url: url.toString(), method: 'GET', redirect: 'manual',
            headers: { 'User-Agent': 'VIBE-SHIELD-SecurityScanner/1.0' },
        });
        return this.differential.run({
            baseline: request(baselineUrl),
            control: request(controlUrl),
            payload: request(payloadUrl),
            signal: snapshot => Boolean(snapshot.location && this._isExternalRedirect(snapshot.location, baseUrl)),
        });
    }
}

export default OpenRedirectDetector;
