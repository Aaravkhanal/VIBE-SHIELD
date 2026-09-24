import { createFinding } from '../../utils/finding.js';
import { DifferentialEngine } from '../differential-engine.js';
import { observedWebCvss } from '../../utils/cvss-evidence.js';

/**
 * SSRFProber — Tests URL parameters and form inputs for Server-Side Request Forgery.
 *
 * Checks:
 *   - URL parameters that accept URLs (url=, callback=, proxy=, etc.)
 *   - Form fields with URL-like inputs
 *   - Tests with internal IPs (127.0.0.1, 169.254.169.254, etc.)
 *   - Detects if server fetches attacker-controlled URLs
 */
export class SSRFProber {
    constructor(logger) {
        this.logger = logger;
        this.differential = new DifferentialEngine({ logger, timeoutMs: 10000 });
    }

    async probe(surfaceInventory) {
        this.logger?.info?.('SSRF Prober: starting analysis');
        const findings = [];
        const pages = surfaceInventory.pages || [];
        const baseUrl = new URL(surfaceInventory.baseUrl);

        // Parameter names commonly vulnerable to SSRF
        const ssrfParams = [
            'url', 'uri', 'src', 'source', 'link', 'href',
            'callback', 'callback_url', 'redirect', 'redirect_url',
            'proxy', 'proxy_url', 'fetch', 'load', 'request',
            'page', 'path', 'file', 'document', 'doc',
            'image', 'img', 'icon', 'preview', 'thumbnail',
            'feed', 'rss', 'xml', 'api', 'endpoint',
            'webhook', 'hook', 'notify', 'notification_url',
            'target', 'dest', 'destination', 'site',
            'domain', 'host', 'server', 'remote',
            'download', 'import', 'export',
        ];

        // SSRF test payloads (internal/metadata IPs)
        const ssrfPayloads = [
            { url: 'http://127.0.0.1:80', label: 'localhost' },
            { url: 'http://169.254.169.254/latest/meta-data/', label: 'AWS metadata' },
            { url: 'http://metadata.google.internal/computeMetadata/v1/', label: 'GCP metadata' },
            { url: 'http://169.254.169.254/metadata/v1/', label: 'Azure metadata' },
            { url: 'http://[::1]/', label: 'IPv6 localhost' },
            { url: 'http://0.0.0.0/', label: 'zero address' },
            { url: 'http://127.0.0.1:22', label: 'localhost SSH' },
            { url: 'http://127.0.0.1:3306', label: 'localhost MySQL' },
        ];

        const testedEndpoints = new Set();

        // Scan URL parameters
        for (const page of pages) {
            try {
                const pageUrl = new URL(page.url);
                for (const [key, value] of pageUrl.searchParams) {
                    if (!ssrfParams.includes(key.toLowerCase())) continue;

                    const testKey = `${pageUrl.pathname}::${key}`;
                    if (testedEndpoints.has(testKey)) continue;
                    testedEndpoints.add(testKey);

                    // Test each payload
                    for (const payload of ssrfPayloads) {
                        const testUrl = new URL(page.url);
                        testUrl.searchParams.set(key, payload.url);

                        try {
                            const differential = await this._testPayload(page.url, key, value, payload);
                            const response = differential.aggregates.payload.representative;
                            const body = response?.body || '';
                            const isSSRF = differential.confirmed && this._detectSSRFResponse(body, response?.status, payload);

                            if (isSSRF) {
                                findings.push(createFinding({
                                    module: 'security',
                                    title: `SSRF via "${key}" Parameter (${payload.label})`,
                                    severity: payload.label.includes('metadata') ? 'critical' : 'high',
                                    affected_surface: page.url,
                                    description:
                                        `Parameter "${key}" on ${pageUrl.pathname} appears vulnerable to SSRF. ` +
                                        `Payload targeting ${payload.label} (${payload.url}) returned ` +
                                        `indicators of internal resource access. ` +
                                        `An attacker could use this to access internal services, cloud metadata, ` +
                                        `or scan the internal network.`,
                                    evidence: {
                                        parameter: key,
                                        payload: payload.url,
                                        payload_type: payload.label,
                                        response_status: response.status,
                                        response_snippet: body.slice(0, 500),
                                        test_url: testUrl.toString(),
                                        differential: differential.evidence,
                                    },
                                    cvssAssessment: observedWebCvss({
                                        metrics: { attackVector: 'NETWORK', attackComplexity: 'LOW', privilegesRequired: 'NONE', userInteraction: 'NONE', scope: 'CHANGED', confidentiality: 'LOW', integrity: 'NONE', availability: 'NONE' },
                                        request: `GET ${testUrl}`, role: 'anonymous', observation: `${payload.label} internal-resource response`,
                                        boundary: 'The server fetched a resource outside the public web application boundary.',
                                        impacts: { confidentiality: `The response included an ${payload.label} internal-resource indicator. Broad data access was not verified.` },
                                    }),
                                    verification: {
                                        level: 'high_confidence',
                                        reason: 'Repeated internal-resource payloads produced a stable signal absent from both the normal request and harmless external control.',
                                        method: 'repeated-ssrf-differential',
                                        proof: {
                                            originalRequest: { method: 'GET', url: page.url, parameter: key, value },
                                            mutatedRequest: { method: 'GET', url: testUrl.toString(), parameter: key, payload: payload.url },
                                            baselineResponse: differential.evidence.baseline,
                                            vulnerableResponse: differential.evidence.payload,
                                            responseDifference: differential.evidence,
                                            reproductionCommand: `curl -i ${JSON.stringify(testUrl.toString())}`,
                                            accountRole: 'anonymous',
                                        },
                                    },
                                    reproduction: [
                                        `1. Open: ${testUrl.toString()}`,
                                        `2. Observe response contains internal service data`,
                                    ],
                                    remediation:
                                        'Validate and sanitize all URL inputs server-side. ' +
                                        'Use an allowlist of permitted domains/IPs. ' +
                                        'Block requests to internal/private IP ranges (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). ' +
                                        'Disable HTTP redirects in server-side HTTP clients. ' +
                                        'Use cloud metadata service v2 (IMDSv2) with token requirement.',
                                    references: [
                                        'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
                                        'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
                                    ],
                                }));
                                break; // One finding per param
                            }
                        } catch {
                            // Skip failed requests
                        }
                    }
                }
            } catch {
                // Invalid URL
            }
        }

        // Scan API endpoints for SSRF
        const apiEndpoints = surfaceInventory.apiEndpoints || [];
        for (const api of apiEndpoints) {
            if (api.method !== 'POST' && api.method !== 'PUT') continue;

            try {
                const apiUrl = new URL(api.url);

                // Check if the API path suggests URL handling
                const ssrfPathPatterns = [
                    '/fetch', '/proxy', '/download', '/import', '/webhook',
                    '/preview', '/screenshot', '/render', '/pdf', '/convert',
                    '/load', '/callback', '/scrape', '/crawl',
                ];

                const hasSSRFPath = ssrfPathPatterns.some(p => apiUrl.pathname.toLowerCase().includes(p));
                if (!hasSSRFPath) continue;

                const testKey = `api::${api.method}::${apiUrl.pathname}`;
                if (testedEndpoints.has(testKey)) continue;
                testedEndpoints.add(testKey);

                findings.push(createFinding({
                    module: 'security',
                    title: `SSRF Input Surface Not Assessed: ${api.method} ${apiUrl.pathname}`,
                    severity: 'info',
                    affected_surface: api.url,
                    description:
                        `API endpoint ${api.method} ${apiUrl.pathname} has a path pattern commonly ` +
                        `associated with SSRF (${ssrfPathPatterns.find(p => apiUrl.pathname.toLowerCase().includes(p))}). ` +
                        `The request-body schema was not available, so the scanner did not inject or verify an SSRF payload.`,
                    evidence: {
                        method: api.method,
                        path: apiUrl.pathname,
                        status: api.status,
                    },
                    verification: {
                        level: 'not_assessed',
                        reason: 'The endpoint path suggests URL processing, but no request-body field could be identified for controlled differential testing.',
                        method: 'surface-discovery',
                    },
                    remediation: 'Ensure all URL inputs to this endpoint are validated against an allowlist.',
                }));
            } catch {
                // Skip
            }
        }

        this.logger?.info?.(`SSRF Prober: found ${findings.length} issues`);
        return findings;
    }

    _detectSSRFResponse(body, status, payload) {
        // Check for indicators that an internal resource was accessed
        const bodyLower = body.toLowerCase();

        // Cloud metadata indicators
        if (payload.label.includes('metadata')) {
            const metadataIndicators = [
                'ami-id', 'instance-id', 'instance-type', 'local-ipv4',
                'security-credentials', 'iam', 'access-key',
                'computeMetadata', 'project-id', 'service-accounts',
                'subscriptionId', 'resourceGroupName',
            ];
            return metadataIndicators.some(ind => bodyLower.includes(ind.toLowerCase()));
        }

        // Localhost indicators
        if (payload.label === 'localhost') {
            // If we get a different response than normal (not the site's 404/error page)
            return status === 200 && (
                bodyLower.includes('server') ||
                bodyLower.includes('apache') ||
                bodyLower.includes('nginx') ||
                bodyLower.includes('iis') ||
                bodyLower.includes('directory listing')
            );
        }

        // Port scan indicators (connection refused = port closed but SSRF worked)
        if (payload.label.includes('SSH') || payload.label.includes('MySQL')) {
            return body.includes('SSH') || body.includes('mysql') || body.includes('connection refused');
        }

        return false;
    }

    async _testPayload(originalUrl, parameter, originalValue, payload) {
        const makeUrl = value => {
            const url = new URL(originalUrl);
            url.searchParams.set(parameter, value);
            return url.toString();
        };
        const request = value => ({
            url: makeUrl(value), method: 'GET', redirect: 'follow',
            headers: { 'User-Agent': 'VIBE-SHIELD-SecurityScanner/1.0' }, timeoutMs: 10000,
        });
        return this.differential.run({
            baseline: request(originalValue),
            control: request('https://example.invalid/vibe-shield-control'),
            payload: request(payload.url),
            signal: snapshot => this._detectSSRFResponse(snapshot.body, snapshot.status, payload),
        });
    }
}

export default SSRFProber;
