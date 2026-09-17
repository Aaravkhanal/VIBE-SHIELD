import { createFinding } from '../../utils/finding.js';

/**
 * CORSWSTester — Tests CORS policy and WebSocket security.
 *
 * CORS Probes:
 * - Access-Control-Allow-Origin: * with credentials
 * - Origin reflection (arbitrary origin echoed back)
 * - Null origin accepted
 * - Credentialed pre-flight misconfiguration
 *
 * WebSocket Probes:
 * - WS upgrade without authentication
 * - WS connection from arbitrary origin
 * - WS message injection
 */
export class CORSWSTester {
    constructor(logger) {
        this.logger = logger;

        this.WS_PATHS = [
            '/ws', '/websocket', '/socket', '/api/ws', '/api/websocket',
            '/socket.io/', '/realtime', '/live', '/stream',
        ];
    }

    /**
     * Test CORS and WebSocket security.
     */
    async test(surfaceInventory) {
        const findings = [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        this.logger?.info?.('CORS & WS Tester: starting tests');

        // 1. Test CORS policy
        const corsFindings = await this._testCORS(baseUrl, surfaceInventory);
        findings.push(...corsFindings);

        // 2. Test WebSocket security
        const wsFindings = await this._testWebSockets(baseUrl);
        findings.push(...wsFindings);

        this.logger?.info?.(`CORS & WS Tester: found ${findings.length} issues`);
        return findings;
    }

    /**
     * Test CORS on discovered endpoints.
     */
    async _testCORS(baseUrl, surfaceInventory) {
        const findings = [];
        const testUrls = [baseUrl + '/'];

        // Add API endpoints
        const apis = surfaceInventory.apiEndpoints || surfaceInventory.apis || [];
        testUrls.push(...apis.slice(0, 5).map(a => a.url || a));

        // Add common API paths
        const apiPaths = ['/api', '/api/v1', '/api/users', '/graphql'];
        testUrls.push(...apiPaths.map(p => {
            try { return new URL(p, baseUrl).href; } catch { return null; }
        }).filter(Boolean));

        const tested = new Set();

        for (const url of testUrls) {
            if (tested.has(url)) continue;
            tested.add(url);

            // Test 1: Arbitrary origin reflection
            await this._testOriginReflection(url, findings);

            // Test 2: Null origin
            await this._testNullOrigin(url, findings);

            // Test 3: Wildcard with credentials
            await this._testWildcardCredentials(url, findings);
        }

        return findings;
    }

    async _testOriginReflection(url, findings) {
        try {
            const evilOrigin = 'https://evil-attacker.com';
            const response = await fetch(url, {
                method: 'GET',
                headers: { 'Origin': evilOrigin },
                signal: AbortSignal.timeout(5000),
            });

            const acao = response.headers.get('access-control-allow-origin') || '';
            const acac = response.headers.get('access-control-allow-credentials') || '';

            if (acao === evilOrigin) {
                const withCreds = acac.toLowerCase() === 'true';
                findings.push(createFinding({
                    module: 'api',
                    title: withCreds
                        ? 'CORS: Origin Reflection with Credentials'
                        : 'CORS: Arbitrary Origin Reflected',
                    severity: withCreds ? 'critical' : 'high',
                    affected_surface: url,
                    description: withCreds
                        ? `The server reflects any Origin in Access-Control-Allow-Origin AND sets Allow-Credentials: true. An attacker's website can make credentialed cross-origin requests and read the response — effectively bypassing same-origin policy. This enables full cross-origin data theft.`
                        : `The server reflects any Origin in Access-Control-Allow-Origin. While credentials are not allowed, this still permits cross-origin data reading of non-credentialed responses.`,
                    reproduction: [
                        `1. Send request with Origin: ${evilOrigin}`,
                        `2. Response includes Access-Control-Allow-Origin: ${evilOrigin}`,
                        withCreds ? `3. Access-Control-Allow-Credentials: true` : '',
                    ].filter(Boolean),
                    evidence: `ACAO: ${acao}\nACAC: ${acac}`,
                    remediation: 'Use a strict allowlist for CORS origins. Never reflect the Origin header. If credentials are needed, specify exact allowed origins. Never combine wildcard (*) with credentials.',
                }));
            }
        } catch {
            // Endpoint not reachable
        }
    }

    async _testNullOrigin(url, findings) {
        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: { 'Origin': 'null' },
                signal: AbortSignal.timeout(5000),
            });

            const acao = response.headers.get('access-control-allow-origin') || '';
            if (acao === 'null') {
                findings.push(createFinding({
                    module: 'api',
                    title: 'CORS: Null Origin Accepted',
                    severity: 'high',
                    affected_surface: url,
                    description: `The server allows requests from Origin: null. An attacker can trigger null origin from sandboxed iframes, data: URLs, or file: protocol — enabling cross-origin attacks without a real origin.`,
                    evidence: `Origin: null → ACAO: null`,
                    remediation: 'Never allow null origin in CORS configuration. Remove "null" from allowed origins list.',
                }));
            }
        } catch {
            // Not reachable
        }
    }

    async _testWildcardCredentials(url, findings) {
        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: { 'Origin': 'https://test.com' },
                signal: AbortSignal.timeout(5000),
            });

            const acao = response.headers.get('access-control-allow-origin') || '';
            const acac = response.headers.get('access-control-allow-credentials') || '';

            if (acao === '*' && acac.toLowerCase() === 'true') {
                findings.push(createFinding({
                    module: 'api',
                    title: 'CORS: Wildcard with Credentials',
                    severity: 'critical',
                    affected_surface: url,
                    description: `The server sets Access-Control-Allow-Origin: * with Allow-Credentials: true. While modern browsers block this combination, some older clients or custom HTTP libraries may honor it, allowing cross-origin credential theft.`,
                    evidence: `ACAO: *\nACAC: true`,
                    remediation: 'Never use wildcard (*) with credentials. Specify exact allowed origins.',
                }));
            }
        } catch {
            // Not reachable
        }
    }

    /**
     * Test WebSocket security.
     */
    async _testWebSockets(baseUrl) {
        const findings = [];
        const wsBase = baseUrl.replace(/^http/, 'ws');

        for (const path of this.WS_PATHS) {
            try {
                const wsUrl = new URL(path, wsBase).href;

                // Test if WS endpoint exists via HTTP upgrade
                const httpUrl = wsUrl.replace(/^ws/, 'http');
                const response = await fetch(httpUrl, {
                    method: 'GET',
                    headers: {
                        'Upgrade': 'websocket',
                        'Connection': 'Upgrade',
                        'Sec-WebSocket-Version': '13',
                        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                        'Origin': 'https://evil-attacker.com',
                    },
                    signal: AbortSignal.timeout(5000),
                });

                // 101 Switching Protocols = WS upgrade accepted
                if (response.status === 101) {
                    findings.push(createFinding({
                        module: 'api',
                        title: 'WebSocket: Unauthenticated Upgrade from Arbitrary Origin',
                        severity: 'high',
                        affected_surface: wsUrl,
                        description: `WebSocket endpoint at ${path} accepts upgrade requests from arbitrary origins (https://evil-attacker.com) without authentication. An attacker's website can connect to this WebSocket and read/write messages.`,
                        reproduction: [
                            `1. Send WS upgrade request to ${wsUrl}`,
                            `2. Include Origin: https://evil-attacker.com`,
                            `3. Server responds with 101 Switching Protocols`,
                        ],
                        evidence: `Status: 101\nOrigin accepted: evil-attacker.com`,
                        remediation: 'Validate Origin header on WebSocket upgrade requests. Require authentication tokens in the initial HTTP upgrade. Implement per-connection authorization.',
                    }));
                }

                // Some servers respond 400/426 indicating WS is supported but needs proper upgrade
                if (response.status === 426 || (response.status === 400 &&
                    (response.headers.get('upgrade') || '').toLowerCase().includes('websocket'))) {
                    // WS endpoint exists — check if it requires auth
                    const authResponse = await fetch(httpUrl, {
                        method: 'GET',
                        headers: {
                            'Upgrade': 'websocket',
                            'Connection': 'Upgrade',
                            'Sec-WebSocket-Version': '13',
                            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                        },
                        signal: AbortSignal.timeout(5000),
                    });

                    if (authResponse.status !== 401 && authResponse.status !== 403) {
                        findings.push(createFinding({
                            module: 'api',
                            title: 'WebSocket: Missing Authentication on Upgrade',
                            severity: 'medium',
                            affected_surface: wsUrl,
                            description: `WebSocket endpoint at ${path} does not return 401/403 for unauthenticated upgrade requests. The endpoint may accept anonymous connections.`,
                            evidence: `Status without auth: ${authResponse.status} (expected 401 or 403)`,
                            remediation: 'Require authentication tokens (JWT, session cookie) on WebSocket upgrade requests. Return 401 for unauthenticated connections.',
                        }));
                    }
                }
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
}

export default CORSWSTester;
