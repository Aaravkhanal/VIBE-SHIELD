import { createFinding } from '../../utils/finding.js';
import { observedWebCvss } from '../../utils/cvss-evidence.js';
import { DifferentialEngine } from '../differential-engine.js';

/**
 * AccessBoundaryTester — Tests access control boundaries.
 *
 * Probes:
 * - Horizontal IDOR (access other users' resources by changing ID)
 * - Vertical escalation (access admin from unprivileged context)
 * - Guest access (perform auth-required actions without login)
 * - Free-to-paid bypass (access premium features without subscription)
 * - Direct object reference enumeration
 */
export class AccessBoundaryTester {
    constructor(logger) {
        this.logger = logger;
        this.differential = new DifferentialEngine({ logger, timeoutMs: 10000 });

        // Common ID parameter names
        this.ID_PARAMS = ['id', 'user_id', 'userId', 'uid', 'account_id', 'accountId',
            'profile_id', 'order_id', 'orderId', 'item_id', 'itemId'];

        // Admin/privileged paths to test
        this.ADMIN_PATHS = [
            '/admin', '/admin/', '/admin/dashboard', '/admin/users',
            '/admin/settings', '/admin/config', '/manage', '/manage/users',
            '/internal', '/internal/api', '/api/admin', '/api/admin/users',
            '/api/internal', '/settings/admin', '/dashboard/admin',
        ];

        // Premium/paid feature paths
        this.PREMIUM_PATHS = [
            '/premium', '/pro', '/enterprise', '/features/premium',
            '/api/premium', '/api/pro', '/upgrade', '/api/export',
            '/api/analytics', '/api/reports/advanced', '/api/bulk',
        ];
    }

    /**
     * Test access boundaries against discovered surfaces.
     */
    async test(businessContext, surfaceInventory) {
        const findings = [];

        this.logger?.info?.('Access Boundary Tester: starting tests');

        // 1. Test vertical escalation (admin access)
        const verticalFindings = await this._testVerticalEscalation(surfaceInventory);
        findings.push(...verticalFindings);

        // 2. Test IDOR on API endpoints
        const idorFindings = await this._testIDOR(businessContext, surfaceInventory);
        findings.push(...idorFindings);

        // 3. Test free-to-paid bypass
        const premiumFindings = await this._testPremiumBypass(surfaceInventory);
        findings.push(...premiumFindings);

        // 4. Test guest access to authenticated routes
        const guestFindings = await this._testGuestAccess(businessContext);
        findings.push(...guestFindings);

        this.logger?.info?.(`Access Boundary Tester: found ${findings.length} issues`);
        return findings;
    }

    /**
     * Test vertical privilege escalation — can unprivileged users access admin?
     */
    async _testVerticalEscalation(surfaceInventory) {
        const findings = [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        for (const path of this.ADMIN_PATHS) {
            try {
                const url = new URL(path, baseUrl).href;
                const differential = await this._urlDifferential(baseUrl, url, snapshot => this._isAdminContent(snapshot.body));
                const response = differential.aggregates.payload.representative;

                // If admin page is accessible (200) without auth, that's a finding
                if (differential.confirmed && response?.status === 200) {
                    const text = response.body || '';
                    // Verify it's actually admin content, not a generic 200
                    if (this._isAdminContent(text)) {
                        findings.push(createFinding({
                            module: 'logic',
                            title: 'Vertical Privilege Escalation: Admin Accessible',
                            severity: 'critical',
                            affected_surface: url,
                            description: `Admin endpoint ${path} is accessible without authentication. An unauthenticated user can access administrative functionality.`,
                            reproduction: [
                                `1. Open ${url} in a private/incognito browser`,
                                `2. Admin page loads without login requirement`,
                            ],
                            evidence: { url, status: response.status, differential: differential.evidence },
                            cvssAssessment: observedWebCvss({
                                metrics: { attackVector: 'NETWORK', attackComplexity: 'LOW', privilegesRequired: 'NONE', userInteraction: 'NONE', scope: 'UNCHANGED', confidentiality: 'LOW', integrity: 'NONE', availability: 'NONE' },
                                request: `GET ${url}`, role: 'anonymous', observation: 'admin-specific page response',
                                impacts: { confidentiality: 'The unauthenticated request returned admin-specific content; administrative actions were not tested.' },
                            }),
                            verification: {
                                level: 'high_confidence',
                                reason: 'Repeated unauthenticated requests returned stable admin-specific content that was unique to the candidate endpoint.',
                                method: 'authorization-boundary-differential',
                                proof: {
                                    originalRequest: { method: 'GET', url },
                                    mutatedRequest: { method: 'GET', url },
                                    baselineResponse: differential.evidence.baseline,
                                    vulnerableResponse: differential.evidence.payload,
                                    responseDifference: differential.evidence.comparisons,
                                    reproductionCommand: `curl -i ${JSON.stringify(url)}`,
                                    accountRole: 'anonymous',
                                },
                            },
                            remediation: 'Implement authentication and authorization checks on all admin endpoints. Use middleware to verify user role before granting access. Return 401/403 for unauthorized requests.',
                        }));
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    /**
     * Test IDOR — can resource IDs be manipulated to access other users' data?
     */
    async _testIDOR(businessContext, surfaceInventory) {
        const findings = [];
        const apis = surfaceInventory.apiEndpoints || surfaceInventory.apis || [];

        for (const api of apis) {
            const url = api.url || api;

            // Check if URL contains numeric IDs that could be enumerated
            const idMatch = url.match(/\/(\d+)(\/|$|\?)/);
            if (!idMatch) continue;

            const originalId = idMatch[1];
            const testIds = [
                String(parseInt(originalId) + 1),
                String(parseInt(originalId) - 1),
                '1',
                '0',
            ];

            for (const testId of testIds) {
                if (testId === originalId) continue;

                const tamperedUrl = url.replace(`/${originalId}`, `/${testId}`);
                try {
                    const differential = await this._urlDifferential(url, tamperedUrl);
                    const response = differential.aggregates.payload.representative;

                    if (differential.confirmed && differential.uniqueDifferential && response?.status >= 200 && response.status < 300) {
                        const text = response.body || '';
                        if (text.length > 50 && !this._isGenericResponse(text)) {
                            findings.push(createFinding({
                                module: 'logic',
                                title: 'IDOR: Insecure Direct Object Reference',
                                severity: 'high',
                                affected_surface: tamperedUrl,
                                description: `Changing the resource ID from ${originalId} to ${testId} in ${url} returned data without authorization check. An attacker can enumerate IDs to access other users' data.`,
                                reproduction: [
                                    `1. Original URL: ${url}`,
                                    `2. Change ID ${originalId} to ${testId}`,
                                    `3. Server returns data for the different resource`,
                                ],
                                evidence: { originalId, testId, responseStatus: response.status, responseLength: text.length, differential: differential.evidence },
                                verification: {
                                    level: 'high_confidence',
                                    reason: 'The tampered resource request produced a stable response differential beyond the benign control mutation.',
                                    method: 'idor-response-differential',
                                    proof: {
                                        originalRequest: { method: 'GET', url },
                                        mutatedRequest: { method: 'GET', url: tamperedUrl },
                                        baselineResponse: differential.evidence.baseline,
                                        vulnerableResponse: differential.evidence.payload,
                                        responseDifference: differential.evidence.comparisons,
                                        reproductionCommand: `curl -i ${JSON.stringify(tamperedUrl)}`,
                                        accountRole: 'anonymous',
                                    },
                                },
                                remediation: 'Implement authorization checks that verify the requesting user owns the resource. Use UUIDs instead of sequential IDs. Always validate resource ownership server-side.',
                            }));
                            break; // One IDOR per endpoint is enough
                        }
                    }
                } catch {
                    continue;
                }
            }
        }

        return findings;
    }

    /**
     * Test premium/paid feature bypass.
     */
    async _testPremiumBypass(surfaceInventory) {
        const findings = [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        for (const path of this.PREMIUM_PATHS) {
            try {
                const url = new URL(path, baseUrl).href;
                const differential = await this._urlDifferential(baseUrl, url, snapshot => snapshot.status === 200 && (snapshot.body?.length || 0) > 100);
                const response = differential.aggregates.payload.representative;

                if (differential.confirmed && response?.status === 200) {
                    const text = response.body || '';
                    if (text.length > 100 && !this._isGenericResponse(text)) {
                        findings.push(createFinding({
                            module: 'logic',
                            title: 'Access Bypass: Premium Feature Accessible',
                            severity: 'high',
                            affected_surface: url,
                            description: `Premium endpoint ${path} is accessible without a paid subscription. Unauthenticated users can access features intended for paying customers.`,
                            reproduction: [
                                `1. Open ${url} without authentication`,
                                `2. Premium content is accessible`,
                            ],
                            evidence: { url, status: response.status, differential: differential.evidence },
                            verification: {
                                level: 'high_confidence',
                                reason: 'Repeated unauthenticated requests returned stable premium-feature content unique to the candidate route.',
                                method: 'premium-access-differential',
                                proof: {
                                    originalRequest: { method: 'GET', url },
                                    mutatedRequest: { method: 'GET', url },
                                    baselineResponse: differential.evidence.baseline,
                                    vulnerableResponse: differential.evidence.payload,
                                    responseDifference: differential.evidence.comparisons,
                                    reproductionCommand: `curl -i ${JSON.stringify(url)}`,
                                    accountRole: 'anonymous',
                                },
                            },
                            remediation: 'Verify subscription status server-side before serving premium content. Implement tier-based access control in middleware.',
                        }));
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    /**
     * Test guest access to authenticated routes.
     */
    async _testGuestAccess(businessContext) {
        const findings = [];
        const authSurfaces = businessContext.domains?.auth || [];

        // Look for API endpoints in auth domain that should require login
        const apiEndpoints = businessContext.apiEndpoints?.auth || [];

        for (const endpoint of apiEndpoints) {
            // Skip login/register endpoints (these should be accessible)
            if (/login|signin|register|signup|forgot|reset/i.test(endpoint.url)) continue;

            try {
                const endpointOrigin = new URL(endpoint.url).origin + '/';
                const differential = await this._urlDifferential(endpointOrigin, endpoint.url, snapshot => this._containsSensitiveData(snapshot.body));
                const response = differential.aggregates.payload.representative;

                if (differential.confirmed && response?.status >= 200 && response.status < 300) {
                    const text = response.body || '';
                    if (this._containsSensitiveData(text)) {
                        findings.push(createFinding({
                            module: 'logic',
                            title: 'Guest Access: Authenticated Endpoint Exposed',
                            severity: 'high',
                            affected_surface: endpoint.url,
                            description: `Authenticated endpoint ${endpoint.url} returns sensitive data without requiring authentication token/session.`,
                            reproduction: [
                                `1. Send ${endpoint.method} to ${endpoint.url} without auth headers`,
                                `2. Server returns sensitive data`,
                            ],
                            evidence: { url: endpoint.url, method: endpoint.method, status: response.status, differential: differential.evidence },
                            cvssAssessment: observedWebCvss({
                                metrics: { attackVector: 'NETWORK', attackComplexity: 'LOW', privilegesRequired: 'NONE', userInteraction: 'NONE', scope: 'UNCHANGED', confidentiality: 'LOW', integrity: 'NONE', availability: 'NONE' },
                                request: `GET ${endpoint.url}`, role: 'anonymous', observation: 'sensitive-data response',
                                impacts: { confidentiality: 'The unauthenticated response included data matching the sensitive-data detector; the extent of disclosure was not measured.' },
                            }),
                            verification: {
                                level: 'high_confidence',
                                reason: 'Repeated unauthenticated requests returned a stable sensitive-data response that differed from the control mutation.',
                                method: 'guest-access-differential',
                                proof: {
                                    originalRequest: { method: endpoint.method || 'GET', url: endpoint.url },
                                    mutatedRequest: { method: endpoint.method || 'GET', url: endpoint.url },
                                    baselineResponse: differential.evidence.baseline,
                                    vulnerableResponse: differential.evidence.payload,
                                    responseDifference: differential.evidence.comparisons,
                                    reproductionCommand: `curl -i ${JSON.stringify(endpoint.url)}`,
                                    accountRole: 'anonymous',
                                },
                            },
                            remediation: 'Require authentication tokens on all protected endpoints. Return 401 for unauthenticated requests. Never rely on client-side route guards alone.',
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
        const firstUrl = pages[0].url || pages[0];
        try {
            const parsed = new URL(firstUrl);
            return `${parsed.protocol}//${parsed.host}`;
        } catch {
            return null;
        }
    }

    _isAdminContent(text) {
        return /admin|dashboard|manage|settings|users|configuration/i.test(text) &&
            text.length > 200;
    }

    _isGenericResponse(text) {
        return /not found|404|403|unauthorized|forbidden|error/i.test(text) &&
            text.length < 500;
    }

    _containsSensitiveData(text) {
        return /@[\w.-]+\.\w+/.test(text) || // email
            /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/.test(text) || // phone
            /"(password|token|secret|key)":/i.test(text) || // sensitive fields
            (text.length > 200 && /"(id|user|name|email)":/i.test(text)); // user data
    }

    async _urlDifferential(baselineUrl, payloadUrl, signal = null) {
        const baseline = new URL(baselineUrl);
        const control = new URL(baselineUrl);
        control.searchParams.set('__vibe_control', '1');
        return this.differential.run({
            baseline: { url: baseline.toString(), method: 'GET', redirect: 'manual' },
            control: { url: control.toString(), method: 'GET', redirect: 'manual' },
            payload: { url: payloadUrl, method: 'GET', redirect: 'manual' },
            signal,
        });
    }
}

export default AccessBoundaryTester;
