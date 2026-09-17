import { createFinding } from '../../utils/finding.js';

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
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(url, {
                    method: 'GET',
                    redirect: 'manual',
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                // If admin page is accessible (200) without auth, that's a finding
                if (response.status === 200) {
                    const text = await response.text();
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
                            evidence: `URL: ${url}\nStatus: ${response.status}\nContent indicators: admin content detected`,
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
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 5000);

                    const response = await fetch(tamperedUrl, {
                        method: 'GET',
                        signal: controller.signal,
                    });
                    clearTimeout(timeout);

                    if (response.ok) {
                        const text = await response.text();
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
                                evidence: `Original ID: ${originalId}\nTest ID: ${testId}\nResponse status: ${response.status}\nResponse length: ${text.length} bytes`,
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
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(url, {
                    method: 'GET',
                    redirect: 'manual',
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (response.status === 200) {
                    const text = await response.text();
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
                            evidence: `URL: ${url}\nStatus: ${response.status}`,
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
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(endpoint.url, {
                    method: endpoint.method || 'GET',
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (response.ok) {
                    const text = await response.text();
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
                            evidence: `URL: ${endpoint.url}\nMethod: ${endpoint.method}\nStatus: ${response.status}`,
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
}

export default AccessBoundaryTester;
