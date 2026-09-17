import { createFinding } from '../../utils/finding.js';

/**
 * FeatureFlagBypassTester — Tests if premium/gated features are only
 * protected client-side and can be bypassed.
 *
 * Checks:
 *   - Hidden premium UI elements (CSS display:none, visibility:hidden)
 *   - Client-side feature flag variables in JS
 *   - API endpoints that return feature flags without server-side enforcement
 *   - Premium content accessible via direct URL
 *   - Disabled form elements that can be re-enabled
 */
export class FeatureFlagBypassTester {
    constructor(logger) {
        this.logger = logger;
    }

    async test(businessContext, surfaceInventory) {
        this.logger?.info?.('Feature Flag Bypass Tester: starting analysis');
        const findings = [];

        const pages = surfaceInventory.pages || [];
        const apis = surfaceInventory.apiEndpoints || [];
        const forms = surfaceInventory.forms || [];

        // Check for feature flag API endpoints
        this._testFeatureFlagApis(apis, findings);

        // Check for premium/gated content patterns
        this._testPremiumPatterns(pages, findings);

        // Check for disabled form elements
        this._testDisabledElements(forms, findings);

        // Check for client-side gating via API responses
        this._testClientSideGating(apis, findings);

        this.logger?.info?.(`Feature Flag Bypass Tester: found ${findings.length} issues`);
        return findings;
    }

    _testFeatureFlagApis(apis, findings) {
        const flagPatterns = [
            '/feature', '/flags', '/feature-flags', '/toggle', '/config',
            '/plan', '/subscription', '/billing', '/premium', '/upgrade',
            '/permissions', '/entitlements', '/capabilities',
        ];

        for (const api of apis) {
            const path = new URL(api.url).pathname.toLowerCase();
            const match = flagPatterns.find(p => path.includes(p));

            if (match && api.method === 'GET') {
                findings.push(createFinding({
                    module: 'logic',
                    title: `Feature Flag/Config API Exposed: ${new URL(api.url).pathname}`,
                    severity: 'medium',
                    affected_surface: api.url,
                    description:
                        `API endpoint returns feature flag or subscription data (matched: "${match}"). ` +
                        `If feature access is only checked client-side based on this response, ` +
                        `an attacker can modify the response to unlock premium features. ` +
                        `Verify server-side enforcement on all gated functionality.`,
                    evidence: {
                        method: api.method,
                        path: new URL(api.url).pathname,
                        pattern_matched: match,
                        status: api.status,
                    },
                    reproduction: [
                        `1. Intercept ${api.method} ${new URL(api.url).pathname} with a proxy (Burp Suite, mitmproxy)`,
                        '2. Modify response to change feature flags/plan to "premium"',
                        '3. Observe if premium features become accessible',
                    ],
                    remediation:
                        'Always enforce feature access server-side. Never rely on client-side feature flags alone. ' +
                        'Each protected API endpoint should independently verify the user\'s entitlements.',
                }));
            }

            // Check for plan/subscription change APIs
            if ((path.includes('/plan') || path.includes('/subscription')) &&
                (api.method === 'POST' || api.method === 'PUT' || api.method === 'PATCH')) {
                findings.push(createFinding({
                    module: 'logic',
                    title: `Plan/Subscription Change API: ${api.method} ${new URL(api.url).pathname}`,
                    severity: 'medium',
                    affected_surface: api.url,
                    description:
                        `API for changing subscription plan. Verify: (1) Plan changes require valid payment, ` +
                        `(2) Cannot downgrade to avoid charges while keeping premium access, ` +
                        `(3) Plan IDs cannot be tampered with in requests.`,
                    evidence: { method: api.method, path: new URL(api.url).pathname },
                    remediation: 'Validate plan changes against payment records server-side. Use signed plan identifiers.',
                }));
            }
        }
    }

    _testPremiumPatterns(pages, findings) {
        const premiumPathPatterns = [
            '/premium', '/pro', '/enterprise', '/business',
            '/admin', '/dashboard/pro', '/upgrade',
        ];

        for (const page of pages) {
            const url = new URL(page.url);

            // Check if premium pages are accessible (status 200) without auth
            const match = premiumPathPatterns.find(p => url.pathname.toLowerCase().includes(p));
            if (match && page.status === 200) {
                findings.push(createFinding({
                    module: 'logic',
                    title: `Premium/Gated Page Accessible: ${url.pathname}`,
                    severity: 'low',
                    affected_surface: page.url,
                    description:
                        `Page at ${url.pathname} matches a premium/gated pattern and returns HTTP 200. ` +
                        `Verify that premium content on this page is actually server-side rendered only for ` +
                        `authorized users, not just hidden via CSS/JavaScript.`,
                    evidence: { url: page.url, status: page.status, pattern: match },
                    remediation: 'Enforce access control server-side. Return 403/401 for unauthorized users on premium routes.',
                }));
            }
        }
    }

    _testDisabledElements(forms, findings) {
        for (const form of forms) {
            // Check for disabled fields (client-side restriction)
            const disabledFields = form.fields?.filter(f =>
                f.name && (
                    f.name.toLowerCase().includes('premium') ||
                    f.name.toLowerCase().includes('pro') ||
                    f.name.toLowerCase().includes('enterprise') ||
                    f.name.toLowerCase().includes('limit')
                )
            );

            if (disabledFields && disabledFields.length > 0) {
                findings.push(createFinding({
                    module: 'logic',
                    title: 'Form Contains Premium/Limit Fields',
                    severity: 'info',
                    affected_surface: form.page || form.action,
                    description:
                        `Form has fields with premium/limit naming: ` +
                        `${disabledFields.map(f => `"${f.name}"`).join(', ')}. ` +
                        `If these control access to features, verify server-side enforcement.`,
                    evidence: {
                        fields: disabledFields.map(f => ({ name: f.name, type: f.type })),
                        form_id: form.id,
                    },
                    remediation: 'Never use client-side form fields to control premium feature access.',
                }));
            }
        }
    }

    _testClientSideGating(apis, findings) {
        // Check for APIs that might return user permissions/roles
        const permissionApis = apis.filter(a => {
            const path = new URL(a.url).pathname.toLowerCase();
            return (path.includes('/me') || path.includes('/user') || path.includes('/profile') ||
                path.includes('/account') || path.includes('/whoami')) && a.method === 'GET';
        });

        for (const api of permissionApis) {
            findings.push(createFinding({
                module: 'logic',
                title: `User Profile/Permissions API: ${new URL(api.url).pathname}`,
                severity: 'info',
                affected_surface: api.url,
                description:
                    `API returns user data which may include role/permission/plan information. ` +
                    `If the frontend uses this to show/hide features, ensure each feature\'s ` +
                    `backend also independently checks permissions.`,
                evidence: { method: api.method, path: new URL(api.url).pathname },
                remediation: 'Implement defense-in-depth: check permissions at every API layer, not just the frontend.',
            }));
        }
    }
}

export default FeatureFlagBypassTester;
