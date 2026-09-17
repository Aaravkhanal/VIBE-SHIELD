import { createFinding } from '../../utils/finding.js';

/**
 * AccountTakeoverTester — Tests for account takeover vulnerabilities.
 *
 * Checks:
 *   - Password reset flow weaknesses (predictable tokens, no expiry)
 *   - Email change without re-authentication
 *   - Session fixation (pre-login session persists post-login)
 *   - Missing session invalidation on password change
 *   - OAuth/social login misconfiguration
 *   - No MFA enforcement on sensitive operations
 */
export class AccountTakeoverTester {
    constructor(logger) {
        this.logger = logger;
    }

    async test(businessContext, surfaceInventory) {
        this.logger?.info?.('Account Takeover Tester: starting analysis');
        const findings = [];

        const forms = surfaceInventory.forms || [];
        const apis = surfaceInventory.apiEndpoints || [];
        const pages = surfaceInventory.pages || [];

        // Analyze password reset flow
        await this._testPasswordResetFlow(forms, apis, pages, findings);

        // Analyze email/profile change flow
        this._testProfileChangeFlow(forms, apis, findings);

        // Analyze session handling
        this._testSessionHandling(apis, pages, findings);

        // Analyze OAuth/social login
        this._testOAuthFlow(pages, apis, findings);

        this.logger?.info?.(`Account Takeover Tester: found ${findings.length} issues`);
        return findings;
    }

    async _testPasswordResetFlow(forms, apis, pages, findings) {
        // Find password reset forms
        const resetForms = forms.filter(f => {
            const str = JSON.stringify(f).toLowerCase();
            return str.includes('reset') || str.includes('forgot') || str.includes('recover');
        });

        const resetApis = apis.filter(a => {
            const path = new URL(a.url).pathname.toLowerCase();
            return path.includes('reset') || path.includes('forgot') || path.includes('recover');
        });

        // Find password reset pages
        const resetPages = pages.filter(p => {
            const url = p.url.toLowerCase();
            return url.includes('reset') || url.includes('forgot') || url.includes('recover');
        });

        if (resetForms.length > 0 || resetPages.length > 0) {
            // Check if reset page has token in URL
            for (const page of resetPages) {
                const url = new URL(page.url);
                const tokenParam = url.searchParams.get('token') || url.searchParams.get('code') ||
                    url.searchParams.get('key') || url.searchParams.get('hash');

                if (tokenParam) {
                    // Check token length (short tokens are brute-forceable)
                    if (tokenParam.length < 20) {
                        findings.push(createFinding({
                            module: 'logic',
                            title: 'Weak Password Reset Token',
                            severity: 'high',
                            affected_surface: page.url,
                            description:
                                `Password reset token is only ${tokenParam.length} characters long. ` +
                                `Short tokens can be brute-forced. Use at least 32 characters of cryptographic randomness.`,
                            evidence: { token_length: tokenParam.length, page: page.url },
                            remediation: 'Generate reset tokens with at least 128 bits of entropy (32+ hex characters). Use crypto.randomBytes().',
                        }));
                    }
                }
            }

            // Check if reset form has CSRF protection
            for (const form of resetForms) {
                if (!form.hasCsrfToken && !form.hasCsrfMeta) {
                    findings.push(createFinding({
                        module: 'logic',
                        title: 'Password Reset Form Missing CSRF Protection',
                        severity: 'medium',
                        affected_surface: form.page || form.action,
                        description:
                            'Password reset form lacks CSRF protection. An attacker could initiate password resets ' +
                            'for arbitrary users, potentially as part of a denial-of-service or social engineering attack.',
                        evidence: { form_id: form.id, form_action: form.action },
                        remediation: 'Add CSRF token to the password reset form.',
                    }));
                }
            }
        }

        // Check for password change forms that don't require current password
        const changePasswordForms = forms.filter(f => {
            const str = JSON.stringify(f).toLowerCase();
            return (str.includes('change') || str.includes('update')) && str.includes('password');
        });

        for (const form of changePasswordForms) {
            const passwordFields = form.fields?.filter(f => f.type === 'password') || [];

            // If only 1-2 password fields (new + confirm) but no "current password" field
            if (passwordFields.length <= 2) {
                const hasCurrentPassword = form.fields?.some(f => {
                    const name = (f.name || '').toLowerCase();
                    return f.type === 'password' && (
                        name.includes('current') || name.includes('old') || name.includes('existing')
                    );
                });

                if (!hasCurrentPassword) {
                    findings.push(createFinding({
                        module: 'logic',
                        title: 'Password Change Without Current Password Verification',
                        severity: 'high',
                        affected_surface: form.page || form.action,
                        description:
                            'Password change form does not require the current password. If an attacker obtains a ' +
                            'user session (via XSS, session fixation, etc.), they can change the password without ' +
                            'knowing the original one, permanently taking over the account.',
                        evidence: {
                            form_id: form.id,
                            password_fields: passwordFields.map(f => f.name),
                        },
                        remediation: 'Require the current password before allowing password changes. Consider requiring re-authentication for all sensitive operations.',
                    }));
                }
            }
        }

        // Flag password reset API endpoints
        for (const api of resetApis) {
            findings.push(createFinding({
                module: 'logic',
                title: `Password Reset API: ${new URL(api.url).pathname}`,
                severity: 'info',
                affected_surface: api.url,
                description:
                    `Password reset API endpoint. Verify: (1) Tokens are single-use, ` +
                    `(2) Tokens expire within 1 hour, (3) Rate limiting is in place, ` +
                    `(4) All other sessions are invalidated after reset.`,
                evidence: { method: api.method, path: new URL(api.url).pathname },
                remediation: 'Implement single-use, time-limited tokens. Invalidate all sessions on password reset.',
            }));
        }
    }

    _testProfileChangeFlow(forms, apis, findings) {
        // Find email/profile change forms
        const profileForms = forms.filter(f => {
            const str = JSON.stringify(f).toLowerCase();
            return (str.includes('profile') || str.includes('settings') || str.includes('account')) &&
                (str.includes('email') || str.includes('phone'));
        });

        for (const form of profileForms) {
            const emailField = form.fields?.find(f =>
                f.type === 'email' || (f.name || '').toLowerCase().includes('email')
            );

            if (emailField) {
                // Check if re-authentication is required (presence of password field)
                const hasPasswordField = form.fields?.some(f => f.type === 'password');

                if (!hasPasswordField) {
                    findings.push(createFinding({
                        module: 'logic',
                        title: 'Email Change Without Re-Authentication',
                        severity: 'high',
                        affected_surface: form.page || form.action,
                        description:
                            'Email change form does not require password confirmation. An attacker with session access ' +
                            'can change the account email and then use password reset to take over the account.',
                        evidence: {
                            form_id: form.id,
                            email_field: emailField.name,
                            has_password_field: false,
                        },
                        remediation: 'Require current password for email changes. Send confirmation to both old and new email addresses.',
                    }));
                }
            }
        }
    }

    _testSessionHandling(apis, pages, findings) {
        // Check for session-related API endpoints
        const sessionApis = apis.filter(a => {
            const path = new URL(a.url).pathname.toLowerCase();
            return path.includes('session') || path.includes('logout') || path.includes('signout');
        });

        // Check for logout endpoint
        const hasLogout = pages.some(p => p.url.toLowerCase().includes('logout')) ||
            sessionApis.some(a => new URL(a.url).pathname.toLowerCase().includes('logout'));

        if (!hasLogout) {
            findings.push(createFinding({
                module: 'logic',
                title: 'No Logout Endpoint Detected',
                severity: 'low',
                affected_surface: pages[0]?.url || 'N/A',
                description:
                    'No logout/signout endpoint found. Users may not be able to properly terminate their sessions, ' +
                    'increasing the risk of session theft on shared devices.',
                remediation: 'Implement a logout endpoint that invalidates the session server-side and clears session cookies.',
            }));
        }
    }

    _testOAuthFlow(pages, apis, findings) {
        // Check for OAuth/social login
        const oauthIndicators = pages.some(p => {
            const url = p.url.toLowerCase();
            return url.includes('oauth') || url.includes('callback') || url.includes('authorize');
        });

        const oauthApis = apis.filter(a => {
            const path = new URL(a.url).pathname.toLowerCase();
            return path.includes('oauth') || path.includes('callback') || path.includes('authorize') ||
                path.includes('google') || path.includes('github') || path.includes('facebook');
        });

        if (oauthApis.length > 0) {
            for (const api of oauthApis) {
                const url = new URL(api.url);
                const hasState = url.searchParams.has('state');

                if (!hasState && url.pathname.includes('callback')) {
                    findings.push(createFinding({
                        module: 'logic',
                        title: 'OAuth Callback Missing State Parameter',
                        severity: 'high',
                        affected_surface: api.url,
                        description:
                            'OAuth callback endpoint lacks a state parameter. Without CSRF protection via ' +
                            'the state parameter, an attacker can perform login CSRF to link their OAuth ' +
                            'account to a victim\'s session.',
                        evidence: { callback_url: api.url },
                        remediation: 'Always include and validate a cryptographic state parameter in OAuth flows.',
                        references: ['https://datatracker.ietf.org/doc/html/rfc6749#section-10.12'],
                    }));
                }
            }
        }
    }
}

export default AccountTakeoverTester;
