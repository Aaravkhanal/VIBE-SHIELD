import { createFinding } from '../../utils/finding.js';

/**
 * EmailEnumerationTester — Tests if login/register/reset forms reveal
 * whether an email/username exists in the system.
 *
 * Checks:
 *   - Different responses for existing vs non-existing emails on login
 *   - Registration form reveals taken emails
 *   - Password reset reveals valid emails
 *   - Response timing differences (side-channel)
 */
export class EmailEnumerationTester {
    constructor(logger) {
        this.logger = logger;
    }

    async test(businessContext, surfaceInventory) {
        this.logger?.info?.('Email Enumeration Tester: starting analysis');
        const findings = [];

        const forms = surfaceInventory.forms || [];
        const apis = surfaceInventory.apiEndpoints || [];
        const baseUrl = surfaceInventory.baseUrl;

        // Find auth-related forms
        const loginForms = forms.filter(f => this._isLoginForm(f));
        const registerForms = forms.filter(f => this._isRegisterForm(f));
        const resetForms = forms.filter(f => this._isResetForm(f));

        // Find auth-related APIs
        const authApis = apis.filter(a => this._isAuthApi(a));

        this.logger?.info?.(
            `Email Enumeration: ${loginForms.length} login forms, ${registerForms.length} register forms, ` +
            `${resetForms.length} reset forms, ${authApis.length} auth APIs`
        );

        // Test login forms
        for (const form of loginForms) {
            const emailField = form.fields?.find(f =>
                f.type === 'email' || ['email', 'username', 'user', 'login'].includes(f.name?.toLowerCase())
            );

            if (emailField) {
                // Test with two different non-existent emails
                const testEmail1 = `vibe_shield_test_${Date.now()}@nonexistent-domain-test.com`;
                const testEmail2 = `vibe_shield_test_${Date.now() + 1}@nonexistent-domain-test.com`;

                try {
                    const [response1, response2] = await Promise.all([
                        this._submitForm(form, { [emailField.name]: testEmail1, password: 'WrongPass123!' }),
                        this._submitForm(form, { [emailField.name]: testEmail2, password: 'WrongPass123!' }),
                    ]);

                    if (response1 && response2) {
                        // Check for different error messages (enumeration indicator)
                        if (response1.body !== response2.body) {
                            const diff = this._findDifference(response1.body, response2.body);
                            if (diff) {
                                findings.push(createFinding({
                                    module: 'logic',
                                    title: 'Login Form May Enable Email Enumeration',
                                    severity: 'medium',
                                    affected_surface: form.page || form.action,
                                    description:
                                        `Login form returns different responses for different email addresses, ` +
                                        `potentially revealing which emails are registered. ` +
                                        `Difference found: "${diff}".`,
                                    evidence: {
                                        form_id: form.id,
                                        email_field: emailField.name,
                                        difference: diff,
                                    },
                                    remediation:
                                        'Return a generic error message regardless of whether the email exists: ' +
                                        '"Invalid email or password". Avoid "Email not found" or "Wrong password" messages.',
                                }));
                            }
                        }

                        // Check timing difference (>500ms indicates database lookup variation)
                        const timeDiff = Math.abs(response1.time - response2.time);
                        if (timeDiff > 500) {
                            findings.push(createFinding({
                                module: 'logic',
                                title: 'Login Form Timing Side-Channel (Potential Enumeration)',
                                severity: 'low',
                                affected_surface: form.page || form.action,
                                description:
                                    `Login form shows ${timeDiff}ms timing difference between requests. ` +
                                    `This could allow email enumeration via timing analysis.`,
                                evidence: {
                                    time_diff_ms: timeDiff,
                                    response1_time: response1.time,
                                    response2_time: response2.time,
                                },
                                remediation:
                                    'Normalize response times by adding constant-time comparison or artificial delay. ' +
                                    'Always perform password hashing even for non-existent accounts.',
                            }));
                        }
                    }
                } catch (err) {
                    this.logger?.debug?.(`Login enumeration test failed: ${err.message}`);
                }
            }
        }

        // Flag registration forms that might reveal existing emails
        for (const form of registerForms) {
            const emailField = form.fields?.find(f =>
                f.type === 'email' || f.name?.toLowerCase().includes('email')
            );

            if (emailField) {
                findings.push(createFinding({
                    module: 'logic',
                    title: 'Registration Form — Potential Email Enumeration',
                    severity: 'low',
                    affected_surface: form.page || form.action,
                    description:
                        `Registration form with email field "${emailField.name}" detected. ` +
                        `Verify that the form does not reveal whether an email is already registered ` +
                        `(e.g., "This email is already taken" vs generic error).`,
                    evidence: {
                        form_id: form.id,
                        email_field: emailField.name,
                        form_action: form.action,
                    },
                    remediation:
                        'If the email exists, send a "continue registration" link to that email instead of ' +
                        'displaying "email already taken" on the form. Use rate limiting on registration endpoint.',
                }));
            }
        }

        // Flag password reset forms
        for (const form of resetForms) {
            findings.push(createFinding({
                module: 'logic',
                title: 'Password Reset Form — Potential Email Enumeration',
                severity: 'low',
                affected_surface: form.page || form.action,
                description:
                    `Password reset form detected. Verify it returns the same message for ` +
                    `existing and non-existing emails (e.g., "If an account exists, a reset link was sent").`,
                evidence: { form_id: form.id, form_action: form.action },
                remediation:
                    'Always respond with "If an account with that email exists, we sent a reset link." ' +
                    'Do not reveal whether the email is registered.',
            }));
        }

        // Flag auth API endpoints
        for (const api of authApis) {
            const path = new URL(api.url).pathname;
            if (path.includes('check') || path.includes('exists') || path.includes('validate')) {
                findings.push(createFinding({
                    module: 'logic',
                    title: `User Existence Check API: ${path}`,
                    severity: 'medium',
                    affected_surface: api.url,
                    description:
                        `API endpoint ${path} may directly reveal whether a user exists. ` +
                        `This is a common email enumeration vector.`,
                    evidence: { method: api.method, path, status: api.status },
                    remediation: 'Remove or rate-limit user existence check endpoints. Use CAPTCHA or proof-of-work.',
                }));
            }
        }

        this.logger?.info?.(`Email Enumeration Tester: found ${findings.length} issues`);
        return findings;
    }

    async _submitForm(form, data) {
        try {
            const formData = new URLSearchParams();
            for (const [key, value] of Object.entries(data)) {
                formData.append(key, value);
            }

            const start = Date.now();
            const response = await fetch(form.action, {
                method: form.method || 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'VIBE SHIELD-SecurityScanner/1.0',
                },
                body: formData.toString(),
                redirect: 'follow',
                signal: AbortSignal.timeout(15000),
            });
            const time = Date.now() - start;
            const body = await response.text();

            return { status: response.status, body: body.slice(0, 2000), time };
        } catch {
            return null;
        }
    }

    _findDifference(body1, body2) {
        // Look for common enumeration phrases
        const indicators = [
            'not found', 'does not exist', 'no account', 'invalid email',
            'wrong password', 'incorrect password', 'already registered',
            'already exists', 'not registered', 'email taken',
        ];

        for (const ind of indicators) {
            const in1 = body1.toLowerCase().includes(ind);
            const in2 = body2.toLowerCase().includes(ind);
            if (in1 !== in2) return ind;
        }
        return null;
    }

    _isLoginForm(form) {
        const str = JSON.stringify(form).toLowerCase();
        return (str.includes('login') || str.includes('signin') || str.includes('sign-in')) &&
            form.fields?.some(f => f.type === 'password');
    }

    _isRegisterForm(form) {
        const str = JSON.stringify(form).toLowerCase();
        return (str.includes('register') || str.includes('signup') || str.includes('sign-up') || str.includes('create')) &&
            form.fields?.some(f => f.type === 'password');
    }

    _isResetForm(form) {
        const str = JSON.stringify(form).toLowerCase();
        return str.includes('reset') || str.includes('forgot') || str.includes('recover');
    }

    _isAuthApi(api) {
        const path = new URL(api.url).pathname.toLowerCase();
        return path.includes('/auth') || path.includes('/login') || path.includes('/register') ||
            path.includes('/signup') || path.includes('/user') || path.includes('/account');
    }
}

export default EmailEnumerationTester;
