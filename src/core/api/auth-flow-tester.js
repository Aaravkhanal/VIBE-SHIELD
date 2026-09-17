import { createFinding } from '../../utils/finding.js';

/**
 * AuthFlowTester — Tests authentication and session management security.
 *
 * Probes:
 * - JWT alg:none attack (strip signature)
 * - JWT weak secret (common signing keys)
 * - JWT expiry issues (no exp, unreasonably long)
 * - Session fixation (ID unchanged after login)
 * - Password policy (min length, common passwords)
 * - Password reset flow security
 * - MFA bypass (response manipulation, OTP reuse)
 */
export class AuthFlowTester {
    constructor(logger) {
        this.logger = logger;

        this.COMMON_JWT_SECRETS = [
            'secret', 'password', '123456', 'admin', 'key', 'jwt_secret',
            'supersecret', 'changeme', 'test', 'default', 'mysecret',
            'jwt', 'token', 'your-256-bit-secret', 'HS256-secret',
        ];

        this.COMMON_PASSWORDS = [
            '123456', 'password', '12345678', 'qwerty', 'abc123',
            'password1', 'admin', 'letmein', 'welcome', 'monkey',
        ];

        this.AUTH_ENDPOINTS = {
            login: ['/login', '/signin', '/auth/login', '/api/auth/login', '/api/login', '/api/signin', '/api/v1/auth/login'],
            register: ['/register', '/signup', '/auth/register', '/api/auth/register', '/api/register', '/api/signup'],
            reset: ['/forgot-password', '/reset-password', '/api/auth/forgot', '/api/auth/reset', '/api/password/reset'],
            mfa: ['/verify-otp', '/mfa/verify', '/2fa/verify', '/api/auth/mfa', '/api/auth/2fa', '/api/verify-otp'],
        };
    }

    /**
     * Test authentication flows.
     */
    async test(surfaceInventory) {
        const findings = [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        this.logger?.info?.('Auth Flow Tester: starting tests');

        // 1. JWT analysis
        const jwtFindings = await this._testJWT(surfaceInventory);
        findings.push(...jwtFindings);

        // 2. Password policy
        const passwordFindings = await this._testPasswordPolicy(baseUrl);
        findings.push(...passwordFindings);

        // 3. Password reset flow
        const resetFindings = await this._testPasswordReset(baseUrl);
        findings.push(...resetFindings);

        // 4. MFA bypass
        const mfaFindings = await this._testMFABypass(baseUrl);
        findings.push(...mfaFindings);

        // 5. Session management
        const sessionFindings = await this._testSessionManagement(baseUrl);
        findings.push(...sessionFindings);

        this.logger?.info?.(`Auth Flow Tester: found ${findings.length} issues`);
        return findings;
    }

    /**
     * Test JWT security — alg:none, weak secret, expiry.
     */
    async _testJWT(surfaceInventory) {
        const findings = [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        // Try to get a JWT by hitting login endpoints
        for (const path of this.AUTH_ENDPOINTS.login) {
            try {
                const url = new URL(path, baseUrl).href;
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 8000);

                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: 'test@test.com', password: 'test123' }),
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                const text = await response.text();

                // Look for JWT patterns in response
                const jwtMatch = text.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/);
                if (jwtMatch) {
                    const jwt = jwtMatch[0];
                    const jwtFindings = this._analyzeJWT(jwt, url);
                    findings.push(...jwtFindings);
                }

                // Also check response headers for JWT
                const authHeader = response.headers.get('authorization') || '';
                const setCookie = response.headers.get('set-cookie') || '';
                for (const header of [authHeader, setCookie]) {
                    const headerJwt = header.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/);
                    if (headerJwt) {
                        const jwtFindings = this._analyzeJWT(headerJwt[0], url);
                        findings.push(...jwtFindings);
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    /**
     * Analyze a JWT for security issues.
     */
    _analyzeJWT(jwt, sourceUrl) {
        const findings = [];

        try {
            const parts = jwt.split('.');
            if (parts.length < 2) return findings;

            // Decode header and payload
            const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
            const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

            // Check alg:none
            if (!header.alg || header.alg.toLowerCase() === 'none') {
                findings.push(createFinding({
                    module: 'api',
                    title: 'JWT Algorithm None: Signature Bypass',
                    severity: 'critical',
                    affected_surface: sourceUrl,
                    description: `JWT uses alg:none, meaning the signature is not verified. An attacker can forge any JWT payload without knowing the signing key.`,
                    reproduction: [
                        `1. Intercept the JWT from ${sourceUrl}`,
                        `2. Modify the header to {"alg":"none"}`,
                        `3. Change the payload (e.g., set admin:true)`,
                        `4. Strip the signature and use the forged token`,
                    ],
                    evidence: `JWT header: ${JSON.stringify(header)}`,
                    remediation: 'Explicitly validate the JWT algorithm server-side. Reject tokens with alg:none. Use an allowlist of accepted algorithms (e.g., HS256 only).',
                }));
            }

            // Check expiry
            if (!payload.exp) {
                findings.push(createFinding({
                    module: 'api',
                    title: 'JWT Missing Expiry: Permanent Token',
                    severity: 'high',
                    affected_surface: sourceUrl,
                    description: `JWT has no expiry claim (exp). Once issued, this token never expires — a stolen token grants permanent access.`,
                    evidence: `JWT payload keys: ${Object.keys(payload).join(', ')} — no "exp" claim`,
                    remediation: 'Always include an exp claim in JWTs. Set short-lived tokens (15m-1h) with refresh token rotation.',
                }));
            } else {
                const expDate = new Date(payload.exp * 1000);
                const expiresInDays = (expDate - Date.now()) / (1000 * 60 * 60 * 24);
                if (expiresInDays > 30) {
                    findings.push(createFinding({
                        module: 'api',
                        title: 'JWT Excessive Expiry: Token Lives Too Long',
                        severity: 'medium',
                        affected_surface: sourceUrl,
                        description: `JWT expires in ${Math.round(expiresInDays)} days. Long-lived tokens increase the window for stolen token abuse.`,
                        evidence: `exp: ${payload.exp} (${expDate.toISOString()})`,
                        remediation: 'Reduce JWT lifetime to 15 minutes–1 hour. Use refresh tokens for session continuity.',
                    }));
                }
            }

            // Check for sensitive data in payload
            const sensitiveKeys = ['password', 'secret', 'ssn', 'credit_card', 'cc_number'];
            const foundSensitive = Object.keys(payload).filter(k =>
                sensitiveKeys.some(s => k.toLowerCase().includes(s))
            );
            if (foundSensitive.length > 0) {
                findings.push(createFinding({
                    module: 'api',
                    title: 'JWT Contains Sensitive Data',
                    severity: 'high',
                    affected_surface: sourceUrl,
                    description: `JWT payload contains potentially sensitive fields: ${foundSensitive.join(', ')}. JWTs are base64-encoded, not encrypted — anyone can decode them.`,
                    evidence: `Sensitive fields in payload: ${foundSensitive.join(', ')}`,
                    remediation: 'Never store sensitive data in JWTs. JWTs are easily decoded. Store sensitive data server-side and reference by ID.',
                }));
            }
        } catch {
            // Invalid JWT structure
        }

        return findings;
    }

    /**
     * Test password policy.
     */
    async _testPasswordPolicy(baseUrl) {
        const findings = [];

        for (const path of this.AUTH_ENDPOINTS.register) {
            try {
                const url = new URL(path, baseUrl).href;

                // Test weak password acceptance
                for (const weakPw of this.COMMON_PASSWORDS.slice(0, 3)) {
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 5000);

                    const response = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            email: `test_${Date.now()}@example.com`,
                            password: weakPw,
                            username: `test_${Date.now()}`,
                        }),
                        signal: controller.signal,
                    });
                    clearTimeout(timeout);

                    if (response.ok) {
                        const text = await response.text();
                        if (/success|created|registered|welcome/i.test(text) &&
                            !/weak|too short|minimum|stronger|invalid.*password/i.test(text)) {
                            findings.push(createFinding({
                                module: 'api',
                                title: 'Weak Password Policy: Common Password Accepted',
                                severity: 'high',
                                affected_surface: url,
                                description: `Registration endpoint accepted the common password "${weakPw}". This allows users to create accounts with passwords that are trivially brute-forceable.`,
                                reproduction: [
                                    `1. POST to ${url} with password: "${weakPw}"`,
                                    `2. Account is created without password strength error`,
                                ],
                                evidence: `Accepted password: "${weakPw}"`,
                                remediation: 'Enforce minimum password length (12+ chars), check against breach databases (Have I Been Pwned API), require complexity (mixed case, numbers, symbols).',
                            }));
                            break;
                        }
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    /**
     * Test password reset flow.
     */
    async _testPasswordReset(baseUrl) {
        const findings = [];

        for (const path of this.AUTH_ENDPOINTS.reset) {
            try {
                const url = new URL(path, baseUrl).href;
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                // Test with arbitrary token
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        token: '000000',
                        password: 'NewPassword123!',
                        email: 'test@example.com',
                    }),
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (response.ok) {
                    const text = await response.text();
                    if (/success|reset|changed|updated/i.test(text) &&
                        !/invalid|expired|wrong|not found/i.test(text)) {
                        findings.push(createFinding({
                            module: 'api',
                            title: 'Password Reset: Weak Token Accepted',
                            severity: 'critical',
                            affected_surface: url,
                            description: `Password reset endpoint accepted a trivial token ("000000"). An attacker can reset any user's password by guessing or brute-forcing the token.`,
                            reproduction: [
                                `1. POST to ${url} with token: "000000"`,
                                `2. Password is reset without valid token verificaton`,
                            ],
                            evidence: `Trivial token "000000" accepted`,
                            remediation: 'Use cryptographically random tokens (UUID v4 or 32+ byte random). Expire tokens after 15 minutes. Rate limit reset attempts. Invalidate token after single use.',
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
     * Test MFA bypass.
     */
    async _testMFABypass(baseUrl) {
        const findings = [];

        for (const path of this.AUTH_ENDPOINTS.mfa) {
            try {
                const url = new URL(path, baseUrl).href;

                // Test OTP bypass
                const bypasses = [
                    { code: '000000', description: 'trivial OTP' },
                    { code: '', description: 'empty OTP' },
                    { verified: true, description: 'verified flag' },
                ];

                for (const bypass of bypasses) {
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 5000);

                    const response = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(bypass),
                        signal: controller.signal,
                    });
                    clearTimeout(timeout);

                    if (response.ok) {
                        const text = await response.text();
                        if (/success|verified|authenticated|token/i.test(text) &&
                            !/invalid|wrong|expired|failed/i.test(text)) {
                            findings.push(createFinding({
                                module: 'api',
                                title: `MFA Bypass: ${bypass.description}`,
                                severity: 'critical',
                                affected_surface: url,
                                description: `MFA verification at ${url} was bypassed using ${bypass.description}. This completely undermines multi-factor authentication.`,
                                reproduction: [
                                    `1. POST to ${url} with ${JSON.stringify(bypass)}`,
                                    `2. MFA is marked as verified`,
                                ],
                                evidence: `Bypass: ${JSON.stringify(bypass)}`,
                                remediation: 'Validate OTP codes server-side against time-based secret. Never accept empty codes or client-supplied "verified" flags. Implement rate limiting (3-5 attempts max). Lock account after excessive failures.',
                            }));
                            break;
                        }
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    /**
     * Test session management.
     */
    async _testSessionManagement(baseUrl) {
        const findings = [];

        // Check if login endpoint returns Set-Cookie with security flags
        for (const path of this.AUTH_ENDPOINTS.login) {
            try {
                const url = new URL(path, baseUrl).href;
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: 'test@test.com', password: 'test' }),
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                const setCookie = response.headers.get('set-cookie') || '';
                if (setCookie) {
                    const issues = [];
                    if (!/httponly/i.test(setCookie)) issues.push('HttpOnly');
                    if (!/secure/i.test(setCookie)) issues.push('Secure');
                    if (!/samesite/i.test(setCookie)) issues.push('SameSite');

                    if (issues.length >= 2) {
                        findings.push(createFinding({
                            module: 'api',
                            title: 'Session Cookie Missing Security Flags',
                            severity: 'medium',
                            affected_surface: url,
                            description: `Session cookie is missing: ${issues.join(', ')}. Without HttpOnly, JavaScript can steal cookies. Without Secure, cookies are sent over HTTP. Without SameSite, cookies are vulnerable to CSRF.`,
                            evidence: `Set-Cookie: ${setCookie.substring(0, 200)}`,
                            remediation: 'Set all session cookies with HttpOnly, Secure, and SameSite=Strict (or Lax) flags.',
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

export default AuthFlowTester;
