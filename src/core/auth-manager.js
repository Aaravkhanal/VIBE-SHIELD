import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { Writable } from 'stream';

/**
 * AuthManager — Handles authenticated scanning.
 * 
 * Supports 3 login strategies:
 * 1. Form-based: Auto-detects login forms, fills credentials, submits
 * 2. API-based: POSTs JSON to login endpoint, extracts tokens
 * 3. Cookie injection: Uses pre-configured session cookies
 * 
 * Stores Playwright storageState (cookies + localStorage) per role.
 * All downstream agents inherit auth context automatically.
 */
export class AuthManager {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.authStates = new Map();  // role → { state, postLoginUrl, discoveredLinks }
        this.authTokens = new Map();  // role → { token, type }
        this.loginFormInfo = null;    // { type, triggerSelector, isModal, url }
        this._browser = null;
    }

    /**
     * Authenticate all configured credentials.
     * If no credentials are configured but a login form is detected,
     * interactively prompts the user in the terminal.
     * Returns a Map of role → storageState for Playwright contexts.
     */
    async authenticate() {
        let credentials = this.config.credentials || [];

        // If no credentials configured, check for login form and prompt interactively
        if (credentials.filter(c => c.username && c.password).length === 0) {
            const loginUrl = this.config.auth?.login_url || await this._discoverLoginPage();
            if (loginUrl) {
                const formType = this.loginFormInfo?.type || 'password';

                // Only prompt for credentials on password-based logins
                // OTP/social/phone logins can't be automated via simple credentials
                if (formType === 'password' || formType === 'email') {
                    const prompted = await this._promptForCredentials(loginUrl);
                    if (!prompted) {
                        this.logger?.info?.('No credentials provided — scanning unauthenticated');
                        return this.authStates;
                    }
                    this.logger?.info?.(`Auth complete: ${this.authStates.size} role(s) authenticated`);
                    return this.authStates;
                } else if (formType === 'phone' || formType === 'otp') {
                    // Phone/OTP — prompt for phone number and OTP interactively
                    const otpResult = await this._promptForOTPLogin(loginUrl);
                    if (!otpResult) {
                        this.logger?.info?.('No phone credentials provided — scanning unauthenticated');
                        return this.authStates;
                    }
                    this.logger?.info?.(`Auth complete: ${this.authStates.size} role(s) authenticated via OTP`);
                    return this.authStates;
                } else {
                    // Social login — can't automate, scan unauthenticated
                    const detail = this.loginFormInfo?.details || formType;
                    this.logger?.info?.(`Login form detected (${formType}: ${detail}) — cannot auto-authenticate, scanning unauthenticated`);
                    this.logger?.info?.('Tip: Use --login-url and --auth-strategy cookie to provide pre-authenticated session cookies');
                    return this.authStates;
                }
            } else {
                this.logger?.info?.('No login form detected — scanning unauthenticated');
                return this.authStates;
            }
        }

        // CLI flags or config provided credentials — authenticate them
        const authConfig = this.config.auth || {};
        this._browser = await chromium.launch({ headless: true });

        for (const cred of credentials) {
            if (!cred.username || !cred.password) {
                this.logger?.debug?.(`Skipping role "${cred.role}" — no username/password`);
                continue;
            }

            try {
                const strategy = authConfig.strategy || 'auto';
                this.logger?.info?.(`Authenticating as "${cred.role}" via ${strategy}...`);

                let state;
                switch (strategy) {
                    case 'form':
                        state = await this._loginViaForm(cred, authConfig);
                        break;
                    case 'api':
                        state = await this._loginViaAPI(cred, authConfig);
                        break;
                    case 'cookie':
                        state = await this._injectCookies(cred, authConfig);
                        break;
                    case 'auto':
                    default:
                        state = await this._autoLogin(cred, authConfig);
                        break;
                }

                if (state) {
                    this.authStates.set(cred.role, state);
                    const cookieCount = state.state?.cookies?.length || state.cookies?.length || 0;
                    this.logger?.info?.(`✔ Authenticated as "${cred.role}" — ${cookieCount} cookies stored`);
                } else {
                    this.logger?.warn?.(`✘ Authentication failed for "${cred.role}"`);
                }
            } catch (err) {
                this.logger?.error?.(`Auth error for "${cred.role}": ${err.message}`);
            }
        }

        await this._browser.close();
        this._browser = null;

        this.logger?.info?.(`Auth complete: ${this.authStates.size}/${credentials.filter(c => c.username).length} roles authenticated`);
        return this.authStates;
    }

    /**
     * Auto-detect login strategy: try form first, fall back to API.
     */
    async _autoLogin(cred, authConfig) {
        // Step 1: Find login page
        const loginUrl = authConfig.login_url || await this._discoverLoginPage();
        if (!loginUrl) {
            this.logger?.debug?.('No login page found — trying API login');
            return this._loginViaAPI(cred, authConfig);
        }

        // Step 2: Try form-based login
        const state = await this._loginViaForm(cred, { ...authConfig, login_url: loginUrl });
        if (state) return state;

        // Step 3: Fall back to API login
        return this._loginViaAPI(cred, authConfig);
    }

    /**
     * Form-based login: navigate to login page, fill form, submit.
     */
    async _loginViaForm(cred, authConfig) {
        const loginUrl = authConfig.login_url || `${this.config.target_url}/login`;
        const context = await this._browser.newContext({
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        });
        const page = await context.newPage();

        try {
            await page.goto(loginUrl, { waitUntil: 'networkidle', timeout: 15000 });

            // Find the login form
            const usernameSelector = authConfig.username_selector || await this._findUsernameField(page);
            const passwordSelector = authConfig.password_selector || await this._findPasswordField(page);
            const submitSelector = authConfig.submit_selector || await this._findSubmitButton(page);

            if (!usernameSelector || !passwordSelector) {
                this.logger?.debug?.('Could not find login form fields');
                await page.close();
                await context.close();
                return null;
            }

            // Fill credentials
            await page.fill(usernameSelector, cred.username);
            await page.fill(passwordSelector, cred.password);

            // Submit and wait for navigation
            const [response] = await Promise.all([
                page.waitForNavigation({ waitUntil: 'networkidle', timeout: 10000 }).catch(() => null),
                submitSelector
                    ? page.click(submitSelector)
                    : page.keyboard.press('Enter'),
            ]);

            // Verify login succeeded
            const loggedIn = await this._verifyLogin(page, loginUrl);
            if (!loggedIn) {
                this.logger?.debug?.(`Form login failed for "${cred.role}" — still on login page`);
                await page.close();
                await context.close();
                return null;
            }

            // Capture post-login URL (e.g., /dashboard, /app, /home)
            const postLoginUrl = page.url();
            this.logger?.debug?.(`Post-login URL: ${postLoginUrl}`);

            // Discover links on the post-login page (authenticated pages to crawl)
            const discoveredLinks = await page.evaluate(() => {
                const anchors = Array.from(document.querySelectorAll('a[href]'));
                return anchors.map(a => a.href)
                    .filter(href => href && !href.startsWith('javascript:') && !href.startsWith('mailto:'));
            }).catch(() => []);

            this.logger?.debug?.(`Post-login page has ${discoveredLinks.length} links`);

            // Extract storage state (cookies + localStorage)
            const state = await context.storageState();
            await page.close();
            await context.close();
            return { state, postLoginUrl, discoveredLinks };
        } catch (err) {
            this.logger?.debug?.(`Form login error: ${err.message}`);
            await page.close().catch(() => { });
            await context.close().catch(() => { });
            return null;
        }
    }

    /**
     * API-based login: POST credentials to login endpoint.
     */
    async _loginViaAPI(cred, authConfig) {
        const loginEndpoints = authConfig.api_login_url
            ? [authConfig.api_login_url]
            : [
                `${this.config.target_url}/api/auth/login`,
                `${this.config.target_url}/api/login`,
                `${this.config.target_url}/auth/login`,
                `${this.config.target_url}/api/v1/auth/login`,
                `${this.config.target_url}/api/sessions`,
            ];

        for (const endpoint of loginEndpoints) {
            try {
                const resp = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: cred.username,
                        username: cred.username,
                        password: cred.password,
                    }),
                    signal: AbortSignal.timeout(10000),
                });

                if (resp.ok) {
                    const data = await resp.json().catch(() => ({}));
                    const token = data.token || data.access_token || data.accessToken
                        || data.jwt || data.session_token || data.data?.token;

                    if (token) {
                        this.authTokens.set(cred.role, {
                            token,
                            type: data.token_type || 'Bearer',
                        });

                        // Create a browser context with the token as a cookie
                        const context = await this._browser.newContext({
                            ignoreHTTPSErrors: true,
                        });

                        // Set cookies from response
                        const setCookieHeaders = resp.headers.getSetCookie?.() || [];
                        if (setCookieHeaders.length > 0) {
                            const cookies = this._parseSetCookieHeaders(setCookieHeaders);
                            await context.addCookies(cookies);
                        }

                        // Also add token as localStorage
                        const page = await context.newPage();
                        await page.goto(this.config.target_url, { waitUntil: 'domcontentloaded', timeout: 10000 });
                        await page.evaluate((tkn) => {
                            localStorage.setItem('token', tkn);
                            localStorage.setItem('access_token', tkn);
                            localStorage.setItem('auth_token', tkn);
                        }, token);

                        const state = await context.storageState();
                        await page.close();
                        await context.close();

                        this.logger?.debug?.(`API login succeeded at ${endpoint}`);
                        return state;
                    }

                    // No token but 200 — might use cookies only
                    const setCookieHeaders = resp.headers.getSetCookie?.() || [];
                    if (setCookieHeaders.length > 0) {
                        const context = await this._browser.newContext({ ignoreHTTPSErrors: true });
                        const cookies = this._parseSetCookieHeaders(setCookieHeaders);
                        await context.addCookies(cookies);
                        const state = await context.storageState();
                        await context.close();
                        this.logger?.debug?.(`API login succeeded at ${endpoint} (cookie-based)`);
                        return state;
                    }
                }
            } catch {
                // Try next endpoint
            }
        }

        return null;
    }

    /**
     * Cookie injection: use pre-configured cookies from config.
     */
    async _injectCookies(cred, authConfig) {
        const cookies = cred.cookies || authConfig.cookies || [];
        if (cookies.length === 0) return null;

        const context = await this._browser.newContext({ ignoreHTTPSErrors: true });
        const targetUrl = new URL(this.config.target_url);

        const playwrightCookies = cookies.map(c => ({
            name: c.name,
            value: c.value,
            domain: c.domain || targetUrl.hostname,
            path: c.path || '/',
            httpOnly: c.httpOnly ?? true,
            secure: c.secure ?? targetUrl.protocol === 'https:',
            sameSite: c.sameSite || 'Lax',
        }));

        await context.addCookies(playwrightCookies);
        const state = await context.storageState();
        await context.close();
        return state;
    }

    // ═══ Helper Methods ═══

    /**
     * Detect auth-related form elements on the current page.
     * Returns { found: boolean, type: 'password'|'otp'|'phone'|'social'|'email', details: string }
     */
    async _detectAuthForm(page) {
        return page.evaluate(() => {
            // — Priority 1: Traditional password field
            if (document.querySelector('input[type="password"]')) {
                return { found: true, type: 'password', details: 'Password input field detected' };
            }

            // — Priority 2: Phone / mobile number input (OTP-based auth)
            const phoneSelectors = [
                'input[type="tel"]',
                'input[name*="phone"]', 'input[name*="mobile"]',
                'input[id*="phone"]', 'input[id*="mobile"]',
                'input[placeholder*="phone" i]', 'input[placeholder*="mobile" i]',
                'input[autocomplete="tel"]',
            ];
            for (const sel of phoneSelectors) {
                const el = document.querySelector(sel);
                if (el && el.offsetParent !== null) {
                    return { found: true, type: 'phone', details: `Phone input detected: ${sel}` };
                }
            }

            // — Priority 3: OTP input fields
            const otpSelectors = [
                'input[name*="otp"]', 'input[id*="otp"]',
                'input[autocomplete="one-time-code"]',
                'input[placeholder*="OTP" i]', 'input[placeholder*="verification code" i]',
            ];
            for (const sel of otpSelectors) {
                const el = document.querySelector(sel);
                if (el && el.offsetParent !== null) {
                    return { found: true, type: 'otp', details: `OTP input detected: ${sel}` };
                }
            }

            // — Priority 4: Social / OAuth login buttons
            const allButtons = Array.from(document.querySelectorAll('button, a, [role="button"]'));
            const socialPatterns = /sign\s*in\s*with\s*(google|facebook|apple|github|microsoft|twitter)|continue\s*with\s*(google|facebook|apple|github)|log\s*in\s*with\s*(google|facebook|apple|github)/i;
            for (const btn of allButtons) {
                const text = btn.textContent?.trim() || '';
                const ariaLabel = btn.getAttribute('aria-label') || '';
                if (socialPatterns.test(text) || socialPatterns.test(ariaLabel)) {
                    return { found: true, type: 'social', details: `Social login button: "${text.substring(0, 60)}"` };
                }
            }

            // — Priority 5: Google sign-in iframe or div
            const gsiFrame = document.querySelector('iframe[src*="accounts.google.com"], div.g_id_signin, #g_id_onload');
            if (gsiFrame) {
                return { found: true, type: 'social', details: 'Google Sign-In widget detected' };
            }

            // — Priority 6: Email-only login (passwordless / magic link)
            const emailField = document.querySelector('input[type="email"], input[name="email"], input[autocomplete="email"]');
            if (emailField && emailField.offsetParent !== null) {
                // Only count as login if there's login-related context around it
                const bodyText = document.body?.textContent?.toLowerCase() || '';
                const hasLoginContext = /sign\s*in|log\s*in|authenticate|get\s*started|create.*account|register/i.test(bodyText);
                if (hasLoginContext) {
                    return { found: true, type: 'email', details: 'Email field with login context detected' };
                }
            }

            return { found: false, type: null, details: null };
        });
    }

    /**
     * Discover login page by probing common login URLs and interactive elements.
     * Uses Playwright to render pages (SPAs render login forms via JS).
     * Now also detects OTP, phone, social login, and modal-based auth flows.
     */
    async _discoverLoginPage() {
        const paths = ['/login', '/signin', '/auth/login', '/auth/signin', '/sign-in',
            '/account/login', '/user/login', '/admin/login', '/api/auth/signin',
            '/sign_in', '/users/sign_in', '/session/new'];
        const baseUrl = this.config.target_url;

        // Launch a browser to render pages (SPA login forms are JS-rendered)
        let browser;
        try {
            browser = await chromium.launch({ headless: true });
        } catch {
            // Fallback to fetch if browser can't launch
            return this._discoverLoginPageViaFetch();
        }

        const context = await browser.newContext({
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        });

        try {
            // ── Phase 1: Probe common login URL paths ──
            for (const p of paths) {
                try {
                    const url = new URL(p, baseUrl).href;
                    const page = await context.newPage();

                    const response = await page.goto(url, {
                        waitUntil: 'networkidle',
                        timeout: 10000,
                    });

                    if (!response || response.status() >= 400) {
                        await page.close();
                        continue;
                    }

                    const authForm = await this._detectAuthForm(page);
                    await page.close();

                    if (authForm.found) {
                        this.loginFormInfo = {
                            type: authForm.type,
                            triggerSelector: null,
                            isModal: false,
                            url,
                            details: authForm.details,
                        };
                        this.logger?.info?.(`Discovered login page: ${url} (${authForm.type}: ${authForm.details})`);
                        await context.close();
                        await browser.close();
                        return url;
                    }
                } catch {
                    // Skip this path
                }
            }

            // ── Phase 2: Check the homepage for inline login forms ──
            let homePage;
            try {
                homePage = await context.newPage();
                await homePage.goto(baseUrl, { waitUntil: 'networkidle', timeout: 10000 });

                const homeAuthForm = await this._detectAuthForm(homePage);
                if (homeAuthForm.found) {
                    this.loginFormInfo = {
                        type: homeAuthForm.type,
                        triggerSelector: null,
                        isModal: false,
                        url: baseUrl,
                        details: homeAuthForm.details,
                    };
                    this.logger?.info?.(`Discovered login form on homepage: ${baseUrl} (${homeAuthForm.type})`);
                    await homePage.close();
                    await context.close();
                    await browser.close();
                    return baseUrl;
                }
            } catch {
                homePage = null;
            }

            // ── Phase 3: Click login trigger buttons/links to discover modals ──
            if (homePage) {
                const loginTriggerSelectors = [
                    // Text-based (Playwright :has-text)
                    'a:has-text("Login")', 'a:has-text("Log in")', 'a:has-text("Sign in")',
                    'a:has-text("Sign In")', 'a:has-text("Log In")',
                    'button:has-text("Login")', 'button:has-text("Log in")',
                    'button:has-text("Sign in")', 'button:has-text("Sign In")',
                    'button:has-text("Log In")', 'button:has-text("Get Started")',
                    'button:has-text("My Account")', 'a:has-text("My Account")',
                    // Attribute-based
                    '[data-testid*="login"]', '[data-testid*="signin"]',
                    '[aria-label*="login" i]', '[aria-label*="sign in" i]',
                    '[href*="login"]', '[href*="signin"]', '[href*="sign-in"]',
                ];

                for (const triggerSel of loginTriggerSelectors) {
                    try {
                        const trigger = await homePage.$(triggerSel);
                        if (!trigger) continue;

                        // Check if trigger is visible
                        const isVisible = await trigger.isVisible().catch(() => false);
                        if (!isVisible) continue;

                        this.logger?.debug?.(`Clicking login trigger: ${triggerSel}`);

                        // Snapshot URL before click
                        const urlBefore = homePage.url();

                        // Click and wait for either navigation or DOM change
                        await Promise.all([
                            homePage.waitForEvent('framenavigated', { timeout: 3000 })
                                .catch(() => null),
                            trigger.click(),
                        ]);

                        // Wait a moment for modals/SPAs to render
                        await homePage.waitForTimeout(1500);

                        // Check if a modal/dialog appeared
                        const modalDetected = await homePage.evaluate(() => {
                            const modalSelectors = [
                                '[role="dialog"]', '[role="alertdialog"]',
                                '.modal', '.Modal', '[class*="modal"]', '[class*="Modal"]',
                                '[class*="dialog"]', '[class*="Dialog"]',
                                '[class*="overlay"]', '[class*="Overlay"]',
                                '[class*="popup"]', '[class*="Popup"]',
                                '[class*="auth"]', '[class*="Auth"]',
                                '[class*="login"]', '[class*="Login"]',
                            ];
                            for (const sel of modalSelectors) {
                                const el = document.querySelector(sel);
                                if (el && el.offsetParent !== null) return true;
                            }
                            return false;
                        });

                        const urlAfter = homePage.url();
                        const navigated = urlAfter !== urlBefore;

                        // Now check for auth forms in the current state
                        const postClickAuth = await this._detectAuthForm(homePage);

                        if (postClickAuth.found) {
                            this.loginFormInfo = {
                                type: postClickAuth.type,
                                triggerSelector: triggerSel,
                                isModal: modalDetected && !navigated,
                                url: navigated ? urlAfter : baseUrl,
                                details: postClickAuth.details,
                            };
                            const location = modalDetected ? 'modal' : (navigated ? `page ${urlAfter}` : 'homepage');
                            this.logger?.info?.(`Discovered login form via button click → ${location} (${postClickAuth.type}: ${postClickAuth.details})`);
                            await homePage.close();
                            await context.close();
                            await browser.close();
                            return navigated ? urlAfter : baseUrl;
                        }

                        // If we navigated away, go back for next attempt
                        if (navigated) {
                            await homePage.goto(baseUrl, { waitUntil: 'networkidle', timeout: 10000 }).catch(() => { });
                        } else if (modalDetected) {
                            // Try to close the modal (press Escape) before next attempt
                            await homePage.keyboard.press('Escape');
                            await homePage.waitForTimeout(500);
                        }
                    } catch {
                        // Skip this trigger
                    }
                }
                await homePage.close().catch(() => { });
            }
        } finally {
            await context.close().catch(() => { });
            await browser.close().catch(() => { });
        }

        return null;
    }

    /**
     * Fallback login page discovery using fetch (for non-SPA sites).
     */
    async _discoverLoginPageViaFetch() {
        const paths = ['/login', '/signin', '/auth/login', '/auth/signin', '/sign-in',
            '/account/login', '/user/login', '/admin/login'];
        const baseUrl = this.config.target_url;

        for (const p of paths) {
            try {
                const url = new URL(p, baseUrl).href;
                const resp = await fetch(url, {
                    redirect: 'follow',
                    signal: AbortSignal.timeout(5000),
                });
                if (resp.ok) {
                    const body = await resp.text();
                    // Detect password, phone, OTP, or email login fields in HTML
                    const hasPassword = /type=["']password["']/i.test(body);
                    const hasPhone = /type=["']tel["']|name=["'][^"']*(?:phone|mobile)[^"']*["']/i.test(body);
                    const hasOtp = /name=["'][^"']*otp[^"']*["']|autocomplete=["']one-time-code["']/i.test(body);
                    const hasLoginContext = /login|sign.?in|authenticate/i.test(body);

                    if (hasPassword || ((hasPhone || hasOtp) && hasLoginContext)) {
                        const type = hasPassword ? 'password' : hasPhone ? 'phone' : 'otp';
                        this.loginFormInfo = { type, triggerSelector: null, isModal: false, url, details: `Detected via fetch (${type})` };
                        this.logger?.debug?.(`Discovered login page via fetch: ${url} (${type})`);
                        return url;
                    }
                }
            } catch { /* skip */ }
        }
        return null;
    }

    /**
     * Interactively prompt the user for credentials in the terminal.
     * Retries up to 3 times on auth failure.
     * Returns { role, username, password } or null if skipped.
     */
    async _promptForCredentials(loginUrl) {
        // Don't prompt in CI/CD or non-interactive environments
        if (!process.stdin.isTTY) return null;

        // Stop the spinner before prompting (hook set by CLI)
        this._onBeforePrompt?.();

        const chalk = await import('chalk').then(m => m.default).catch(() => ({ hex: () => s => s, dim: s => s, yellow: s => s, green: s => s, red: s => s, bold: s => s }));

        console.log();
        console.log(chalk.yellow('  🔑 Login form detected at: ') + chalk.dim(loginUrl));
        console.log(chalk.dim('     Enter credentials for authenticated scanning, or press Enter to skip.'));

        const MAX_RETRIES = 3;

        for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            console.log();

            if (attempt > 1) {
                console.log(chalk.red(`  ✘ Login failed. Attempt ${attempt}/${MAX_RETRIES} — try again or press Enter to skip.`));
                console.log();
            }

            const username = await this._ask(chalk.dim('  Username/Email: '));
            if (!username) {
                console.log(chalk.dim('  Skipped — scanning unauthenticated.'));
                console.log();
                return null;
            }

            const password = await this._askSecret(chalk.dim('  Password: '));
            if (!password) {
                console.log(chalk.dim('  Skipped — scanning unauthenticated.'));
                console.log();
                return null;
            }

            const role = attempt === 1
                ? (await this._ask(chalk.dim('  Role name (default: user): ')) || 'user')
                : 'user';

            const cred = { role, username, password };

            // Try to actually authenticate with these credentials
            console.log(chalk.dim('  Verifying credentials...'));

            this._browser = this._browser || await (await import('playwright')).chromium.launch({ headless: true });
            const authConfig = this.config.auth || {};
            const state = await this._autoLogin(cred, { ...authConfig, login_url: loginUrl });

            if (state) {
                this.authStates.set(role, state);
                console.log(chalk.green(`  ✔ Login successful as "${role}"`));
                console.log();
                await this._browser.close();
                this._browser = null;
                return cred;
            }

            // Last attempt failed
            if (attempt === MAX_RETRIES) {
                console.log(chalk.red(`  ✘ Login failed after ${MAX_RETRIES} attempts — scanning unauthenticated.`));
                console.log();
                await this._browser.close();
                this._browser = null;
                return null;
            }
        }

        return null;
    }

    /**
     * Interactive OTP login flow via terminal.
     * 1. Prompts for phone number
     * 2. Opens browser, triggers login, fills phone, clicks "Request OTP"
     * 3. Prompts for OTP
     * 4. Fills OTP, verifies login, captures auth state
     */
    async _promptForOTPLogin(loginUrl) {
        // Don't prompt in CI/CD or non-interactive environments
        if (!process.stdin.isTTY) return null;

        // Stop the spinner before prompting (hook set by CLI)
        this._onBeforePrompt?.();

        const chalk = await import('chalk').then(m => m.default).catch(() => ({
            hex: () => s => s, dim: s => s, yellow: s => s, green: s => s, red: s => s, bold: s => s, cyan: s => s
        }));

        console.log();
        console.log(chalk.yellow('  📱 Phone/OTP login detected at: ') + chalk.dim(loginUrl));
        console.log(chalk.dim('     Enter your phone number for authenticated scanning, or press Enter to skip.'));
        console.log();

        const phoneNumber = await this._ask(chalk.dim('  Phone number (e.g. 9876543210): '));
        if (!phoneNumber) {
            console.log(chalk.dim('  Skipped — scanning unauthenticated.'));
            console.log();
            return null;
        }

        // Launch browser and navigate to trigger the login
        console.log(chalk.dim('  Opening login form...'));
        let browser;
        try {
            browser = await chromium.launch({ headless: true });
        } catch (err) {
            console.log(chalk.red(`  ✘ Could not launch browser: ${err.message}`));
            return null;
        }

        const context = await browser.newContext({
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        });

        const page = await context.newPage();

        try {
            await page.goto(loginUrl, { waitUntil: 'networkidle', timeout: 15000 });

            // If login is behind a trigger button (modal), click it first
            const triggerSelector = this.loginFormInfo?.triggerSelector;
            if (triggerSelector) {
                this.logger?.debug?.(`Clicking login trigger: ${triggerSelector}`);
                const trigger = await page.$(triggerSelector);
                if (trigger) {
                    await trigger.click();
                }
            }

            // Find the phone number field — wait for it to appear (modals may render async)
            const phoneSelectors = [
                'input[type="tel"]',
                'input[id*="mobile"]', 'input[id*="phone"]',
                'input[name*="phone"]', 'input[name*="mobile"]',
                'input[placeholder*="phone" i]', 'input[placeholder*="mobile" i]',
                'input[autocomplete="tel"]',
            ];
            const combinedPhoneSelector = phoneSelectors.join(', ');

            // Wait up to 8s for any phone input to appear in the DOM
            let phoneField = null;
            try {
                const foundEl = await page.waitForSelector(combinedPhoneSelector, {
                    state: 'visible',
                    timeout: 8000,
                });
                if (foundEl) {
                    // Identify which specific selector matched
                    for (const sel of phoneSelectors) {
                        const el = await page.$(sel);
                        if (el) {
                            const isVisible = await el.isVisible().catch(() => false);
                            if (isVisible) { phoneField = sel; break; }
                        }
                    }
                }
            } catch {
                this.logger?.debug?.('Phone input did not appear within timeout');
            }

            if (!phoneField) {
                console.log(chalk.red('  ✘ Could not find phone number input field'));
                await page.close(); await context.close(); await browser.close();
                return null;
            }

            this.logger?.debug?.(`Filling phone field: ${phoneField}`);
            await page.fill(phoneField, phoneNumber);
            await page.waitForTimeout(500);

            // Find and click "Request OTP" / "Send OTP" / "Get OTP" button
            const otpButtonSelectors = [
                'button:has-text("Request OTP")', 'button:has-text("Send OTP")',
                'button:has-text("Get OTP")', 'button:has-text("Verify")',
                'button:has-text("Continue")', 'button:has-text("Next")',
                'button:has-text("Submit")', 'button:has-text("Proceed")',
                '[id*="otp"][role="button"]', '[id*="otp"] button',
                'button[id*="otp"]', 'button[id*="get_otp"]',
                'button[type="submit"]',
            ];

            let otpButtonClicked = false;
            for (const sel of otpButtonSelectors) {
                try {
                    const btn = await page.$(sel);
                    if (btn) {
                        const isVisible = await btn.isVisible().catch(() => false);
                        if (!isVisible) continue;
                        // Check if button is enabled
                        const isDisabled = await btn.isDisabled().catch(() => false);
                        if (isDisabled) {
                            await page.waitForTimeout(1000);
                            const stillDisabled = await btn.isDisabled().catch(() => false);
                            if (stillDisabled) continue;
                        }
                        this.logger?.debug?.(`Clicking OTP request button: ${sel}`);
                        await btn.click();
                        otpButtonClicked = true;
                        break;
                    }
                } catch { /* try next */ }
            }

            if (!otpButtonClicked) {
                // Fallback: press Enter to submit the form
                this.logger?.debug?.('No OTP button found, pressing Enter');
                await page.keyboard.press('Enter');
            }

            // Wait for OTP input to appear or page to transition
            console.log(chalk.dim('  OTP requested — waiting for SMS...'));
            await page.waitForTimeout(3000);

            // Prompt for OTP
            console.log();
            const otp = await this._ask(chalk.dim('  Enter OTP received on your phone: '));
            if (!otp) {
                console.log(chalk.dim('  Skipped — scanning unauthenticated.'));
                await page.close(); await context.close(); await browser.close();
                return null;
            }

            // Find OTP input fields and fill them
            // Some sites use a single input, others use multiple single-digit inputs
            const otpFilled = await this._fillOTP(page, otp);

            if (!otpFilled) {
                console.log(chalk.red('  ✘ Could not find OTP input field'));
                await page.close(); await context.close(); await browser.close();
                return null;
            }

            // Find and click verify/submit button after OTP
            const verifyButtonSelectors = [
                'button[id*="verify"]', 'button[id*="otp"]',
                'button:has-text("Verify")', 'button:has-text("Submit")',
                'button:has-text("Confirm")', 'button:has-text("Log in")',
                'button:has-text("Login")', 'button:has-text("Sign in")',
                'button:has-text("Continue")', 'button:has-text("Proceed")',
                'button[type="submit"]',
            ];

            let verifyClicked = false;
            for (const sel of verifyButtonSelectors) {
                try {
                    const btn = await page.$(sel);
                    if (btn) {
                        const isVisible = await btn.isVisible().catch(() => false);
                        if (isVisible) {
                            this.logger?.debug?.(`Clicking verify button: ${sel}`);
                            await btn.click();
                            verifyClicked = true;
                            break;
                        }
                    }
                } catch { /* try next */ }
            }

            if (!verifyClicked) {
                await page.keyboard.press('Enter');
            }

            // Wait for login to complete
            console.log(chalk.dim('  Verifying OTP...'));
            await page.waitForTimeout(5000);

            // Verify we're logged in
            const loggedIn = await this._verifyLogin(page, loginUrl);

            if (loggedIn) {
                const postLoginUrl = page.url();

                // Discover links on authenticated page
                const discoveredLinks = await page.evaluate(() => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(href => href && !href.startsWith('javascript:') && !href.startsWith('mailto:'));
                }).catch(() => []);

                const state = await context.storageState();
                console.log(chalk.green('  ✔ OTP login successful!'));
                console.log();
                await page.close(); await context.close(); await browser.close();
                this.authStates.set('user', { state, postLoginUrl, discoveredLinks });
                return true;
            } else {
                console.log(chalk.red('  ✘ OTP verification failed — could not confirm login'));
                console.log(chalk.dim('  Continuing with unauthenticated scan.'));
                console.log();
                await page.close(); await context.close(); await browser.close();
                return null;
            }
        } catch (err) {
            this.logger?.debug?.(`OTP login error: ${err.message}`);
            console.log(chalk.red(`  ✘ OTP login error: ${err.message}`));
            await page.close().catch(() => {});
            await context.close().catch(() => {});
            await browser.close().catch(() => {});
            return null;
        }
    }

    /**
     * Fill OTP into the page.
     * Handles both single-input and multi-digit-input OTP forms.
     * Uses Playwright's type() for realistic key events that trigger framework handlers.
     */
    async _fillOTP(page, otp) {
        // Wait a moment for OTP screen to fully render
        await page.waitForTimeout(1000);

        // Try 1: Multiple single-digit OTP inputs (most common modern pattern)
        // Use Playwright's click + type for each input to trigger proper JS events
        const multiDigitContainerSelectors = [
            '[class*="otp"]', '[class*="OTP"]',
            '[class*="verification-code"]', '[class*="pin-input"]',
            '[class*="code-input"]',
            '[id*="otp"]', '[id*="verification"]',
        ];

        // First check for multi-digit inputs in known containers
        for (const containerSel of multiDigitContainerSelectors) {
            try {
                const container = await page.$(containerSel);
                if (!container) continue;

                const inputs = await container.$$('input');
                if (inputs.length >= 4 && inputs.length <= 8) {
                    this.logger?.debug?.(`Found ${inputs.length} OTP digit inputs in ${containerSel}`);
                    const digits = otp.split('');
                    for (let i = 0; i < Math.min(digits.length, inputs.length); i++) {
                        await inputs[i].click();
                        await inputs[i].fill('');  // Clear first
                        await inputs[i].type(digits[i], { delay: 50 });
                        await page.waitForTimeout(100); // Let framework handle focus shift
                    }
                    return true;
                }
            } catch { /* try next container */ }
        }

        // Try 2: maxlength=1 inputs anywhere on the page (generic multi-digit)
        try {
            const digitInputs = await page.$$('input[maxlength="1"]');
            if (digitInputs.length >= 4 && digitInputs.length <= 8) {
                this.logger?.debug?.(`Found ${digitInputs.length} maxlength=1 OTP inputs`);
                const digits = otp.split('');
                for (let i = 0; i < Math.min(digits.length, digitInputs.length); i++) {
                    await digitInputs[i].click();
                    await digitInputs[i].fill('');
                    await digitInputs[i].type(digits[i], { delay: 50 });
                    await page.waitForTimeout(100);
                }
                return true;
            }
        } catch { /* continue to single input */ }

        // Try 3: Single OTP input field
        const singleOtpSelectors = [
            'input[name*="otp"]', 'input[id*="otp"]',
            'input[autocomplete="one-time-code"]',
            'input[placeholder*="OTP" i]',
            'input[placeholder*="verification" i]',
            'input[placeholder*="code" i]',
            'input[type="number"][maxlength]',
        ];

        for (const sel of singleOtpSelectors) {
            try {
                const el = await page.$(sel);
                if (el) {
                    const isVisible = await el.isVisible().catch(() => false);
                    if (isVisible) {
                        this.logger?.debug?.(`Filling single OTP input: ${sel}`);
                        await el.click();
                        await el.fill(otp);
                        return true;
                    }
                }
            } catch { /* try next */ }
        }

        // Try 4: Any visible text/tel input that isn't the phone field
        try {
            const allInputs = await page.$$('input:visible');
            for (const inp of allInputs) {
                const type = await inp.getAttribute('type') || 'text';
                const id = await inp.getAttribute('id') || '';
                const name = await inp.getAttribute('name') || '';
                // Skip inputs that look like phone/email fields
                if (/phone|mobile|email/i.test(id + name)) continue;
                if (type === 'hidden' || type === 'email') continue;
                const isVisible = await inp.isVisible().catch(() => false);
                if (isVisible) {
                    this.logger?.debug?.(`Filling fallback input (type=${type}, id=${id})`);
                    await inp.click();
                    await inp.fill(otp);
                    return true;
                }
            }
        } catch { /* skip */ }

        return false;
    }

    /**
     * Prompt for regular text input.
     */
    _ask(prompt) {
        return new Promise((resolve) => {
            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout,
            });
            rl.question(prompt, (answer) => {
                rl.close();
                resolve(answer.trim());
            });
        });
    }

    /**
     * Prompt for password input with masking (shows * for each character).
     * Uses a muted output stream to prevent raw character echo.
     */
    _askSecret(prompt) {
        return new Promise((resolve) => {
            // Write the prompt
            process.stdout.write(prompt);

            let secret = '';

            // Create a muted writable stream that swallows all output
            const mutedOut = new Writable({
                write(_chunk, _encoding, callback) {
                    callback(); // swallow all output — we handle display manually
                },
            });

            const rl = readline.createInterface({
                input: process.stdin,
                output: mutedOut,
                terminal: true,
            });

            // Listen for keypress events
            process.stdin.setRawMode(true);

            const onData = (buf) => {
                const c = buf.toString();

                if (c === '\n' || c === '\r' || c === '\u0004') {
                    // Enter — done
                    process.stdin.setRawMode(false);
                    process.stdin.removeListener('data', onData);
                    process.stdout.write('\n');
                    rl.close();
                    resolve(secret);
                } else if (c === '\u0003') {
                    // Ctrl+C
                    process.stdin.setRawMode(false);
                    process.stdin.removeListener('data', onData);
                    rl.close();
                    process.exit(0);
                } else if (c === '\u007F' || c === '\b') {
                    // Backspace
                    if (secret.length > 0) {
                        secret = secret.slice(0, -1);
                        process.stdout.write('\b \b');
                    }
                } else if (c.charCodeAt(0) >= 32) {
                    // Printable character only
                    secret += c;
                    process.stdout.write('•');
                }
            };

            process.stdin.on('data', onData);
            process.stdin.resume();
        });
    }

    /**
     * Auto-detect username field selector.
     */
    async _findUsernameField(page) {
        const selectors = [
            'input[type="email"]',
            'input[name="email"]',
            'input[name="username"]',
            'input[name="user"]',
            'input[name="login"]',
            'input[id="email"]',
            'input[id="username"]',
            'input[autocomplete="email"]',
            'input[autocomplete="username"]',
            'input[type="text"]:first-of-type',
        ];
        for (const sel of selectors) {
            const el = await page.$(sel);
            if (el) return sel;
        }
        return null;
    }

    /**
     * Auto-detect password field selector.
     */
    async _findPasswordField(page) {
        const selectors = [
            'input[type="password"]',
            'input[name="password"]',
            'input[name="passwd"]',
            'input[name="pass"]',
            'input[id="password"]',
            'input[autocomplete="current-password"]',
        ];
        for (const sel of selectors) {
            const el = await page.$(sel);
            if (el) return sel;
        }
        return null;
    }

    /**
     * Auto-detect submit button selector.
     */
    async _findSubmitButton(page) {
        const selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Log in")',
            'button:has-text("Sign in")',
            'button:has-text("Login")',
            'button:has-text("Submit")',
            'form button',
        ];
        for (const sel of selectors) {
            const el = await page.$(sel);
            if (el) return sel;
        }
        return null;
    }

    /**
     * Verify login succeeded using multiple strict signals.
     * Returns true only when strong evidence of successful login exists.
     */
    async _verifyLogin(page, loginUrl) {
        // Wait a moment for SPAs to settle (toasts, redirects, state changes)
        await page.waitForTimeout(1500);

        const currentUrl = page.url();

        // ── FAIL FAST: Check for error indicators ──
        const hasErrors = await page.evaluate(() => {
            const body = document.body?.textContent?.toLowerCase() || '';
            const errorPatterns = [
                'invalid password', 'incorrect password', 'wrong password',
                'invalid credentials', 'invalid email', 'invalid username',
                'authentication failed', 'login failed', 'sign in failed',
                'account not found', 'user not found', 'no account',
                'too many attempts', 'account locked', 'access denied',
                'incorrect email', 'email or password', 'check your credentials',
            ];

            // Check text content for error messages
            if (errorPatterns.some(p => body.includes(p))) return true;

            // Check for visible error/alert elements
            const errorSelectors = [
                '[role="alert"]', '.error', '.error-message', '.alert-error',
                '.alert-danger', '.toast-error', '.notification-error',
                '[class*="error"]', '[class*="Error"]',
                '[data-testid*="error"]', '[aria-invalid="true"]',
            ];
            for (const sel of errorSelectors) {
                const el = document.querySelector(sel);
                if (el && el.offsetParent !== null && el.textContent.trim().length > 0) {
                    return true;
                }
            }
            return false;
        });

        if (hasErrors) {
            this.logger?.debug?.('Login verification: error indicators detected on page');
            return false;
        }

        // ── CHECK 1: Auth cookies/tokens were set ──
        const cookies = await page.context().cookies();
        const authCookieNames = [
            'session', 'sess', 'sid', 'token', 'auth', 'jwt',
            'access_token', 'refresh_token', '_session', 'connect.sid',
            'sb-access-token', 'sb-refresh-token',  // Supabase
            'next-auth', '__session',                // Next.js/Firebase
        ];
        const hasAuthCookies = cookies.some(c =>
            authCookieNames.some(name =>
                c.name.toLowerCase().includes(name)
            )
        );

        // Check localStorage for tokens
        const hasLocalStorageAuth = await page.evaluate(() => {
            const tokenKeys = ['token', 'access_token', 'auth_token', 'jwt', 'session',
                'sb-access-token', 'supabase.auth.token'];
            for (const key of tokenKeys) {
                if (localStorage.getItem(key)) return true;
            }
            // Check all keys for auth-related values
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                if (k && (k.includes('auth') || k.includes('token') || k.includes('session'))) {
                    const v = localStorage.getItem(k);
                    if (v && v.length > 10) return true;
                }
            }
            return false;
        }).catch(() => false);

        if (hasAuthCookies || hasLocalStorageAuth) {
            this.logger?.debug?.('Login verification: auth cookies/tokens detected');
            return true;
        }

        // ── CHECK 2: URL navigated away from login page ──
        const loginPaths = ['/login', '/signin', '/sign-in', '/auth/login', '/auth/signin'];
        const wasOnLoginPath = loginPaths.some(p => loginUrl.includes(p));
        const isStillOnLoginPath = loginPaths.some(p => currentUrl.includes(p));

        if (wasOnLoginPath && !isStillOnLoginPath && currentUrl !== loginUrl) {
            this.logger?.debug?.(`Login verification: URL changed from ${loginUrl} to ${currentUrl}`);
            return true;
        }

        // ── CHECK 3: Page no longer has password field AND has logged-in UI ──
        const hasPasswordField = await page.$('input[type="password"]');
        if (!hasPasswordField) {
            // Only trust this if we also see logged-in indicators
            const hasLoggedInUI = await page.evaluate(() => {
                // Look for logout buttons/links (text-based search — :has-text isn't valid CSS)
                const buttons = Array.from(document.querySelectorAll('button, a'));
                const hasLogoutBtn = buttons.some(el => {
                    const text = el.textContent?.trim().toLowerCase() || '';
                    return text === 'log out' || text === 'sign out' ||
                        text === 'logout' || text === 'signout' ||
                        text === 'disconnect' || text === 'exit';
                });
                if (hasLogoutBtn) return true;

                // Check for aria-label based logout
                const ariaLogout = document.querySelector(
                    '[aria-label*="logout"], [aria-label*="sign out"], [aria-label*="log out"]'
                );
                if (ariaLogout) return true;

                // Check for avatar/profile menu (common logged-in indicator)
                const avatar = document.querySelector(
                    '[class*="avatar"], [class*="Avatar"], ' +
                    '[data-testid*="avatar"], [data-testid*="user-menu"]'
                );
                if (avatar) return true;

                return false;
            });

            if (hasLoggedInUI) {
                this.logger?.debug?.('Login verification: password field gone + logged-in UI detected');
                return true;
            }
        }

        this.logger?.debug?.('Login verification: no strong evidence of successful login');
        return false;
    }

    /**
     * Parse Set-Cookie headers into Playwright cookie format.
     */
    _parseSetCookieHeaders(headers) {
        const targetUrl = new URL(this.config.target_url);
        return headers.map(header => {
            const parts = header.split(';').map(p => p.trim());
            const [nameValue, ...attrs] = parts;
            const eqIdx = nameValue.indexOf('=');
            const name = nameValue.substring(0, eqIdx);
            const value = nameValue.substring(eqIdx + 1);

            const cookie = {
                name,
                value,
                domain: targetUrl.hostname,
                path: '/',
            };

            for (const attr of attrs) {
                const [key, val] = attr.split('=').map(s => s.trim());
                switch (key.toLowerCase()) {
                    case 'domain': cookie.domain = val; break;
                    case 'path': cookie.path = val; break;
                    case 'httponly': cookie.httpOnly = true; break;
                    case 'secure': cookie.secure = true; break;
                    case 'samesite': cookie.sameSite = val; break;
                }
            }

            return cookie;
        }).filter(c => c.name && c.value);
    }

    /**
     * Get Playwright storageState for a specific role.
     */
    getAuthState(role) {
        const entry = this.authStates.get(role);
        if (!entry) return null;
        // Handle both old (plain state) and new ({ state, postLoginUrl }) shapes
        return entry.state || entry;
    }

    /**
     * Get post-login URL for a specific role (where the user lands after login).
     */
    getPostLoginUrl(role) {
        const entry = this.authStates.get(role);
        return entry?.postLoginUrl || null;
    }

    /**
     * Get links discovered on the post-login page for a specific role.
     */
    getDiscoveredLinks(role) {
        const entry = this.authStates.get(role);
        return entry?.discoveredLinks || [];
    }

    /**
     * Get auth token for a specific role (for API-based agents).
     */
    getAuthToken(role) {
        return this.authTokens.get(role) || null;
    }

    /**
     * Get all authenticated roles.
     */
    get roles() {
        return [...this.authStates.keys()];
    }

    /**
     * Check if any auth is available.
     */
    get isAuthenticated() {
        return this.authStates.size > 0;
    }

    /**
     * Create a Playwright browser context with auth for a given role.
     */
    async createAuthContext(browser, role) {
        const state = this.getAuthState(role);
        if (!state) return null;

        return browser.newContext({
            storageState: state,
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        });
    }

    /**
     * Get fetch headers with auth token for a given role.
     */
    getFetchHeaders(role) {
        const tokenInfo = this.authTokens.get(role);
        if (!tokenInfo) return {};
        return {
            'Authorization': `${tokenInfo.type} ${tokenInfo.token}`,
        };
    }
}

export default AuthManager;
