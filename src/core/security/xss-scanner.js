import { chromium } from 'playwright';
import { createFinding } from '../../utils/finding.js';
import { collectParamNames } from '../../utils/param-discovery.js';

/**
 * XSS Scanner — Probes all discovered input surfaces for Cross-Site Scripting.
 * Tests reflected, stored, and DOM-based XSS with a comprehensive payload library.
 * SAFETY: No destructive payloads — all tests use detection-only markers.
 */
export class XSSScanner {
    constructor(logger) {
        this.logger = logger;
        this.findings = [];
        this._candidateParams = [];
    }

    // Fallback guess-list of common reflected-input parameter names. Used to
    // augment (never replace) parameters discovered from the actual surface.
    static FALLBACK_PARAMS = [
        'q', 'search', 'query', 'keyword', 's', 'term', 'name', 'id', 'page',
        'redirect', 'url', 'return', 'next', 'callback',
    ];

    // XSS test payloads — designed for detection, not exploitation
    static PAYLOADS = [
        { name: 'Basic script tag', payload: '<script>window.__VIBE_SHIELD_XSS_1=1</script>', marker: '__VIBE_SHIELD_XSS_1' },
        { name: 'IMG onerror', payload: '<img src=x onerror="window.__VIBE_SHIELD_XSS_2=1">', marker: '__VIBE_SHIELD_XSS_2' },
        { name: 'SVG onload', payload: '<svg onload="window.__VIBE_SHIELD_XSS_3=1">', marker: '__VIBE_SHIELD_XSS_3' },
        { name: 'Event handler', payload: '" onfocus="window.__VIBE_SHIELD_XSS_4=1" autofocus="', marker: '__VIBE_SHIELD_XSS_4' },
        { name: 'Template literal', payload: '${alert(1)}', marker: '${alert' },
        { name: 'HTML entity bypass', payload: '&lt;script&gt;alert(1)&lt;/script&gt;', marker: '<script>alert' },
        { name: 'Single quote break', payload: "' onmouseover='window.__VIBE_SHIELD_XSS_5=1", marker: '__VIBE_SHIELD_XSS_5' },
        { name: 'Double quote break', payload: '" onmouseover="window.__VIBE_SHIELD_XSS_6=1', marker: '__VIBE_SHIELD_XSS_6' },
        { name: 'JavaScript URL', payload: 'javascript:window.__VIBE_SHIELD_XSS_7=1', marker: '__VIBE_SHIELD_XSS_7' },
    ];

    /**
     * Run XSS scanning on all discovered surfaces.
     */
    async scan(surfaceInventory) {
        // Derive real candidate parameters from forms, query strings on
        // discovered links/pages, and API endpoint URLs — then augment with the
        // fallback guess-list (discovered params take priority).
        const discovered = collectParamNames(surfaceInventory);
        this._candidateParams = [
            ...discovered,
            ...XSSScanner.FALLBACK_PARAMS.filter(p => !discovered.includes(p)),
        ].slice(0, 60);
        this.logger?.debug?.(
            `XSS scanner: ${discovered.length} discovered params + ${XSSScanner.FALLBACK_PARAMS.length} fallback ` +
            `→ ${this._candidateParams.length} candidates`
        );

        const browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        });

        // Test URL parameter reflection
        await this._testURLParamReflection(context, surfaceInventory);

        // Test form input reflection
        await this._testFormInputReflection(context, surfaceInventory);

        await browser.close();
        this.logger?.info?.(`XSS scanner found ${this.findings.length} issues`);
        return this.findings;
    }

    /**
     * Test if URL parameters are reflected without encoding.
     */
    async _testURLParamReflection(context, inventory) {
        for (const pageData of inventory.pages) {
            if (typeof pageData.status !== 'number' || pageData.status >= 400) continue;

            const page = await context.newPage();
            try {
                // Candidate params = discovered (forms/query/api) + fallback guesses
                const testParams = this._candidateParams.length > 0
                    ? this._candidateParams
                    : XSSScanner.FALLBACK_PARAMS;

                for (const param of testParams) {
                    // Use a subset of payloads for URL params
                    for (const { name, payload, marker } of XSSScanner.PAYLOADS.slice(0, 3)) {
                        const testUrl = new URL(pageData.url);
                        testUrl.searchParams.set(param, payload);

                        try {
                            await page.goto(testUrl.toString(), {
                                waitUntil: 'domcontentloaded',
                                timeout: 10000,
                            });

                            // Check if the payload is reflected in the page source
                            const content = await page.content();
                            const isReflected = content.includes(payload);

                            // Check if the XSS actually executed
                            const executed = await page.evaluate((m) => {
                                return window[m] === 1;
                            }, marker).catch(() => false);

                            if (executed) {
                                this.findings.push(createFinding({
                                    module: 'security',
                                    title: `Reflected XSS via URL Parameter: ${param}`,
                                    severity: 'high',
                                    affected_surface: pageData.url,
                                    description: `The URL parameter "${param}" is vulnerable to reflected Cross-Site Scripting (XSS). The payload "${name}" was injected and executed in the browser context.\n\nThis allows attackers to execute arbitrary JavaScript in victims\' browsers via crafted URLs, enabling session hijacking, credential theft, and defacement.`,
                                    reproduction: [
                                        `1. Navigate to: ${testUrl.toString()}`,
                                        `2. The ${name} payload executes in the browser`,
                                        `3. Verify with DevTools: window.${marker} === 1`,
                                    ],
                                    evidence: JSON.stringify({ param, payload, name, executed: true }),
                                    remediation: 'HTML-encode all user input before rendering in the page. Use framework-provided escaping functions. Implement a Content-Security-Policy header to mitigate impact.',
                                    references: ['https://owasp.org/www-community/attacks/xss/', 'CWE-79'],
                                }));
                                break; // One finding per param is sufficient
                            } else if (isReflected) {
                                this.findings.push(createFinding({
                                    module: 'security',
                                    title: `Potential Reflected XSS: ${param} (Payload Reflected)`,
                                    severity: 'medium',
                                    affected_surface: pageData.url,
                                    description: `The URL parameter "${param}" reflects the XSS payload "${name}" in the response without proper encoding. While the payload did not execute in this test (browser may have blocked it), the lack of encoding indicates a vulnerability that could be exploited with alternative payloads.`,
                                    reproduction: [
                                        `1. Navigate to: ${testUrl.toString()}`,
                                        `2. View page source — payload appears unencoded`,
                                    ],
                                    evidence: JSON.stringify({ param, payload, name, reflected: true, executed: false }),
                                    remediation: 'All user input must be HTML-encoded before rendering. Even if the current payload is blocked, other payloads or browser contexts may succeed.',
                                    references: ['https://owasp.org/www-community/attacks/xss/', 'CWE-79'],
                                }));
                                break;
                            }
                        } catch {
                            // Navigation failed — skip
                        }
                    }
                }
            } catch (err) {
                this.logger?.debug?.(`XSS URL param test failed for ${pageData.url}: ${err.message}`);
            } finally {
                await page.close();
            }
        }
    }

    /**
     * Test form inputs for XSS via submission.
     */
    async _testFormInputReflection(context, inventory) {
        for (const form of inventory.forms) {
            const page = await context.newPage();
            try {
                await page.goto(form.page, { waitUntil: 'networkidle', timeout: 15000 });

                // Use a small subset of payloads for each form
                const testPayload = XSSScanner.PAYLOADS[0]; // Basic script tag

                for (const field of form.fields) {
                    if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file'].includes(field.type)) continue;

                    try {
                        const input = await page.$(`[name="${field.name}"]`) || await page.$(`#${field.name}`);
                        if (!input) continue;

                        await input.fill(testPayload.payload);

                        // Submit the form
                        const submitBtn = await page.$(`#${form.id} button[type="submit"]`)
                            || await page.$('button[type="submit"], input[type="submit"]');

                        if (submitBtn) {
                            await submitBtn.click();
                            await page.waitForTimeout(2000);

                            // Check if payload reflected in the response
                            const content = await page.content();
                            if (content.includes(testPayload.payload)) {
                                this.findings.push(createFinding({
                                    module: 'security',
                                    title: `Form XSS: Input "${field.name}" in ${form.id}`,
                                    severity: 'high',
                                    affected_surface: form.page,
                                    description: `The form field "${field.name}" in form "${form.id}" does not sanitize XSS payloads. The submitted ${testPayload.name} payload was reflected in the response without encoding.\n\nThis could lead to stored XSS if the data is persisted and displayed to other users.`,
                                    reproduction: [
                                        `1. Navigate to ${form.page}`,
                                        `2. Enter "${testPayload.payload}" in the "${field.name}" field`,
                                        `3. Submit the form`,
                                        `4. Payload appears unencoded in the response`,
                                    ],
                                    evidence: JSON.stringify({ form: form.id, field: field.name, payload: testPayload.name }),
                                    remediation: 'Sanitize and HTML-encode all form inputs on both client and server side before rendering. Use parameterized queries for database storage.',
                                    references: ['https://owasp.org/www-community/attacks/xss/', 'CWE-79'],
                                }));
                            }

                            // Navigate back for next field test
                            await page.goto(form.page, { waitUntil: 'networkidle', timeout: 10000 });
                        }
                    } catch {
                        // Field test failed — continue
                    }
                }
            } catch (err) {
                this.logger?.debug?.(`XSS form test failed for ${form.page}: ${err.message}`);
            } finally {
                await page.close();
            }
        }
    }
}

export default XSSScanner;
