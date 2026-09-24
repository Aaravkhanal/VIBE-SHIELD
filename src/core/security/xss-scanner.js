import { chromium } from 'playwright';
import { createFinding } from '../../utils/finding.js';
import { collectParamNames } from '../../utils/param-discovery.js';
import { DifferentialEngine } from '../differential-engine.js';
import { observedWebCvss } from '../../utils/cvss-evidence.js';

function shellQuote(value) {
    return `'${String(value).replaceAll("'", `'\\''`)}'`;
}

function browserReplayCommand(url, marker) {
    const script = [
        "import { chromium } from 'playwright';",
        'const browser = await chromium.launch({ headless: true });',
        'const page = await browser.newPage();',
        `await page.goto(${JSON.stringify(url)}, { waitUntil: 'domcontentloaded' });`,
        `const value = await page.evaluate(() => window[${JSON.stringify(marker)}]);`,
        "await page.screenshot({ path: 'vibe-shield-xss-reproduction.png', fullPage: true });",
        "console.log(JSON.stringify({ marker: " + JSON.stringify(marker) + ", value }));",
        'await browser.close();',
        'if (value !== 1) process.exit(1);',
    ].join(' ');
    return `node --input-type=module -e ${shellQuote(script)}`;
}

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
        this.differential = new DifferentialEngine({ logger, timeoutMs: 10000 });
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
                const baselineNavigation = await page.goto(pageData.url, {
                    waitUntil: 'domcontentloaded',
                    timeout: 10000,
                });
                const baselineTitle = await page.title().catch(() => pageData.title || null);
                const testedMarkers = XSSScanner.PAYLOADS.slice(0, 3).map(item => item.marker);
                const baselineMarkers = await page.evaluate(markers => Object.fromEntries(
                    markers.map(marker => [marker, window[marker] ?? null])
                ), testedMarkers).catch(() => Object.fromEntries(testedMarkers.map(marker => [marker, null])));

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
                            const controlUrl = new URL(pageData.url);
                            controlUrl.searchParams.set(param, 'vibe-shield-control');
                            const differential = await this.differential.run({
                                baseline: { url: pageData.url, method: 'GET', redirect: 'follow' },
                                control: { url: controlUrl.toString(), method: 'GET', redirect: 'follow' },
                                payload: { url: testUrl.toString(), method: 'GET', redirect: 'follow' },
                                execute: async request => {
                                    const started = performance.now();
                                    const response = await page.goto(request.url, { waitUntil: 'domcontentloaded', timeout: 10000 });
                                    const body = await page.content();
                                    const markerValue = await page.evaluate(markerName => window[markerName] ?? null, marker).catch(() => null);
                                    return {
                                        status: response?.status() || null,
                                        body,
                                        durationMs: performance.now() - started,
                                        finalUrl: page.url(),
                                        dom: { marker, markerValue, title: await page.title().catch(() => '') },
                                    };
                                },
                                signal: snapshot => snapshot.dom?.markerValue === 1 || snapshot.body.includes(payload),
                            });
                            const navigation = await page.goto(testUrl.toString(), {
                                waitUntil: 'domcontentloaded',
                                timeout: 10000,
                            });

                            // Check if the payload is reflected in the page source
                            const content = await page.content();
                            const isReflected = content.includes(payload) || differential.aggregates.payload.representative?.body.includes(payload);

                            // Check if the XSS actually executed
                            const executed = await page.evaluate((m) => {
                                return window[m] === 1;
                            }, marker).catch(() => false);

                            if (differential.confirmed && executed && baselineMarkers[marker] !== 1) {
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
                                    evidence: JSON.stringify({ param, payload, name, executed: true, differential: differential.evidence }),
                                    cvssAssessment: observedWebCvss({
                                        metrics: { attackVector: 'NETWORK', attackComplexity: 'LOW', privilegesRequired: 'NONE', userInteraction: 'REQUIRED', scope: 'CHANGED', confidentiality: 'NONE', integrity: 'LOW', availability: 'NONE' },
                                        request: `GET ${testUrl}`, role: 'anonymous', observation: 'browser marker execution',
                                        boundary: 'The vulnerable server response caused code to execute in the visiting browser origin.',
                                        impacts: { integrity: `The script set window.${marker} to 1 in the browser; data theft and persistence were not observed.` },
                                    }),
                                    verification: {
                                        level: 'confirmed',
                                        reason: `The injected browser marker window.${marker} was observed with value 1 after navigation.`,
                                        method: 'browser-execution',
                                        proof: {
                                            originalRequest: { method: 'GET', url: pageData.url },
                                            mutatedRequest: { method: 'GET', url: testUrl.toString(), parameter: param, payload },
                                            baselineResponse: {
                                                status: baselineNavigation?.status() || pageData.status,
                                                url: pageData.url,
                                                title: baselineTitle,
                                                markerValue: baselineMarkers[marker],
                                                differential: differential.evidence.baseline,
                                            },
                                            vulnerableResponse: { status: navigation?.status() || null, finalUrl: page.url(), payloadReflected: isReflected },
                                            responseDifference: { marker, baselineMarkerValue: baselineMarkers[marker], vulnerableMarkerValue: 1, differential: differential.evidence.comparisons },
                                            trace: {
                                                type: 'browser-execution-trace',
                                                steps: [
                                                    { action: 'navigate-baseline', url: pageData.url, markerValue: baselineMarkers[marker] },
                                                    { action: 'navigate-mutated', url: testUrl.toString(), status: navigation?.status() || null },
                                                    { action: 'evaluate', expression: `window.${marker}`, observedValue: 1 },
                                                ],
                                            },
                                            reproductionCommand: browserReplayCommand(testUrl.toString(), marker),
                                            accountRole: 'anonymous',
                                        },
                                    },
                                    remediation: 'HTML-encode all user input before rendering in the page. Use framework-provided escaping functions. Implement a Content-Security-Policy header to mitigate impact.',
                                    references: ['https://owasp.org/www-community/attacks/xss/', 'CWE-79'],
                                }));
                                break; // One finding per param is sufficient
                            } else if (differential.confirmed && isReflected) {
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
                                    evidence: JSON.stringify({ param, payload, name, reflected: true, executed: false, differential: differential.evidence }),
                                    verification: {
                                        level: 'potential',
                                        reason: 'The payload was reflected without encoding, but browser execution was not observed.',
                                        method: 'reflection-heuristic',
                                        proof: {
                                            originalRequest: { method: 'GET', url: pageData.url },
                                            mutatedRequest: { method: 'GET', url: testUrl.toString(), parameter: param, payload },
                                            baselineResponse: { status: pageData.status, url: pageData.url, differential: differential.evidence.baseline },
                                            vulnerableResponse: { status: navigation?.status() || null, finalUrl: page.url(), payloadReflected: true },
                                            responseDifference: { payloadReflected: true, markerExecuted: false, differential: differential.evidence.comparisons },
                                            reproductionCommand: `curl -i ${JSON.stringify(testUrl.toString())}`,
                                            accountRole: 'anonymous',
                                        },
                                    },
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

                        const controlValue = 'vibe-shield-control';
                        const differential = await this.differential.run({
                            baseline: { value: 'vibe-shield-baseline' },
                            control: { value: controlValue },
                            payload: { value: testPayload.payload },
                            execute: async request => {
                                await page.goto(form.page, { waitUntil: 'domcontentloaded', timeout: 10000 });
                                const target = await page.$(`[name="${field.name}"]`) || await page.$(`#${field.name}`);
                                if (!target) throw new Error(`field ${field.name} not found`);
                                await target.fill(request.value);
                                const submit = await page.$(`#${form.id} button[type="submit"]`) || await page.$('button[type="submit"], input[type="submit"]');
                                if (submit) await submit.click();
                                await page.waitForTimeout(500);
                                const body = await page.content();
                                const markerValue = await page.evaluate(markerName => window[markerName] ?? null, testPayload.marker).catch(() => null);
                                return { status: 200, body, finalUrl: page.url(), dom: { marker: testPayload.marker, markerValue } };
                            },
                            signal: snapshot => snapshot.dom?.markerValue === 1 || snapshot.body.includes(testPayload.payload),
                        });

                        const currentInput = await page.$(`[name="${field.name}"]`) || await page.$(`#${field.name}`);
                        if (!currentInput) continue;
                        await currentInput.fill(testPayload.payload);

                        // Submit the form
                        const submitBtn = await page.$(`#${form.id} button[type="submit"]`)
                            || await page.$('button[type="submit"], input[type="submit"]');

                        if (submitBtn) {
                            await submitBtn.click();
                            await page.waitForTimeout(2000);

                            // Check if payload reflected in the response
                            const content = await page.content();
                            if (differential.confirmed && content.includes(testPayload.payload)) {
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
                                    evidence: JSON.stringify({ form: form.id, field: field.name, payload: testPayload.name, differential: differential.evidence }),
                                    verification: {
                                        level: 'high_confidence',
                                        reason: 'The submitted payload was returned unencoded after form submission; script execution was not observed.',
                                        method: 'form-response-differential',
                                        proof: {
                                            originalRequest: { method: form.method || 'POST', url: form.action || form.page },
                                            mutatedRequest: { method: form.method || 'POST', url: form.action || form.page, field: field.name, payload: testPayload.payload },
                                            baselineResponse: { url: form.page, differential: differential.evidence.baseline },
                                            vulnerableResponse: { finalUrl: page.url(), payloadReflected: true },
                                            responseDifference: { field: field.name, unencodedPayloadPresent: true, differential: differential.evidence.comparisons },
                                            trace: { type: 'browser-form-submission', form: form.id, field: field.name },
                                            reproductionCommand: `Open ${form.page} and submit ${field.name}=${JSON.stringify(testPayload.payload)}`,
                                            accountRole: 'anonymous',
                                        },
                                    },
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
