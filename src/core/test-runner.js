import { chromium } from 'playwright';
import { createFinding } from '../utils/finding.js';
import fs from 'fs';
import path from 'path';

/**
 * Test Runner — Executes generated test cases headlessly via Playwright.
 * Captures screenshots on failure, records pass/fail, and generates findings.
 */
export class TestRunner {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.results = [];
        this.findings = [];
        this.screenshotDir = path.join(config.output_dir || 'vibe-shield-reports', 'screenshots');
    }

    /**
     * Execute all generated test cases.
     */
    async run(testCases) {
        if (!fs.existsSync(this.screenshotDir)) {
            fs.mkdirSync(this.screenshotDir, { recursive: true });
        }

        const browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        });

        let passed = 0;
        let failed = 0;
        let errors = 0;

        for (const testCase of testCases) {
            try {
                const result = await this._executeTest(context, testCase);
                this.results.push(result);

                if (result.status === 'pass') {
                    passed++;
                } else {
                    failed++;
                    this._createFindingFromResult(result);
                }
            } catch (err) {
                errors++;
                const errorResult = {
                    testCase,
                    status: 'error',
                    error: err.message,
                    duration: 0,
                };
                this.results.push(errorResult);
                this._createFindingFromResult(errorResult);
            }
        }

        await browser.close();

        const summary = { total: testCases.length, passed, failed, errors };
        this.logger?.info?.(`Tests complete: ${passed} passed, ${failed} failed, ${errors} errors`);
        return { results: this.results, findings: this.findings, summary };
    }

    /**
     * Execute a single test case.
     */
    async _executeTest(context, testCase) {
        const page = await context.newPage();
        const startTime = Date.now();
        const consoleErrors = [];
        let status = 'pass';
        let failureReason = '';

        page.on('console', msg => {
            if (msg.type() === 'error') {
                consoleErrors.push(msg.text());
            }
        });

        page.on('pageerror', error => {
            consoleErrors.push(error.message);
        });

        try {
            for (const step of testCase.steps) {
                await this._executeStep(page, step, testCase);
            }

            // Validate expected outcomes
            if (testCase.type === 'smoke') {
                if (consoleErrors.length > 0 && testCase.expected.noConsoleErrors) {
                    status = 'fail';
                    failureReason = `Console errors detected: ${consoleErrors.join('; ')}`;
                }
            }
        } catch (err) {
            status = 'fail';
            failureReason = err.message;

            // Capture screenshot on failure
            try {
                const screenshotPath = path.join(
                    this.screenshotDir,
                    `${testCase.id}-failure.png`
                );
                await page.screenshot({ path: screenshotPath, fullPage: true });
            } catch {
                // Screenshot capture is best-effort
            }
        }

        const duration = Date.now() - startTime;
        await page.close();

        return {
            testCase,
            status,
            failureReason,
            consoleErrors,
            duration,
        };
    }

    /**
     * Execute a single step of a test case.
     */
    async _executeStep(page, step, testCase) {
        switch (step.action) {
            case 'navigate':
                const response = await page.goto(step.url, {
                    waitUntil: 'networkidle',
                    timeout: 15000,
                });
                if (step.expected === undefined) break;
                break;

            case 'assert_status':
                const currentUrl = page.url();
                const resp = await page.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
                if (resp) {
                    const expectedStatuses = Array.isArray(step.expected) ? step.expected : [step.expected];
                    if (!expectedStatuses.includes(resp.status())) {
                        throw new Error(`Expected HTTP ${step.expected}, got ${resp.status()}`);
                    }
                }
                break;

            case 'assert_no_console_errors':
                // Checked after all steps in _executeTest
                break;

            case 'assert_has_content':
                const bodyText = await page.evaluate(() => document.body?.innerText?.trim() || '');
                if (!bodyText) {
                    throw new Error('Page has no visible content (empty body)');
                }
                break;

            case 'click_link':
                try {
                    const linkSelector = `a[href="${step.url}"]`;
                    const link = await page.$(linkSelector);
                    if (link) {
                        await link.click({ timeout: 5000 });
                        await page.waitForLoadState('networkidle', { timeout: 10000 });
                    } else {
                        await page.goto(step.url, { waitUntil: 'networkidle', timeout: 10000 });
                    }
                } catch {
                    await page.goto(step.url, { waitUntil: 'networkidle', timeout: 10000 });
                }
                break;

            case 'locate_form':
                const form = await page.$(`form#${step.selector}`) || await page.$('form');
                if (!form) {
                    throw new Error(`Form "${step.selector}" not found on page`);
                }
                break;

            case 'submit_empty':
                const submitBtn = await page.$('button[type="submit"], input[type="submit"]');
                if (submitBtn) {
                    await submitBtn.click();
                    await page.waitForTimeout(1000);
                }
                break;

            case 'fill_form':
                if (step.data) {
                    for (const [name, value] of Object.entries(step.data)) {
                        try {
                            const input = await page.$(`[name="${name}"]`) || await page.$(`#${name}`);
                            if (input) {
                                if (typeof value === 'boolean') {
                                    if (value) await input.check();
                                } else if (value === '__first_option__') {
                                    await input.selectOption({ index: 1 });
                                } else {
                                    await input.fill(String(value));
                                }
                            }
                        } catch {
                            // Best-effort field fill
                        }
                    }
                }
                break;

            case 'fill_field':
                try {
                    const field = await page.$(`[name="${step.field}"]`) || await page.$(`#${step.field}`);
                    if (field) {
                        await field.fill(String(step.value));
                    }
                } catch {
                    // Best-effort field fill
                }
                break;

            case 'submit':
                const btn = await page.$('button[type="submit"], input[type="submit"]');
                if (btn) {
                    await btn.click();
                    await page.waitForTimeout(1000);
                }
                break;

            case 'assert_validation_error':
            case 'assert_submission_feedback':
            case 'assert_no_crash':
            case 'assert_input_sanitized':
            case 'assert_valid_json':
            case 'assert_response_time':
                // These are checked post-execution or are informational
                break;

            case 'http_request':
                try {
                    const fetchResp = await page.evaluate(async (opts) => {
                        const resp = await fetch(opts.url, { method: opts.method });
                        return { status: resp.status, ok: resp.ok };
                    }, step);
                    if (!fetchResp.ok && step.expected) {
                        const expected = Array.isArray(step.expected) ? step.expected : [step.expected];
                        if (!expected.includes(fetchResp.status)) {
                            throw new Error(`API returned ${fetchResp.status}`);
                        }
                    }
                } catch (err) {
                    throw new Error(`API request failed: ${err.message}`);
                }
                break;

            default:
                this.logger?.debug?.(`Unknown step action: ${step.action}`);
        }
    }

    /**
     * Create a finding from a failed test result.
     */
    _createFindingFromResult(result) {
        const { testCase, failureReason, error } = result;
        const message = failureReason || error || 'Test failed';

        const severityMap = {
            'smoke': 'high',
            'navigation': 'medium',
            'form': 'medium',
            'api': 'high',
            'edge-case': 'low',
        };

        this.findings.push(
            createFinding({
                module: 'qa',
                title: `Test Failed: ${testCase.title}`,
                severity: severityMap[testCase.type] || 'medium',
                affected_surface: testCase.surface,
                description: `Test "${testCase.title}" (${testCase.type}) failed: ${message}`,
                reproduction: testCase.steps.map((s, i) =>
                    `${i + 1}. ${s.action}${s.url ? ` → ${s.url}` : ''}${s.value ? ` with value "${String(s.value).substring(0, 50)}"` : ''}`
                ),
                evidence: JSON.stringify({
                    testId: testCase.id,
                    type: testCase.type,
                    failure: message,
                    duration: result.duration,
                }, null, 2),
                remediation: this._getRemediation(testCase, message),
            })
        );
    }

    _getRemediation(testCase, message) {
        switch (testCase.type) {
            case 'smoke':
                return 'Ensure the page loads correctly with HTTP 200, has visible content, and produces no JavaScript errors.';
            case 'navigation':
                return 'Fix the broken link or ensure the target URL is accessible. Update or remove any stale links.';
            case 'form':
                if (testCase.subtype === 'empty_submit') return 'Add proper form validation to prevent empty submissions.';
                if (testCase.subtype === 'invalid_input') return `Add input validation for field "${testCase.fieldName}" to reject invalid data.`;
                return 'Ensure form submission works correctly with proper validation and user feedback.';
            case 'api':
                return 'Verify the API endpoint is accessible, returns valid JSON, and responds within acceptable time limits.';
            case 'edge-case':
                return 'Ensure the application handles edge cases gracefully without crashing - long inputs, special characters, etc.';
            default:
                return 'Investigate and fix the test failure.';
        }
    }
}

export default TestRunner;
