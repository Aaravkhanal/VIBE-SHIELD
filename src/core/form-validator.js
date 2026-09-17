import { chromium } from 'playwright';
import { createFinding } from '../utils/finding.js';

/**
 * Form Validator — Deep form validation testing.
 * Tests required fields, type constraints, boundaries, and submission feedback.
 */
export class FormValidator {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.findings = [];
    }

    /**
     * Validate all forms discovered during crawling.
     */
    async validate(surfaceInventory) {
        if (surfaceInventory.forms.length === 0) {
            this.logger?.info?.('No forms found to validate');
            return [];
        }

        const browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({
            viewport: { width: 1440, height: 900 },
            ignoreHTTPSErrors: true,
        });

        for (const form of surfaceInventory.forms) {
            try {
                await this._validateForm(context, form);
            } catch (err) {
                this.logger?.warn?.(`Failed to validate form ${form.id}: ${err.message}`);
            }
        }

        await browser.close();
        this.logger?.info?.(`Form validator found ${this.findings.length} issues`);
        return this.findings;
    }

    async _validateForm(context, form) {
        // Test required fields enforcement
        await this._testRequiredFields(context, form);
        // Test type constraints
        await this._testTypeConstraints(context, form);
        // Check for error message presence
        this._checkErrorMessageCapability(form);
    }

    /**
     * Test that required fields are enforced on submission.
     */
    async _testRequiredFields(context, form) {
        const requiredFields = form.fields.filter(f => f.required);
        if (requiredFields.length === 0) {
            // No required fields — this might be a finding itself
            const hasInputs = form.fields.filter(f => !['hidden', 'submit', 'button'].includes(f.type));
            if (hasInputs.length > 0) {
                this.findings.push(
                    createFinding({
                        module: 'qa',
                        title: `No Required Fields: ${form.id}`,
                        severity: 'low',
                        affected_surface: form.page,
                        description: `Form "${form.id}" has ${hasInputs.length} input field(s) but none are marked as required. This may allow empty or incomplete submissions.`,
                        reproduction: [
                            `1. Navigate to ${form.page}`,
                            `2. Locate form "${form.id}"`,
                            `3. Note that no fields have the 'required' attribute`,
                        ],
                        remediation: 'Add the `required` attribute to essential form fields to prevent incomplete submissions.',
                    })
                );
            }
            return;
        }

        // Try submitting with empty required fields
        const page = await context.newPage();
        try {
            await page.goto(form.page, { waitUntil: 'networkidle', timeout: 15000 });

            // Click submit without filling anything
            const submitBtn = await page.$(`#${form.id} button[type="submit"], #${form.id} input[type="submit"]`)
                || await page.$('button[type="submit"], input[type="submit"]');

            if (submitBtn) {
                await submitBtn.click();
                await page.waitForTimeout(1500);

                // Check if the page navigated away (submission went through)
                const currentUrl = page.url();
                if (form.action && currentUrl.includes(form.action) && form.action !== form.page) {
                    this.findings.push(
                        createFinding({
                            module: 'qa',
                            title: `Required Field Bypass: ${form.id}`,
                            severity: 'medium',
                            affected_surface: form.page,
                            description: `Form "${form.id}" has ${requiredFields.length} required field(s) but submitted successfully when empty. Server-side validation may be missing.`,
                            reproduction: [
                                `1. Navigate to ${form.page}`,
                                `2. Click submit without filling any fields`,
                                `3. Observe the form submits successfully`,
                            ],
                            remediation: 'Implement both client-side and server-side validation. Never rely solely on HTML required attributes.',
                        })
                    );
                }
            }
        } catch (err) {
            this.logger?.debug?.(`Required field test failed for ${form.id}: ${err.message}`);
        } finally {
            await page.close();
        }
    }

    /**
     * Test type constraints on form fields.
     */
    async _testTypeConstraints(context, form) {
        const typeTestable = form.fields.filter(f =>
            ['email', 'number', 'url', 'tel', 'date'].includes(f.type)
        );

        if (typeTestable.length === 0) return;

        const page = await context.newPage();
        try {
            await page.goto(form.page, { waitUntil: 'networkidle', timeout: 15000 });

            for (const field of typeTestable) {
                const invalidValues = this._getInvalidValues(field.type);
                for (const { value, desc } of invalidValues) {
                    try {
                        const input = await page.$(`[name="${field.name}"]`) || await page.$(`#${field.name}`);
                        if (!input) continue;

                        await input.fill('');
                        await input.fill(value);

                        // Check if HTML validation catches it
                        const isValid = await page.evaluate((name) => {
                            const el = document.querySelector(`[name="${name}"]`) || document.getElementById(name);
                            return el?.checkValidity?.() ?? true;
                        }, field.name);

                        if (isValid) {
                            this.findings.push(
                                createFinding({
                                    module: 'qa',
                                    title: `Weak Type Validation: ${field.name} (${field.type})`,
                                    severity: 'low',
                                    affected_surface: form.page,
                                    description: `Field "${field.name}" (type=${field.type}) accepted invalid value "${value}" (${desc}). Client-side type validation may be insufficient.`,
                                    reproduction: [
                                        `1. Navigate to ${form.page}`,
                                        `2. Enter "${value}" into the ${field.name} field`,
                                        `3. Observe the value is accepted without validation error`,
                                    ],
                                    remediation: `Add proper validation for ${field.type} fields. Use pattern attributes, custom validation, or JavaScript validation.`,
                                })
                            );
                        }
                    } catch {
                        // Best-effort
                    }
                }
            }
        } catch (err) {
            this.logger?.debug?.(`Type constraint test failed for ${form.id}: ${err.message}`);
        } finally {
            await page.close();
        }
    }

    /**
     * Check if form has proper error messaging capability.
     */
    _checkErrorMessageCapability(form) {
        const inputFields = form.fields.filter(f => !['hidden', 'submit', 'button'].includes(f.type));
        const fieldsWithoutPlaceholder = inputFields.filter(f => !f.placeholder);

        if (inputFields.length > 0 && fieldsWithoutPlaceholder.length === inputFields.length) {
            this.findings.push(
                createFinding({
                    module: 'qa',
                    title: `No Input Hints: ${form.id}`,
                    severity: 'info',
                    affected_surface: form.page,
                    description: `Form "${form.id}" has ${inputFields.length} field(s) but none have placeholder text. Placeholders help users understand expected input format.`,
                    reproduction: [
                        `1. Navigate to ${form.page}`,
                        `2. Locate form "${form.id}"`,
                        `3. Note that no fields have placeholder hints`,
                    ],
                    remediation: 'Add placeholder attributes to form fields to guide users on expected input format.',
                })
            );
        }
    }

    _getInvalidValues(type) {
        switch (type) {
            case 'email':
                return [
                    { value: 'notanemail', desc: 'missing @ symbol' },
                    { value: '@nodomain', desc: 'missing local part' },
                ];
            case 'number':
                return [
                    { value: 'abc', desc: 'alphabetic text' },
                    { value: '12.34.56', desc: 'multiple decimals' },
                ];
            case 'url':
                return [
                    { value: 'not-a-url', desc: 'no protocol' },
                ];
            case 'tel':
                return [
                    { value: 'abcdef', desc: 'alphabetic text' },
                ];
            case 'date':
                return [
                    { value: '99-99-9999', desc: 'invalid date' },
                ];
            default:
                return [];
        }
    }
}

export default FormValidator;
