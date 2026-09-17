/**
 * Test Generator — Generates test cases from the Surface Inventory.
 * Produces smoke, navigation, form, API, and edge-case tests.
 */
export class TestGenerator {
    constructor(logger) {
        this.logger = logger;
    }

    /**
     * Generate all test cases from a Surface Inventory.
     * @returns {TestCase[]} Array of test case objects
     */
    generate(surfaceInventory) {
        const tests = [
            ...this._generateSmokeTests(surfaceInventory),
            ...this._generateNavigationTests(surfaceInventory),
            ...this._generateFormTests(surfaceInventory),
            ...this._generateApiTests(surfaceInventory),
            ...this._generateEdgeCaseTests(surfaceInventory),
        ];

        this.logger?.info?.(`Generated ${tests.length} test cases`);
        return tests;
    }

    /**
     * Smoke tests: every page loads with HTTP 200 and no JS errors.
     */
    _generateSmokeTests(inventory) {
        return inventory.pages.map((page, idx) => ({
            id: `SMOKE-${String(idx + 1).padStart(3, '0')}`,
            type: 'smoke',
            surface: page.url,
            title: `Page loads successfully: ${this._shortUrl(page.url)}`,
            steps: [
                { action: 'navigate', url: page.url },
                { action: 'assert_status', expected: 200 },
                { action: 'assert_no_console_errors' },
                { action: 'assert_has_content' },
            ],
            expected: {
                status: 200,
                noConsoleErrors: true,
                hasContent: true,
            },
        }));
    }

    /**
     * Navigation tests: all internal links are reachable.
     */
    _generateNavigationTests(inventory) {
        const tests = [];
        const testedLinks = new Set();

        for (const page of inventory.pages) {
            for (const link of (page.links || [])) {
                if (testedLinks.has(link)) continue;
                testedLinks.add(link);

                tests.push({
                    id: `NAV-${String(tests.length + 1).padStart(3, '0')}`,
                    type: 'navigation',
                    surface: link,
                    sourcePage: page.url,
                    title: `Link reachable: ${this._shortUrl(link)}`,
                    steps: [
                        { action: 'navigate', url: page.url },
                        { action: 'click_link', url: link },
                        { action: 'assert_status', expected: [200, 301, 302] },
                    ],
                    expected: {
                        reachable: true,
                        noErrors: true,
                    },
                });
            }
        }

        return tests;
    }

    /**
     * Form tests: every form can be submitted with valid and invalid data.
     */
    _generateFormTests(inventory) {
        const tests = [];

        for (const form of inventory.forms) {
            // Test 1: Submit empty (required field validation)
            tests.push({
                id: `FORM-${String(tests.length + 1).padStart(3, '0')}`,
                type: 'form',
                subtype: 'empty_submit',
                surface: form.page,
                formId: form.id,
                title: `Empty form submission blocked: ${form.id}`,
                steps: [
                    { action: 'navigate', url: form.page },
                    { action: 'locate_form', selector: form.id },
                    { action: 'submit_empty' },
                    { action: 'assert_validation_error' },
                ],
                expected: {
                    blocked: true,
                    showsValidationError: true,
                },
            });

            // Test 2: Submit with valid data
            const validData = this._generateValidData(form.fields);
            tests.push({
                id: `FORM-${String(tests.length + 1).padStart(3, '0')}`,
                type: 'form',
                subtype: 'valid_submit',
                surface: form.page,
                formId: form.id,
                title: `Valid form submission succeeds: ${form.id}`,
                steps: [
                    { action: 'navigate', url: form.page },
                    { action: 'locate_form', selector: form.id },
                    { action: 'fill_form', data: validData },
                    { action: 'submit' },
                    { action: 'assert_submission_feedback' },
                ],
                expected: {
                    submitted: true,
                    showsFeedback: true,
                },
            });

            // Test 3: Type constraint testing for each field
            for (const field of form.fields) {
                if (field.type === 'hidden' || field.type === 'submit') continue;
                const invalidData = this._generateInvalidData(field);
                if (invalidData) {
                    tests.push({
                        id: `FORM-${String(tests.length + 1).padStart(3, '0')}`,
                        type: 'form',
                        subtype: 'invalid_input',
                        surface: form.page,
                        formId: form.id,
                        fieldName: field.name,
                        title: `Invalid input rejected: ${field.name} in ${form.id}`,
                        steps: [
                            { action: 'navigate', url: form.page },
                            { action: 'locate_form', selector: form.id },
                            { action: 'fill_field', field: field.name, value: invalidData.value },
                            { action: 'submit' },
                            { action: 'assert_validation_error', field: field.name },
                        ],
                        expected: {
                            rejected: true,
                            showsFieldError: true,
                        },
                        invalidData,
                    });
                }
            }
        }

        return tests;
    }

    /**
     * API tests: endpoints respond within timeout with valid responses.
     */
    _generateApiTests(inventory) {
        return inventory.apiEndpoints.map((endpoint, idx) => ({
            id: `API-${String(idx + 1).padStart(3, '0')}`,
            type: 'api',
            surface: endpoint.url,
            method: endpoint.method,
            title: `API responds: ${endpoint.method} ${this._shortUrl(endpoint.url)}`,
            steps: [
                { action: 'http_request', method: endpoint.method, url: endpoint.url },
                { action: 'assert_status', expected: [200, 201, 204, 301, 302] },
                { action: 'assert_response_time', maxMs: 5000 },
                { action: 'assert_valid_json' },
            ],
            expected: {
                validStatus: true,
                withinTimeout: true,
                validJson: true,
            },
        }));
    }

    /**
     * Edge-case tests: boundary values and special characters.
     */
    _generateEdgeCaseTests(inventory) {
        const tests = [];

        for (const form of inventory.forms) {
            for (const field of form.fields) {
                if (field.type === 'hidden' || field.type === 'submit') continue;

                // Extremely long input
                tests.push({
                    id: `EDGE-${String(tests.length + 1).padStart(3, '0')}`,
                    type: 'edge-case',
                    subtype: 'long_input',
                    surface: form.page,
                    formId: form.id,
                    fieldName: field.name,
                    title: `Long input handled: ${field.name}`,
                    steps: [
                        { action: 'navigate', url: form.page },
                        { action: 'fill_field', field: field.name, value: 'A'.repeat(10000) },
                        { action: 'submit' },
                        { action: 'assert_no_crash' },
                    ],
                    expected: { noCrash: true },
                });

                // Special characters
                tests.push({
                    id: `EDGE-${String(tests.length + 1).padStart(3, '0')}`,
                    type: 'edge-case',
                    subtype: 'special_chars',
                    surface: form.page,
                    formId: form.id,
                    fieldName: field.name,
                    title: `Special chars handled: ${field.name}`,
                    steps: [
                        { action: 'navigate', url: form.page },
                        { action: 'fill_field', field: field.name, value: '<script>alert(1)</script>\'";--' },
                        { action: 'submit' },
                        { action: 'assert_no_crash' },
                        { action: 'assert_input_sanitized' },
                    ],
                    expected: { noCrash: true, sanitized: true },
                });
            }
        }

        return tests;
    }

    _generateValidData(fields) {
        const data = {};
        for (const field of fields) {
            switch (field.type) {
                case 'email': data[field.name] = 'test@example.com'; break;
                case 'password': data[field.name] = 'TestPass123!'; break;
                case 'tel': data[field.name] = '+1234567890'; break;
                case 'number': data[field.name] = '42'; break;
                case 'url': data[field.name] = 'https://example.com'; break;
                case 'date': data[field.name] = '2025-01-15'; break;
                case 'checkbox': data[field.name] = true; break;
                case 'select': data[field.name] = '__first_option__'; break;
                default: data[field.name] = 'Test input value'; break;
            }
        }
        return data;
    }

    _generateInvalidData(field) {
        switch (field.type) {
            case 'email': return { value: 'not-an-email', reason: 'Invalid email format' };
            case 'number': return { value: 'not-a-number', reason: 'Non-numeric value in number field' };
            case 'url': return { value: 'not-a-url', reason: 'Invalid URL format' };
            case 'tel': return { value: 'abc', reason: 'Non-phone value in tel field' };
            case 'date': return { value: '99-99-9999', reason: 'Invalid date format' };
            default: return null;
        }
    }

    _shortUrl(url) {
        try {
            const u = new URL(url);
            return u.pathname === '/' ? u.hostname : u.pathname;
        } catch {
            return url;
        }
    }
}

export default TestGenerator;
