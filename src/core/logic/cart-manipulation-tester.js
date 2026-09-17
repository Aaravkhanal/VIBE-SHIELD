import { createFinding } from '../../utils/finding.js';

/**
 * CartManipulationTester — Tests for e-commerce cart/pricing manipulation.
 *
 * Checks:
 *   - Negative quantities in cart forms
 *   - Price values in hidden form fields (client-side pricing)
 *   - Quantity bounds (0, negative, extremely large)
 *   - Hidden total/subtotal fields that can be tampered
 *   - Currency manipulation potential
 */
export class CartManipulationTester {
    constructor(logger) {
        this.logger = logger;
    }

    async test(businessContext, surfaceInventory) {
        this.logger?.info?.('Cart Manipulation Tester: starting analysis');
        const findings = [];

        const forms = surfaceInventory.forms || [];
        const apis = surfaceInventory.apiEndpoints || [];

        // Find cart/checkout forms
        const cartForms = forms.filter(f => this._isCartForm(f));
        const cartApis = apis.filter(a => this._isCartApi(a));

        if (cartForms.length === 0 && cartApis.length === 0) {
            this.logger?.info?.('Cart Manipulation Tester: no cart/checkout surfaces found — skipping');
            return findings;
        }

        for (const form of cartForms) {
            // Check 1: Hidden price fields (client-side pricing)
            const hiddenPriceFields = form.fields?.filter(f =>
                f.type === 'hidden' && this._isPriceField(f)
            );

            if (hiddenPriceFields && hiddenPriceFields.length > 0) {
                findings.push(createFinding({
                    module: 'logic',
                    title: 'Client-Side Price in Hidden Form Fields',
                    severity: 'high',
                    affected_surface: form.page || form.action,
                    description:
                        `Form contains hidden fields with price/amount values: ` +
                        `${hiddenPriceFields.map(f => `"${f.name}"=${f.value || 'unknown'}`).join(', ')}. ` +
                        `An attacker can modify these values in the request to purchase items at arbitrary prices.`,
                    evidence: {
                        form_id: form.id,
                        hidden_price_fields: hiddenPriceFields.map(f => ({
                            name: f.name,
                            value: f.value,
                        })),
                        form_action: form.action,
                        form_method: form.method,
                    },
                    reproduction: [
                        `1. Open page: ${form.page || form.action}`,
                        '2. Inspect form and find hidden price/amount fields',
                        '3. Modify the value to 0.01 or 0',
                        '4. Submit the form',
                        '5. Check if the modified price is accepted',
                    ],
                    remediation:
                        'NEVER trust client-side price values. Calculate totals server-side from the product catalog. ' +
                        'Use product IDs and quantities only from client, look up prices server-side. ' +
                        'Validate the final amount matches the expected price before processing payment.',
                    references: [
                        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/10-Test_Payment_Functionality',
                    ],
                }));
            }

            // Check 2: Quantity fields without min/max
            const quantityFields = form.fields?.filter(f => this._isQuantityField(f));

            for (const field of (quantityFields || [])) {
                const issues = [];
                if (!field.minLength && !field.pattern) {
                    issues.push('no minimum validation (negative values possible)');
                }
                if (!field.maxLength && !field.pattern) {
                    issues.push('no maximum validation (extreme quantities possible)');
                }

                if (issues.length > 0) {
                    findings.push(createFinding({
                        module: 'logic',
                        title: `Cart Quantity Field "${field.name}" Lacks Bounds`,
                        severity: 'medium',
                        affected_surface: form.page || form.action,
                        description:
                            `Quantity field "${field.name}" has ${issues.join(' and ')}. ` +
                            `Testing with negative quantities (-1) could result in negative charges (refund). ` +
                            `Extremely large quantities could cause integer overflow.`,
                        evidence: {
                            field_name: field.name,
                            field_type: field.type,
                            form_id: form.id,
                            issues,
                        },
                        reproduction: [
                            `1. Open: ${form.page || form.action}`,
                            `2. Set quantity field "${field.name}" to -1`,
                            '3. Submit the form',
                            '4. Observe if the order total becomes negative',
                        ],
                        remediation:
                            'Validate quantity bounds server-side: reject zero, negative, and unreasonably large values. ' +
                            'Add HTML min=1 max=999 attributes as a first line of defense.',
                    }));
                }
            }

            // Check 3: Hidden fields with IDs (potential IDOR via cart)
            const hiddenIdFields = form.fields?.filter(f =>
                f.type === 'hidden' && this._isIdField(f)
            );

            if (hiddenIdFields && hiddenIdFields.length > 0) {
                findings.push(createFinding({
                    module: 'logic',
                    title: 'Hidden ID Fields in Cart Form (IDOR Potential)',
                    severity: 'medium',
                    affected_surface: form.page || form.action,
                    description:
                        `Cart form contains hidden ID fields: ` +
                        `${hiddenIdFields.map(f => `"${f.name}"`).join(', ')}. ` +
                        `An attacker could modify these to access other users' carts or orders.`,
                    evidence: {
                        hidden_id_fields: hiddenIdFields.map(f => ({ name: f.name, value: f.value })),
                        form_id: form.id,
                    },
                    remediation:
                        'Verify server-side that the current user owns the referenced cart/order. ' +
                        'Use session-bound cart identifiers instead of user-modifiable hidden fields.',
                }));
            }
        }

        // Check cart APIs
        for (const api of cartApis) {
            const path = new URL(api.url).pathname;
            findings.push(createFinding({
                module: 'logic',
                title: `Cart/Checkout API: ${api.method} ${path}`,
                severity: 'info',
                affected_surface: api.url,
                description:
                    `Cart/checkout API endpoint discovered. ` +
                    `Verify: (1) Prices are calculated server-side, (2) Quantities are bounded, ` +
                    `(3) Cart items belong to the authenticated user, (4) Race conditions on checkout are handled.`,
                evidence: { method: api.method, path, status: api.status },
                remediation: 'Implement server-side validation for all cart operations.',
            }));
        }

        this.logger?.info?.(`Cart Manipulation Tester: found ${findings.length} issues`);
        return findings;
    }

    _isCartForm(form) {
        const str = JSON.stringify(form).toLowerCase();
        const patterns = [
            'cart', 'checkout', 'order', 'purchase', 'buy', 'basket',
            'add-to-cart', 'addtocart', 'quantity', 'qty',
        ];
        return patterns.some(p => str.includes(p));
    }

    _isCartApi(api) {
        const path = new URL(api.url).pathname.toLowerCase();
        const patterns = [
            '/cart', '/checkout', '/order', '/basket', '/purchase',
            '/add-to-cart', '/update-cart', '/payment',
        ];
        return patterns.some(p => path.includes(p));
    }

    _isPriceField(field) {
        const name = (field.name || '').toLowerCase();
        const patterns = ['price', 'amount', 'total', 'subtotal', 'cost', 'fee', 'charge', 'value'];
        return patterns.some(p => name.includes(p));
    }

    _isQuantityField(field) {
        const name = (field.name || '').toLowerCase();
        return name.includes('quantity') || name.includes('qty') || name.includes('count') || name.includes('amount');
    }

    _isIdField(field) {
        const name = (field.name || '').toLowerCase();
        return name.includes('_id') || name.includes('Id') || name === 'id' ||
            name.includes('user_id') || name.includes('order_id') || name.includes('cart_id');
    }
}

export default CartManipulationTester;
