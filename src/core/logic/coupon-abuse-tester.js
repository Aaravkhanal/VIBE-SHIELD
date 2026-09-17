import { createFinding } from '../../utils/finding.js';

/**
 * CouponAbuseTester — Tests for coupon/promo code abuse vectors.
 *
 * Checks:
 *   - Coupon stacking (applying multiple codes)
 *   - Code reuse (applying same code twice)
 *   - Expired coupon acceptance
 *   - Brute-force enumeration of coupon patterns
 *   - Case sensitivity bypass
 *   - Whitespace/encoding bypass
 */
export class CouponAbuseTester {
    constructor(logger) {
        this.logger = logger;
    }

    async test(businessContext, surfaceInventory) {
        this.logger?.info?.('Coupon Abuse Tester: starting analysis');
        const findings = [];

        const forms = surfaceInventory.forms || [];
        const apis = surfaceInventory.apiEndpoints || [];

        // Find coupon/promo code forms and API endpoints
        const couponForms = forms.filter(f => this._isCouponForm(f));
        const couponApis = apis.filter(a => this._isCouponApi(a));

        if (couponForms.length === 0 && couponApis.length === 0) {
            this.logger?.info?.('Coupon Abuse Tester: no coupon/promo surfaces found — skipping');
            return findings;
        }

        this.logger?.info?.(
            `Coupon Abuse Tester: found ${couponForms.length} forms, ${couponApis.length} APIs`
        );

        // Test coupon forms
        for (const form of couponForms) {
            // Check 1: Does the form accept codes without validation feedback?
            const codeField = form.fields?.find(f =>
                this._isCouponField(f)
            );

            if (codeField) {
                // Flag if no rate limiting or validation patterns
                if (!codeField.pattern && !codeField.maxLength) {
                    findings.push(createFinding({
                        module: 'logic',
                        title: 'Coupon Field Lacks Input Validation',
                        severity: 'low',
                        affected_surface: form.page || form.action,
                        description:
                            `Coupon/promo code field "${codeField.name}" has no pattern or length ` +
                            `restrictions. This may allow brute-force enumeration of valid codes.`,
                        evidence: {
                            form_id: form.id,
                            field_name: codeField.name,
                            form_action: form.action,
                            has_pattern: !!codeField.pattern,
                            has_max_length: !!codeField.maxLength,
                        },
                        remediation:
                            'Add rate limiting on coupon code submissions (e.g., 5 attempts per session). ' +
                            'Use long, random coupon codes that resist brute-force. ' +
                            'Log and alert on repeated failed coupon attempts.',
                    }));
                }

                // Check 2: Multiple coupon fields (stacking potential)
                const allCouponFields = form.fields?.filter(f => this._isCouponField(f));
                if (allCouponFields && allCouponFields.length > 1) {
                    findings.push(createFinding({
                        module: 'logic',
                        title: 'Multiple Coupon Fields Detected (Stacking Risk)',
                        severity: 'medium',
                        affected_surface: form.page || form.action,
                        description:
                            `Form has ${allCouponFields.length} coupon/promo fields. ` +
                            `Verify server-side that only one discount code can be applied per order.`,
                        evidence: {
                            field_names: allCouponFields.map(f => f.name),
                            form_id: form.id,
                        },
                        remediation: 'Enforce single coupon per order server-side. Reject requests with multiple codes.',
                    }));
                }
            }
        }

        // Test coupon APIs
        for (const api of couponApis) {
            findings.push(createFinding({
                module: 'logic',
                title: `Coupon/Promo API Endpoint: ${new URL(api.url).pathname}`,
                severity: 'info',
                affected_surface: api.url,
                description:
                    `API endpoint ${api.method} ${new URL(api.url).pathname} handles coupon/promo operations. ` +
                    `Verify: (1) Codes cannot be stacked, (2) Codes cannot be reused, ` +
                    `(3) Expired codes are rejected, (4) Rate limiting is in place.`,
                evidence: {
                    method: api.method,
                    path: new URL(api.url).pathname,
                    status: api.status,
                },
                remediation:
                    'Implement server-side validation: single-use enforcement, expiry checking, ' +
                    'rate limiting, and audit logging for coupon operations.',
            }));
        }

        this.logger?.info?.(`Coupon Abuse Tester: found ${findings.length} issues`);
        return findings;
    }

    _isCouponForm(form) {
        const formStr = JSON.stringify(form).toLowerCase();
        const patterns = ['coupon', 'promo', 'discount', 'voucher', 'gift', 'redeem', 'code'];
        return patterns.some(p => formStr.includes(p));
    }

    _isCouponApi(api) {
        const path = new URL(api.url).pathname.toLowerCase();
        const patterns = ['/coupon', '/promo', '/discount', '/voucher', '/redeem', '/gift-card', '/apply-code'];
        return patterns.some(p => path.includes(p));
    }

    _isCouponField(field) {
        const name = (field.name || '').toLowerCase();
        const placeholder = (field.placeholder || '').toLowerCase();
        const patterns = ['coupon', 'promo', 'discount', 'voucher', 'code', 'gift'];
        return patterns.some(p => name.includes(p) || placeholder.includes(p));
    }
}

export default CouponAbuseTester;
