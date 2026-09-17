import { createFinding } from '../../utils/finding.js';

/**
 * WorkflowEnforcer — Tests that multi-step workflows enforce ordering.
 *
 * Probes:
 * - Step skipping (jump to final step)
 * - Form resubmission (submit same step twice)
 * - State transition bypass (skip verification)
 * - Direct access to confirmation pages
 * - Back-button manipulation
 */
export class WorkflowEnforcer {
    constructor(logger) {
        this.logger = logger;

        // Common final/sensitive steps
        this.FINAL_STEP_PATTERNS = [
            /\/confirm/i, /\/complete/i, /\/finalize/i, /\/success/i,
            /\/receipt/i, /\/thank/i, /\/done/i, /\/result/i,
            /step[_-]?(final|last|\d{2})/i,
        ];

        // Common intermediate steps that shouldn't be skippable
        this.VERIFICATION_STEPS = [
            /\/verify/i, /\/validate/i, /\/review/i, /\/otp/i,
            /\/2fa/i, /\/mfa/i, /\/captcha/i, /\/consent/i,
        ];
    }

    /**
     * Test workflow enforcement.
     */
    async enforce(businessContext, surfaceInventory) {
        const findings = [];

        this.logger?.info?.('Workflow Enforcer: starting tests');

        // 1. Test multi-step flow skipping
        const flowFindings = await this._testFlowSkipping(businessContext, surfaceInventory);
        findings.push(...flowFindings);

        // 2. Test direct access to confirmation pages
        const confirmFindings = await this._testDirectConfirmation(surfaceInventory);
        findings.push(...confirmFindings);

        // 3. Test verification step bypass
        const verifyFindings = await this._testVerificationBypass(surfaceInventory);
        findings.push(...verifyFindings);

        // 4. Test form resubmission
        const resubFindings = await this._testResubmission(businessContext);
        findings.push(...resubFindings);

        this.logger?.info?.(`Workflow Enforcer: found ${findings.length} issues`);
        return findings;
    }

    /**
     * Test if multi-step flows can be skipped.
     */
    async _testFlowSkipping(businessContext, surfaceInventory) {
        const findings = [];
        const flows = businessContext.multiStepFlows || [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        for (const flow of flows) {
            if (flow.pages.length < 2) continue;

            // Try to access the last step directly without doing previous steps
            const lastStep = flow.pages[flow.pages.length - 1];
            try {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(lastStep, {
                    method: 'GET',
                    redirect: 'manual',
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (response.status === 200) {
                    const text = await response.text();
                    if (text.length > 200 && !this._isRedirectPage(text)) {
                        findings.push(createFinding({
                            module: 'logic',
                            title: 'Workflow Skip: Final Step Accessible Directly',
                            severity: 'high',
                            affected_surface: lastStep,
                            description: `The final step of a multi-step flow (${lastStep}) is accessible without completing previous steps. An attacker can skip validation, payment, or verification steps.`,
                            reproduction: [
                                `1. Flow has ${flow.stepCount} steps: ${flow.pages.join(' → ')}`,
                                `2. Navigate directly to the last step: ${lastStep}`,
                                `3. The page loads without requiring prior step completion`,
                            ],
                            evidence: `Flow steps: ${flow.stepCount}\nDirect access: ${lastStep}\nStatus: ${response.status}`,
                            remediation: 'Implement server-side session state tracking for multi-step flows. Verify that all previous steps are completed before allowing access to subsequent steps. Store progress in a server-side session, not client-side.',
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
     * Test direct access to confirmation/success pages.
     */
    async _testDirectConfirmation(surfaceInventory) {
        const findings = [];
        const pages = surfaceInventory.pages || [];

        for (const page of pages) {
            const url = page.url || page;
            const isFinalStep = this.FINAL_STEP_PATTERNS.some(p => p.test(url));
            if (!isFinalStep) continue;

            try {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(url, {
                    method: 'GET',
                    redirect: 'manual',
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (response.status === 200) {
                    const text = await response.text();
                    if (this._isConfirmationPage(text)) {
                        findings.push(createFinding({
                            module: 'logic',
                            title: 'Workflow Bypass: Confirmation Page Directly Accessible',
                            severity: 'medium',
                            affected_surface: url,
                            description: `Confirmation/success page at ${url} is directly accessible without completing the required workflow. This may allow bypassing payment, verification, or other critical steps.`,
                            reproduction: [
                                `1. Navigate directly to ${url}`,
                                `2. Confirmation page loads without prior flow completion`,
                            ],
                            evidence: `URL: ${url}\nStatus: ${response.status}`,
                            remediation: 'Verify server-side that the workflow was completed before showing confirmation pages. Use session tokens to track step completion.',
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
     * Test if verification steps can be bypassed.
     */
    async _testVerificationBypass(surfaceInventory) {
        const findings = [];
        const pages = surfaceInventory.pages || [];

        for (const page of pages) {
            const url = page.url || page;
            const isVerifyStep = this.VERIFICATION_STEPS.some(p => p.test(url));
            if (!isVerifyStep) continue;

            // Try to POST to the verification endpoint with empty/dummy data
            try {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: '000000', token: 'bypass', verified: true }),
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (response.ok) {
                    const text = await response.text();
                    if (/success|verified|confirmed|valid/i.test(text)) {
                        findings.push(createFinding({
                            module: 'logic',
                            title: 'Verification Bypass: Step Accepted Without Valid Input',
                            severity: 'critical',
                            affected_surface: url,
                            description: `The verification step at ${url} accepted dummy data (code: "000000", verified: true). This allows bypassing OTP/2FA/captcha verification.`,
                            reproduction: [
                                `1. POST to ${url} with {"code": "000000", "verified": true}`,
                                `2. Server responds with success`,
                            ],
                            evidence: `Response contained success indicators`,
                            remediation: 'Validate verification codes server-side against stored values. Never trust client-supplied "verified" flags. Implement rate limiting on verification attempts.',
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
     * Test form resubmission (idempotency).
     */
    async _testResubmission(businessContext) {
        const findings = [];
        const paymentForms = (businessContext.domains.payments || [])
            .filter(s => s.type === 'form' || s.type === 'api');

        for (const surface of paymentForms) {
            const url = surface.url;
            if (!url) continue;

            try {
                const body = { amount: 100, action: 'submit' };
                const requests = [];

                // Fire same request twice rapidly
                for (let i = 0; i < 2; i++) {
                    requests.push(
                        fetch(url, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(body),
                            signal: AbortSignal.timeout(5000),
                        }).then(r => ({ status: r.status, ok: r.ok })).catch(() => null)
                    );
                }

                const results = await Promise.all(requests);
                const successes = results.filter(r => r?.ok).length;

                if (successes === 2) {
                    findings.push(createFinding({
                        module: 'logic',
                        title: 'Duplicate Submission: No Idempotency Protection',
                        severity: 'high',
                        affected_surface: url,
                        description: `Payment/transaction endpoint ${url} accepted the same request twice. This could lead to double charges or duplicate orders. No idempotency key or duplicate detection was observed.`,
                        reproduction: [
                            `1. Submit a POST to ${url}`,
                            `2. Immediately submit the identical request again`,
                            `3. Both requests succeed`,
                        ],
                        evidence: `Both requests returned success (${successes}/2 accepted)`,
                        remediation: 'Implement idempotency keys for payment/transaction endpoints. Use unique request IDs and check for duplicates before processing. Add server-side deduplication with a short TTL cache.',
                    }));
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

    _isRedirectPage(text) {
        return /redirect|location\.href|window\.location/i.test(text) && text.length < 500;
    }

    _isConfirmationPage(text) {
        return /thank|success|confirmed|complete|receipt|order.*placed/i.test(text);
    }
}

export default WorkflowEnforcer;
