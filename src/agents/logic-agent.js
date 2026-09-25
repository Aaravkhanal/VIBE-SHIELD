import { BaseAgent } from './base-agent.js';
import { allows, getSafetyMode } from '../utils/safety.js';
import { BusinessRuleInferrer } from '../core/logic/business-rule-inferrer.js';
import { PricingExploiter } from '../core/logic/pricing-exploiter.js';
import { AccessBoundaryTester } from '../core/logic/access-boundary-tester.js';
import { WorkflowEnforcer } from '../core/logic/workflow-enforcer.js';
import { RaceConditionDetector } from '../core/logic/race-condition-detector.js';
import { AbusePatternScanner } from '../core/logic/abuse-pattern-scanner.js';
import { CouponAbuseTester } from '../core/logic/coupon-abuse-tester.js';
import { CartManipulationTester } from '../core/logic/cart-manipulation-tester.js';
import { EmailEnumerationTester } from '../core/logic/email-enumeration-tester.js';
import { AccountTakeoverTester } from '../core/logic/account-takeover-tester.js';
import { FeatureFlagBypassTester } from '../core/logic/feature-flag-bypass-tester.js';

/**
 * VIBE-SHIELD-LOGIC — Business Logic Validation Agent
 *
 * Pipeline:
 * 1. Infer business rules from surface inventory
 * 2. Test pricing/payment manipulation
 * 3. Test access control boundaries (IDOR, escalation)
 * 4. Test workflow enforcement (step skipping, resubmission)
 * 5. Test race conditions (double spend, TOCTOU)
 * 6. Test abuse patterns (referral, reward, subscription)
 * 7. Test coupon/promo abuse (stacking, reuse, expired)
 * 8. Test cart manipulation (negative qty, price tampering)
 * 9. Test email enumeration (login/register/reset forms)
 * 10. Test account takeover flows (password reset, email change, session)
 * 11. Test feature flag bypass (client-side gating)
 *
 * Dependencies: VIBE-SHIELD-CRAWL (runs in Wave 2, parallel with QA + SEC + AI)
 */
export class LogicAgent extends BaseAgent {
    get name() { return 'VIBE-SHIELD-LOGIC'; }
    get dependencies() { return ['VIBE-SHIELD-CRAWL']; }

    async _execute(context) {
        const { config, logger, surfaceInventory } = context;

        if (!surfaceInventory) {
            throw new Error('No surface inventory available — VIBE-SHIELD-CRAWL must run first');
        }

        const safetyMode = getSafetyMode(config);
        this._log(`Safety mode: ${safetyMode}`);

        // Tests that issue real state-changing/mutating requests (or that the
        // user has classified as destructive) require --aggressive. Under
        // passive/safe-active they are skipped with a clear log line.
        const allowDestructive = allows(config, 'aggressive');
        // Active but non-destructive probing requires at least safe-active.
        const allowActive = allows(config, 'safe-active');

        const skipDestructive = (label, phase, pct) => {
            this.skipCheck(label, `Requires aggressive mode; current safety mode is ${safetyMode}`);
            this._log(`${label} skipped — requires --aggressive safety mode (current: ${safetyMode})`);
            this.progress(phase, `${label} skipped (safe mode)`, pct);
        };
        const skipActive = (label, phase, pct) => {
            this.skipCheck(label, `Requires active probing; current safety mode is ${safetyMode}`);
            this._log(`${label} skipped — requires active probing (current: ${safetyMode} mode)`);
            this.progress(phase, `${label} skipped (passive mode)`, pct);
        };

        // Phase 1: Infer business rules
        this.progress('infer', 'Inferring business rules from surface inventory...', 0);

        const inferrer = new BusinessRuleInferrer(logger);
        const businessContext = inferrer.infer(surfaceInventory);

        // Optional, additive LLM domain/invariant inference (no-op when disabled).
        if (context.llmClient?.isEnabled?.()) {
            await inferrer.augmentWithLLM(businessContext, surfaceInventory, context.llmClient);
            if (businessContext.llmInsights?.invariants?.length) {
                this._log(`LLM inferred ${businessContext.llmInsights.invariants.length} candidate business invariants`);
            }
        }

        const activeDomains = Object.entries(businessContext.domains)
            .filter(([, items]) => items.length > 0)
            .map(([domain]) => domain);

        this._log(`Inferred ${activeDomains.length} business domains: ${activeDomains.join(', ') || 'none'}`);
        this.progress('infer', `Found ${activeDomains.length} business domains`, 5);

        if (activeDomains.length === 0) {
            this._log('No business logic surfaces detected — skipping logic tests');
            this.progress('complete', 'No business logic surfaces found — scan skipped', 100);
            return;
        }

        const totalPhases = 11;
        let completed = 1;

        // Phase 2: Pricing exploitation (DESTRUCTIVE — sends mutating requests)
        if (allowDestructive) {
            this.progress('pricing', 'Testing pricing & payment logic...', (completed / totalPhases) * 100);
            try {
                const exploiter = new PricingExploiter(logger, context.coverageTracker);
                const pricingFindings = await exploiter.exploit(businessContext);
                this.addFindings(pricingFindings);
                this._log(`Pricing: ${pricingFindings.length} issues`);
            } catch (err) {
                this._log(`Pricing testing failed: ${err.message}`, 'error');
            }
        } else {
            skipDestructive('Pricing exploitation', 'pricing', (completed / totalPhases) * 100);
        }
        completed++;

        // Phase 3: Access boundary testing (active, non-destructive)
        if (allowActive) {
            this.progress('access', 'Testing access control boundaries...', (completed / totalPhases) * 100);
            try {
                const tester = new AccessBoundaryTester(logger, context.coverageTracker);
                const accessFindings = await tester.test(businessContext, surfaceInventory);
                this.addFindings(accessFindings);
                this._log(`Access: ${accessFindings.length} issues`);
            } catch (err) {
                this._log(`Access boundary testing failed: ${err.message}`, 'error');
            }
        } else {
            skipActive('Access boundary testing', 'access', (completed / totalPhases) * 100);
        }
        completed++;

        // Phase 4: Workflow enforcement (active, non-destructive)
        if (allowActive) {
            this.progress('workflow', 'Testing workflow enforcement...', (completed / totalPhases) * 100);
            try {
                const enforcer = new WorkflowEnforcer(logger);
                const workflowFindings = await enforcer.enforce(businessContext, surfaceInventory);
                this.addFindings(workflowFindings);
                this._log(`Workflow: ${workflowFindings.length} issues`);
            } catch (err) {
                this._log(`Workflow testing failed: ${err.message}`, 'error');
            }
        } else {
            skipActive('Workflow enforcement', 'workflow', (completed / totalPhases) * 100);
        }
        completed++;

        // Phase 5: Race condition detection (DESTRUCTIVE — fires concurrent mutating requests)
        if (allowDestructive) {
            this.progress('race', 'Testing for race conditions...', (completed / totalPhases) * 100);
            try {
                const detector = new RaceConditionDetector(logger);
                const raceFindings = await detector.detect(businessContext, surfaceInventory);
                this.addFindings(raceFindings);
                this._log(`Race conditions: ${raceFindings.length} issues`);
            } catch (err) {
                this._log(`Race condition testing failed: ${err.message}`, 'error');
            }
        } else {
            skipDestructive('Race condition detection', 'race', (completed / totalPhases) * 100);
        }
        completed++;

        // Phase 6: Abuse pattern scanning (active, non-destructive)
        if (allowActive) {
            this.progress('abuse', 'Scanning for abuse patterns...', (completed / totalPhases) * 100);
            try {
                const scanner = new AbusePatternScanner(logger);
                const abuseFindings = await scanner.scan(businessContext, surfaceInventory);
                this.addFindings(abuseFindings);
                this._log(`Abuse patterns: ${abuseFindings.length} issues`);
            } catch (err) {
                this._log(`Abuse pattern scanning failed: ${err.message}`, 'error');
            }
        } else {
            skipActive('Abuse pattern scanning', 'abuse', (completed / totalPhases) * 100);
        }
        completed++;

        // Phase 7: Coupon/promo abuse testing (gated to aggressive per safety policy)
        if (allowDestructive) {
            this.progress('coupon', 'Testing for coupon/promo abuse...', (completed / totalPhases) * 100);
            try {
                const tester = new CouponAbuseTester(logger);
                const couponFindings = await tester.test(businessContext, surfaceInventory);
                this.addFindings(couponFindings);
                this._log(`Coupon abuse: ${couponFindings.length} issues`);
            } catch (err) {
                this._log(`Coupon abuse testing failed: ${err.message}`, 'error');
            }
        } else {
            skipDestructive('Coupon/promo abuse testing', 'coupon', (completed / totalPhases) * 100);
        }
        completed++;

        // Phase 8: Cart manipulation testing (gated to aggressive per safety policy)
        if (allowDestructive) {
            this.progress('cart', 'Testing for cart manipulation...', (completed / totalPhases) * 100);
            try {
                const tester = new CartManipulationTester(logger);
                const cartFindings = await tester.test(businessContext, surfaceInventory);
                this.addFindings(cartFindings);
                this._log(`Cart manipulation: ${cartFindings.length} issues`);
            } catch (err) {
                this._log(`Cart manipulation testing failed: ${err.message}`, 'error');
            }
        } else {
            skipDestructive('Cart manipulation testing', 'cart', (completed / totalPhases) * 100);
        }
        completed++;

        // Phase 9: Email enumeration testing (active, non-destructive)
        if (allowActive) {
            this.progress('email-enum', 'Testing for email enumeration...', (completed / totalPhases) * 100);
            try {
                const tester = new EmailEnumerationTester(logger, context.coverageTracker);
                const emailFindings = await tester.test(businessContext, surfaceInventory);
                this.addFindings(emailFindings);
                this._log(`Email enumeration: ${emailFindings.length} issues`);
            } catch (err) {
                this._log(`Email enumeration testing failed: ${err.message}`, 'error');
            }
        } else {
            skipActive('Email enumeration testing', 'email-enum', (completed / totalPhases) * 100);
        }
        completed++;

        // Phase 10: Account takeover testing (gated to aggressive per safety policy)
        if (allowDestructive) {
            this.progress('account-takeover', 'Testing account takeover flows...', (completed / totalPhases) * 100);
            try {
                const tester = new AccountTakeoverTester(logger);
                const atoFindings = await tester.test(businessContext, surfaceInventory);
                this.addFindings(atoFindings);
                this._log(`Account takeover: ${atoFindings.length} issues`);
            } catch (err) {
                this._log(`Account takeover testing failed: ${err.message}`, 'error');
            }
        } else {
            skipDestructive('Account takeover testing', 'account-takeover', (completed / totalPhases) * 100);
        }
        completed++;

        // Phase 11: Feature flag bypass testing (active, non-destructive)
        if (allowActive) {
            this.progress('feature-flags', 'Testing for feature flag bypass...', (completed / totalPhases) * 100);
            try {
                const tester = new FeatureFlagBypassTester(logger);
                const flagFindings = await tester.test(businessContext, surfaceInventory);
                this.addFindings(flagFindings);
                this._log(`Feature flag bypass: ${flagFindings.length} issues`);
            } catch (err) {
                this._log(`Feature flag bypass testing failed: ${err.message}`, 'error');
            }
        } else {
            skipActive('Feature flag bypass testing', 'feature-flags', (completed / totalPhases) * 100);
        }
        completed++;

        this.progress('complete', `Logic scan complete — ${this._findings.length} total findings`, 100);
    }
}

export default LogicAgent;
