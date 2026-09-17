import { createFinding } from '../../utils/finding.js';
import { inferBusinessDomains } from '../llm/augmentations.js';

/**
 * BusinessRuleInferrer — Infers business rules from the surface inventory.
 * 
 * Categorizes discovered surfaces into business domains:
 * - Payments (cart, checkout, pricing, billing)
 * - Auth (login, register, roles, admin)
 * - Subscriptions (plans, upgrade, downgrade, cancel)
 * - Inventory (products, stock, quantity, orders)
 * - Referrals (invite, refer, rewards, points)
 * - Workflows (multi-step forms, wizards, onboarding)
 */
export class BusinessRuleInferrer {
    constructor(logger) {
        this.logger = logger;

        this.DOMAIN_PATTERNS = {
            payments: {
                urlPatterns: [
                    /\/cart/i, /\/checkout/i, /\/pay/i, /\/billing/i,
                    /\/pricing/i, /\/purchase/i, /\/order/i, /\/invoice/i,
                    /\/coupon/i, /\/discount/i, /\/promo/i, /\/gift/i,
                ],
                formIndicators: ['price', 'amount', 'quantity', 'coupon', 'card', 'payment', 'total', 'subtotal'],
            },
            auth: {
                urlPatterns: [
                    /\/login/i, /\/signin/i, /\/register/i, /\/signup/i,
                    /\/admin/i, /\/dashboard/i, /\/account/i, /\/profile/i,
                    /\/role/i, /\/permission/i, /\/auth/i, /\/oauth/i,
                ],
                formIndicators: ['username', 'password', 'email', 'role', 'token'],
            },
            subscriptions: {
                urlPatterns: [
                    /\/subscri/i, /\/plan/i, /\/upgrade/i, /\/downgrade/i,
                    /\/cancel/i, /\/trial/i, /\/premium/i, /\/tier/i,
                    /\/membership/i, /\/renew/i,
                ],
                formIndicators: ['plan', 'subscription', 'tier', 'billing_cycle'],
            },
            inventory: {
                urlPatterns: [
                    /\/product/i, /\/item/i, /\/stock/i, /\/inventory/i,
                    /\/catalog/i, /\/shop/i, /\/store/i, /\/add-to-cart/i,
                    /\/wishlist/i, /\/quantity/i,
                ],
                formIndicators: ['quantity', 'stock', 'sku', 'product_id', 'item_id'],
            },
            referrals: {
                urlPatterns: [
                    /\/refer/i, /\/invite/i, /\/reward/i, /\/points/i,
                    /\/bonus/i, /\/affiliate/i, /\/earn/i, /\/redeem/i,
                ],
                formIndicators: ['referral_code', 'invite_code', 'points', 'reward'],
            },
            workflows: {
                urlPatterns: [
                    /\/step[_-]?\d/i, /\/wizard/i, /\/onboard/i, /\/setup/i,
                    /\/verify/i, /\/confirm/i, /\/review/i, /\/submit/i,
                    /\/complete/i, /\/finalize/i,
                ],
                formIndicators: ['step', 'next', 'previous', 'progress', 'stage'],
            },
        };
    }

    /**
     * Infer business context from the surface inventory.
     */
    infer(surfaceInventory) {
        const context = {
            domains: {},
            multiStepFlows: [],
            roleGatedPages: [],
            pricingSurfaces: [],
            apiEndpoints: {},
        };

        const pages = surfaceInventory.pages || [];
        const forms = surfaceInventory.forms || [];
        // The crawler emits `apiEndpoints` (not `apis`); read the correct field
        // so business-logic API surfaces are actually categorized.
        const apis = surfaceInventory.apiEndpoints || surfaceInventory.apis || [];

        // 1. Categorize pages by domain
        for (const page of pages) {
            const url = page.url || page;
            for (const [domain, config] of Object.entries(this.DOMAIN_PATTERNS)) {
                if (config.urlPatterns.some(p => p.test(url))) {
                    if (!context.domains[domain]) context.domains[domain] = [];
                    context.domains[domain].push({ type: 'page', url, domain });
                }
            }
        }

        // 2. Categorize APIs by domain
        for (const api of apis) {
            const url = api.url || api;
            for (const [domain, config] of Object.entries(this.DOMAIN_PATTERNS)) {
                if (config.urlPatterns.some(p => p.test(url))) {
                    if (!context.domains[domain]) context.domains[domain] = [];
                    context.domains[domain].push({
                        type: 'api',
                        url,
                        method: api.method || 'GET',
                        domain,
                    });
                    if (!context.apiEndpoints[domain]) context.apiEndpoints[domain] = [];
                    context.apiEndpoints[domain].push({ url, method: api.method || 'GET' });
                }
            }
        }

        // 3. Categorize forms by field names
        for (const form of forms) {
            const fields = (form.fields || []).map(f => (f.name || f.id || '').toLowerCase());
            for (const [domain, config] of Object.entries(this.DOMAIN_PATTERNS)) {
                const hasIndicator = config.formIndicators.some(ind =>
                    fields.some(f => f.includes(ind))
                );
                if (hasIndicator) {
                    if (!context.domains[domain]) context.domains[domain] = [];
                    context.domains[domain].push({
                        type: 'form',
                        url: form.action || form.pageUrl,
                        pageUrl: form.pageUrl,
                        fields: form.fields,
                        domain,
                    });
                }
            }
        }

        // 4. Detect multi-step flows
        context.multiStepFlows = this._detectMultiStepFlows(pages);

        // 5. Detect role-gated pages
        context.roleGatedPages = this._detectRoleGatedPages(pages);

        // 6. Identify pricing surfaces
        context.pricingSurfaces = [
            ...(context.domains.payments || []),
            ...(context.domains.subscriptions || []),
        ];

        // Summary
        const activeDomains = Object.entries(context.domains)
            .filter(([, items]) => items.length > 0)
            .map(([domain, items]) => `${domain}(${items.length})`);

        this.logger?.info?.(`Business Rule Inferrer: detected domains: ${activeDomains.join(', ') || 'none'}`);
        this.logger?.info?.(`  Multi-step flows: ${context.multiStepFlows.length}`);
        this.logger?.info?.(`  Role-gated pages: ${context.roleGatedPages.length}`);
        this.logger?.info?.(`  Pricing surfaces: ${context.pricingSurfaces.length}`);

        return context;
    }

    /**
     * Phase 3 — Augment the regex-based domain inference with LLM-inferred
     * domains and security-relevant invariants. STRICTLY ADDITIVE: the regex
     * DOMAIN_PATTERNS result above is untouched; results are attached under
     * `context.llmInsights` (source:'llm'). No-op when LLM is disabled.
     *
     * Data minimization: only URL paths + form field NAMES are sent (no values,
     * no bodies, no secrets).
     */
    async augmentWithLLM(context, surfaceInventory, llmClient) {
        if (!llmClient?.isEnabled?.()) return context;

        try {
            const pages = surfaceInventory.pages || [];
            const apis = surfaceInventory.apiEndpoints || surfaceInventory.apis || [];
            const forms = surfaceInventory.forms || [];

            const toPath = (u) => {
                try { return new URL(typeof u === 'string' ? u : (u.url || '')).pathname; }
                catch { return typeof u === 'string' ? u : (u?.url || ''); }
            };

            const paths = [...new Set([
                ...pages.map(p => toPath(p.url || p)),
                ...apis.map(a => toPath(a.url || a)),
            ])].filter(Boolean);

            const formFields = [...new Set(
                forms.flatMap(f => (f.fields || []).map(fl => (fl.name || fl.id || '').toLowerCase()))
            )].filter(Boolean);

            const result = await inferBusinessDomains(llmClient, { paths, formFields });
            if (result && (result.domains.length || result.invariants.length)) {
                context.llmInsights = {
                    domains: result.domains,
                    invariants: result.invariants,
                    source: 'llm',
                };
                this.logger?.info?.(`Business Rule Inferrer (LLM): +${result.domains.length} domains, ${result.invariants.length} invariants`);
            }
        } catch (err) {
            this.logger?.debug?.(`Business Rule Inferrer LLM augmentation skipped: ${err.message}`);
        }
        return context;
    }

    /**
     * Detect multi-step flows (pages with step indicators in URLs).
     */
    _detectMultiStepFlows(pages) {
        const flows = [];
        const stepPages = pages.filter(p => {
            const url = p.url || p;
            return /step[_-]?\d|\/\d+\/?$/i.test(url) ||
                /wizard|onboard|setup/i.test(url);
        });

        if (stepPages.length >= 2) {
            flows.push({
                type: 'multi_step',
                pages: stepPages.map(p => p.url || p),
                stepCount: stepPages.length,
            });
        }

        return flows;
    }

    /**
     * Detect role-gated pages (admin, dashboard, etc.).
     */
    _detectRoleGatedPages(pages) {
        return pages.filter(p => {
            const url = p.url || p;
            return /\/admin|\/dashboard|\/manage|\/settings|\/internal/i.test(url);
        }).map(p => ({
            url: p.url || p,
            status: p.status,
            redirected: p.redirectedTo || null,
        }));
    }
}

export default BusinessRuleInferrer;
