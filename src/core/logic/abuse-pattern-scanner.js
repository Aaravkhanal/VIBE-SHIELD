import { createFinding } from '../../utils/finding.js';

/**
 * AbusePatternScanner — Tests for referral, reward, and subscription abuse.
 *
 * Probes:
 * - Self-referral (use own referral code)
 * - Referral loop (circular chains)
 * - Reward farming (rapid repeated claims)
 * - Trial abuse (reset trial limits)
 * - Subscription manipulation (downgrade/cancel/reinstate exploits)
 */
export class AbusePatternScanner {
    constructor(logger) {
        this.logger = logger;

        this.TRIAL_RESET_INDICATORS = [
            /trial.*start/i, /free.*trial/i, /trial.*activated/i,
            /days.*remaining/i, /trial.*extended/i,
        ];
    }

    /**
     * Scan for abuse patterns in business context surfaces.
     */
    async scan(businessContext, surfaceInventory) {
        const findings = [];

        this.logger?.info?.('Abuse Pattern Scanner: starting tests');

        // 1. Self-referral testing
        const referralFindings = await this._testSelfReferral(businessContext);
        findings.push(...referralFindings);

        // 2. Reward farming
        const rewardFindings = await this._testRewardFarming(businessContext);
        findings.push(...rewardFindings);

        // 3. Trial abuse
        const trialFindings = await this._testTrialAbuse(businessContext, surfaceInventory);
        findings.push(...trialFindings);

        // 4. Subscription manipulation
        const subFindings = await this._testSubscriptionAbuse(businessContext);
        findings.push(...subFindings);

        this.logger?.info?.(`Abuse Pattern Scanner: found ${findings.length} issues`);
        return findings;
    }

    /**
     * Test if a user can use their own referral code.
     */
    async _testSelfReferral(businessContext) {
        const findings = [];
        const referralSurfaces = businessContext.domains.referrals || [];

        for (const surface of referralSurfaces) {
            if (surface.type !== 'api' && surface.type !== 'form') continue;

            const url = surface.url;
            // Try self-referral patterns
            const selfReferralBodies = [
                { referral_code: 'SELF', user_id: '1', referred_by: '1' },
                { code: 'TEST123', self: true },
                { referral: 'self', action: 'apply' },
            ];

            for (const body of selfReferralBodies) {
                try {
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 5000);

                    const response = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body),
                        signal: controller.signal,
                    });
                    clearTimeout(timeout);

                    if (response.ok) {
                        const text = await response.text();
                        if (/success|applied|reward|credit|bonus|points/i.test(text)) {
                            findings.push(createFinding({
                                module: 'logic',
                                title: 'Referral Abuse: Self-Referral Accepted',
                                severity: 'high',
                                affected_surface: url,
                                description: `The referral endpoint at ${url} accepted a self-referral request, allowing a user to earn referral rewards for referring themselves. This can be exploited to farm unlimited credits/points.`,
                                reproduction: [
                                    `1. POST to ${url} with self-referral data`,
                                    `2. Server returns success response`,
                                    `3. Repeat to accumulate rewards`,
                                ],
                                evidence: `Response contained reward/success indicators`,
                                remediation: 'Block self-referral by comparing referrer and referred user IDs server-side. Implement IP, email, and device fingerprint deduplication for referral programs.',
                            }));
                            break;
                        }
                    }
                } catch {
                    continue;
                }
            }
        }

        return findings;
    }

    /**
     * Test rapid reward claiming (farming).
     */
    async _testRewardFarming(businessContext) {
        const findings = [];
        const rewardSurfaces = businessContext.domains.referrals || [];

        for (const surface of rewardSurfaces) {
            if (surface.type !== 'api') continue;

            const url = surface.url;
            const body = { action: 'claim', reward_id: '1' };

            // Fire 5 rapid claims
            try {
                const results = await Promise.allSettled(
                    Array.from({ length: 5 }, () =>
                        fetch(url, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(body),
                            signal: AbortSignal.timeout(5000),
                        }).then(async r => ({ ok: r.ok, text: await r.text() })).catch(() => null)
                    )
                );

                const successes = results.filter(r =>
                    r.status === 'fulfilled' && r.value?.ok
                ).length;

                if (successes >= 3) {
                    findings.push(createFinding({
                        module: 'logic',
                        title: 'Reward Farming: No Rate Limiting',
                        severity: 'high',
                        affected_surface: url,
                        description: `The reward endpoint at ${url} accepted ${successes}/5 rapid consecutive claims without rate limiting. An attacker can farm unlimited rewards by scripting rapid requests.`,
                        reproduction: [
                            `1. Send 5 rapid POST requests to ${url}`,
                            `2. ${successes} requests succeeded`,
                            `3. No rate limit or cooldown detected`,
                        ],
                        evidence: `Rapid claims accepted: ${successes}/5`,
                        remediation: 'Implement per-user rate limiting on reward claims. Add cooldown periods between claims. Use unique claim tokens that can only be used once.',
                    }));
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    /**
     * Test trial period abuse (reset trial via re-registration).
     */
    async _testTrialAbuse(businessContext, surfaceInventory) {
        const findings = [];
        const subSurfaces = businessContext.domains.subscriptions || [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        // Check trial-related endpoints
        const trialPaths = ['/trial', '/free-trial', '/start-trial', '/api/trial', '/api/subscription/trial'];

        for (const path of trialPaths) {
            try {
                const url = new URL(path, baseUrl).href;
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);

                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: 'test@example.com', action: 'start_trial' }),
                    signal: controller.signal,
                });
                clearTimeout(timeout);

                if (response.ok) {
                    const text = await response.text();
                    if (this.TRIAL_RESET_INDICATORS.some(p => p.test(text))) {
                        findings.push(createFinding({
                            module: 'logic',
                            title: 'Trial Abuse: Trial Restart Possible',
                            severity: 'medium',
                            affected_surface: url,
                            description: `The trial endpoint at ${url} may allow restarting free trials. If the server doesn't track trial history by account/device/IP, users can create new accounts to get unlimited free trials.`,
                            reproduction: [
                                `1. POST to ${url} with trial start request`,
                                `2. Server responds with trial activation`,
                                `3. Repeat with different email addresses`,
                            ],
                            evidence: `Response contained trial activation indicators`,
                            remediation: 'Track trial usage by multiple signals: email domain, device fingerprint, IP address, payment method. Limit trials to one per payment method or verified identity.',
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
     * Test subscription state manipulation.
     */
    async _testSubscriptionAbuse(businessContext) {
        const findings = [];
        const subSurfaces = businessContext.domains.subscriptions || [];

        for (const surface of subSurfaces) {
            if (surface.type !== 'api') continue;

            const url = surface.url;

            // Test rapid state transitions (downgrade then immediately upgrade)
            const transitions = [
                { action: 'downgrade', plan: 'free' },
                { action: 'upgrade', plan: 'premium' },
                { action: 'cancel' },
                { action: 'reinstate' },
            ];

            let successCount = 0;
            for (const transition of transitions) {
                try {
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 5000);

                    const response = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(transition),
                        signal: controller.signal,
                    });
                    clearTimeout(timeout);

                    if (response.ok) successCount++;
                } catch {
                    continue;
                }
            }

            if (successCount >= 3) {
                findings.push(createFinding({
                    module: 'logic',
                    title: 'Subscription Abuse: Rapid State Transitions Accepted',
                    severity: 'high',
                    affected_surface: url,
                    description: `The subscription endpoint at ${url} accepted ${successCount}/4 rapid state transitions (downgrade → upgrade → cancel → reinstate) without validation. This could allow users to game billing cycles, retain features after downgrade, or exploit prorated refunds.`,
                    reproduction: [
                        `1. Downgrade subscription to free`,
                        `2. Immediately upgrade to premium`,
                        `3. Cancel subscription`,
                        `4. Reinstate subscription`,
                        `All ${successCount} transitions accepted without cooldown`,
                    ],
                    evidence: `Rapid transitions accepted: ${successCount}/4`,
                    remediation: 'Implement state machine validation for subscription transitions. Add cooldown periods between state changes. Validate billing implications server-side before accepting transitions. Log all state changes for audit.',
                }));
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
}

export default AbusePatternScanner;
