import { createFinding } from '../../utils/finding.js';

/**
 * RaceConditionDetector — Tests for race conditions in critical paths.
 *
 * Fires concurrent requests at state-changing endpoints to detect:
 * - Double spend (concurrent payment/transfer)
 * - Duplicate submission (same action processed twice)
 * - TOCTOU (time-of-check vs time-of-use)
 * - Limit bypass (concurrent requests that individually pass limits but collectively exceed)
 * - Inventory oversell (concurrent purchases of limited-stock item)
 */
export class RaceConditionDetector {
    constructor(logger) {
        this.logger = logger;
        this.CONCURRENCY = 10; // Number of simultaneous requests
    }

    /**
     * Test for race conditions on critical endpoints.
     */
    async detect(businessContext, surfaceInventory) {
        const findings = [];

        this.logger?.info?.('Race Condition Detector: starting tests');

        // Gather critical endpoints from all business domains
        const criticalEndpoints = this._gatherCriticalEndpoints(businessContext);

        if (criticalEndpoints.length === 0) {
            this.logger?.info?.('Race Condition Detector: no critical endpoints found — skipping');
            return findings;
        }

        this.logger?.info?.(`Race Condition Detector: testing ${criticalEndpoints.length} endpoints`);

        for (const endpoint of criticalEndpoints) {
            const result = await this._testEndpoint(endpoint);
            if (result) {
                findings.push(result);
            }
        }

        this.logger?.info?.(`Race Condition Detector: found ${findings.length} issues`);
        return findings;
    }

    /**
     * Gather state-changing endpoints that are race-condition sensitive.
     */
    _gatherCriticalEndpoints(businessContext) {
        const endpoints = [];

        // Payment endpoints
        for (const surface of (businessContext.domains.payments || [])) {
            if (surface.type === 'api' || surface.type === 'form') {
                endpoints.push({
                    url: surface.url,
                    method: surface.method || 'POST',
                    category: 'payment',
                    body: { amount: 1, action: 'process' },
                });
            }
        }

        // Inventory endpoints
        for (const surface of (businessContext.domains.inventory || [])) {
            if (surface.type === 'api') {
                endpoints.push({
                    url: surface.url,
                    method: surface.method || 'POST',
                    category: 'inventory',
                    body: { quantity: 1, action: 'purchase' },
                });
            }
        }

        // Referral/reward endpoints
        for (const surface of (businessContext.domains.referrals || [])) {
            if (surface.type === 'api') {
                endpoints.push({
                    url: surface.url,
                    method: surface.method || 'POST',
                    category: 'reward',
                    body: { action: 'claim' },
                });
            }
        }

        // Subscription endpoints
        for (const surface of (businessContext.domains.subscriptions || [])) {
            if (surface.type === 'api') {
                endpoints.push({
                    url: surface.url,
                    method: surface.method || 'POST',
                    category: 'subscription',
                    body: { action: 'change' },
                });
            }
        }

        return endpoints;
    }

    /**
     * Fire concurrent requests at an endpoint and analyze results.
     */
    async _testEndpoint(endpoint) {
        try {
            // Fire N concurrent identical requests
            const requests = Array.from({ length: this.CONCURRENCY }, () =>
                this._fireRequest(endpoint)
            );

            const results = await Promise.allSettled(requests);

            // Analyze results
            const successes = results.filter(r =>
                r.status === 'fulfilled' && r.value?.ok
            );
            const failures = results.filter(r =>
                r.status === 'fulfilled' && r.value && !r.value.ok
            );
            const errors = results.filter(r => r.status === 'rejected');

            // If all requests succeeded, the endpoint may lack concurrency control
            if (successes.length >= 2) {
                // Check if responses are identical (indicating no state change detection)
                const responseBodies = successes
                    .map(r => r.value?.body)
                    .filter(Boolean);

                const allIdentical = responseBodies.length >= 2 &&
                    responseBodies.every(b => b === responseBodies[0]);

                const severity = this._getSeverity(endpoint.category, successes.length);

                return createFinding({
                    module: 'logic',
                    title: `Race Condition: ${this._getCategoryTitle(endpoint.category)}`,
                    severity,
                    affected_surface: endpoint.url,
                    description: `${this.CONCURRENCY} concurrent requests were fired at ${endpoint.url}. ${successes.length}/${this.CONCURRENCY} succeeded, suggesting the endpoint lacks concurrency control. This could lead to ${this._getImpact(endpoint.category)}.`,
                    reproduction: [
                        `1. Prepare ${this.CONCURRENCY} identical ${endpoint.method} requests to ${endpoint.url}`,
                        `2. Fire all requests simultaneously using Promise.all`,
                        `3. ${successes.length} requests returned success (2xx)`,
                        allIdentical
                            ? `4. All success responses were identical — no state change detected`
                            : `4. Responses varied — partial state corruption possible`,
                    ],
                    evidence: `Concurrent requests: ${this.CONCURRENCY}\nSuccesses: ${successes.length}\nFailures: ${failures.length}\nErrors: ${errors.length}\nIdentical responses: ${allIdentical}`,
                    remediation: this._getRemediation(endpoint.category),
                });
            }
        } catch (err) {
            this.logger?.debug?.(`Race test for ${endpoint.url} failed: ${err.message}`);
        }

        return null;
    }

    async _fireRequest(endpoint) {
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 10000);

            const response = await fetch(endpoint.url, {
                method: endpoint.method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(endpoint.body),
                signal: controller.signal,
            });
            clearTimeout(timeout);

            const body = await response.text();
            return { ok: response.ok, status: response.status, body };
        } catch {
            return null;
        }
    }

    _getCategoryTitle(category) {
        const titles = {
            payment: 'Double Spend Risk',
            inventory: 'Oversell Risk',
            reward: 'Reward Farming',
            subscription: 'State Corruption',
        };
        return titles[category] || 'Concurrent Modification';
    }

    _getImpact(category) {
        const impacts = {
            payment: 'double charges, double payouts, or multiple payment processing for a single transaction',
            inventory: 'selling more items than available stock, inventory going negative',
            reward: 'claiming the same reward multiple times, point/credit inflation',
            subscription: 'corrupted subscription state, free access to paid tiers',
        };
        return impacts[category] || 'inconsistent state from concurrent modifications';
    }

    _getSeverity(category, successCount) {
        if (category === 'payment' && successCount >= 2) return 'critical';
        if (category === 'inventory' && successCount >= 3) return 'high';
        if (category === 'reward' && successCount >= 3) return 'high';
        return 'medium';
    }

    _getRemediation(category) {
        const base = 'Implement concurrency control: ';
        const remediations = {
            payment: base + 'Use database-level locking (SELECT FOR UPDATE), idempotency keys, and optimistic concurrency control for all payment operations. Process payments through a queue to serialize concurrent requests.',
            inventory: base + 'Use atomic database operations (UPDATE ... WHERE stock > 0) for inventory decrements. Implement pessimistic locking on stock-sensitive operations.',
            reward: base + 'Use unique constraints on reward claims (user_id + reward_id). Implement rate limiting and claim deduplication. Process reward claims through a serialized queue.',
            subscription: base + 'Use optimistic locking with version numbers on subscription records. Reject concurrent modifications with a 409 Conflict response.',
        };
        return remediations[category] || base + 'Use database-level locking and idempotency keys for state-changing operations.';
    }
}

export default RaceConditionDetector;
