import { DEFAULT_SAFETY_MODE, SAFETY_MODES } from './config.js';

/**
 * Safety tier helpers.
 *
 * Tiers are ordered: passive < safe-active < aggressive.
 * A test declares the MINIMUM tier it requires to run; it runs only when the
 * active safety mode is at least that tier.
 *
 *   passive     — no attack/probing requests, no state-changing requests
 *   safe-active — active but non-destructive probing (default)
 *   aggressive  — destructive/state-changing tests allowed
 */
const TIER_RANK = {
    passive: 0,
    'safe-active': 1,
    aggressive: 2,
};

/** Resolve the active safety mode from a config object. */
export function getSafetyMode(config) {
    const mode = config?.safety_mode;
    return SAFETY_MODES.includes(mode) ? mode : DEFAULT_SAFETY_MODE;
}

/**
 * Returns true if the active safety mode permits a test that requires
 * `requiredTier` (one of 'passive' | 'safe-active' | 'aggressive').
 */
export function allows(config, requiredTier) {
    const current = TIER_RANK[getSafetyMode(config)] ?? TIER_RANK[DEFAULT_SAFETY_MODE];
    const required = TIER_RANK[requiredTier] ?? TIER_RANK['safe-active'];
    return current >= required;
}

export function isPassive(config) {
    return getSafetyMode(config) === 'passive';
}

export function isAggressive(config) {
    return getSafetyMode(config) === 'aggressive';
}

export { SAFETY_MODES };
