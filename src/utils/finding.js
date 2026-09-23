import { randomId } from './id.js';
import { tagFinding } from './owasp-mapper.js';
import { inferCvssForFinding } from './cvss-calculator.js';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Creates a VIBE SHIELD Finding object matching the manifest schema.
 * Automatically tagged with OWASP Top 10 (2021) classification and CVSS v3.1 Quantitative Score.
 */
export function createFinding({
    module = 'qa',
    title,
    severity = 'info',
    affected_surface,
    description,
    reproduction = [],
    evidence = null,
    remediation = '',
    references = [],
    status = 'open',
    source = null,
    cvss = null,
}) {
    const prefix = module.toUpperCase();
    const shortId = randomId(6);

    const baseFinding = {
        id: `VIBE SHIELD-${prefix}-${shortId}`,
        module,
        title,
        severity: severity.toLowerCase(),
        affected_surface,
        description,
        reproduction: Array.isArray(reproduction) ? reproduction : [reproduction],
        evidence,
        remediation,
        references,
        status,
        timestamp: new Date().toISOString(),
        // Provenance: 'llm' marks AI-generated/augmented findings; null = deterministic.
        ...(source ? { source } : {}),
    };

    // Calculate CVSS v3.1 score and vector
    baseFinding.cvss = cvss || inferCvssForFinding(baseFinding);

    // Auto-tag with OWASP Top 10 classification
    return tagFinding(baseFinding);
}

/**
 * Sorts findings by severity (critical first).
 */
export function sortFindings(findings) {
    return [...findings].sort((a, b) => {
        return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    });
}

/**
 * Filters findings by minimum severity threshold.
 */
export function filterBySeverity(findings, threshold = 'low') {
    const thresholdIndex = SEVERITY_ORDER.indexOf(threshold);
    return findings.filter(f => SEVERITY_ORDER.indexOf(f.severity) <= thresholdIndex);
}

/**
 * Generates a summary count by severity.
 */
export function severitySummary(findings) {
    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length };
    for (const f of findings) {
        if (summary[f.severity] !== undefined) summary[f.severity]++;
    }
    return summary;
}

export default { createFinding, sortFindings, filterBySeverity, severitySummary };
