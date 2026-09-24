import { randomId } from './id.js';
import { tagFinding } from './owasp-mapper.js';
import { inferCvssForFinding } from './cvss-calculator.js';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
export const VERIFICATION_LEVELS = Object.freeze({
    confirmed: { label: 'Confirmed', rank: 4 },
    high_confidence: { label: 'High confidence', rank: 3 },
    potential: { label: 'Potential', rank: 2 },
    informational: { label: 'Informational', rank: 1 },
    not_assessed: { label: 'Not assessed', rank: 0 },
});

const PROOF_FIELDS = [
    'originalRequest', 'mutatedRequest', 'baselineResponse', 'vulnerableResponse',
    'responseDifference', 'reproductionCommand', 'timestamp', 'accountRole',
];

function redactProof(value) {
    if (value == null) return null;
    if (Array.isArray(value)) return value.map(redactProof);
    if (typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(([key, item]) => [key,
            /authorization|cookie|password|secret|token|api[-_]?key/i.test(key) ? '[REDACTED]' : redactProof(item)
        ]));
    }
    if (typeof value !== 'string') return value;
    return value
        .replace(/(authorization\s*[:=]\s*bearer\s+)[^\s"']+/ig, '$1[REDACTED]')
        .replace(/((?:password|secret|token|api[-_]?key)\s*[:=]\s*)[^\s&"']+/ig, '$1[REDACTED]')
        .slice(0, 20000);
}

export function normalizeVerification(verification, { severity = 'info', evidence = null, timestamp = new Date().toISOString() } = {}) {
    const supplied = typeof verification === 'string' ? { level: verification } : { ...(verification || {}) };
    let level = supplied.level || (severity === 'info' ? 'informational' : 'potential');
    if (!VERIFICATION_LEVELS[level]) level = 'potential';

    const proof = redactProof({ ...(supplied.proof || {}), timestamp: supplied.proof?.timestamp || timestamp });
    const missingEvidence = PROOF_FIELDS.filter(field => !proof[field]);
    if (!proof.screenshot && !proof.trace) missingEvidence.push('screenshotOrTrace');

    // A confirmed label is reserved for findings with a complete, replayable
    // proof bundle. Incomplete claims are downgraded instead of overstated.
    const requestedLevel = level;
    if (level === 'confirmed' && missingEvidence.length > 0) level = evidence ? 'high_confidence' : 'potential';

    return {
        level,
        label: VERIFICATION_LEVELS[level].label,
        reason: supplied.reason || ({
            confirmed: 'The scanner executed the exploit and recorded observable impact.',
            high_confidence: 'Controlled requests produced a repeatable security-relevant response change.',
            potential: 'Heuristic evidence requires manual verification.',
            informational: 'Attack-surface discovery or configuration observation.',
            not_assessed: 'The scanner could not assess this condition with the available access or capability.',
        })[level],
        method: supplied.method || (level === 'informational' ? 'observation' : level === 'potential' ? 'heuristic' : 'active-verification'),
        requestedLevel: requestedLevel !== level ? requestedLevel : undefined,
        proof,
        missingEvidence,
    };
}

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
    verification = null,
}) {
    const prefix = module.toUpperCase();
    const shortId = randomId(6);

    const timestamp = new Date().toISOString();
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
        timestamp,
        verification: normalizeVerification(verification, { severity, evidence, timestamp }),
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

export function verificationSummary(findings = []) {
    const summary = Object.fromEntries(Object.keys(VERIFICATION_LEVELS).map(level => [level, 0]));
    summary.total = findings.length;
    for (const finding of findings) {
        const level = finding.verification?.level || (finding.severity === 'info' ? 'informational' : 'potential');
        summary[VERIFICATION_LEVELS[level] ? level : 'potential']++;
    }
    return summary;
}

export default { createFinding, sortFindings, filterBySeverity, severitySummary, verificationSummary, normalizeVerification };
