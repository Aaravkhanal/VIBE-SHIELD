/**
 * CVSS v3.1 Specification Compliant Quantitative Scoring Engine
 * Spec: https://www.first.org/cvss/v3.1/specification-document
 */

export const CVSS_METRIC_WEIGHTS = {
    AV: {
        N: { val: 0.85, label: 'Network', desc: 'Remotely exploitable across the public Internet' },
        A: { val: 0.62, label: 'Adjacent', desc: 'Requires adjacent network access (e.g. local subnet, bluetooth)' },
        L: { val: 0.55, label: 'Local', desc: 'Requires local shell access or user executing locally' },
        P: { val: 0.20, label: 'Physical', desc: 'Requires physical access to the device or hardware' }
    },
    AC: {
        L: { val: 0.77, label: 'Low', desc: 'No specialized access condition; attack repeatable at will' },
        H: { val: 0.44, label: 'High', desc: 'Requires rare race conditions, complex reconnaissance, or prerequisites' }
    },
    PR: {
        N: { valU: 0.85, valC: 0.85, label: 'None', desc: 'Unauthenticated attacker' },
        L: { valU: 0.62, valC: 0.68, label: 'Low', desc: 'Basic authenticated user privileges required' },
        H: { valU: 0.27, valC: 0.50, label: 'High', desc: 'Administrative / privileged access required' }
    },
    UI: {
        N: { val: 0.85, label: 'None', desc: 'Vulnerability can be exploited without victim interaction' },
        R: { val: 0.62, label: 'Required', desc: 'Victim must click a link, submit a form, or take action' }
    },
    S: {
        U: { label: 'Unchanged', desc: 'Vulnerability impacts only the immediate vulnerable component' },
        C: { label: 'Changed', desc: 'Impacts resources beyond the security boundary (e.g. sandbox breakout, SSRF)' }
    },
    C: {
        N: { val: 0.0, label: 'None', desc: 'No confidentiality impact' },
        L: { val: 0.22, label: 'Low', desc: 'Minor disclosure of non-sensitive data' },
        H: { val: 0.56, label: 'High', desc: 'Total compromise of confidentiality / full data leak' }
    },
    I: {
        N: { val: 0.0, label: 'None', desc: 'No integrity impact' },
        L: { val: 0.22, label: 'Low', desc: 'Modification of minor non-critical data' },
        H: { val: 0.56, label: 'High', desc: 'Total loss of integrity / unauthorized code modification' }
    },
    A: {
        N: { val: 0.0, label: 'None', desc: 'No availability impact' },
        L: { val: 0.22, label: 'Low', desc: 'Reduced performance or intermittent interruptions' },
        H: { val: 0.56, label: 'High', desc: 'Total denial of service or resource shutdown' }
    }
};

/**
 * CVSS v3.1 official roundup function
 */
export function roundup(val) {
    const intVal = Math.round(val * 100000);
    if (intVal % 10000 === 0) {
        return intVal / 100000;
    }
    return (Math.floor(intVal / 10000) + 1) / 10;
}

/**
 * Calculate CVSS v3.1 Base Score and subscores from metric selections
 */
export function calculateCvss({
    AV = 'N',
    AC = 'L',
    PR = 'N',
    UI = 'N',
    S = 'U',
    C = 'H',
    I = 'H',
    A = 'N'
} = {}) {
    // Normalize keys
    const av = AV.toUpperCase();
    const ac = AC.toUpperCase();
    const pr = PR.toUpperCase();
    const ui = UI.toUpperCase();
    const s = S.toUpperCase();
    const c = C.toUpperCase();
    const i = I.toUpperCase();
    const a = A.toUpperCase();

    const avVal = CVSS_METRIC_WEIGHTS.AV[av]?.val ?? 0.85;
    const acVal = CVSS_METRIC_WEIGHTS.AC[ac]?.val ?? 0.77;
    const isScopeChanged = s === 'C';
    const prVal = isScopeChanged 
        ? (CVSS_METRIC_WEIGHTS.PR[pr]?.valC ?? 0.85)
        : (CVSS_METRIC_WEIGHTS.PR[pr]?.valU ?? 0.85);
    const uiVal = CVSS_METRIC_WEIGHTS.UI[ui]?.val ?? 0.85;

    const cVal = CVSS_METRIC_WEIGHTS.C[c]?.val ?? 0.0;
    const iVal = CVSS_METRIC_WEIGHTS.I[i]?.val ?? 0.0;
    const aVal = CVSS_METRIC_WEIGHTS.A[a]?.val ?? 0.0;

    // Exploitability subscore
    const exploitability = 8.22 * avVal * acVal * prVal * uiVal;

    // ISS (Impact Sub-Score)
    const iss = 1 - ((1 - cVal) * (1 - iVal) * (1 - aVal));

    // Impact subscore
    let impact = 0;
    if (isScopeChanged) {
        impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    } else {
        impact = 6.42 * iss;
    }

    // Base score
    let baseScore = 0.0;
    if (impact <= 0) {
        baseScore = 0.0;
    } else if (!isScopeChanged) {
        baseScore = roundup(Math.min(impact + exploitability, 10));
    } else {
        baseScore = roundup(Math.min(1.08 * (impact + exploitability), 10));
    }

    baseScore = Math.max(0.0, Math.min(10.0, baseScore));

    // Severity mapping
    let severity = 'NONE';
    let color = '#738a9c';
    if (baseScore >= 9.0) {
        severity = 'CRITICAL';
        color = '#ff3366';
    } else if (baseScore >= 7.0) {
        severity = 'HIGH';
        color = '#ff9900';
    } else if (baseScore >= 4.0) {
        severity = 'MEDIUM';
        color = '#ffcc00';
    } else if (baseScore >= 0.1) {
        severity = 'LOW';
        color = '#00f0ff';
    }

    const vectorString = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;

    return {
        score: baseScore.toFixed(1),
        numericScore: baseScore,
        severity,
        color,
        vectorString,
        exploitabilityScore: (Math.round(exploitability * 10) / 10).toFixed(1),
        impactScore: (Math.max(0, Math.round(impact * 10) / 10)).toFixed(1),
        metrics: {
            AV: { code: av, ...CVSS_METRIC_WEIGHTS.AV[av] },
            AC: { code: ac, ...CVSS_METRIC_WEIGHTS.AC[ac] },
            PR: { code: pr, ...CVSS_METRIC_WEIGHTS.PR[pr] },
            UI: { code: ui, ...CVSS_METRIC_WEIGHTS.UI[ui] },
            S: { code: s, ...CVSS_METRIC_WEIGHTS.S[s] },
            C: { code: c, ...CVSS_METRIC_WEIGHTS.C[c] },
            I: { code: i, ...CVSS_METRIC_WEIGHTS.I[i] },
            A: { code: a, ...CVSS_METRIC_WEIGHTS.A[a] }
        }
    };
}

/**
 * Parse a standard CVSS v3.1 vector string into metrics and calculate the score
 */
export function parseCvssVector(vectorString) {
    if (!vectorString || typeof vectorString !== 'string') {
        return calculateCvss();
    }

    const metrics = {};
    const parts = vectorString.split('/');
    for (const part of parts) {
        const [k, v] = part.split(':');
        if (k && v && ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'].includes(k.toUpperCase())) {
            metrics[k.toUpperCase()] = v.toUpperCase();
        }
    }

    return calculateCvss(metrics);
}

/**
 * Infer intelligent, realistic CVSS v3.1 metrics for any given finding
 */
export function inferCvssForFinding(finding = {}) {
    const title = (finding.title || '').toLowerCase();
    const desc = (finding.description || '').toLowerCase();
    const module = (finding.module || finding.agent || '').toLowerCase();
    const severity = (finding.severity || 'low').toLowerCase();

    // Specific vulnerability heuristics
    if (title.includes('prompt injection') || title.includes('jailbreak') || title.includes('system prompt')) {
        return calculateCvss({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' }); // 9.3 Critical
    }
    if (title.includes('sql injection') || title.includes('sqli') || desc.includes('database query')) {
        return calculateCvss({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }); // 9.8 Critical
    }
    if (title.includes('ssrf') || title.includes('server-side request forgery')) {
        return calculateCvss({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'L', A: 'N' }); // 9.3 Critical
    }
    if (title.includes('cors') || title.includes('origin')) {
        return calculateCvss({ AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'L', A: 'N' }); // 7.1 High
    }
    if (title.includes('api key') || title.includes('secret') || title.includes('token') || title.includes('exposed credential')) {
        return calculateCvss({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }); // 7.5 High
    }
    if (title.includes('rate limit') || title.includes('dos') || title.includes('denial of service')) {
        return calculateCvss({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'H' }); // 7.5 High
    }
    if (title.includes('content-security-policy') || title.includes('csp') || title.includes('hsts') || title.includes('header')) {
        return calculateCvss({ AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' }); // 5.4 Medium
    }
    if (title.includes('cookie') || title.includes('httponly') || title.includes('samesite')) {
        return calculateCvss({ AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' }); // 3.1 Low
    }
    if (title.includes('auth') || title.includes('jwt') || title.includes('bypass')) {
        return calculateCvss({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' }); // 9.1 Critical
    }

    // Default by severity tier
    switch (severity) {
        case 'critical':
            return calculateCvss({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }); // 9.8 Critical
        case 'high':
            return calculateCvss({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }); // 7.5 High
        case 'medium':
            return calculateCvss({ AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' }); // 5.4 Medium
        case 'low':
            return calculateCvss({ AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' }); // 3.1 Low
        default:
            return calculateCvss({ AV: 'N', AC: 'H', PR: 'L', UI: 'R', S: 'U', C: 'N', I: 'N', A: 'N' }); // 0.0 None
    }
}

export default {
    CVSS_METRIC_WEIGHTS,
    roundup,
    calculateCvss,
    parseCvssVector,
    inferCvssForFinding
};
