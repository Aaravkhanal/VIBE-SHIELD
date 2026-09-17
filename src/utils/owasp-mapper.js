/**
 * OWASP Top 10 (2021) Mapper
 *
 * Maps VIBE SHIELD findings to OWASP categories automatically based on
 * finding title, module, and description patterns.
 */

// ═══════════════════════════════════════════════
// OWASP Top 10 (2021) Definitions
// ═══════════════════════════════════════════════

export const OWASP_TOP_10 = [
    {
        id: 'A01:2021',
        name: 'Broken Access Control',
        description: 'Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data.',
        cwe: [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275],
    },
    {
        id: 'A02:2021',
        name: 'Cryptographic Failures',
        description: 'Failures related to cryptography which often lead to sensitive data exposure. This includes use of weak cryptographic algorithms, improper key management, and transmission of data in clear text.',
        cwe: [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
    },
    {
        id: 'A03:2021',
        name: 'Injection',
        description: 'Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. This includes SQL, NoSQL, OS, LDAP injection, as well as XSS and prompt injection.',
        cwe: [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917],
    },
    {
        id: 'A04:2021',
        name: 'Insecure Design',
        description: 'A broad category focusing on risks related to design and architectural flaws. Insecure design cannot be fixed by a perfect implementation — the security controls were never created to defend against specific attacks.',
        cwe: [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173],
    },
    {
        id: 'A05:2021',
        name: 'Security Misconfiguration',
        description: 'Security misconfiguration is the most commonly seen issue. This includes insecure default configurations, incomplete configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages.',
        cwe: [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174],
    },
    {
        id: 'A06:2021',
        name: 'Vulnerable and Outdated Components',
        description: 'Components such as libraries, frameworks, and other software modules run with the same privileges as the application. If a vulnerable component is exploited, it can facilitate serious data loss or server takeover.',
        cwe: [1035, 1104],
    },
    {
        id: 'A07:2021',
        name: 'Identification and Authentication Failures',
        description: 'Confirmation of the user\'s identity, authentication, and session management is critical to protect against authentication-related attacks.',
        cwe: [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216],
    },
    {
        id: 'A08:2021',
        name: 'Software and Data Integrity Failures',
        description: 'Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This includes insecure deserialization and use of software from untrusted sources.',
        cwe: [345, 353, 426, 494, 502, 565, 784, 829, 830, 913],
    },
    {
        id: 'A09:2021',
        name: 'Security Logging and Monitoring Failures',
        description: 'Insufficient logging, detection, monitoring, and active response allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper with or extract data.',
        cwe: [117, 223, 532, 778],
    },
    {
        id: 'A10:2021',
        name: 'Server-Side Request Forgery (SSRF)',
        description: 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.',
        cwe: [918],
    },
];

// ═══════════════════════════════════════════════
// Pattern → OWASP Category Mapping
// ═══════════════════════════════════════════════

const MAPPING_RULES = [
    // A01: Broken Access Control
    { pattern: /csrf|cross.site.request/i, owasp: 'A01:2021' },
    { pattern: /idor|insecure.direct.object/i, owasp: 'A01:2021' },
    { pattern: /access.control|access.boundary|authorization/i, owasp: 'A01:2021' },
    { pattern: /privilege.escalation|vertical.escalation|horizontal.escalation/i, owasp: 'A01:2021' },
    { pattern: /forced.browsing|directory.listing/i, owasp: 'A01:2021' },
    { pattern: /cors.misconfig|cors.origin|cors.credential/i, owasp: 'A01:2021' },
    { pattern: /clickjacking|x-frame/i, owasp: 'A01:2021' },
    { pattern: /open.redirect/i, owasp: 'A01:2021' },
    { pattern: /guest.*access|missing.*auth.*endpoint/i, owasp: 'A01:2021' },
    { pattern: /account.takeover/i, owasp: 'A01:2021' },
    { pattern: /feature.flag.bypass/i, owasp: 'A01:2021' },

    // A02: Cryptographic Failures
    { pattern: /secret|api.key|token.*exposed|credential.*leak|password.*exposed/i, owasp: 'A02:2021' },
    { pattern: /tls|ssl|certificate|weak.cipher/i, owasp: 'A02:2021' },
    { pattern: /hsts|http.*not.*redirect|cleartext/i, owasp: 'A02:2021' },
    { pattern: /cookie.*secure|cookie.*httponly|cookie.*samesite/i, owasp: 'A02:2021' },
    { pattern: /sensitive.data.*exposure|data.*leak/i, owasp: 'A02:2021' },

    // A03: Injection
    { pattern: /xss|cross.site.script/i, owasp: 'A03:2021' },
    { pattern: /sql.injection|sqli/i, owasp: 'A03:2021' },
    { pattern: /prompt.injection|prompt.*inject/i, owasp: 'A03:2021' },
    { pattern: /command.injection|os.command/i, owasp: 'A03:2021' },
    { pattern: /ldap.injection/i, owasp: 'A03:2021' },
    { pattern: /nosql.injection/i, owasp: 'A03:2021' },
    { pattern: /header.injection|crlf/i, owasp: 'A03:2021' },
    { pattern: /template.injection|ssti/i, owasp: 'A03:2021' },
    { pattern: /jailbreak/i, owasp: 'A03:2021' },
    { pattern: /guardrail.bypass/i, owasp: 'A03:2021' },
    { pattern: /ai.mediated.xss|unsanitized.*output/i, owasp: 'A03:2021' },

    // A04: Insecure Design
    { pattern: /race.condition/i, owasp: 'A04:2021' },
    { pattern: /business.logic|workflow.violation/i, owasp: 'A04:2021' },
    { pattern: /pricing.manipulation|price.*tamper/i, owasp: 'A04:2021' },
    { pattern: /coupon.*abuse|discount.*abuse|promo.*abuse/i, owasp: 'A04:2021' },
    { pattern: /cart.*manipulation|quantity.*manipulation/i, owasp: 'A04:2021' },
    { pattern: /email.enumeration/i, owasp: 'A04:2021' },
    { pattern: /rate.limit|brute.force/i, owasp: 'A04:2021' },
    { pattern: /missing.*captcha/i, owasp: 'A04:2021' },
    { pattern: /file.upload.*bypass|unrestricted.*upload/i, owasp: 'A04:2021' },
    { pattern: /excessive.agency/i, owasp: 'A04:2021' },

    // A05: Security Misconfiguration
    { pattern: /missing.*header|security.header/i, owasp: 'A05:2021' },
    { pattern: /content.security.policy|csp/i, owasp: 'A05:2021' },
    { pattern: /verbose.error|error.*disclosure|stack.trace/i, owasp: 'A05:2021' },
    { pattern: /directory.listing|exposed.*directory/i, owasp: 'A05:2021' },
    { pattern: /debug.*endpoint|admin.*exposed|management.*endpoint/i, owasp: 'A05:2021' },
    { pattern: /default.credential|default.password/i, owasp: 'A05:2021' },
    { pattern: /information.disclosure/i, owasp: 'A05:2021' },
    { pattern: /graphql.*introspection/i, owasp: 'A05:2021' },
    { pattern: /subdomain/i, owasp: 'A05:2021' },
    { pattern: /misconfigur/i, owasp: 'A05:2021' },

    // A06: Vulnerable and Outdated Components
    { pattern: /dependency.*vuln|outdated.*package|known.*vuln|cve-/i, owasp: 'A06:2021' },
    { pattern: /vulnerable.*component|vulnerable.*library/i, owasp: 'A06:2021' },
    { pattern: /npm.*audit|dependency.*audit/i, owasp: 'A06:2021' },

    // A07: Identification and Authentication Failures
    { pattern: /auth.*bypass|broken.*auth|authentication.*failure/i, owasp: 'A07:2021' },
    { pattern: /jwt.*none|jwt.*signature|jwt.*weak/i, owasp: 'A07:2021' },
    { pattern: /session.*fixation|session.*hijack/i, owasp: 'A07:2021' },
    { pattern: /weak.*password|password.*policy/i, owasp: 'A07:2021' },
    { pattern: /oauth.*misconfig|oauth.*vuln/i, owasp: 'A07:2021' },
    { pattern: /api.key.*no.*rotation|api.key.*weak/i, owasp: 'A07:2021' },

    // A08: Software and Data Integrity Failures
    { pattern: /deserialization|prototype.pollution/i, owasp: 'A08:2021' },
    { pattern: /subresource.integrity|sri/i, owasp: 'A08:2021' },
    { pattern: /untrusted.*source|supply.chain/i, owasp: 'A08:2021' },

    // A09: Security Logging and Monitoring Failures
    { pattern: /logging.*failure|no.*logging|insufficient.*log/i, owasp: 'A09:2021' },
    { pattern: /monitoring.*gap|no.*monitoring/i, owasp: 'A09:2021' },

    // A10: Server-Side Request Forgery
    { pattern: /ssrf|server.side.request/i, owasp: 'A10:2021' },
    { pattern: /cloud.*metadata|169\.254/i, owasp: 'A10:2021' },
];

// ═══════════════════════════════════════════════
// Module-level fallback mapping
// ═══════════════════════════════════════════════

const MODULE_FALLBACK = {
    security: 'A05:2021',  // Security misconfiguration as default for security findings
    ai: 'A03:2021',        // Injection for AI findings
    logic: 'A04:2021',     // Insecure design for business logic findings
    api: 'A07:2021',       // Auth failures for API findings
    qa: null,              // QA findings may not map to OWASP
};

// ═══════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════

/**
 * Look up the OWASP category for a given finding.
 * Returns { id, name } or null if no mapping found.
 */
export function classifyFinding(finding) {
    const text = `${finding.title} ${finding.description || ''}`;

    // Try pattern matching first (most specific)
    for (const rule of MAPPING_RULES) {
        if (rule.pattern.test(text)) {
            const cat = OWASP_TOP_10.find(c => c.id === rule.owasp);
            return { id: cat.id, name: cat.name };
        }
    }

    // Fall back to module-level mapping
    const fallbackId = MODULE_FALLBACK[finding.module];
    if (fallbackId) {
        const cat = OWASP_TOP_10.find(c => c.id === fallbackId);
        return { id: cat.id, name: cat.name };
    }

    return null;
}

/**
 * Enrich a finding with its OWASP classification.
 * Adds `owasp` field: { id: 'A03:2021', name: 'Injection' }
 */
export function tagFinding(finding) {
    finding.owasp = classifyFinding(finding);
    return finding;
}

/**
 * Generate a compliance status for all OWASP Top 10 categories.
 *
 * @param {Array} findings - Array of findings (should already have `owasp` field)
 * @returns {Object} - { score, total, categories: [ { id, name, status, findings, ... } ] }
 */
export function getComplianceStatus(findings) {
    const categories = OWASP_TOP_10.map(cat => {
        const matched = findings.filter(f => f.owasp?.id === cat.id);
        const criticalOrHigh = matched.filter(f => f.severity === 'critical' || f.severity === 'high');

        return {
            id: cat.id,
            name: cat.name,
            description: cat.description,
            status: matched.length === 0 ? 'pass' : criticalOrHigh.length > 0 ? 'fail' : 'warn',
            findingsCount: matched.length,
            criticalCount: matched.filter(f => f.severity === 'critical').length,
            highCount: matched.filter(f => f.severity === 'high').length,
            mediumCount: matched.filter(f => f.severity === 'medium').length,
            lowCount: matched.filter(f => f.severity === 'low').length,
            infoCount: matched.filter(f => f.severity === 'info').length,
            findings: matched,
        };
    });

    const passing = categories.filter(c => c.status === 'pass').length;

    return {
        framework: 'OWASP Top 10 (2021)',
        score: passing,
        total: OWASP_TOP_10.length,
        percentage: Math.round((passing / OWASP_TOP_10.length) * 100),
        categories,
    };
}

export default { OWASP_TOP_10, classifyFinding, tagFinding, getComplianceStatus };
