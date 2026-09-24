import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { getVersion } from '../utils/version.js';
import { normalizeVerification } from '../utils/finding.js';

/**
 * SARIF Generator — Generates Static Analysis Results Interchange Format (SARIF) v2.1.0
 * for integration with GitHub Security Dashboard, GitLab SAST, and Azure DevOps.
 */

/** CWE mapping for common finding patterns */
const CWE_MAP = {
    xss: { id: 'CWE-79', name: 'Cross-site Scripting (XSS)' },
    sqli: { id: 'CWE-89', name: 'SQL Injection' },
    nosqli: { id: 'CWE-943', name: 'NoSQL Injection' },
    csrf: { id: 'CWE-352', name: 'Cross-Site Request Forgery' },
    idor: { id: 'CWE-639', name: 'Authorization Bypass Through User-Controlled Key' },
    ssrf: { id: 'CWE-918', name: 'Server-Side Request Forgery' },
    'open redirect': { id: 'CWE-601', name: 'URL Redirection to Untrusted Site' },
    'missing header': { id: 'CWE-693', name: 'Protection Mechanism Failure' },
    hsts: { id: 'CWE-319', name: 'Cleartext Transmission of Sensitive Information' },
    csp: { id: 'CWE-1021', name: 'Improper Restriction of Rendered UI Layers' },
    cors: { id: 'CWE-942', name: 'Overly Permissive Cross-domain Whitelist' },
    tls: { id: 'CWE-295', name: 'Improper Certificate Validation' },
    jwt: { id: 'CWE-347', name: 'Improper Verification of Cryptographic Signature' },
    'api key': { id: 'CWE-312', name: 'Cleartext Storage of Sensitive Information' },
    secret: { id: 'CWE-798', name: 'Use of Hard-coded Credentials' },
    'prompt injection': { id: 'CWE-77', name: 'Command Injection' },
    'race condition': { id: 'CWE-362', name: 'Concurrent Execution Using Shared Resource' },
    'access control': { id: 'CWE-284', name: 'Improper Access Control' },
    'file upload': { id: 'CWE-434', name: 'Unrestricted Upload of File with Dangerous Type' },
    'path traversal': { id: 'CWE-22', name: 'Path Traversal' },
    graphql: { id: 'CWE-200', name: 'Exposure of Sensitive Information' },
    'rate limit': { id: 'CWE-307', name: 'Improper Restriction of Excessive Authentication Attempts' },
    websocket: { id: 'CWE-306', name: 'Missing Authentication for Critical Function' },
    password: { id: 'CWE-521', name: 'Weak Password Requirements' },
    mfa: { id: 'CWE-308', name: 'Use of Single-factor Authentication' },
    session: { id: 'CWE-614', name: 'Sensitive Cookie Without Secure Flag' },
    oauth: { id: 'CWE-346', name: 'Origin Validation Error' },
    'pricing': { id: 'CWE-20', name: 'Improper Input Validation' },
    'workflow': { id: 'CWE-841', name: 'Improper Enforcement of Behavioral Workflow' },
    'abuse': { id: 'CWE-799', name: 'Improper Control of Interaction Frequency' },
};

const SEVERITY_TO_SARIF = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note',
    info: 'note',
};

/**
 * Generate SARIF v2.1.0 report from VIBE SHIELD findings.
 */
export function generateSARIF(findings, meta = {}) {
    const rules = [];
    const results = [];
    const ruleIndex = new Map();

    for (const finding of findings) {
        const verification = finding.verification || normalizeVerification(null, finding);
        // Build rule ID
        const ruleId = finding.id || `VIBE SHIELD-${finding.module?.toUpperCase()}-0000`;

        if (!ruleIndex.has(ruleId)) {
            ruleIndex.set(ruleId, rules.length);

            const cwe = _matchCWE(finding);
            const rule = {
                id: ruleId,
                name: finding.title?.replace(/[^a-zA-Z0-9]/g, '') || 'Unknown',
                shortDescription: { text: finding.title || 'Unknown finding' },
                fullDescription: { text: finding.description || finding.title || '' },
                defaultConfiguration: { level: SEVERITY_TO_SARIF[finding.severity] || 'note' },
                helpUri: finding.references?.[0] || 'https://owasp.org/www-project-top-ten/',
                properties: {
                    tags: [finding.module || 'security', finding.severity],
                    precision: verification.level === 'confirmed' ? 'very-high' : verification.level === 'high_confidence' ? 'high' : verification.level === 'potential' ? 'medium' : 'low',
                    'security-severity': _cvssFromSeverity(finding.severity),
                },
            };

            if (cwe) {
                rule.properties.tags.push(`external/cwe/${cwe.id.replace('CWE-', '')}`);
                rule.relationships = [{
                    target: { id: cwe.id, toolComponent: { name: 'CWE' } },
                    kinds: ['superset'],
                }];
            }

            rules.push(rule);
        }

        // Represent the affected surface as a proper absolute web URI rather
        // than anchoring it to the source tree (no %SRCROOT%), so GitHub does
        // not try to map DAST URLs to repository files.
        const webUri = _toWebUri(finding.affected_surface || meta.target);

        // Build result
        const result = {
            ruleId,
            ruleIndex: ruleIndex.get(ruleId),
            level: SEVERITY_TO_SARIF[finding.severity] || 'note',
            message: { text: finding.description || finding.title },
            locations: [{
                physicalLocation: {
                    artifactLocation: {
                        uri: webUri,
                    },
                },
            }],
            // Stable per-result fingerprint so GitHub can track findings across
            // runs (derived from module + normalized title + affected surface).
            partialFingerprints: {
                'vibe-shieldFindingHash/v1': _fingerprint(finding),
            },
            properties: {
                severity: finding.severity,
                module: finding.module,
                status: finding.status || 'open',
                timestamp: finding.timestamp || new Date().toISOString(),
                affectedUrl: finding.affected_surface || meta.target || null,
                verificationLevel: verification.level,
                verificationLabel: verification.label,
                verificationMethod: verification.method,
                verificationReason: verification.reason,
                evidenceGaps: verification.missingEvidence,
            },
        };

        // Describe the tested surface as a SARIF webRequest where we can, which
        // signals to consumers that this is a dynamic (DAST) finding.
        const webRequest = _toWebRequest(finding.affected_surface || meta.target);
        if (webRequest) {
            result.webRequest = webRequest;
        }

        if (finding.remediation) {
            result.fixes = [{ description: { text: finding.remediation } }];
        }

        if (finding.evidence) {
            result.codeFlows = [{
                message: { text: 'Evidence' },
                threadFlows: [{
                    locations: [{
                        location: {
                            message: { text: typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence) },
                            physicalLocation: {
                                artifactLocation: { uri: webUri },
                            },
                        },
                    }],
                }],
            }];
        }

        if (Object.keys(verification.proof || {}).length > 1) {
            result.attachments = [{
                description: { text: `VIBE SHIELD verification proof (${verification.label})` },
                artifactLocation: { uri: webUri },
                properties: { proof: verification.proof },
            }];
        }

        results.push(result);
    }

    const sarif = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
            tool: {
                driver: {
                    name: 'VIBE SHIELD',
                    version: meta.version || getVersion(),
                    semanticVersion: meta.version || getVersion(),
                    informationUri: 'https://github.com/Aaravkhanal/vibe-shield',
                    rules,
                },
            },
            results,
            invocations: [{
                executionSuccessful: true,
                startTimeUtc: meta.scannedAt || new Date().toISOString(),
            }],
        }],
    };

    return sarif;
}

/**
 * Write SARIF to file.
 */
export function writeSARIF(findings, outputDir, meta = {}) {
    const sarif = generateSARIF(findings, meta);
    const sarifPath = path.join(outputDir, 'report.sarif');
    fs.writeFileSync(sarifPath, JSON.stringify(sarif, null, 2), 'utf-8');
    return sarifPath;
}

/**
 * Normalize an affected surface into a clean absolute web URI.
 * Falls back to a stable placeholder when it isn't a parseable URL.
 */
function _toWebUri(surface) {
    if (!surface) return 'urn:vibe-shield:unknown-surface';
    try {
        const u = new URL(surface);
        return u.toString();
    } catch {
        // Not a URL (e.g. a file path or descriptive surface) — keep it as a
        // logical identifier so GitHub doesn't treat it as a source artifact.
        return `urn:vibe-shield:surface:${encodeURIComponent(String(surface))}`;
    }
}

/**
 * Build a minimal SARIF webRequest object for a tested URL, when possible.
 */
function _toWebRequest(surface) {
    if (!surface) return null;
    try {
        const u = new URL(surface);
        return {
            protocol: u.protocol.replace(':', ''),
            target: u.toString(),
            method: 'GET',
        };
    } catch {
        return null;
    }
}

/**
 * Derive a stable fingerprint for cross-run finding tracking.
 * Based on module + normalized title + affected surface (host + path only,
 * so transient query values don't churn the hash between runs).
 */
function _fingerprint(finding) {
    const module = (finding.module || 'security').toLowerCase();
    const title = (finding.title || '')
        .toLowerCase()
        .replace(/\s+/g, ' ')
        .trim();

    let surface = finding.affected_surface || '';
    try {
        const u = new URL(surface);
        surface = `${u.origin}${u.pathname}`;
    } catch {
        // leave non-URL surfaces as-is
    }

    const basis = `${module}|${title}|${surface.toLowerCase()}`;
    return crypto.createHash('sha256').update(basis).digest('hex');
}

/**
 * Match a finding to a CWE based on title/description patterns.
 */
function _matchCWE(finding) {
    const text = `${finding.title} ${finding.description}`.toLowerCase();
    for (const [pattern, cwe] of Object.entries(CWE_MAP)) {
        if (text.includes(pattern)) return cwe;
    }
    return null;
}

/**
 * Map VIBE SHIELD severity to CVSS-like numeric score.
 */
function _cvssFromSeverity(severity) {
    const map = { critical: '9.8', high: '7.5', medium: '5.0', low: '2.5', info: '0.0' };
    return map[severity] || '0.0';
}

export default { generateSARIF, writeSARIF };
