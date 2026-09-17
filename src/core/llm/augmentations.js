/**
 * LLM augmentations — task-specific helpers built on top of LLMClient.
 *
 * Every function here is STRICTLY ADDITIVE: it returns null on any failure (no
 * client, disabled, budget exhausted, parse error) so callers fall back to their
 * deterministic behavior. Each function applies DATA MINIMIZATION — it sends the
 * smallest useful slice of data for its task, never raw target dumps or secrets.
 */

const SYSTEM_BASE =
    'You are a security engineering assistant embedded in the VIBE SHIELD scanner. ' +
    'Be precise, terse, and factual. Never fabricate findings.';

/** Extract the first JSON value (object or array) from a model response. */
function parseJsonLoose(text) {
    if (!text || typeof text !== 'string') return null;
    // Strip code fences if present.
    const cleaned = text.replace(/```(?:json)?/gi, '').trim();
    try {
        return JSON.parse(cleaned);
    } catch {
        /* fall through to bracket scan */
    }
    const start = cleaned.search(/[[{]/);
    if (start === -1) return null;
    const open = cleaned[start];
    const close = open === '{' ? '}' : ']';
    const end = cleaned.lastIndexOf(close);
    if (end <= start) return null;
    try {
        return JSON.parse(cleaned.slice(start, end + 1));
    } catch {
        return null;
    }
}

function snippet(str, n = 400) {
    if (!str) return '';
    const s = typeof str === 'string' ? str : JSON.stringify(str);
    return s.length > n ? s.slice(0, n) + '…' : s;
}

/**
 * Phase 0 — Framework-specific remediation for a single finding.
 * Data sent: title, module, severity, description (no raw target bodies).
 */
export async function enhanceRemediation(llmClient, finding) {
    if (!llmClient?.isEnabled?.()) return null;

    const prompt =
        `Provide concise, actionable remediation for this web/AI security finding. ` +
        `Prefer concrete, framework-specific fixes (name the framework only if implied by the finding). ` +
        `Plain text, max ~120 words, no preamble.\n\n` +
        `Title: ${finding.title}\n` +
        `Module: ${finding.module}\n` +
        `Severity: ${finding.severity}\n` +
        `Description: ${snippet(finding.description, 600)}`;

    const text = await llmClient.ask({ system: SYSTEM_BASE, prompt, maxTokens: 300, temperature: 0 });
    const out = text && text.trim();
    return out ? out : null;
}

/**
 * Phase 2 — Triage / false-positive assessment for a borderline finding.
 * Data sent: title, severity, description, short evidence snippet.
 * Returns { assessment, confidence, note, source } or null. Advisory only —
 * never changes the deterministic severity.
 */
export async function triageFinding(llmClient, finding) {
    if (!llmClient?.isEnabled?.()) return null;

    const prompt =
        `Assess whether this scanner finding is likely a TRUE positive or a FALSE positive. ` +
        `Consider typical false-positive patterns. Respond with ONLY JSON: ` +
        `{"assessment":"true_positive|false_positive|uncertain","confidence":0.0-1.0,"note":"<=160 chars"}.\n\n` +
        `Title: ${finding.title}\n` +
        `Severity: ${finding.severity}\n` +
        `Description: ${snippet(finding.description, 500)}\n` +
        `Evidence: ${snippet(finding.evidence, 400)}`;

    const text = await llmClient.ask({ system: SYSTEM_BASE, prompt, maxTokens: 160, temperature: 0 });
    const json = parseJsonLoose(text);
    if (!json || !json.assessment) return null;
    const confidence = Number(json.confidence);
    return {
        assessment: String(json.assessment),
        confidence: Number.isFinite(confidence) ? Math.max(0, Math.min(1, confidence)) : null,
        note: json.note ? String(json.note).slice(0, 200) : '',
        source: 'llm',
    };
}

/**
 * Phase 2 — Enrich an attack-chain correlation narrative.
 * Data sent: correlation title + existing narrative (already derived, no raw data).
 */
export async function enrichCorrelation(llmClient, correlation) {
    if (!llmClient?.isEnabled?.()) return null;

    const prompt =
        `Improve this attack-chain narrative for a security report. Keep it factual and concrete, ` +
        `explain WHY the combination is exploitable and the realistic impact. Plain text, <=100 words.\n\n` +
        `Title: ${correlation.title}\n` +
        `Current narrative: ${snippet(correlation.narrative, 600)}`;

    const text = await llmClient.ask({ system: SYSTEM_BASE, prompt, maxTokens: 240, temperature: 0 });
    const out = text && text.trim();
    return out ? out : null;
}

/**
 * Phase 2 — Natural-language executive summary.
 * Data sent: severity counts, target, finding TITLES only (no bodies/evidence).
 */
export async function generateExecutiveSummary(llmClient, { target, summary, topTitles = [], correlationTitles = [] }) {
    if (!llmClient?.isEnabled?.()) return null;

    const prompt =
        `Write a brief executive summary (<=150 words) of this security scan for a technical leader. ` +
        `State overall risk posture and the most important themes. No markdown headings, plain paragraphs.\n\n` +
        `Target: ${target}\n` +
        `Counts: ${JSON.stringify(summary)}\n` +
        `Top findings: ${topTitles.slice(0, 12).map(t => `- ${t}`).join('\n')}\n` +
        (correlationTitles.length ? `Attack chains: ${correlationTitles.slice(0, 6).join('; ')}` : '');

    const text = await llmClient.ask({ system: SYSTEM_BASE, prompt, maxTokens: 320, temperature: 0 });
    const out = text && text.trim();
    return out ? out : null;
}

/**
 * Phase 1 — Generate context-aware prompt-injection/jailbreak payloads tailored
 * to an extracted system prompt.
 * Data sent: a snippet of the (already-leaked) system prompt + the target URL host.
 * Returns array of { name, category, payload, marker, destructive } or null.
 */
export async function generateInjectionPayloads(llmClient, { systemPrompt, surfaceUrl, allowDestructive = false, max = 6 }) {
    if (!llmClient?.isEnabled?.()) return null;

    const prompt =
        `An AI endpoint leaked (part of) its system prompt. Craft up to ${max} prompt-injection / jailbreak ` +
        `test payloads tailored to bypass THIS system prompt's specific guardrails. ` +
        `${allowDestructive
            ? 'You MAY include payloads that attempt to trigger state-changing/tool actions.'
            : 'Do NOT include payloads that attempt destructive or state-changing actions; detection-only.'} ` +
        `Each payload must instruct the model to emit a unique uppercase canary marker so success is detectable. ` +
        `Respond with ONLY a JSON array of objects: ` +
        `{"name":"...","category":"role_override|instruction_override|jailbreak|delimiter_escape|encoding_bypass","payload":"...","marker":"CANARY_TOKEN","destructive":false}.\n\n` +
        `Target host: ${(() => { try { return new URL(surfaceUrl).host; } catch { return 'unknown'; } })()}\n` +
        `Leaked system prompt (snippet): ${snippet(systemPrompt, 800)}`;

    const text = await llmClient.ask({ system: SYSTEM_BASE, prompt, maxTokens: 900, temperature: 0 });
    const json = parseJsonLoose(text);
    if (!Array.isArray(json)) return null;

    const seen = new Set();
    const out = [];
    for (const p of json) {
        if (!p || typeof p.payload !== 'string' || !p.payload.trim()) continue;
        const key = p.payload.trim();
        if (seen.has(key)) continue;
        seen.add(key);
        const destructive = !!p.destructive;
        if (destructive && !allowDestructive) continue; // safety gate (also enforced by caller)
        out.push({
            name: String(p.name || 'LLM-generated payload').slice(0, 120),
            category: String(p.category || 'instruction_override'),
            payload: key,
            marker: p.marker ? String(p.marker).slice(0, 64) : null,
            destructive,
        });
        if (out.length >= max) break;
    }
    return out.length ? out : null;
}

/**
 * Phase 3 — Augment business-domain inference.
 * Data sent: discovered URL paths + form field names only (no values, no bodies).
 * Returns { domains: [{name, urls?}], invariants: [string] } or null.
 */
export async function inferBusinessDomains(llmClient, { paths = [], formFields = [] }) {
    if (!llmClient?.isEnabled?.()) return null;

    const prompt =
        `Given these URL paths and form field names from a web app, infer business domains beyond simple ` +
        `keyword matching (e.g. payments, auth, subscriptions, inventory, referrals, workflows, messaging, kyc) ` +
        `and propose security-relevant business invariants worth testing. ` +
        `Respond with ONLY JSON: {"domains":["..."],"invariants":["..."]}.\n\n` +
        `Paths: ${JSON.stringify(paths.slice(0, 60))}\n` +
        `Form fields: ${JSON.stringify(formFields.slice(0, 60))}`;

    const text = await llmClient.ask({ system: SYSTEM_BASE, prompt, maxTokens: 400, temperature: 0 });
    const json = parseJsonLoose(text);
    if (!json) return null;
    return {
        domains: Array.isArray(json.domains) ? json.domains.map(String).slice(0, 20) : [],
        invariants: Array.isArray(json.invariants) ? json.invariants.map(String).slice(0, 20) : [],
    };
}

export default {
    enhanceRemediation,
    triageFinding,
    enrichCorrelation,
    generateExecutiveSummary,
    generateInjectionPayloads,
    inferBusinessDomains,
};
