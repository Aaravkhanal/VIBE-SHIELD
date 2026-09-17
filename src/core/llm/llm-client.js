import { isPassive } from '../../utils/safety.js';
import { OpenAIProvider } from './providers/openai-provider.js';
import { AnthropicProvider } from './providers/anthropic-provider.js';
import { NullProvider } from './providers/null-provider.js';

/**
 * LLMClient — the single facade every consumer touches.
 *
 * Responsibilities:
 *   - Provider selection (openai | anthropic | null)
 *   - API key injection FROM ENV ONLY (never stored in config)
 *   - Enforce enablement + consent + safety-mode gating (egress disabled in passive)
 *   - Per-scan token + call budget, per-call timeout (AbortSignal.timeout)
 *   - Retry/backoff on 429, circuit-breaker on connection failure
 *   - Returns null whenever disabled/unavailable/over-budget so callers degrade
 *
 * Hard rule: ask() NEVER throws to callers and NEVER returns secrets. If the LLM
 * is not usable for any reason, it returns null and the caller keeps its
 * deterministic behavior.
 */

const PROVIDER_ENV = {
    openai: 'OPENAI_API_KEY',
    anthropic: 'ANTHROPIC_API_KEY',
};

const DEFAULT_MODELS = {
    openai: 'gpt-4o-mini',
    anthropic: 'claude-3-5-haiku-latest',
};

/**
 * Resolve the runtime LLM state from config + env. The returned `apiKey` (if
 * any) is for immediate provider construction only and is never persisted.
 */
function resolveLLMRuntime(config) {
    const llm = (config && config.llm) || {};
    const providerName = llm.provider || 'openai';
    const model = llm.model || DEFAULT_MODELS[providerName] || null;
    const envVar = PROVIDER_ENV[providerName];
    const apiKey = envVar ? process.env[envVar] : null;

    const base = { providerName, model, envVar };

    if (!llm.enabled) {
        return { ...base, enabled: false, reason: 'not enabled (set llm.enabled or pass --llm)' };
    }
    if (isPassive(config)) {
        return { ...base, enabled: false, reason: 'disabled in passive safety mode (no third-party egress)' };
    }
    if (!PROVIDER_ENV[providerName]) {
        return { ...base, enabled: false, reason: `unknown provider "${providerName}" (use openai|anthropic)` };
    }
    if (!llm.consent) {
        return { ...base, enabled: false, reason: 'no consent (set llm.consent=true or pass --llm-consent)' };
    }
    if (!apiKey) {
        return { ...base, enabled: false, reason: `no API key in env ${envVar}` };
    }
    return { ...base, enabled: true, reason: 'active', apiKey };
}

function createProvider(name, opts) {
    if (name === 'openai') return new OpenAIProvider(opts);
    if (name === 'anthropic') return new AnthropicProvider(opts);
    return new NullProvider(opts);
}

function isConnectionError(err) {
    const code = err?.cause?.code || err?.code;
    return ['ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNRESET', 'UND_ERR_CONNECT_TIMEOUT'].includes(code);
}

export class LLMClient {
    constructor(config, logger) {
        this.config = config || {};
        this.logger = logger || null;

        const llm = this.config.llm || {};
        this._maxCalls = Number.isFinite(llm.max_calls) ? llm.max_calls : 50;
        this._perCallTokens = Number.isFinite(llm.max_tokens) ? llm.max_tokens : 1024;
        this._tokenBudget = Number.isFinite(llm.token_budget) ? llm.token_budget : 100000;
        this._timeoutMs = (Number.isFinite(llm.timeout_seconds) ? llm.timeout_seconds : 30) * 1000;

        this._calls = 0;
        this._tokensUsed = 0;
        this._circuitOpen = false;
        this._warnedBudget = false;

        const runtime = resolveLLMRuntime(this.config);
        this.enabled = runtime.enabled;
        this.reason = runtime.reason;
        this.providerName = runtime.providerName;
        this.model = runtime.model;

        if (this.enabled) {
            this.provider = createProvider(runtime.providerName, {
                apiKey: runtime.apiKey,
                model: runtime.model,
                baseUrl: llm.base_url || null,
                logger,
            });
            // One-line consent/egress warning. Never logs the key.
            this.logger?.warn?.(
                `[LLM] Augmentation ENABLED via ${runtime.providerName}/${runtime.model}. ` +
                `Minimal finding/target data may be sent to a third-party API. ` +
                `Disable by removing --llm or setting llm.enabled=false.`
            );
        } else {
            this.provider = new NullProvider({ logger });
        }
    }

    /** True if a real provider is active. */
    isEnabled() {
        return this.enabled && !this._circuitOpen;
    }

    /** Human-readable one-line status (no secrets). */
    static describe(config) {
        const r = resolveLLMRuntime(config);
        if (r.enabled) return `enabled (${r.providerName}/${r.model})`;
        return `disabled — ${r.reason}`;
    }

    /** Per-scan usage snapshot (for logging, never includes keys). */
    usage() {
        return { calls: this._calls, tokensUsed: this._tokensUsed, circuitOpen: this._circuitOpen };
    }

    /**
     * Ask the LLM. Returns the completion text, or null on any disablement /
     * budget exhaustion / error. Never throws.
     */
    async ask({ system, prompt, maxTokens, temperature = 0 } = {}) {
        if (!this.enabled || this._circuitOpen || !prompt) return null;

        if (this._calls >= this._maxCalls || this._tokensUsed >= this._tokenBudget) {
            if (!this._warnedBudget) {
                this._warnedBudget = true;
                this.logger?.debug?.('[LLM] budget exhausted — further augmentation skipped');
            }
            return null;
        }

        const outTokens = Math.min(maxTokens || this._perCallTokens, this._perCallTokens);
        this._calls++;

        let attempt = 0;
        const maxAttempts = 2;
        while (attempt <= maxAttempts) {
            try {
                const res = await this.provider.complete({
                    system,
                    prompt,
                    maxTokens: outTokens,
                    temperature,
                    signal: AbortSignal.timeout(this._timeoutMs),
                });
                this._tokensUsed += res?.usage?.total_tokens || outTokens;
                return res?.text ?? null;
            } catch (err) {
                if (err?.status === 429 && attempt < maxAttempts) {
                    const backoff = 1000 * Math.pow(2, attempt);
                    await new Promise(r => setTimeout(r, backoff));
                    attempt++;
                    continue;
                }
                if (isConnectionError(err)) {
                    this._circuitOpen = true;
                    this.logger?.warn?.('[LLM] connection failure — disabling LLM augmentation for the remainder of this scan');
                    return null;
                }
                // Logger format redacts secrets; keep the message terse regardless.
                this.logger?.debug?.(`[LLM] call failed (${err?.status || err?.name || 'error'}) — degrading to deterministic behavior`);
                return null;
            }
        }
        return null;
    }
}

export { resolveLLMRuntime, PROVIDER_ENV, DEFAULT_MODELS };
export default LLMClient;
