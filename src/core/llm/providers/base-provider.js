/**
 * BaseLLMProvider — Abstract interface for LLM provider adapters.
 *
 * Mirrors the abstract-base pattern used by BaseAgent: subclasses MUST implement
 * `name` and `complete()`. Providers are thin HTTP adapters built on the
 * Node ≥20 global `fetch` — no third-party SDKs.
 */
export class BaseLLMProvider {
    constructor({ apiKey, model, baseUrl, logger } = {}) {
        if (new.target === BaseLLMProvider) {
            throw new Error('BaseLLMProvider is abstract — extend it, do not instantiate directly.');
        }
        // The API key is held only in this adapter instance for the duration of
        // the scan. It is NEVER written to config, logs, reports, or findings.
        this._apiKey = apiKey || null;
        this.model = model || null;
        this.baseUrl = baseUrl || null;
        this.logger = logger || null;
    }

    /** Provider display name (e.g. "openai"). Must be overridden. */
    get name() { throw new Error('Provider must define a name'); }

    /**
     * Perform a single completion.
     * @param {object} req
     * @param {string} req.system   - system instruction
     * @param {string} req.prompt   - user prompt
     * @param {number} req.maxTokens - max output tokens
     * @param {number} req.temperature
     * @param {AbortSignal} req.signal
     * @returns {Promise<{text: string|null, usage: {total_tokens: number}}>}
     */
    async complete(_req) {
        throw new Error(`${this.name} must implement complete()`);
    }

    /** Build an Error carrying an HTTP status so the client can branch (e.g. 429). */
    _httpError(status, label) {
        return Object.assign(new Error(`${this.name} API error: ${label || status}`), { status });
    }
}

export default BaseLLMProvider;
