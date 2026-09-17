import { BaseLLMProvider } from './base-provider.js';

/**
 * NullProvider — No-op provider used when LLM augmentation is disabled or for
 * tests. Always returns null text so every consumer degrades gracefully to its
 * deterministic, non-LLM behavior.
 */
export class NullProvider extends BaseLLMProvider {
    constructor(opts = {}) {
        // Allow direct instantiation (it's the safe default).
        super({ ...opts, apiKey: null });
    }

    get name() { return 'null'; }

    async complete() {
        return { text: null, usage: { total_tokens: 0 } };
    }
}

export default NullProvider;
