import { BaseLLMProvider } from './base-provider.js';

/**
 * AnthropicProvider — Adapter for the Anthropic Messages API.
 * Uses the built-in global fetch (Node ≥20). No SDK dependency.
 */
export class AnthropicProvider extends BaseLLMProvider {
    get name() { return 'anthropic'; }

    async complete({ system, prompt, maxTokens = 1024, temperature = 0, signal } = {}) {
        const base = (this.baseUrl || 'https://api.anthropic.com/v1').replace(/\/$/, '');
        const url = `${base}/messages`;

        const res = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': this._apiKey,
                'anthropic-version': '2023-06-01',
            },
            body: JSON.stringify({
                model: this.model,
                max_tokens: maxTokens,
                temperature,
                system: system || undefined,
                messages: [{ role: 'user', content: prompt }],
            }),
            signal,
        });

        if (!res.ok) {
            await res.text().catch(() => '');
            throw this._httpError(res.status, res.statusText);
        }

        const json = await res.json();
        // content is an array of blocks; concatenate any text blocks.
        const text = Array.isArray(json?.content)
            ? json.content.filter(b => b?.type === 'text').map(b => b.text).join('').trim() || null
            : null;
        const total = (json?.usage?.input_tokens || 0) + (json?.usage?.output_tokens || 0);
        return { text, usage: { total_tokens: total } };
    }
}

export default AnthropicProvider;
