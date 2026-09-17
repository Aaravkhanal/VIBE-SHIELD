import { BaseLLMProvider } from './base-provider.js';

/**
 * OpenAIProvider — Adapter for the OpenAI Chat Completions API.
 * Uses the built-in global fetch (Node ≥20). No SDK dependency.
 */
export class OpenAIProvider extends BaseLLMProvider {
    get name() { return 'openai'; }

    async complete({ system, prompt, maxTokens = 1024, temperature = 0, signal } = {}) {
        const base = (this.baseUrl || 'https://api.openai.com/v1').replace(/\/$/, '');
        const url = `${base}/chat/completions`;

        const messages = [];
        if (system) messages.push({ role: 'system', content: system });
        messages.push({ role: 'user', content: prompt });

        const res = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${this._apiKey}`,
            },
            body: JSON.stringify({
                model: this.model,
                temperature,
                max_tokens: maxTokens,
                messages,
            }),
            signal,
        });

        if (!res.ok) {
            // Drain body without surfacing it (it may echo request data); never log keys.
            await res.text().catch(() => '');
            throw this._httpError(res.status, res.statusText);
        }

        const json = await res.json();
        const text = json?.choices?.[0]?.message?.content ?? null;
        const total = json?.usage?.total_tokens
            ?? ((json?.usage?.prompt_tokens || 0) + (json?.usage?.completion_tokens || 0));
        return { text, usage: { total_tokens: total || 0 } };
    }
}

export default OpenAIProvider;
