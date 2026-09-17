import { createFinding } from '../../utils/finding.js';

/**
 * AIEndpointDetector — Discovers LLM-backed endpoints in the target application.
 * 
 * Detection methods:
 * 1. URL pattern matching (/chat, /ask, /prompt, /complete, /generate, /ai)
 * 2. Response heuristics: prose responses, markdown, high latency (LLM inference)
 * 3. Form detection: textareas that POST to JSON APIs
 * 4. Content-Type analysis: streaming responses (text/event-stream)
 */
export class AIEndpointDetector {
    constructor(logger) {
        this.logger = logger;

        // URL patterns that indicate AI/LLM endpoints
        this.AI_PATH_PATTERNS = [
            /\/chat/i, /\/ask/i, /\/prompt/i, /\/complet/i, /\/generat/i,
            /\/ai\b/i, /\/llm/i, /\/openai/i, /\/anthropic/i, /\/claude/i,
            /\/gpt/i, /\/copilot/i, /\/assistant/i, /\/convers/i,
            /\/message/i, /\/query/i, /\/answer/i, /\/predict/i,
            /\/inference/i, /\/embed/i, /\/summariz/i, /\/translat/i,
        ];

        // Response indicators of LLM output
        this.LLM_RESPONSE_INDICATORS = [
            /as an ai/i,
            /i'm an ai/i,
            /i cannot|i can't/i,
            /as a language model/i,
            /i'd be happy to/i,
            /here'?s (a|an|the|my|what)/i,
            /\*\*[A-Z].*\*\*/,            // Markdown bold headers typical of LLMs
            /^\d+\.\s+\*\*/m,              // Numbered lists with bold (GPT-style)
            /```[\w]*\n/,                   // Code blocks in response
        ];
    }

    /**
     * Detect AI-facing endpoints from the surface inventory.
     * Returns an array of detected AI surfaces.
     */
    async detect(surfaceInventory) {
        const aiSurfaces = [];
        const seenApiUrls = new Set();

        // 1. Check discovered API endpoints.
        //    NOTE: the crawler emits `apiEndpoints` (not `apis`) — read the
        //    correct field so API-discovered surfaces are actually considered.
        const apis = surfaceInventory.apiEndpoints || surfaceInventory.apis || [];
        for (const api of apis) {
            const url = api.url || api;
            if (!url || seenApiUrls.has(url)) continue;

            const method = (api.method || 'POST').toUpperCase();
            const contentType = api.contentType || '';
            const matchesPattern = this._matchesAIPattern(url);
            // Non-GET or JSON endpoints are plausible LLM surfaces even when the
            // URL itself doesn't match a known AI path — they get probed below.
            const isJsonOrMutating =
                contentType.includes('application/json') ||
                (method !== 'GET' && method !== 'OPTIONS' && method !== 'HEAD');

            if (matchesPattern) {
                seenApiUrls.add(url);
                aiSurfaces.push({
                    type: 'api',
                    url,
                    method,
                    confidence: 'high',
                    reason: 'URL pattern matches known AI endpoint',
                });
            } else if (isJsonOrMutating) {
                seenApiUrls.add(url);
                aiSurfaces.push({
                    type: 'api',
                    url,
                    method,
                    confidence: 'low',
                    reason: 'Non-GET/JSON API endpoint — probing for LLM behavior',
                });
            }
        }

        // 2. Check page URLs and links for AI patterns
        const pages = surfaceInventory.pages || [];
        for (const page of pages) {
            const url = page.url || page;
            if (this._matchesAIPattern(url)) {
                aiSurfaces.push({
                    type: 'page',
                    url,
                    method: 'GET',
                    confidence: 'medium',
                    reason: 'Page URL matches AI endpoint pattern',
                });
            }
        }

        // 3. Check forms with textareas (likely chat inputs)
        const forms = surfaceInventory.forms || [];
        for (const form of forms) {
            const hasTextarea = (form.fields || []).some(f =>
                f.type === 'textarea' || f.tag === 'textarea'
            );
            const actionMatchesAI = form.action && this._matchesAIPattern(form.action);

            if (hasTextarea && actionMatchesAI) {
                aiSurfaces.push({
                    type: 'form',
                    url: form.action || form.pageUrl,
                    pageUrl: form.pageUrl,
                    method: form.method || 'POST',
                    fields: form.fields,
                    confidence: 'high',
                    reason: 'Form with textarea posting to AI endpoint',
                });
            } else if (hasTextarea) {
                aiSurfaces.push({
                    type: 'form',
                    url: form.action || form.pageUrl,
                    pageUrl: form.pageUrl,
                    method: form.method || 'POST',
                    fields: form.fields,
                    confidence: 'low',
                    reason: 'Form with textarea (potential AI input)',
                });
            }
        }

        // 4. Probe candidate endpoints with a benign message
        const probed = [];
        for (const surface of aiSurfaces) {
            if (surface.type === 'api' || (surface.type === 'form' && surface.confidence === 'high')) {
                const probeResult = await this._probeEndpoint(surface);
                if (probeResult) {
                    surface.confidence = 'confirmed';
                    surface.probeEvidence = probeResult;
                    probed.push(surface);
                } else {
                    probed.push(surface); // keep even unconfirmed
                }
            } else {
                probed.push(surface);
            }
        }

        this.logger?.info?.(`AI Endpoint Detector: found ${probed.length} potential AI surfaces (${probed.filter(s => s.confidence === 'confirmed').length} confirmed)`);
        return probed;
    }

    /**
     * Check if a URL matches known AI endpoint patterns.
     */
    _matchesAIPattern(url) {
        if (!url) return false;
        try {
            const path = new URL(url, 'http://localhost').pathname;
            return this.AI_PATH_PATTERNS.some(p => p.test(path));
        } catch {
            return this.AI_PATH_PATTERNS.some(p => p.test(url));
        }
    }

    /**
     * Probe an endpoint with a benign message to check for LLM-like responses.
     */
    async _probeEndpoint(surface) {
        try {
            const url = surface.url;
            const payloads = [
                { message: 'Hello, what can you help me with?' },
                { prompt: 'Hello, what can you help me with?' },
                { query: 'Hello, what can you help me with?' },
                { input: 'Hello, what can you help me with?' },
                { text: 'Hello, what can you help me with?' },
                { content: 'Hello, what can you help me with?' },
            ];

            for (const body of payloads) {
                try {
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 10000);

                    const startTime = Date.now();
                    const response = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body),
                        signal: controller.signal,
                    });
                    const latency = Date.now() - startTime;
                    clearTimeout(timeout);

                    if (!response.ok) continue;

                    const text = await response.text();

                    // Check for LLM response indicators
                    const isLLMResponse = this._isLLMResponse(text, latency);
                    if (isLLMResponse) {
                        return {
                            field: Object.keys(body)[0],
                            latency,
                            responseLength: text.length,
                            indicators: isLLMResponse,
                        };
                    }
                } catch {
                    continue;
                }
            }
            return null;
        } catch {
            return null;
        }
    }

    /**
     * Analyze response text and latency for LLM indicators.
     */
    _isLLMResponse(text, latency) {
        const indicators = [];

        // High latency (LLM inference typically > 500ms)
        if (latency > 500) {
            indicators.push(`High latency: ${latency}ms (likely LLM inference)`);
        }

        // Long prose response to short input
        if (text.length > 200) {
            indicators.push(`Long response: ${text.length} chars`);
        }

        // Check for LLM output patterns
        for (const pattern of this.LLM_RESPONSE_INDICATORS) {
            if (pattern.test(text)) {
                indicators.push(`Pattern match: ${pattern.source}`);
            }
        }

        // Streaming response format
        if (text.includes('data: {') || text.includes('"choices"')) {
            indicators.push('OpenAI-style streaming/response format detected');
        }

        return indicators.length >= 2 ? indicators : null;
    }
}

export default AIEndpointDetector;
