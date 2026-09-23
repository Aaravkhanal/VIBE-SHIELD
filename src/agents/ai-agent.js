import { BaseAgent } from './base-agent.js';
import { allows, getSafetyMode } from '../utils/safety.js';
import { generateInjectionPayloads } from '../core/llm/augmentations.js';
import { AIEndpointDetector } from '../core/ai/ai-endpoint-detector.js';
import { PromptInjector } from '../core/ai/prompt-injector.js';
import { JailbreakTester } from '../core/ai/jailbreak-tester.js';
import { SystemPromptExtractor } from '../core/ai/system-prompt-extractor.js';
import { OutputAnalyzer } from '../core/ai/output-analyzer.js';
import { GuardrailProber } from '../core/ai/guardrail-prober.js';
import { ModelDoSTester } from '../core/ai/model-dos-tester.js';
import { IndirectInjector } from '../core/ai/indirect-injector.js';

/**
 * VIBE-SHIELD-AI — Prompt Injection & AI Abuse Detection Agent
 * 
 * Pipeline:
 * 1. Detect AI endpoints (auto-discovery from surface inventory)
 * 2. Prompt Injection testing (24 payloads)
 * 3. Jailbreak testing (16 techniques)
 * 4. System Prompt Extraction (17 techniques)
 * 5. Output Analysis (AI-mediated XSS)
 * 6. Guardrail Probing (PII, agency, tool abuse)
 * 7. Model DoS Testing (context bombing, token loops)
 * 8. Indirect Injection Testing (6 embedded payloads)
 * 
 * Dependencies: VIBE-SHIELD-CRAWL (runs in Wave 2, parallel with QA + SEC)
 */
export class AIAgent extends BaseAgent {
    get name() { return 'VIBE-SHIELD-AI'; }
    get dependencies() { return ['VIBE-SHIELD-CRAWL']; }

    async _execute(context) {
        const { config, logger, surfaceInventory } = context;

        if (!surfaceInventory) {
            throw new Error('No surface inventory available — VIBE-SHIELD-CRAWL must run first');
        }

        // AI endpoint detection and abuse testing send live requests (benign
        // probes + injection payloads), so they require at least safe-active.
        if (!allows(config, 'safe-active')) {
            this.assessment = 'not_assessed';
            this._log(`AI abuse testing skipped — requires active probing (current: ${getSafetyMode(config)} mode)`);
            this.progress('complete', 'AI testing skipped (passive mode)', 100);
            return;
        }

        // Phase 1: Detect AI endpoints
        this.progress('detect', 'Detecting AI-powered endpoints...', 0);

        const detector = new AIEndpointDetector(logger);
        const aiSurfaces = await detector.detect(surfaceInventory);

        this._log(`Detected ${aiSurfaces.length} AI surfaces (${aiSurfaces.filter(s => s.confidence === 'confirmed').length} confirmed)`);
        this.progress('detect', `Found ${aiSurfaces.length} AI endpoints`, 10);

        if (aiSurfaces.length === 0) {
            this.assessment = 'not_assessed';
            this._log('No AI endpoints detected — skipping AI abuse tests');
            this.progress('complete', 'No AI endpoints found — scan skipped', 100);
            return;
        }

        // Create shared sendMessage function for sub-modules
        const injector = new PromptInjector(logger);
        const sendMessage = injector._sendMessage.bind(injector);

        // Phase 2: Prompt Injection
        this.progress('injection', 'Testing for prompt injection...', 15);
        try {
            const injectionFindings = await injector.inject(aiSurfaces);
            this.addFindings(injectionFindings);
            this._log(`Prompt injection: ${injectionFindings.length} vulnerabilities`);
        } catch (err) {
            this._log(`Prompt injection testing failed: ${err.message}`, 'error');
        }
        this.progress('injection', 'Prompt injection testing complete', 30);

        // Phase 3: Jailbreak Testing
        this.progress('jailbreak', 'Testing jailbreak techniques...', 30);
        try {
            const tester = new JailbreakTester(logger);
            const jailbreakFindings = await tester.test(aiSurfaces, sendMessage);
            this.addFindings(jailbreakFindings);
            this._log(`Jailbreak: ${jailbreakFindings.length} vulnerabilities`);
        } catch (err) {
            this._log(`Jailbreak testing failed: ${err.message}`, 'error');
        }
        this.progress('jailbreak', 'Jailbreak testing complete', 50);

        // Phase 4: System Prompt Extraction
        this.progress('extraction', 'Attempting system prompt extraction...', 50);
        let extractionFindings = [];
        try {
            const extractor = new SystemPromptExtractor(logger);
            extractionFindings = await extractor.extract(aiSurfaces, sendMessage);
            this.addFindings(extractionFindings);
            this._log(`System prompt extraction: ${extractionFindings.length} leaks`);
        } catch (err) {
            this._log(`System prompt extraction failed: ${err.message}`, 'error');
        }
        this.progress('extraction', 'System prompt extraction complete', 70);

        // Phase 4.5: LLM-generated, context-aware injection payloads (optional).
        // Only runs when LLM augmentation is active (egress is auto-disabled in
        // passive mode). Generated DESTRUCTIVE payloads require --aggressive;
        // non-destructive generated probes need safe-active (already satisfied).
        const llmClient = context.llmClient;
        if (llmClient?.isEnabled?.()) {
            try {
                // Reuse the (already-leaked) system prompt as generation context.
                const leaked = extractionFindings
                    .map(f => {
                        const m = /Extracted content:\n([\s\S]*)/.exec(f.evidence || '');
                        return m ? m[1].trim() : '';
                    })
                    .filter(Boolean)[0] || '';

                if (leaked) {
                    const allowDestructive = allows(config, 'aggressive');
                    const generated = await generateInjectionPayloads(llmClient, {
                        systemPrompt: leaked,
                        surfaceUrl: aiSurfaces[0]?.url || config.target_url,
                        allowDestructive,
                    });
                    if (generated?.length) {
                        const genFindings = await injector.injectGenerated(aiSurfaces, generated, { allowDestructive });
                        this.addFindings(genFindings);
                        this._log(`LLM-generated payloads: ${genFindings.length} findings from ${generated.length} tailored payloads`);
                    }
                } else {
                    this._log('No leaked system prompt — skipping LLM payload generation');
                }
            } catch (err) {
                this._log(`LLM payload generation failed: ${err.message}`, 'error');
            }
        }

        // Phase 5: Output Analysis (AI-mediated XSS)
        this.progress('output', 'Analyzing AI output sanitization...', 70);
        try {
            const analyzer = new OutputAnalyzer(logger);
            const outputFindings = await analyzer.analyze(aiSurfaces, sendMessage);
            this.addFindings(outputFindings);
            this._log(`Output analysis: ${outputFindings.length} issues`);
        } catch (err) {
            this._log(`Output analysis failed: ${err.message}`, 'error');
        }
        this.progress('output', 'Output analysis complete', 85);

        // Phase 6: Guardrail Probing
        this.progress('guardrails', 'Probing AI guardrails...', 85);
        try {
            const prober = new GuardrailProber(logger);
            const guardrailFindings = await prober.probe(aiSurfaces, sendMessage);
            this.addFindings(guardrailFindings);
            this._log(`Guardrails: ${guardrailFindings.length} bypasses`);
        } catch (err) {
            this._log(`Guardrail probing failed: ${err.message}`, 'error');
        }
        this.progress('guardrails', 'Guardrail probing complete', 80);

        // Phase 7: Model DoS
        this.progress('dos', 'Testing model DoS vectors...', 80);
        try {
            const dosTester = new ModelDoSTester(logger);
            const dosFindings = await dosTester.test(aiSurfaces, sendMessage);
            this.addFindings(dosFindings);
            this._log(`Model DoS: ${dosFindings.length} issues`);
        } catch (err) {
            this._log(`Model DoS testing failed: ${err.message}`, 'error');
        }
        this.progress('dos', 'Model DoS testing complete', 90);

        // Phase 8: Indirect Injection
        this.progress('indirect', 'Testing indirect prompt injection...', 90);
        try {
            const indirectInjector = new IndirectInjector(logger);
            const indirectFindings = await indirectInjector.test(aiSurfaces, sendMessage);
            this.addFindings(indirectFindings);
            this._log(`Indirect injection: ${indirectFindings.length} vulnerabilities`);
        } catch (err) {
            this._log(`Indirect injection testing failed: ${err.message}`, 'error');
        }
        this.progress('indirect', 'Indirect injection testing complete', 100);

        this.progress('complete', `AI scan complete — ${this._findings.length} total findings`, 100);
    }
}

export default AIAgent;
