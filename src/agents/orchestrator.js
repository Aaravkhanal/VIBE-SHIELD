import { EventBus } from './event-bus.js';
import { FindingsLedger } from './findings-ledger.js';
import { getVersion } from '../utils/version.js';
import { LLMClient } from '../core/llm/llm-client.js';
import { enrichCorrelation, triageFinding } from '../core/llm/augmentations.js';

/**
 * Orchestrator — Central coordinator for the VIBE SHIELD multi-agent system.
 * 
 * Responsibilities:
 * 1. Register and manage agent lifecycle
 * 2. Resolve dependencies via topological sort
 * 3. Execute independent agents in parallel
 * 4. Provide shared context (config, logger, event bus, surface inventory)
 * 5. Synthesize final results (dedup, correlate, score)
 */
export class Orchestrator {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.eventBus = new EventBus();
        this.ledger = new FindingsLedger(this.eventBus);

        // Optional LLM augmentation client (default OFF). Constructed once and
        // shared with all agents via context so any agent can opt in. Returns
        // null on every call when disabled/unavailable → callers degrade.
        this.llmClient = new LLMClient(config, logger);

        this._agents = new Map();       // name → agent instance
        this._sharedContext = {         // passed to all agents
            config,
            logger,
            eventBus: this.eventBus,
            ledger: this.ledger,
            surfaceInventory: null,       // set by VIBE-SHIELD-CRAWL
            llmClient: this.llmClient,    // optional; null-equivalent when disabled
        };

        this._startTime = null;
        this._haltedOnCritical = false;
    }

    /**
     * Register an agent with the orchestrator.
     */
    register(agent) {
        if (this._agents.has(agent.name)) {
            this.logger?.warn?.(`Agent "${agent.name}" already registered, skipping`);
            return this;
        }
        this._agents.set(agent.name, agent);
        this.logger?.info?.(`Registered agent: ${agent.name}`);
        return this; // chainable
    }

    /**
     * Subscribe to orchestrator events.
     */
    on(event, handler) {
        this.eventBus.on(event, handler);
        return this;
    }

    /**
     * Run all registered agents with dependency resolution and parallel execution.
     */
    async run() {
        this._startTime = Date.now();
        const executionOrder = this._resolveExecutionOrder();

        this.eventBus.emit('scan:started', {
            timestamp: new Date().toISOString(),
            modules: [...this._agents.keys()],
        });

        this.logger?.info?.(`Orchestrator starting with ${this._agents.size} agents`);
        this.logger?.info?.(`Execution order: ${executionOrder.map(g => g.map(a => a.name).join(' + ')).join(' → ')}`);

        // Initialize all agents
        for (const [, agent] of this._agents) {
            await agent.init(this._sharedContext);
        }

        // Listen for critical findings if halt_on_critical is enabled
        if (this.config.halt_on_critical) {
            this.eventBus.on('finding:new', ({ finding }) => {
                if (finding?.severity === 'critical') {
                    this._haltedOnCritical = true;
                    this.logger?.warn?.(`\n⛔ CRITICAL finding detected — halting scan (halt_on_critical=true)`);
                    this.logger?.warn?.(`   ${finding.title}`);
                }
            });
        }

        // Execute in dependency-resolved waves
        for (const wave of executionOrder) {
            if (wave.length === 1) {
                // Single agent — run sequentially
                await this._runAgent(wave[0]);
            } else {
                // Multiple agents — run in parallel
                this.logger?.info?.(`Running ${wave.length} agents in parallel: ${wave.map(a => a.name).join(', ')}`);
                const results = await Promise.allSettled(
                    wave.map(agent => this._runAgent(agent))
                );

                // Log any failures
                for (let i = 0; i < results.length; i++) {
                    if (results[i].status === 'rejected') {
                        this.logger?.error?.(`Agent ${wave[i].name} failed: ${results[i].reason?.message}`);
                    }
                }
            }

            // Check halt_on_critical after each wave
            if (this._haltedOnCritical) {
                this.logger?.warn?.('Scan halted after critical finding. Proceeding to synthesis.');
                break;
            }
        }

        // Cleanup all agents
        for (const [, agent] of this._agents) {
            try {
                await agent.cleanup();
            } catch (err) {
                this.logger?.debug?.(`Cleanup for ${agent.name}: ${err.message}`);
            }
        }

        // Synthesis phase
        const duration = Date.now() - this._startTime;
        const results = this._synthesize(duration);

        // Optional LLM augmentation of synthesized results (additive, best-effort).
        // The deterministic correlate()/dedup output above is the source of truth.
        await this._llmAugment(results);

        this.eventBus.emit('scan:completed', {
            timestamp: new Date().toISOString(),
            duration,
            totalFindings: this.ledger.count,
            haltedOnCritical: this._haltedOnCritical,
        });

        // Send webhook notification if configured
        if (this.config.notify_webhook) {
            await this._sendWebhook(results);
        }

        return results;
    }

    /**
     * Run a single agent with error boundary.
     */
    async _runAgent(agent) {
        try {
            if (agent.dependencies.some(name => this._agents.get(name)?.status === 'error')) {
                agent._status = 'skipped';
                this.eventBus.emit('agent:skipped', { agentName: agent.name, message: 'Dependency failed' });
                return;
            }
            await agent.run();

            // If this is the crawl agent, store surface inventory for downstream agents
            if (agent.name === 'VIBE-SHIELD-CRAWL' && this._sharedContext.surfaceInventory === null) {
                // The crawl agent should have set this
                this.logger?.debug?.('Surface inventory should be set by VIBE-SHIELD-CRAWL');
            }
        } catch (error) {
            // Agent errors are non-fatal — other agents continue
            this.logger?.error?.(`Agent ${agent.name} failed: ${error.message}`);
        }
    }

    /**
     * Resolve agents into execution waves based on dependencies.
     * Uses topological sort — agents in the same wave have no inter-dependencies.
     * 
     * Example:
     *   VIBE-SHIELD-CRAWL (no deps)    → Wave 1
     *   VIBE-SHIELD-QA (dep: CRAWL)    → Wave 2
     *   VIBE-SHIELD-SEC (dep: CRAWL)   → Wave 2 (parallel with QA)
     */
    _resolveExecutionOrder() {
        const waves = [];
        const completed = new Set();
        const remaining = new Map(this._agents);

        let iterations = 0;
        const maxIterations = remaining.size + 1;

        while (remaining.size > 0 && iterations < maxIterations) {
            iterations++;
            const currentWave = [];

            for (const [name, agent] of remaining) {
                const depsResolved = agent.dependencies.every(dep => completed.has(dep));
                if (depsResolved) {
                    currentWave.push(agent);
                }
            }

            if (currentWave.length === 0) {
                const stuck = [...remaining.keys()].join(', ');
                throw new Error(`Circular dependency detected among agents: ${stuck}`);
            }

            for (const agent of currentWave) {
                remaining.delete(agent.name);
                completed.add(agent.name);
            }

            waves.push(currentWave);
        }

        return waves;
    }

    /**
     * Synthesis phase — deduplicate, correlate, and build final report data.
     */
    _synthesize(duration) {
        const exported = this.ledger.export();

        // Build per-agent summary
        const agentSummaries = {};
        for (const [name, agent] of this._agents) {
            agentSummaries[name] = {
                status: agent.status,
                duration: agent.duration,
                findingsCount: agent.findings.length,
                errors: agent.errors,
                assessment: agent.assessment,
            };
        }

        return {
            findings: exported.findings,
            deduplicated: exported.deduplicated,
            summary: exported.summary,
            dedupSummary: exported.dedupSummary,
            dedupStats: exported.dedupStats,
            correlations: exported.correlations,
            agents: agentSummaries,
            surfaceInventory: this._sharedContext.surfaceInventory,
            duration,
            eventLog: this.eventBus.getLog(),
        };
    }

    /**
     * Phase 2 — LLM augmentation of synthesized results. STRICTLY ADDITIVE:
     *   - Enriches attack-chain correlation narratives (keeps original as fallback).
     *   - Triages borderline findings (advisory `llm_triage` note only; never
     *     mutates the deterministic severity or pass/fail).
     * No-op when the LLM client is disabled/over-budget (returns immediately).
     */
    async _llmAugment(results) {
        const client = this.llmClient;
        if (!client?.isEnabled?.()) return;

        try {
            // Enrich correlation narratives.
            for (const c of results.correlations || []) {
                const enriched = await enrichCorrelation(client, c);
                if (enriched) {
                    c.narrative_llm = enriched;
                    c.narrative_source = 'llm';
                }
            }

            // Triage borderline findings only (limit egress + budget).
            const borderline = (results.deduplicated || results.findings || [])
                .filter(f => this._isBorderline(f))
                .slice(0, 15);
            for (const f of borderline) {
                const triage = await triageFinding(client, f);
                if (triage) f.llm_triage = triage;
            }
        } catch (err) {
            this.logger?.debug?.(`[LLM] augmentation skipped: ${err.message}`);
        }
    }

    /** Heuristic: which findings are "borderline" and worth LLM triage. */
    _isBorderline(f) {
        if (!f) return false;
        if (f.severity === 'medium' || f.severity === 'low') return true;
        const text = `${f.title || ''} ${f.description || ''}`.toLowerCase();
        return /\b(potential|possible|may|might|suspected|likely|reflected)\b/.test(text);
    }

    /**
     * Get the status of all agents.
     */
    getStatus() {
        const status = {};
        for (const [name, agent] of this._agents) {
            status[name] = {
                status: agent.status,
                duration: agent.duration,
                findings: agent.findings.length,
            };
        }
        return status;
    }

    /**
     * Send scan results to configured webhook (Slack, Linear, PagerDuty, etc.)
     */
    async _sendWebhook(results) {
        const webhookUrl = this.config.notify_webhook;
        if (!webhookUrl) return;

        try {
            const payload = {
                agent: 'VIBE SHIELD',
                version: getVersion(),
                target: this.config.target_url,
                timestamp: new Date().toISOString(),
                duration: results.duration,
                totalFindings: results.findings?.length || 0,
                summary: results.summary,
                criticalCount: results.summary?.critical || 0,
                highCount: results.summary?.high || 0,
                haltedOnCritical: this._haltedOnCritical,
            };

            await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(10000),
            });

            this.logger?.info?.(`Webhook notification sent to ${webhookUrl}`);
        } catch (err) {
            this.logger?.warn?.(`Webhook notification failed: ${err.message}`);
        }
    }
}

export default Orchestrator;
