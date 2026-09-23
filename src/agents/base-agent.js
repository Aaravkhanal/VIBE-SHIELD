/**
 * BaseAgent — Abstract base class for all VIBE SHIELD agents.
 * 
 * Lifecycle: init() → run() → cleanup()
 * 
 * Subclasses must implement:
 *   - name (string)
 *   - dependencies (string[]) — names of agents that must complete before this one
 *   - _execute(context) — the agent's main work
 */
export class BaseAgent {
    constructor() {
        if (new.target === BaseAgent) {
            throw new Error('BaseAgent is abstract — extend it, do not instantiate directly.');
        }

        this._status = 'idle';       // idle → initializing → running → done → error
        this._startTime = null;
        this._endTime = null;
        this._findings = [];
        this.errors = [];
        this.assessment = 'assessed';
        this._eventBus = null;
        this._logger = null;
        this._config = null;
        this._context = null;
    }

    /** Agent display name (e.g. "VIBE-SHIELD-QA"). Must be overridden. */
    get name() { throw new Error('Agent must define a name'); }

    /** Agent names this agent depends on. Override to add dependencies. */
    get dependencies() { return []; }

    /** Current agent status. */
    get status() { return this._status; }

    /** Duration in ms (only valid after completion). */
    get duration() {
        if (!this._startTime) return 0;
        const end = this._endTime || Date.now();
        return end - this._startTime;
    }

    /** All findings collected by this agent. */
    get findings() { return [...this._findings]; }

    /**
     * Initialize the agent with shared context.
     * Called by the Orchestrator before run().
     */
    async init(context) {
        this._status = 'initializing';
        this._config = context.config;
        this._logger = context.logger;
        this._eventBus = context.eventBus;
        this._context = context;

        this._eventBus.emit('agent:registered', { agentName: this.name });
        this._log(`Agent initialized`);
    }

    /**
     * Execute the agent. Handles lifecycle, timing, and error boundaries.
     * Do NOT override — implement _execute() instead.
     */
    async run() {
        this._status = 'running';
        this._startTime = Date.now();

        this._eventBus.emit('agent:started', {
            agentName: this.name,
            timestamp: new Date().toISOString(),
        });
        this._log(`Agent started`);

        try {
            await this._execute(this._context);
            this._status = this.errors.length ? 'partial' : 'done';
            this._endTime = Date.now();

            this._eventBus.emit('agent:completed', {
                agentName: this.name,
                timestamp: new Date().toISOString(),
                duration: this.duration,
                findingsCount: this._findings.length,
                status: this._status,
                errors: this.errors,
            });
            this._log(`Agent completed — ${this._findings.length} findings in ${this.duration}ms`);

        } catch (error) {
            this._status = 'error';
            this._endTime = Date.now();

            this._eventBus.emit('agent:error', {
                agentName: this.name,
                error: error.message,
                timestamp: new Date().toISOString(),
            });
            this._log(`Agent error: ${error.message}`, 'error');
            throw error;
        }
    }

    /**
     * Cleanup resources. Override in subclass if needed.
     */
    async cleanup() {
        // Default: no-op. Subclasses can override for resource cleanup.
    }

    /**
     * Main execution logic. Must be implemented by subclass.
     */
    async _execute(_context) {
        throw new Error(`${this.name} must implement _execute()`);
    }

    /**
     * Add a finding to this agent's collection and publish it.
     */
    addFinding(finding) {
        this._findings.push(finding);
        this._eventBus.emit('finding:new', {
            finding,
            agentName: this.name,
        });
    }

    /**
     * Add multiple findings at once.
     */
    addFindings(findings) {
        for (const f of findings) {
            this.addFinding(f);
        }
    }

    /**
     * Emit a progress update for UI consumption.
     */
    progress(phase, message, percent = null) {
        this._eventBus.emit('agent:progress', {
            agentName: this.name,
            phase,
            message,
            progress: percent,
        });
    }

    /**
     * Internal logging helper.
     */
    _log(message, level = 'info') {
        if (level === 'error') this.errors.push(message);
        if (this._logger?.[level]) {
            this._logger[level](`[${this.name}] ${message}`);
        }
    }
}

export default BaseAgent;
