import EventEmitter from 'events';

/**
 * EventBus — Central message bus for inter-agent communication.
 * 
 * Event types:
 *   agent:registered   { agentName }
 *   agent:started      { agentName, timestamp }
 *   agent:progress     { agentName, phase, message, progress }
 *   agent:completed    { agentName, timestamp, duration, findingsCount }
 *   agent:error        { agentName, error, timestamp }
 *   finding:new        { finding, agentName }
 *   surface:discovered { inventory, agentName }
 *   scan:started       { timestamp, modules }
 *   scan:completed     { timestamp, duration, totalFindings }
 */
export class EventBus extends EventEmitter {
    constructor() {
        super();
        this.setMaxListeners(50);
        this._log = [];
    }

    /**
     * Emit an event and record it in the audit log.
     */
    emit(event, data = {}) {
        const entry = {
            event,
            data,
            timestamp: new Date().toISOString(),
        };
        this._log.push(entry);
        return super.emit(event, data);
    }

    /**
     * Get the full event log for audit/debugging.
     */
    getLog() {
        return [...this._log];
    }

    /**
     * Get events filtered by type.
     */
    getEvents(eventType) {
        return this._log.filter(e => e.event === eventType);
    }

    /**
     * Clear the event log.
     */
    clearLog() {
        this._log = [];
    }
}

export default EventBus;
