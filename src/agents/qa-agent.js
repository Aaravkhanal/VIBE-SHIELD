import { BaseAgent } from './base-agent.js';
import { BrokenFlowDetector } from '../core/broken-flow-detector.js';
import { ConsoleMonitor } from '../core/console-monitor.js';
import { TestGenerator } from '../core/test-generator.js';
import { TestRunner } from '../core/test-runner.js';
import { FormValidator } from '../core/form-validator.js';
import { ResponsiveChecker } from '../core/responsive-checker.js';

/**
 * VIBE-SHIELD-QA — Quality Assurance & Functional Testing Agent
 * 
 * Runs all Module 01 sub-modules against the surface inventory:
 * Broken Flow Detection → Console Monitoring → Test Generation & Execution →
 * Form Validation → Responsive Checking
 * 
 * Dependencies: VIBE-SHIELD-CRAWL
 */
export class QAAgent extends BaseAgent {
    get name() { return 'VIBE-SHIELD-QA'; }
    get dependencies() { return ['VIBE-SHIELD-CRAWL']; }

    constructor() {
        super();
        this._testSummary = {};
    }

    get testSummary() { return this._testSummary; }

    async _execute(context) {
        const { config, logger, surfaceInventory } = context;

        if (!surfaceInventory) {
            throw new Error('No surface inventory available — VIBE-SHIELD-CRAWL must run first');
        }

        const phases = [
            { name: 'broken-flows', label: 'Detecting broken flows' },
            { name: 'console', label: 'Analyzing console output' },
            { name: 'tests', label: 'Generating & running tests' },
            { name: 'forms', label: 'Validating forms' },
            { name: 'responsive', label: 'Checking responsiveness' },
        ];

        let completedPhases = 0;

        // Phase 1: Broken Flow Detection
        this.progress(phases[0].name, phases[0].label, 0);
        try {
            const detector = new BrokenFlowDetector(logger);
            const findings = detector.analyze(surfaceInventory);
            this.addFindings(findings);
            this._log(`Broken flows: ${findings.length} issues`);
        } catch (err) {
            this._log(`Broken flow detection failed: ${err.message}`, 'error');
        }
        completedPhases++;
        this.progress(phases[0].name, `Broken flows complete`, (completedPhases / phases.length) * 100);

        // Phase 2: Console Monitoring
        this.progress(phases[1].name, phases[1].label, (completedPhases / phases.length) * 100);
        try {
            const monitor = new ConsoleMonitor(logger);
            const findings = monitor.analyze(surfaceInventory);
            this.addFindings(findings);
            this._log(`Console: ${findings.length} issues`);
        } catch (err) {
            this._log(`Console analysis failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 3: Test Generation & Execution
        this.progress(phases[2].name, phases[2].label, (completedPhases / phases.length) * 100);
        try {
            const generator = new TestGenerator(logger);
            const testCases = generator.generate(surfaceInventory);
            this._log(`Generated ${testCases.length} test cases`);

            const runner = new TestRunner(config, logger);
            const results = await runner.run(testCases);
            this._testSummary = results.summary;
            this.addFindings(results.findings);
            this._log(`Tests: ${results.summary.passed} passed, ${results.summary.failed} failed`);
        } catch (err) {
            this._log(`Test execution failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 4: Form Validation
        this.progress(phases[3].name, phases[3].label, (completedPhases / phases.length) * 100);
        try {
            const validator = new FormValidator(config, logger);
            const findings = await validator.validate(surfaceInventory);
            this.addFindings(findings);
            this._log(`Forms: ${findings.length} issues`);
        } catch (err) {
            this._log(`Form validation failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 5: Responsive Checking
        this.progress(phases[4].name, phases[4].label, (completedPhases / phases.length) * 100);
        try {
            const checker = new ResponsiveChecker(config, logger);
            const findings = await checker.check(surfaceInventory);
            this.addFindings(findings);
            this._log(`Responsive: ${findings.length} issues`);
        } catch (err) {
            this._log(`Responsive check failed: ${err.message}`, 'error');
        }
        completedPhases++;

        this.progress('complete', `QA complete — ${this._findings.length} total findings`, 100);
    }
}

export default QAAgent;
