import { BaseAgent } from './base-agent.js';
import { allows, getSafetyMode } from '../utils/safety.js';
import { HeaderAnalyzer } from '../core/security/header-analyzer.js';
import { SecretDetector } from '../core/security/secret-detector.js';
import { XSSScanner } from '../core/security/xss-scanner.js';
import { SQLiProber } from '../core/security/sqli-prober.js';
import { DependencyAuditor } from '../core/security/dependency-auditor.js';
import { TLSChecker } from '../core/security/tls-checker.js';
import { InfraScanner } from '../core/security/infra-scanner.js';
import { FileUploadTester } from '../core/security/file-upload-tester.js';
import { CSRFDetector } from '../core/security/csrf-detector.js';
import { OpenRedirectDetector } from '../core/security/open-redirect-detector.js';
import { SubdomainScanner } from '../core/security/subdomain-scanner.js';
import { CookieAuditor } from '../core/security/cookie-auditor.js';
import { CSPValidator } from '../core/security/csp-validator.js';
import { ClickjackingDetector } from '../core/security/clickjacking-detector.js';
import { SSRFProber } from '../core/security/ssrf-prober.js';

/**
 * VIBE-SHIELD-SEC — Security Vulnerability Scanning Agent
 * 
 * Runs all Module 02 sub-modules against the surface inventory:
 * Header Analysis → Secret Detection → XSS Scanning → SQL Injection Probing →
 * Dependency Audit → TLS Check → Infrastructure Scan → File Upload →
 * CSRF Detection → Open Redirect Detection → Subdomain Enumeration →
 * Cookie Audit → CSP Validation → Clickjacking Detection → SSRF Probing
 * 
 * Dependencies: VIBE-SHIELD-CRAWL
 */
export class SecurityAgent extends BaseAgent {
    get name() { return 'VIBE-SHIELD-SEC'; }
    get dependencies() { return ['VIBE-SHIELD-CRAWL']; }

    async _execute(context) {
        const { config, logger, surfaceInventory } = context;

        if (!surfaceInventory) {
            throw new Error('No surface inventory available — VIBE-SHIELD-CRAWL must run first');
        }

        // Active attack probing (injecting payloads) requires at least
        // safe-active. In passive mode we only run read-only/analysis checks.
        const allowActive = allows(config, 'safe-active');
        const safetyMode = getSafetyMode(config);
        const skipActive = (label) => {
            this.skipCheck(label, `Requires active probing; current safety mode is ${safetyMode}`);
            this._log(`${label} skipped — requires active probing (current: ${safetyMode} mode)`);
        };

        const phases = [
            { name: 'headers', label: 'Analyzing security headers' },
            { name: 'secrets', label: 'Scanning for exposed secrets' },
            { name: 'xss', label: 'Probing for XSS vulnerabilities' },
            { name: 'sqli', label: 'Probing for SQL injection' },
            { name: 'deps', label: 'Auditing dependencies' },
            { name: 'tls', label: 'Checking TLS configuration' },
            { name: 'infra', label: 'Scanning infrastructure' },
            { name: 'upload', label: 'Testing file upload security' },
            { name: 'csrf', label: 'Detecting missing CSRF protection' },
            { name: 'redirect', label: 'Probing for open redirects' },
            { name: 'subdomains', label: 'Checking authorized subdomain scope' },
            { name: 'cookies', label: 'Auditing cookie security' },
            { name: 'csp', label: 'Validating Content Security Policy' },
            { name: 'clickjacking', label: 'Detecting clickjacking vulnerabilities' },
            { name: 'ssrf', label: 'Probing for SSRF vulnerabilities' },
        ];

        let completedPhases = 0;

        // Phase 1: Header Analysis
        this.progress(phases[0].name, phases[0].label, 0);
        try {
            const analyzer = new HeaderAnalyzer(logger);
            const findings = await analyzer.analyze(surfaceInventory);
            this.addFindings(findings);
            this._log(`Headers: ${findings.length} issues`);
        } catch (err) {
            this._log(`Header analysis failed: ${err.message}`, 'error');
        }
        completedPhases++;
        this.progress(phases[0].name, 'Header analysis complete', (completedPhases / phases.length) * 100);

        // Phase 2: Secret Detection
        this.progress(phases[1].name, phases[1].label, (completedPhases / phases.length) * 100);
        try {
            const detector = new SecretDetector(logger);
            const findings = await detector.detect(surfaceInventory);
            this.addFindings(findings);
            this._log(`Secrets: ${findings.length} exposures`);
        } catch (err) {
            this._log(`Secret detection failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 3: XSS Scanning (active probing)
        if (allowActive) {
            this.progress(phases[2].name, phases[2].label, (completedPhases / phases.length) * 100);
            try {
                const scanner = new XSSScanner(logger, context.coverageTracker);
                const findings = await scanner.scan(surfaceInventory);
                this.addFindings(findings);
                this._log(`XSS: ${findings.length} vulnerabilities`);
            } catch (err) {
                this._log(`XSS scanning failed: ${err.message}`, 'error');
            }
        } else {
            skipActive('XSS scanning');
        }
        completedPhases++;

        // Phase 4: SQL Injection Probing (active probing)
        if (allowActive) {
            this.progress(phases[3].name, phases[3].label, (completedPhases / phases.length) * 100);
            try {
                const prober = new SQLiProber(logger, context.coverageTracker);
                const findings = await prober.probe(surfaceInventory);
                this.addFindings(findings);
                this._log(`SQLi: ${findings.length} vulnerabilities`);
            } catch (err) {
                this._log(`SQLi probing failed: ${err.message}`, 'error');
            }
        } else {
            skipActive('SQLi probing');
        }
        completedPhases++;

        // Phase 5: Dependency Audit
        this.progress(phases[4].name, phases[4].label, (completedPhases / phases.length) * 100);
        try {
            const auditor = new DependencyAuditor(config, logger);
            const findings = await auditor.audit();
            this.addFindings(findings);
            this._log(`Dependencies: ${findings.length} issues`);
        } catch (err) {
            this._log(`Dependency audit failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 6: TLS/SSL Check
        this.progress(phases[5].name, phases[5].label, (completedPhases / phases.length) * 100);
        try {
            const checker = new TLSChecker(logger);
            const findings = await checker.check(surfaceInventory);
            this.addFindings(findings);
            this._log(`TLS: ${findings.length} issues`);
        } catch (err) {
            this._log(`TLS check failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 7: Infrastructure Scan (active probing of admin/debug endpoints)
        if (allowActive) {
            this.progress(phases[6].name, phases[6].label, (completedPhases / phases.length) * 100);
            try {
                const scanner = new InfraScanner(logger);
                const findings = await scanner.scan(surfaceInventory);
                this.addFindings(findings);
                this._log(`Infrastructure: ${findings.length} issues`);
            } catch (err) {
                this._log(`Infrastructure scan failed: ${err.message}`, 'error');
            }
        } else {
            skipActive('Infrastructure scan');
        }
        completedPhases++;

        // Phase 8: File Upload Testing (active probing)
        if (allowActive) {
            this.progress(phases[7].name, phases[7].label, (completedPhases / phases.length) * 100);
            try {
                const uploader = new FileUploadTester(logger);
                const findings = await uploader.test(surfaceInventory);
                this.addFindings(findings);
                this._log(`File uploads: ${findings.length} issues`);
            } catch (err) {
                this._log(`File upload testing failed: ${err.message}`, 'error');
            }
        } else {
            skipActive('File upload testing');
        }
        completedPhases++;

        // Phase 9: CSRF Detection
        this.progress(phases[8].name, phases[8].label, (completedPhases / phases.length) * 100);
        try {
            const detector = new CSRFDetector(logger);
            const findings = await detector.detect(surfaceInventory);
            this.addFindings(findings);
            this._log(`CSRF: ${findings.length} issues`);
        } catch (err) {
            this._log(`CSRF detection failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 10: Open Redirect Detection (active probing)
        if (allowActive) {
            this.progress(phases[9].name, phases[9].label, (completedPhases / phases.length) * 100);
            try {
                const detector = new OpenRedirectDetector(logger, context.coverageTracker);
                const findings = await detector.detect(surfaceInventory);
                this.addFindings(findings);
                this._log(`Open redirects: ${findings.length} issues`);
            } catch (err) {
                this._log(`Open redirect detection failed: ${err.message}`, 'error');
            }
        } else {
            skipActive('Open redirect detection');
        }
        completedPhases++;

        // Phase 11: Subdomain Enumeration
        this.progress(phases[10].name, phases[10].label, (completedPhases / phases.length) * 100);
        try {
            const scanner = new SubdomainScanner(config, logger);
            const findings = await scanner.scan(surfaceInventory);
            this.addFindings(findings);
            this._log(`Subdomains: ${findings.length} findings`);
        } catch (err) {
            this._log(`Subdomain scanning failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 12: Cookie Security Audit
        this.progress(phases[11].name, phases[11].label, (completedPhases / phases.length) * 100);
        try {
            const auditor = new CookieAuditor(logger);
            const findings = await auditor.audit(surfaceInventory);
            this.addFindings(findings);
            this._log(`Cookies: ${findings.length} issues`);
        } catch (err) {
            this._log(`Cookie audit failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 13: CSP Validation
        this.progress(phases[12].name, phases[12].label, (completedPhases / phases.length) * 100);
        try {
            const validator = new CSPValidator(logger);
            const findings = await validator.validate(surfaceInventory);
            this.addFindings(findings);
            this._log(`CSP: ${findings.length} issues`);
        } catch (err) {
            this._log(`CSP validation failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 14: Clickjacking Detection
        this.progress(phases[13].name, phases[13].label, (completedPhases / phases.length) * 100);
        try {
            const detector = new ClickjackingDetector(logger);
            const findings = await detector.detect(surfaceInventory);
            this.addFindings(findings);
            this._log(`Clickjacking: ${findings.length} issues`);
        } catch (err) {
            this._log(`Clickjacking detection failed: ${err.message}`, 'error');
        }
        completedPhases++;

        // Phase 15: SSRF Probing (active probing)
        if (allowActive) {
            this.progress(phases[14].name, phases[14].label, (completedPhases / phases.length) * 100);
            try {
                const prober = new SSRFProber(logger, context.coverageTracker);
                const findings = await prober.probe(surfaceInventory);
                this.addFindings(findings);
                this._log(`SSRF: ${findings.length} issues`);
            } catch (err) {
                this._log(`SSRF probing failed: ${err.message}`, 'error');
            }
        } else {
            skipActive('SSRF probing');
        }
        completedPhases++;

        this.progress('complete', `Security scan complete — ${this._findings.length} total findings`, 100);
    }
}

export default SecurityAgent;
