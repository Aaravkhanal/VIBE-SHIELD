import { createFinding } from '../../utils/finding.js';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

/**
 * Dependency Auditor — Audits project dependencies for known CVEs.
 * Runs npm audit and parses vulnerability advisories into VIBE SHIELD findings.
 */
export class DependencyAuditor {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.findings = [];
    }

    /**
     * Run dependency audit on the project.
     */
    async audit() {
        // A website URL does not identify the scanner's own local package tree.
        if (!this.config.project_root) {
            this.logger?.info?.('Dependency audit not assessed: no target project directory configured.');
            return [];
        }
        const projectRoot = path.resolve(this.config.project_root);

        // Try npm audit first
        if (fs.existsSync(path.join(projectRoot, 'package-lock.json')) ||
            fs.existsSync(path.join(projectRoot, 'package.json'))) {
            await this._runNpmAudit(projectRoot);
        }

        // Check for known vulnerable patterns in package.json
        await this._checkPackageJson(projectRoot);

        this.logger?.info?.(`Dependency auditor found ${this.findings.length} issues`);
        return this.findings;
    }

    /**
     * Run npm audit and parse results.
     */
    async _runNpmAudit(projectRoot) {
        try {
            const lockPath = path.join(projectRoot, 'package-lock.json');
            if (!fs.existsSync(lockPath)) {
                this.logger?.debug?.('No package-lock.json found, skipping npm audit');
                return;
            }

            let auditOutput;
            try {
                auditOutput = execSync('npm audit --json 2>/dev/null', {
                    cwd: projectRoot,
                    maxBuffer: 10 * 1024 * 1024,
                    timeout: 30000,
                    encoding: 'utf-8',
                });
            } catch (err) {
                // npm audit exits with non-zero if vulnerabilities found — that's expected
                auditOutput = err.stdout || err.output?.[1] || '';
            }

            if (!auditOutput) return;

            let auditData;
            try {
                auditData = JSON.parse(auditOutput);
            } catch {
                this.logger?.debug?.('Failed to parse npm audit JSON output');
                return;
            }

            // Parse npm audit v2+ format
            if (auditData.vulnerabilities) {
                for (const [pkgName, vuln] of Object.entries(auditData.vulnerabilities)) {
                    const severity = this._mapSeverity(vuln.severity);

                    this.findings.push(createFinding({
                        module: 'security',
                        title: `Vulnerable Dependency: ${pkgName} (${vuln.severity})`,
                        severity,
                        affected_surface: `npm:${pkgName}`,
                        description: `The package "${pkgName}" (${vuln.range || 'unknown version'}) has known security vulnerabilities.\n\n${vuln.via?.map?.(v => typeof v === 'string' ? v : `- ${v.title || v.name}: ${v.url || ''}`).join('\\n') || 'See npm advisory for details.'}\n\nVulnerable range: ${vuln.range || 'unknown'}\nSeverity: ${vuln.severity}\nDirect: ${vuln.isDirect ? 'Yes' : 'No (transitive)'}`,
                        reproduction: [
                            '1. Run `npm audit` in the project root',
                            `2. Observe vulnerability in ${pkgName}`,
                        ],
                        evidence: JSON.stringify({
                            package: pkgName,
                            severity: vuln.severity,
                            range: vuln.range,
                            fixAvailable: vuln.fixAvailable,
                            isDirect: vuln.isDirect,
                        }, null, 2),
                        remediation: vuln.fixAvailable
                            ? `Run \`npm audit fix\` to automatically resolve. If fix is not compatible, manually update ${pkgName} to a patched version.`
                            : `No automatic fix available. Check if a newer major version of ${pkgName} resolves the vulnerability, or look for alternative packages.`,
                        references: vuln.via?.filter?.(v => typeof v === 'object' && v.url)?.map?.(v => v.url) || [],
                    }));
                }
            }

            // Summary
            if (auditData.metadata?.vulnerabilities) {
                const meta = auditData.metadata.vulnerabilities;
                const total = meta.total || Object.values(meta).reduce((a, b) => a + (typeof b === 'number' ? b : 0), 0);
                this.logger?.info?.(`npm audit: ${total} vulnerabilities found (${meta.critical || 0} critical, ${meta.high || 0} high, ${meta.moderate || 0} moderate, ${meta.low || 0} low)`);
            }
        } catch (err) {
            this.logger?.debug?.(`npm audit failed: ${err.message}`);
        }
    }

    /**
     * Check package.json for known risky patterns.
     */
    async _checkPackageJson(projectRoot) {
        const pkgPath = path.join(projectRoot, 'package.json');
        if (!fs.existsSync(pkgPath)) return;

        try {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
            const allDeps = {
                ...(pkg.dependencies || {}),
                ...(pkg.devDependencies || {}),
            };

            // Check for wildcard versions
            for (const [name, version] of Object.entries(allDeps)) {
                if (version === '*' || version === 'latest') {
                    this.findings.push(createFinding({
                        module: 'security',
                        title: `Unpinned Dependency: ${name} (${version})`,
                        severity: 'medium',
                        affected_surface: `npm:${name}`,
                        description: `The dependency "${name}" uses version "${version}". Unpinned dependencies can introduce breaking changes or supply chain attacks when a compromised version is published.`,
                        reproduction: [
                            `1. Check package.json`,
                            `2. "${name}": "${version}" — no version pinned`,
                        ],
                        remediation: `Pin ${name} to a specific version range. Use \`npm install ${name}@<version>\` to install a specific version.`,
                    }));
                }
            }

            // Check for known risky scripts
            const scripts = pkg.scripts || {};
            const riskyPatterns = ['curl', 'wget', 'eval', 'exec', 'child_process'];
            for (const [scriptName, scriptCmd] of Object.entries(scripts)) {
                for (const pattern of riskyPatterns) {
                    if (scriptCmd.toLowerCase().includes(pattern)) {
                        this.findings.push(createFinding({
                            module: 'security',
                            title: `Risky Script Pattern: "${pattern}" in "${scriptName}"`,
                            severity: 'medium',
                            affected_surface: 'package.json scripts',
                            description: `The npm script "${scriptName}" contains the pattern "${pattern}": \`${scriptCmd}\`. This could indicate a supply chain risk or unsafe operation.`,
                            reproduction: [
                                `1. Inspect package.json scripts.${scriptName}`,
                                `2. Script contains: ${scriptCmd}`,
                            ],
                            remediation: `Review the script for safety. Ensure "${pattern}" usage is intentional and secure.`,
                        }));
                    }
                }
            }
        } catch (err) {
            this.logger?.debug?.(`package.json check failed: ${err.message}`);
        }
    }

    _mapSeverity(npmSeverity) {
        const map = {
            'critical': 'critical',
            'high': 'high',
            'moderate': 'medium',
            'medium': 'medium',
            'low': 'low',
            'info': 'info',
        };
        return map[npmSeverity?.toLowerCase()] || 'medium';
    }
}

export default DependencyAuditor;
