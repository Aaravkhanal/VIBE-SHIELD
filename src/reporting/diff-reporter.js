import fs from 'fs';
import path from 'path';

/**
 * DiffReporter — Compares findings between scan runs for regression detection.
 *
 * Generates a diff report showing:
 * - New findings (appeared in current run)
 * - Resolved findings (was in previous, not in current)
 * - Persistent findings (in both runs)
 * - Severity changes
 */
export class DiffReporter {
    constructor(logger) {
        this.logger = logger;
    }

    /**
     * Generate diff between current findings and the most recent previous run.
     */
    generateDiff(currentFindings, outputDir, target) {
        const previousFindings = this._loadPreviousFindings(outputDir, target);

        if (!previousFindings) {
            this.logger?.info?.('Diff Report: no previous scan found — skipping regression diff');
            return null;
        }

        const diff = this._computeDiff(previousFindings, currentFindings);

        // Write diff report
        const diffPath = path.join(outputDir, 'diff-report.json');
        fs.writeFileSync(diffPath, JSON.stringify(diff, null, 2), 'utf-8');

        // Write markdown diff
        const mdPath = path.join(outputDir, 'diff-report.md');
        fs.writeFileSync(mdPath, this._generateMarkdown(diff), 'utf-8');

        this.logger?.info?.(`Diff Report: ${diff.new.length} new, ${diff.resolved.length} resolved, ${diff.persistent.length} persistent`);

        return diff;
    }

    /**
     * Load findings from the most recent previous scan run.
     */
    _loadPreviousFindings(currentOutputDir, target) {
        try {
            const reportsRoot = path.dirname(currentOutputDir);
            if (!fs.existsSync(reportsRoot)) return null;

            const runs = fs.readdirSync(reportsRoot)
                .filter(d => fs.statSync(path.join(reportsRoot, d)).isDirectory())
                .sort((a, b) => fs.statSync(path.join(reportsRoot, b)).mtimeMs - fs.statSync(path.join(reportsRoot, a)).mtimeMs);

            // Find the most recent run that isn't the current one
            const currentName = path.basename(currentOutputDir);
            for (const run of runs) {
                if (run === currentName) continue;
                const reportPath = path.join(reportsRoot, run, 'report.json');
                if (fs.existsSync(reportPath)) {
                    const data = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
                    if (target && data.meta?.target !== target) continue;
                    if (data.coverage?.status !== 'complete') continue;
                    return data.findings || [];
                }
            }
        } catch (err) {
            this.logger?.debug?.(`Diff: could not load previous findings: ${err.message}`);
        }

        return null;
    }

    /**
     * Compute the diff between two finding sets.
     * Matching is done by title + affected_surface (not ID, since IDs change per run).
     */
    _computeDiff(previousFindings, currentFindings) {
        const key = f => `${f.title}::${f.affected_surface}`;

        const prevMap = new Map(previousFindings.map(f => [key(f), f]));
        const currMap = new Map(currentFindings.map(f => [key(f), f]));

        const newFindings = [];
        const resolved = [];
        const persistent = [];
        const severityChanges = [];

        // Find new and persistent
        for (const [k, curr] of currMap) {
            if (prevMap.has(k)) {
                persistent.push(curr);
                const prev = prevMap.get(k);
                if (prev.severity !== curr.severity) {
                    severityChanges.push({
                        title: curr.title,
                        affected_surface: curr.affected_surface,
                        previousSeverity: prev.severity,
                        currentSeverity: curr.severity,
                    });
                }
            } else {
                newFindings.push(curr);
            }
        }

        // Find resolved
        for (const [k, prev] of prevMap) {
            if (!currMap.has(k)) {
                resolved.push(prev);
            }
        }

        return {
            timestamp: new Date().toISOString(),
            previousRunFindings: previousFindings.length,
            currentRunFindings: currentFindings.length,
            new: newFindings,
            resolved,
            persistent,
            severityChanges,
            regressionDetected: newFindings.length > 0,
        };
    }

    /**
     * Generate markdown diff report.
     */
    _generateMarkdown(diff) {
        let md = `# 呪 VIBE SHIELD — Regression Diff Report\n\n`;
        md += `**Generated:** ${diff.timestamp}\n`;
        md += `**Previous Run:** ${diff.previousRunFindings} findings\n`;
        md += `**Current Run:** ${diff.currentRunFindings} findings\n\n`;

        md += `## Summary\n\n`;
        md += `| Category | Count |\n`;
        md += `|----------|-------|\n`;
        md += `| 🆕 New Findings | ${diff.new.length} |\n`;
        md += `| ✅ Resolved | ${diff.resolved.length} |\n`;
        md += `| ⏳ Persistent | ${diff.persistent.length} |\n`;
        md += `| 🔄 Severity Changes | ${diff.severityChanges.length} |\n\n`;

        if (diff.new.length > 0) {
            md += `## 🆕 New Findings (Regressions)\n\n`;
            for (const f of diff.new) {
                md += `- **[${f.severity.toUpperCase()}]** ${f.title} — ${f.affected_surface}\n`;
            }
            md += '\n';
        }

        if (diff.resolved.length > 0) {
            md += `## ✅ Resolved Findings\n\n`;
            for (const f of diff.resolved) {
                md += `- ~~[${f.severity.toUpperCase()}] ${f.title} — ${f.affected_surface}~~\n`;
            }
            md += '\n';
        }

        if (diff.severityChanges.length > 0) {
            md += `## 🔄 Severity Changes\n\n`;
            for (const c of diff.severityChanges) {
                md += `- ${c.title}: ${c.previousSeverity} → **${c.currentSeverity}**\n`;
            }
            md += '\n';
        }

        md += `\n*Report generated by VIBE SHIELD 呪 Diff Engine*\n`;
        return md;
    }
}

export default DiffReporter;
