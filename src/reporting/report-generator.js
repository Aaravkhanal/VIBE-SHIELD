import fs from 'fs';
import path from 'path';
import { sortFindings, filterBySeverity, severitySummary, verificationSummary, normalizeVerification } from '../utils/finding.js';
import { writeSARIF } from './sarif-generator.js';
import { DiffReporter } from './diff-reporter.js';
import { getVersion } from '../utils/version.js';
import { enhanceRemediation, generateExecutiveSummary } from '../core/llm/augmentations.js';

/** Friendly labels for module keys, used in report headings. */
const MODULE_LABELS = {
  qa: 'QA & Functional Testing',
  security: 'Security Vulnerability Scanning',
  ai: 'Prompt Injection & AI Abuse',
  logic: 'Business Logic Validation',
  api: 'API & Auth Flow Verification',
};

/** Build a human-readable label from a list of executed module keys. */
function formatModules(modules) {
  if (!Array.isArray(modules) || modules.length === 0) return 'Security & Quality';
  return modules.map(m => MODULE_LABELS[m] || m).join(', ');
}

/**
 * Report Generator — Generates structured output in JSON, Markdown, HTML, and SARIF formats.
 */
export class ReportGenerator {
  constructor(config, logger, llmClient = null) {
    this.config = config;
    this.logger = logger;
    // Optional LLM client. When null/disabled, all augmentation is skipped and
    // reports render exactly as before (template remediation, no AI summary).
    this.llmClient = llmClient;
  }

  /**
   * Generate all reports from findings and test results.
   */
  async generate({ agents, findings, deduplicated, dedupStats, correlations, testSummary, surfaceInventory, coverageManifest, outputDir, modules }) {
    const reportDir = outputDir || path.join(process.cwd(), 'vibe-shield-reports', this._timestamp());
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }

    const withVerification = item => item.verification ? item : { ...item, verification: normalizeVerification(null, item) };
    const filteredFindings = filterBySeverity(
      sortFindings((findings || []).map(withVerification)),
      this.config.severity_threshold || 'low'
    );

    // Use deduplicated findings for human-readable reports
    const reportFindings = deduplicated
      ? filterBySeverity(sortFindings(deduplicated.map(withVerification)), this.config.severity_threshold || 'low')
      : filteredFindings;

    const summary = severitySummary(filteredFindings);
    const dedupSummary = severitySummary(reportFindings);

    // Resolve which modules actually ran: explicit arg → config → enabled list.
    const executedModules = (modules && modules.length > 0)
      ? modules
      : (this.config.modules_enabled || []);

    const reportData = {
      meta: {
        agent: 'VIBE SHIELD',
        version: getVersion(),
        modules: executedModules,
        modulesLabel: formatModules(executedModules),
        target: this.config.target_url,
        scannedAt: new Date().toISOString(),
        duration: testSummary?.duration || null,
      },
      agents: agents || {},
      coverage: {
        status: !agents || Object.values(agents).some(a => a.status !== 'done') || (surfaceInventory?.pages || []).some(p => typeof p.status !== 'number' || p.status >= 400) ? 'incomplete' : 'complete',
        manifest: coverageManifest || null,
        safetyMode: this.config.safety_mode || 'safe-active',
        dependencyAudit: this.config.project_root ? 'Target source directory configured' : 'Not assessed: no target source directory',
        note: 'Automated findings reflect the tested surfaces and selected modules. Zero findings do not establish that a website is vulnerability-free.',
      },
      summary,
      dedupSummary,
      verificationSummary: verificationSummary(reportFindings),
      dedupStats: dedupStats || null,
      correlations: correlations || [],
      testSummary: testSummary || {},
      surfaceInventory: {
        pages: (surfaceInventory?.pages || []).map(({ url, status, title }) => ({ url, status, title })),
        totalPages: surfaceInventory?.totalPages || 0,
        totalApis: surfaceInventory?.totalApis || 0,
        totalForms: surfaceInventory?.totalForms || 0,
      },
      findings: reportFindings,
      rawFindings: filteredFindings,
      scoringFindings: sortFindings((deduplicated || findings || []).map(withVerification)).map(item => ({
        module: item.module, severity: item.severity, verification: { level: item.verification.level },
      })),
    };

    // Optional, additive LLM augmentation (remediation + executive summary).
    // No-op when the client is disabled; reports render unchanged on null.
    await this._augmentWithLLM(reportFindings, reportData);

    // Generate JSON
    const jsonPath = path.join(reportDir, 'report.json');
    fs.writeFileSync(jsonPath, JSON.stringify(reportData, null, 2), 'utf-8');

    // Generate Markdown (uses deduped findings)
    const mdPath = path.join(reportDir, 'report.md');
    fs.writeFileSync(mdPath, this._generateMarkdown(reportData), 'utf-8');

    // Generate HTML (uses deduped findings)
    const htmlPath = path.join(reportDir, 'report.html');
    fs.writeFileSync(htmlPath, this._generateHTML(reportData), 'utf-8');

    // Generate SARIF (uses raw findings for CI/CD accuracy)
    const sarifPath = writeSARIF(filteredFindings, reportDir, reportData.meta);
    this.logger?.info?.(`SARIF report generated: ${sarifPath}`);

    // Generate Diff Report (regression detection)
    const diffReporter = new DiffReporter(this.logger);
    const diff = diffReporter.generateDiff(filteredFindings, reportDir, this.config.target_url);

    this.logger?.info?.(`Reports generated at ${reportDir}`);
    return { reportDir, jsonPath, mdPath, htmlPath, sarifPath, summary, dedupSummary, diff };
  }


  /**
   * Phase 0 + Phase 2 LLM augmentation. STRICTLY ADDITIVE and best-effort:
   *   - Per-finding remediation (falls back to template when LLM returns null).
   *   - One executive-summary paragraph (omitted when null).
   * Tags LLM-derived content so the report can label it.
   */
  async _augmentWithLLM(findings, reportData) {
    const client = this.llmClient;
    if (!client?.isEnabled?.()) return;

    try {
      // Remediation: only top findings to respect call/token budget.
      const prioritized = findings
        .filter(f => ['critical', 'high', 'medium'].includes(f.severity))
        .slice(0, 20);
      for (const f of prioritized) {
        const text = await enhanceRemediation(client, f);
        if (text) {
          f.remediation_llm = text;
          f.remediation_source = 'llm';
        }
      }

      // Executive summary (titles + counts only — data minimization).
      const summaryText = await generateExecutiveSummary(client, {
        target: reportData.meta.target,
        summary: reportData.dedupSummary || reportData.summary,
        topTitles: findings.slice(0, 15).map(f => `[${f.severity}] ${f.title}`),
      });
      if (summaryText) {
        reportData.meta.executiveSummary = summaryText;
        reportData.meta.executiveSummarySource = 'llm';
      }
    } catch (err) {
      this.logger?.debug?.(`[LLM] report augmentation skipped: ${err.message}`);
    }
  }

  _generateMarkdown(data) {
    const { meta, testSummary, surfaceInventory, findings } = data;
    const summary = data.dedupSummary || data.summary;
    let md = '';

    md += `# 呪 VIBE SHIELD Security & Quality Report\n\n`;
    md += `**Target:** ${meta.target}  \n`;
    md += `**Modules:** ${meta.modulesLabel || formatModules(meta.modules)}  \n`;
    md += `**Scanned:** ${meta.scannedAt}  \n`;
    md += `**Agent Version:** ${meta.version}  \n\n`;

    md += `---\n\n`;
    md += `## Executive Summary\n\n`;
    md += `**Coverage:** ${data.coverage?.status || 'unknown'}. ${data.coverage?.note || ''}\n\n`;
    if (meta.executiveSummary) {
      md += `${meta.executiveSummary}\n\n`;
      md += `*(AI-assisted summary — advisory only)*\n\n`;
    }
    md += `| Metric | Value |\n`;
    md += `|--------|-------|\n`;
    md += `| Total Findings | ${summary.total} |\n`;
    md += `| Critical | 🔴 ${summary.critical} |\n`;
    md += `| High | 🟠 ${summary.high} |\n`;
    md += `| Medium | 🟡 ${summary.medium} |\n`;
    md += `| Low | 🔵 ${summary.low} |\n`;
    md += `| Info | ⚪ ${summary.info} |\n\n`;

    const verification = data.verificationSummary || verificationSummary(findings);
    md += `### Verification confidence\n\n`;
    md += `| Level | Findings | Meaning |\n`;
    md += `|-------|----------|---------|\n`;
    md += `| Confirmed | ${verification.confirmed} | Exploit executed with observable, replayable proof |\n`;
    md += `| High confidence | ${verification.high_confidence} | Repeatable controlled response difference |\n`;
    md += `| Potential | ${verification.potential} | Heuristic evidence requiring review |\n`;
    md += `| Informational | ${verification.informational} | Surface or configuration observation |\n`;
    md += `| Not assessed | ${verification.not_assessed} | Access or capability was unavailable |\n\n`;

    if (testSummary.total) {
      md += `### Test Execution\n\n`;
      md += `| Metric | Value |\n`;
      md += `|--------|-------|\n`;
      md += `| Total Tests | ${testSummary.total} |\n`;
      md += `| Passed | ✅ ${testSummary.passed} |\n`;
      md += `| Failed | ❌ ${testSummary.failed} |\n`;
      md += `| Errors | ⚠️ ${testSummary.errors} |\n\n`;
    }

    md += `### Coverage\n\n`;
    md += `| Surface | Count |\n`;
    md += `|---------|-------|\n`;
    md += `| Pages Crawled | ${surfaceInventory.totalPages} |\n`;
    md += `| API Endpoints | ${surfaceInventory.totalApis} |\n`;
    md += `| Forms Discovered | ${surfaceInventory.totalForms} |\n\n`;
    const manifest = data.coverage?.manifest;
    if (manifest) {
      md += `**Measured coverage:** ${manifest.percent == null ? 'Not measured' : `${manifest.percent}%`} — ${manifest.denominator}\n\n`;
      md += `| Surface | Discovered | Exercised |\n|---------|-----------:|----------:|\n`;
      for (const [label, key, tested] of [['Pages', 'pages', 'scanned'], ['API endpoints', 'apiEndpoints', 'tested'], ['Forms', 'forms', 'submitted'], ['Parameters', 'parameters', 'mutated']]) {
        md += `| ${label} | ${manifest[key]?.discovered ?? 0} | ${manifest[key]?.[tested] ?? 0} |\n`;
      }
      md += `\n**Authenticated routes reached:** ${manifest.authenticatedRoutesReached}  \n**Roles tested:** ${manifest.userRolesTested?.join(', ') || 'None'}  \n**AI endpoints:** ${manifest.aiEndpoints?.confirmed || 0} confirmed, ${manifest.aiEndpoints?.suspected || 0} suspected\n\n`;
      md += `| Module | Status | Skipped checks |\n|--------|--------|----------------|\n${Object.entries(manifest.modules || {}).map(([name, module]) => `| ${name} | ${module.status} | ${(module.skippedChecks || []).map(check => check.label).join(', ') || 'None'} |`).join('\n')}\n\n`;
      if (manifest.blockedTests?.length) md += `**Blocked tests:**\n${manifest.blockedTests.map(block => `- ${block.reason}: ${block.url} (${block.detail})`).join('\n')}\n\n`;
    }

    md += `---\n\n`;
    md += `## Findings\n\n`;

    if (findings.length === 0) {
      md += `✅ No findings at the configured severity threshold.\n\n`;
    }

    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
      const sevFindings = findings.filter(f => f.severity === sev);
      if (sevFindings.length === 0) continue;

      const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
      md += `### ${icons[sev]} ${sev.toUpperCase()} (${sevFindings.length})\n\n`;

      for (const f of sevFindings) {
        const verification = f.verification || normalizeVerification(null, f);
        md += `#### ${f.id}: ${f.title}\n\n`;
        md += `**Severity:** ${f.severity.toUpperCase()}`;
        if (f.owasp) md += `  |  **OWASP:** ${f.owasp.id} ${f.owasp.name}`;
        md += `  \n`;
        md += `**Affected:** ${f.affected_surface}  \n`;
        md += `**Status:** ${f.status}  \n\n`;
        md += `**Verification:** ${verification.label} — ${verification.reason}  \n`;
        md += `**Method:** ${verification.method}  \n\n`;
        md += f.cvss?.scoreStatus && f.cvss?.reasons
          ? `**CVSS v3.1:** ${f.cvss.score} (${f.cvss.vectorString}) — ${f.cvss.scoreStatus === 'provisional' ? 'provisional assessment' : 'evidence-based assessment'}\n\n**Metric reasons:**\n${Object.entries(f.cvss.reasons).map(([metric, reason]) => `- ${metric}: ${reason}`).join('\n')}\n\n`
          : `**CVSS v3.1:** Not assessed; the detector did not establish all base metrics.\n\n`;
        md += `${f.description}\n\n`;

        if (Object.keys(verification.proof || {}).length > 1) {
          md += `**Verification Proof:**\n\n\`\`\`json\n${JSON.stringify(verification.proof, null, 2)}\n\`\`\`\n\n`;
        }
        if (verification.missingEvidence?.length) md += `**Evidence gaps:** ${verification.missingEvidence.join(', ')}\n\n`;

        if (f.reproduction.length > 0) {
          md += `**Reproduction Steps:**\n`;
          for (const step of f.reproduction) {
            md += `${step}\n`;
          }
          md += `\n`;
        }

        const remediation = f.remediation_llm || f.remediation;
        if (remediation) {
          const tag = f.remediation_llm ? ' (AI-assisted)' : '';
          md += `**Remediation${tag}:** ${remediation}\n\n`;
        }

        if (f.llm_triage) {
          const conf = f.llm_triage.confidence != null ? ` (confidence ${(f.llm_triage.confidence * 100).toFixed(0)}%)` : '';
          md += `**AI triage (advisory):** ${f.llm_triage.assessment}${conf}${f.llm_triage.note ? ` — ${f.llm_triage.note}` : ''}\n\n`;
        }

        md += `---\n\n`;
      }
    }

    md += `\n*Report generated by VIBE SHIELD 呪 v${meta.version}*\n`;
    return md;
  }

  _generateHTML(data) {
    const { meta, testSummary, surfaceInventory, findings } = data;
    const summary = data.dedupSummary || data.summary;
    const sevColors = {
      critical: '#ff1744',
      high: '#ff6d00',
      medium: '#ffd600',
      low: '#2979ff',
      info: '#90a4ae',
    };
    const confidence = data.verificationSummary || verificationSummary(findings);
    const manifest = data.coverage?.manifest;

    return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VIBE SHIELD Report — ${this._escapeHtml(meta.target)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --bg: #0a0a0f; --surface: #12121a; --surface-2: #1a1a25;
      --text: #e0e0e8; --text-dim: #8888a0; --accent: #00ff88;
      --critical: #ff1744; --high: #ff6d00; --medium: #ffd600;
      --low: #2979ff; --info: #90a4ae; --border: #2a2a3a;
    }
    body {
      font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
      background: var(--bg); color: var(--text); line-height: 1.6;
      padding: 2rem; max-width: 1200px; margin: 0 auto;
    }
    h1 { font-size: 1.8rem; color: var(--accent); margin-bottom: 0.5rem; }
    h2 { font-size: 1.3rem; color: var(--text); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
    h3 { font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }
    .meta { color: var(--text-dim); font-size: 0.85rem; margin-bottom: 2rem; }
    .meta span { margin-right: 2rem; }
    .summary-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 1rem; margin: 1rem 0 2rem;
    }
    .summary-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 1rem; text-align: center;
    }
    .summary-card .count { font-size: 2rem; font-weight: bold; }
    .summary-card .label { font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; }
    .sev-critical .count { color: var(--critical); }
    .sev-high .count { color: var(--high); }
    .sev-medium .count { color: var(--medium); }
    .sev-low .count { color: var(--low); }
    .sev-info .count { color: var(--info); }
    .chart-bar {
      display: flex; height: 8px; border-radius: 4px; overflow: hidden;
      margin: 1rem 0; background: var(--surface);
    }
    .chart-bar div { height: 100%; transition: width 0.3s; }
    .finding-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 1.25rem; margin: 1rem 0;
      border-left: 4px solid var(--info);
    }
    .finding-card.critical { border-left-color: var(--critical); }
    .finding-card.high { border-left-color: var(--high); }
    .finding-card.medium { border-left-color: var(--medium); }
    .finding-card.low { border-left-color: var(--low); }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
    .finding-id { font-size: 0.75rem; color: var(--text-dim); }
    .finding-title { font-weight: bold; font-size: 0.95rem; }
    .sev-badge {
      display: inline-block; padding: 2px 8px; border-radius: 4px;
      font-size: 0.7rem; font-weight: bold; text-transform: uppercase;
    }
    .sev-badge.critical { background: var(--critical); color: #fff; }
    .sev-badge.high { background: var(--high); color: #000; }
    .sev-badge.medium { background: var(--medium); color: #000; }
    .sev-badge.low { background: var(--low); color: #fff; }
    .sev-badge.info { background: var(--info); color: #000; }
    .verification-badge { display:inline-block; margin-left:.5rem; padding:2px 8px; border:1px solid var(--border); border-radius:999px; font-size:.68rem; font-weight:bold; text-transform:uppercase; }
    .verification-badge.confirmed { color:#00e676; border-color:#00e676; }
    .verification-badge.high_confidence { color:#29b6f6; border-color:#29b6f6; }
    .verification-badge.potential { color:#ffd600; border-color:#ffd600; }
    .verification-badge.informational, .verification-badge.not_assessed { color:var(--text-dim); }
    .verification-copy { margin-top:.65rem; padding:.65rem .75rem; border-left:2px solid var(--border); color:var(--text-dim); font-size:.78rem; }
    .finding-desc { font-size: 0.85rem; color: var(--text-dim); margin: 0.5rem 0; white-space: pre-wrap; }
    .finding-details { margin-top: 0.75rem; }
    .finding-details summary { cursor: pointer; font-size: 0.8rem; color: var(--accent); }
    .finding-details pre { background: var(--surface-2); padding: 0.75rem; border-radius: 4px; margin-top: 0.5rem; font-size: 0.8rem; overflow-x: auto; }
    .filter-bar { display: flex; gap: 0.5rem; margin: 1rem 0; flex-wrap: wrap; }
    .filter-btn {
      background: var(--surface); border: 1px solid var(--border); color: var(--text);
      padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: 0.8rem; font-family: inherit;
    }
    .filter-btn.active { border-color: var(--accent); color: var(--accent); }
    .filter-btn:hover { border-color: var(--accent); }
    footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 0.75rem; text-align: center; }
    .coverage { margin: 1rem 0; padding: 1rem; border: 1px solid var(--border); line-height: 1.6; }
    .finding, .meta { overflow-wrap: anywhere; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; }
    @media (max-width: 600px) { body { padding: 1rem; } .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
    @media print {
      :root { --bg: white; --surface: white; --surface-2: #eee; --text: #111; --text-dim: #444; --border: #bbb; --accent: #176144; }
      body { padding: 0; } .filters, .print-button { display: none; }
      .finding-card, .summary-grid { break-inside: avoid; } pre { color: #111; background: #eee; }
    }
  </style>
</head>
<body>
  <h1>VIBE SHIELD</h1>
  <p class="coverage"><strong>Coverage: ${this._escapeHtml(data.coverage?.status || 'unknown')}</strong> · ${this._escapeHtml(data.coverage?.note || 'Automated findings apply only to the tested surfaces.')}</p>
  <button class="filter-btn print-button" onclick="document.querySelectorAll('details').forEach(d => d.open = true); window.print()">Print / Save PDF</button>
  <div class="meta">
    <span>Target: ${this._escapeHtml(meta.target)}</span>
    <span>Modules: ${this._escapeHtml(meta.modulesLabel || formatModules(meta.modules))}</span>
    <span>Scanned: ${new Date(meta.scannedAt).toLocaleString()}</span>
  </div>

  ${meta.executiveSummary ? `
  <h2>Executive Summary</h2>
  <div class="finding-card" style="border-left-color:var(--accent)">
    <div class="finding-desc">${this._escapeHtml(meta.executiveSummary)}</div>
    <div style="font-size:0.7rem;color:var(--text-dim);margin-top:0.5rem">AI-assisted summary — advisory only</div>
  </div>` : ''}

  <h2>Severity Breakdown</h2>
  <div class="summary-grid">
    <div class="summary-card sev-critical"><div class="count">${summary.critical}</div><div class="label">Critical</div></div>
    <div class="summary-card sev-high"><div class="count">${summary.high}</div><div class="label">High</div></div>
    <div class="summary-card sev-medium"><div class="count">${summary.medium}</div><div class="label">Medium</div></div>
    <div class="summary-card sev-low"><div class="count">${summary.low}</div><div class="label">Low</div></div>
    <div class="summary-card sev-info"><div class="count">${summary.info}</div><div class="label">Info</div></div>
  </div>

  <div class="chart-bar">
    ${summary.total > 0 ? `
    <div style="width:${(summary.critical / summary.total) * 100}%;background:var(--critical)"></div>
    <div style="width:${(summary.high / summary.total) * 100}%;background:var(--high)"></div>
    <div style="width:${(summary.medium / summary.total) * 100}%;background:var(--medium)"></div>
    <div style="width:${(summary.low / summary.total) * 100}%;background:var(--low)"></div>
    <div style="width:${(summary.info / summary.total) * 100}%;background:var(--info)"></div>
    ` : '<div style="width:100%;background:var(--accent)"></div>'}
  </div>

  <h2>Verification Confidence</h2>
  <div class="summary-grid">
    <div class="summary-card"><div class="count" style="color:#00e676">${confidence.confirmed}</div><div class="label">Confirmed</div></div>
    <div class="summary-card"><div class="count" style="color:#29b6f6">${confidence.high_confidence}</div><div class="label">High confidence</div></div>
    <div class="summary-card"><div class="count" style="color:#ffd600">${confidence.potential}</div><div class="label">Potential</div></div>
    <div class="summary-card"><div class="count" style="color:var(--info)">${confidence.informational}</div><div class="label">Informational</div></div>
    <div class="summary-card"><div class="count" style="color:var(--text-dim)">${confidence.not_assessed}</div><div class="label">Not assessed</div></div>
  </div>

  <h2>Coverage</h2>
  <div class="summary-grid">
    <div class="summary-card"><div class="count" style="color:var(--accent)">${surfaceInventory.totalPages}</div><div class="label">Pages</div></div>
    <div class="summary-card"><div class="count" style="color:var(--accent)">${surfaceInventory.totalApis}</div><div class="label">API Endpoints</div></div>
    <div class="summary-card"><div class="count" style="color:var(--accent)">${surfaceInventory.totalForms}</div><div class="label">Forms</div></div>
    ${testSummary?.total ? `
    <div class="summary-card"><div class="count" style="color:var(--accent)">${testSummary.total}</div><div class="label">Tests Run</div></div>
    <div class="summary-card"><div class="count" style="color:#00e676">${testSummary.passed}</div><div class="label">Passed</div></div>
    <div class="summary-card"><div class="count" style="color:var(--critical)">${testSummary.failed + (testSummary.errors || 0)}</div><div class="label">Failed</div></div>
    ` : ''}
  </div>

  <h2>Module coverage</h2>
  ${manifest ? `<p><strong>Measured coverage:</strong> ${manifest.percent == null ? 'Not measured' : `${manifest.percent}%`}. ${this._escapeHtml(manifest.denominator)}</p>
  <div class="summary-grid">
    ${[['Pages', 'pages', 'scanned'], ['API endpoints', 'apiEndpoints', 'tested'], ['Forms', 'forms', 'submitted'], ['Parameters', 'parameters', 'mutated']].map(([label, key, tested]) => `<div class="summary-card"><div class="count">${manifest[key]?.[tested] ?? 0}/${manifest[key]?.discovered ?? 0}</div><div class="label">${label} exercised</div></div>`).join('')}
    <div class="summary-card"><div class="count">${manifest.authenticatedRoutesReached ?? 0}</div><div class="label">Authenticated routes reached</div></div>
    <div class="summary-card"><div class="count">${manifest.aiEndpoints?.confirmed ?? 0}/${(manifest.aiEndpoints?.confirmed ?? 0) + (manifest.aiEndpoints?.suspected ?? 0)}</div><div class="label">AI endpoints confirmed</div></div>
  </div>
  <p><strong>Roles tested:</strong> ${this._escapeHtml(manifest.userRolesTested?.join(', ') || 'None')}</p>
  <p><strong>Module outcomes:</strong> ${Object.entries(manifest.moduleCounts || {}).map(([key, count]) => `${this._escapeHtml(key)} ${count}`).join(' · ')}</p>
  ${manifest.blockedTests?.length ? `<h3>Blocked tests</h3><ul>${manifest.blockedTests.map(block => `<li>${this._escapeHtml(block.reason)}: ${this._escapeHtml(block.url)} (${this._escapeHtml(block.detail)})</li>`).join('')}</ul>` : ''}` : '<p>Coverage measurements were not recorded for this scan.</p>'}
  <ul>${Object.entries(manifest?.modules || data.agents || {}).map(([name, agent]) => `<li><strong>${this._escapeHtml(name)}:</strong> ${this._escapeHtml(agent.status)}${(agent.skippedChecks || []).map(check => `<p>Skipped ${this._escapeHtml(check.label)}: ${this._escapeHtml(check.reason)}</p>`).join('')}${(agent.errors || []).map(error => `<p>${this._escapeHtml(error)}</p>`).join('')}</li>`).join('')}</ul>
  <p>Safety mode: ${this._escapeHtml(data.coverage?.safetyMode || 'Unknown')}. Dependency audit: ${this._escapeHtml(data.coverage?.dependencyAudit || 'Not assessed')}.</p>
  <h2>Findings (${summary.total})</h2>
  ${findings.length === 0 ? '<p>No findings at the configured threshold. Review coverage and scan errors before drawing conclusions.</p>' : ''}
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('all', this)">All (${summary.total})</button>
    ${summary.critical > 0 ? `<button class="filter-btn" onclick="filterFindings('critical', this)">Critical (${summary.critical})</button>` : ''}
    ${summary.high > 0 ? `<button class="filter-btn" onclick="filterFindings('high', this)">High (${summary.high})</button>` : ''}
    ${summary.medium > 0 ? `<button class="filter-btn" onclick="filterFindings('medium', this)">Medium (${summary.medium})</button>` : ''}
    ${summary.low > 0 ? `<button class="filter-btn" onclick="filterFindings('low', this)">Low (${summary.low})</button>` : ''}
    ${summary.info > 0 ? `<button class="filter-btn" onclick="filterFindings('info', this)">Info (${summary.info})</button>` : ''}
  </div>

  <div id="findings-container">
    ${findings.map(f => {
      const verification = f.verification || normalizeVerification(null, f);
      return `
    <div class="finding-card ${f.severity}" data-severity="${f.severity}">
      <div class="finding-header">
        <span class="finding-id">${f.id}</span>
        <span><span class="sev-badge ${f.severity}">${f.severity}</span><span class="verification-badge ${verification.level}">${this._escapeHtml(verification.label)}</span></span>
      </div>
      <div class="finding-title">${this._escapeHtml(f.title)}</div>
      <div class="finding-desc">${this._escapeHtml(f.description)}</div>
      <div class="verification-copy"><strong>${this._escapeHtml(verification.label)}:</strong> ${this._escapeHtml(verification.reason)}<br><strong>Method:</strong> ${this._escapeHtml(verification.method)}</div>
      <div class="verification-copy"><strong>CVSS v3.1:</strong> ${f.cvss?.scoreStatus && f.cvss?.reasons ? `${this._escapeHtml(f.cvss.score)} · ${this._escapeHtml(f.cvss.vectorString)} · ${f.cvss.scoreStatus === 'provisional' ? 'Provisional' : 'Evidence based'}` : 'Not assessed; impact metrics were not established.'}</div>
      <div style="font-size:0.8rem;color:var(--text-dim);margin-top:0.5rem">
        <strong>Affected:</strong> ${this._escapeHtml(f.affected_surface)}
        ${f.owasp ? `<span style="margin-left:1rem;padding:2px 6px;border-radius:3px;background:#1a1a25;color:#00ff88;font-size:0.7rem;font-weight:bold">${f.owasp.id} ${this._escapeHtml(f.owasp.name)}</span>` : ''}
      </div>
      ${(f.remediation_llm || f.remediation) ? `<div style="font-size:0.85rem;margin-top:0.5rem;color:var(--accent)"><strong>Fix${f.remediation_llm ? ' (AI-assisted)' : ''}:</strong> ${this._escapeHtml(f.remediation_llm || f.remediation)}</div>` : ''}
      ${f.llm_triage ? `<div style="font-size:0.8rem;margin-top:0.5rem;color:var(--text-dim)"><strong>AI triage (advisory):</strong> ${this._escapeHtml(f.llm_triage.assessment)}${f.llm_triage.confidence != null ? ` (${(f.llm_triage.confidence * 100).toFixed(0)}%)` : ''}${f.llm_triage.note ? ` — ${this._escapeHtml(f.llm_triage.note)}` : ''}</div>` : ''}
      <details class="finding-details">
        <summary>Evidence & Reproduction</summary>
        <pre>${this._escapeHtml(f.reproduction?.join?.('\n') || '')}</pre>
        ${f.evidence ? `<pre>${this._escapeHtml(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2))}</pre>` : ''}
        ${Object.keys(verification.proof || {}).length > 1 ? `<pre>${this._escapeHtml(JSON.stringify(verification.proof, null, 2))}</pre>` : ''}
        ${f.cvss?.reasons ? `<pre>${this._escapeHtml(JSON.stringify(f.cvss.reasons, null, 2))}</pre>` : ''}
        ${verification.missingEvidence?.length ? `<p style="font-size:.75rem;color:var(--text-dim);margin-top:.5rem"><strong>Evidence gaps:</strong> ${this._escapeHtml(verification.missingEvidence.join(', '))}</p>` : ''}
      </details>
    </div>`;
    }).join('')}
  </div>

  <footer>VIBE SHIELD 呪 v${meta.version} — Autonomous Security & Quality Intelligence</footer>

  <script>
    function filterFindings(severity, button) {
      const cards = document.querySelectorAll('.finding-card');
      const btns = document.querySelectorAll('.filter-btn');
      btns.forEach(b => b.classList.remove('active'));
      button.classList.add('active');
      cards.forEach(card => {
        card.style.display = severity === 'all' || card.dataset.severity === severity ? 'block' : 'none';
      });
    }
  </script>
</body>
</html>`;
  }

  _escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  _timestamp() {
    return new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
  }
}

export default ReportGenerator;
