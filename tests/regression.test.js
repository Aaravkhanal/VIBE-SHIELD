import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Crawler } from '../src/core/crawler.js';
import { HeaderAnalyzer } from '../src/core/security/header-analyzer.js';
import { ReportGenerator } from '../src/reporting/report-generator.js';
import { calculateSecurityScore, generateSvgBadge } from '../src/utils/security-score.js';
import { completeScan, applyScanEvent, validateScanRequest } from '../src/utils/scan-state.js';
import { Orchestrator } from '../src/agents/orchestrator.js';
import { BaseAgent } from '../src/agents/base-agent.js';
import { createFinding, normalizeVerification, verificationSummary } from '../src/utils/finding.js';

const report = (target = 'http://fixture.test/') => ({ meta: { target, modules: ['security'], scannedAt: new Date().toISOString() }, coverage: { status: 'complete' }, agents: {}, surfaceInventory: { totalPages: 1 }, summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 }, findings: [] });
const scan = (scanId = 'test') => ({ scanId, url: 'http://fixture.test/', startTime: Date.now(), agents: { 'VIBE-SHIELD-SEC': { status: 'pending' } }, terminalLogs: [] });
function temp(t) { const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vibe-regression-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir; }

test('crawler resolves when page budget is reached with links queued', { timeout: 1000 }, async () => {
    const crawler = new Crawler({ crawler: { max_pages: 1, concurrency: 2 } });
    crawler.baseUrl = new URL('http://fixture.test');
    crawler._crawlPage = async () => ['http://fixture.test/next'];
    await crawler._runParallelCrawl({}, [{ url: 'http://fixture.test/', depth: 0 }]);
    assert.equal(crawler.visited.size, 1);
});

test('scan completion never reuses another scan report', t => {
    const root = temp(t); fs.mkdirSync(path.join(root, 'unrelated'));
    fs.writeFileSync(path.join(root, 'unrelated/report.json'), JSON.stringify(report()));
    const state = scan(); const score = completeScan(state, 1, root);
    assert.equal(state.status, 'failed'); assert.equal(state.report, null); assert.equal(score.overallScore, null);
});

test('matching reports load by exact scan ID and preserve zero scores', t => {
    const root = temp(t); fs.mkdirSync(path.join(root, 'test'));
    const data = report(); data.summary.critical = 4;
    fs.writeFileSync(path.join(root, 'test/report.json'), JSON.stringify(data));
    const state = scan(); const score = completeScan(state, 0, root);
    assert.equal(state.status, 'completed'); assert.equal(score.overallScore, 0);
    assert.equal(state.reportHtmlUrl, '/vibe-shield-reports/test/report.html');
    assert.ok(fs.existsSync(path.join(root, 'test/terminal.json')));
});

test('mismatched target and incomplete scans cannot receive a passing score', t => {
    const root = temp(t); fs.mkdirSync(path.join(root, 'test'));
    fs.writeFileSync(path.join(root, 'test/report.json'), JSON.stringify(report('https://wrong.test/')));
    assert.equal(completeScan(scan(), 0, root).overallScore, null);
    const data = report(); data.coverage.status = 'incomplete';
    fs.writeFileSync(path.join(root, 'test/report.json'), JSON.stringify(data));
    const state = scan(); assert.equal(completeScan(state, 0, root).overallScore, null); assert.equal(state.status, 'partial');
});

test('score does not invent grades or untested category scores', () => {
    assert.equal(calculateSecurityScore(null).overallScore, null);
    assert.equal(calculateSecurityScore({ findings: [] }).overallScore, null);
    assert.equal(calculateSecurityScore(report()).subCategories.aiSafety.score, null);
    assert.doesNotMatch(generateSvgBadge('<script>', 50, 'red" onload="alert(1)'), /<script>|onload=/);
});

test('structured progress tracks errors, skips, and findings', () => {
    const state = scan(); const agentName = 'VIBE-SHIELD-SEC';
    applyScanEvent(state, { event: 'agent:started', data: { agentName } });
    applyScanEvent(state, { event: 'agent:progress', data: { agentName, progress: 50, message: 'Checking headers' } });
    assert.equal(state.agents[agentName].message, 'Checking headers');
    applyScanEvent(state, { event: 'finding:new', data: { agentName, finding: { title: 'Missing CSP', severity: 'medium' } } });
    assert.equal(state.liveFindingsCount, 1);
    applyScanEvent(state, { event: 'agent:error', data: { agentName, error: 'Offline' } });
    assert.equal(state.agents[agentName].status, 'error');
});

test('every finding carries a conservative verification level', () => {
    const potential = createFinding({ module: 'security', title: 'Possible issue', severity: 'high', affected_surface: 'https://fixture.test', description: 'heuristic' });
    const information = createFinding({ module: 'security', title: 'Surface found', severity: 'info', affected_surface: 'https://fixture.test', description: 'observed' });
    assert.equal(potential.verification.level, 'potential');
    assert.equal(information.verification.level, 'informational');
    assert.deepEqual(verificationSummary([potential, information]), {
        confirmed: 0, high_confidence: 0, potential: 1, informational: 1, not_assessed: 0, total: 2
    });
});

test('confirmed findings require complete replayable proof and redact secrets', () => {
    const incomplete = normalizeVerification({ level: 'confirmed', proof: { trace: { executed: true } } }, { severity: 'high', evidence: 'marker' });
    assert.equal(incomplete.level, 'high_confidence');
    assert.ok(incomplete.missingEvidence.includes('originalRequest'));

    const complete = normalizeVerification({ level: 'confirmed', proof: {
        originalRequest: { url: 'https://fixture.test', headers: { Authorization: 'Bearer private-token' } },
        mutatedRequest: { url: 'https://fixture.test?q=payload' }, baselineResponse: { status: 200 },
        vulnerableResponse: { status: 200 }, responseDifference: { markerExecuted: true },
        trace: { marker: 'executed' }, reproductionCommand: 'curl https://fixture.test?q=payload',
        timestamp: new Date().toISOString(), accountRole: 'anonymous'
    } }, { severity: 'high', evidence: 'marker' });
    assert.equal(complete.level, 'confirmed');
    assert.equal(complete.proof.originalRequest.headers.Authorization, '[REDACTED]');
    assert.deepEqual(complete.missingEvidence, []);
});

test('invalid scan inputs rejected before spawning', () => {
    assert.throws(() => validateScanRequest('file:///etc/passwd', ['security'], 10, 'passive'));
    assert.throws(() => validateScanRequest('https://test.test', ['bad'], 10, 'passive'));
    assert.throws(() => validateScanRequest('https://test.test', ['security'], 'NaN', 'passive'));
    assert.throws(() => validateScanRequest('https://test.test', ['security'], 10, 'bad'));
});

test('headers use captured browser responses and evaluate each route', async () => {
    const analyzer = new HeaderAnalyzer();
    analyzer._fetchHeaders = () => { throw new Error('should not refetch'); };
    const findings = await analyzer.analyze({ pages: [{ url: 'http://fixture.test/a', status: 200, headers: {} }, { url: 'http://fixture.test/b', status: 200, headers: {} }] });
    assert.ok(findings.some(f => f.affected_surface.endsWith('/a')));
    assert.ok(findings.some(f => f.affected_surface.endsWith('/b')));
});

test('all report formats use deduplicated counts, escaped target and coverage', async t => {
    const root = temp(t);
    const finding = { id: 'one', severity: 'high', title: 'XSS', description: 'test', module: 'security', affected_surface: '/', reproduction: ['first', 'second'] };
    const generator = new ReportGenerator({ target_url: 'https://fixture.test/<script>alert(1)</script>' });
    await generator.generate({ findings: [finding, { ...finding, id: 'two' }], deduplicated: [finding], agents: { security: { status: 'partial' } }, outputDir: root, modules: ['security'], surfaceInventory: { totalPages: 1, pages: [{ url: '/', status: 200 }] } });
    const html = fs.readFileSync(path.join(root, 'report.html'), 'utf8');
    assert.match(html, /Findings \(1\)/); assert.match(html, /Coverage: incomplete/);
    assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
    assert.match(html, /first\nsecond/);
    assert.match(html, /Verification Confidence/);
    const json = JSON.parse(fs.readFileSync(path.join(root, 'report.json'), 'utf8'));
    assert.equal(json.findings[0].verification.level, 'potential');
    assert.equal(json.verificationSummary.potential, 1);
    const sarif = JSON.parse(fs.readFileSync(path.join(root, 'report.sarif'), 'utf8'));
    assert.equal(sarif.runs[0].results[0].properties.verificationLevel, 'potential');
    for (const file of ['report.json', 'report.md', 'report.sarif']) assert.ok(fs.existsSync(path.join(root, file)), file);
});

test('failed dependency skips downstream modules without a clean result', async () => {
    class Crawl extends BaseAgent { get name() { return 'VIBE-SHIELD-CRAWL'; } async _execute() { throw new Error('offline'); } }
    class Downstream extends BaseAgent { get name() { return 'VIBE-SHIELD-SEC'; } get dependencies() { return ['VIBE-SHIELD-CRAWL']; } async _execute() { throw new Error('must not execute'); } }
    const orchestrator = new Orchestrator({}, null); orchestrator.register(new Crawl()).register(new Downstream());
    const results = await orchestrator.run();
    assert.equal(results.agents['VIBE-SHIELD-CRAWL'].status, 'error');
    assert.equal(results.agents['VIBE-SHIELD-SEC'].status, 'skipped');
});

test('website scans do not audit the scanner own dependencies', async () => {
    const { DependencyAuditor } = await import('../src/core/security/dependency-auditor.js');
    const auditor = new DependencyAuditor({});
    auditor._runNpmAudit = () => { throw new Error('wrong project'); };
    auditor._checkPackageJson = () => { throw new Error('wrong project'); };
    assert.deepEqual(await auditor.audit(), []);
});

test('no AI findings do not imply guardrails are verified', async () => {
    const { evaluateAiThreatMatrix } = await import('../src/utils/ai-threat-matrix.js');
    assert.ok(evaluateAiThreatMatrix({}).every(c => c.status === 'NOT_VERIFIED'));
    assert.ok(evaluateAiThreatMatrix({ findings: [{ module: 'security', title: 'Missing CSP header', description: '' }] }).every(c => c.status === 'NOT_VERIFIED'));
});

test('IP and localhost scans never enumerate unrelated external domains', async () => {
    const { SubdomainScanner } = await import('../src/core/security/subdomain-scanner.js');
    const scanner = new SubdomainScanner(); scanner._bruteforceScan = () => { throw new Error('out of scope'); };
    assert.deepEqual(await scanner.scan({ baseUrl: 'http://127.0.0.1:8080' }), []);
    assert.deepEqual(await scanner.scan({ baseUrl: 'http://localhost:8080' }), []);
});

test('IDs preserve requested URL-safe length and reject invalid bounds', async () => {
    const { randomId } = await import('../src/utils/id.js');
    for (const size of [6, 8, 21, 40]) assert.match(randomId(size), new RegExp(`^[A-Za-z0-9_-]{${size}}$`));
    assert.throws(() => randomId(-1)); assert.throws(() => randomId(1.5));
    assert.equal(new Set(Array.from({ length: 1000 }, () => randomId(8))).size, 1000);
});
