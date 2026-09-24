import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';
import { Crawler } from '../src/core/crawler.js';
import { XSSScanner } from '../src/core/security/xss-scanner.js';
import { SQLiProber } from '../src/core/security/sqli-prober.js';

const fixture = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    res.setHeader('Content-Type', 'text/html');
    if (url.pathname.startsWith('/unavailable')) { res.writeHead(404); return res.end('Not available'); }
    const input = url.searchParams.get('q') || '';
    if (url.pathname === '/sql' && input.includes("'")) return res.end('ERROR: syntax error at or near PostgreSQL');
    const output = url.pathname === '/escaped' ? input.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;') : input;
    res.end(`<html><head><title>Local regression fixture</title></head><body><h1>Fixture</h1>${output}<a href="/next">Next</a></body></html>`);
});
fixture.listen(0, '127.0.0.1'); await once(fixture, 'listening');
const target = `http://127.0.0.1:${fixture.address().port}`;
const reportsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vibe-browser-'));
const server = spawn(process.execPath, ['src/server.js'], { env: { ...process.env, PORT: '3197', VIBE_SHIELD_REPORTS_DIR: reportsDir }, stdio: ['ignore', 'pipe', 'pipe'] });
let serverLog = ''; server.stdout.on('data', b => serverLog += b); server.stderr.on('data', b => serverLog += b);
let browser; const createdScans = [];
try {
    for (let i = 0; i < 100; i++) {
        try { if ((await fetch('http://127.0.0.1:3197/')).ok) break; } catch {}
        await new Promise(r => setTimeout(r, 100));
    }
    browser = await chromium.launch();
    const context = await browser.newContext();
    const crawler = new Crawler({ crawler: { max_pages: 1, timeout: 5000 } });
    const inventory = await crawler.crawl(target + '/');
    assert.equal(inventory.totalPages, 1); assert.ok(inventory.pages[0].headers);
    const scanner = new XSSScanner(); scanner._candidateParams = ['q'];
    await scanner._testURLParamReflection(context, inventory);
    assert.ok(scanner.findings.some(f => f.severity === 'high' && JSON.parse(f.evidence).executed), 'executable XSS must be detected');
    const executedXss = scanner.findings.find(f => f.verification?.level === 'confirmed');
    assert.ok(executedXss, 'browser-executed XSS must be marked confirmed');
    assert.equal(executedXss.verification.missingEvidence.length, 0);
    assert.equal(executedXss.verification.proof.baselineResponse.markerValue, null);
    assert.equal(executedXss.verification.proof.responseDifference.vulnerableMarkerValue, 1);
    assert.match(executedXss.verification.proof.reproductionCommand, /playwright/);
    assert.equal(executedXss.verification.proof.trace.steps.at(-1).observedValue, 1);
    assert.equal(executedXss.cvss.scoreStatus, 'evidence_based');
    assert.equal(executedXss.cvss.selectedMetrics.userInteraction, 'REQUIRED');
    assert.match(executedXss.cvss.reasons.integrity, /window\./);
    const escaped = new XSSScanner(); escaped._candidateParams = ['q'];
    await escaped._testURLParamReflection(context, { pages: [{ url: target + '/escaped', status: 200 }] });
    assert.equal(escaped.findings.length, 0, 'escaped payload must not be XSS');
    const sql = await new SQLiProber()._errorBasedTest(target + '/sql', 'q');
    assert.equal(sql.severity, 'critical');
    assert.equal(sql.cvss.selectedMetrics.confidentiality, 'LOW');
    assert.equal(sql.cvss.selectedMetrics.integrity, 'NONE');
    console.log('PASS: real browser crawl limit, executed XSS, escaped negative control, SQL error detection');

    const page = await context.newPage(); const pageErrors = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    await page.goto('http://127.0.0.1:3197/', { waitUntil: 'domcontentloaded' });
    await page.locator('#scan-config-toggle-btn').click();
    assert.equal(await page.locator('#organization-domains').isDisabled(), true);
    await page.locator('#external-subdomains').check();
    assert.equal(await page.locator('#organization-domains').isEnabled(), true);
    await page.locator('#external-subdomains').uncheck();
    await page.locator('#target-url').fill(target + '/');
    // Keep only security selected and choose passive mode for the full pipeline fixture.
    await page.evaluate(() => {
        document.querySelectorAll('.module-check').forEach(label => { const input = label.querySelector('input'); input.checked = input.value === 'security'; label.classList.toggle('checked', input.checked); });
        document.querySelector('#safety-mode').value = 'passive';
        document.querySelector('#max-pages').value = '1';
    });
    const responsePromise = page.waitForResponse(r => r.url().endsWith('/api/scan') && r.request().method() === 'POST');
    await page.locator('form').first().evaluate(form => form.requestSubmit());
    const response = await responsePromise; const start = await response.json(); assert.ok(start.scanId, JSON.stringify(start)); createdScans.push(start.scanId);
    await page.waitForFunction(() => document.querySelector('#terminal-output').textContent.includes('Starting'), { timeout: 15000 });
    let status;
    for (let i = 0; i < 180; i++) {
        status = await (await fetch(`http://127.0.0.1:3197/api/scan/${start.scanId}`)).json();
        if (status.completed) break;
        await new Promise(r => setTimeout(r, 1000));
    }
    assert.equal(status.status, 'completed', JSON.stringify(status));
    assert.equal(status.report.meta.target, target + '/');
    assert.ok(status.report.findings.length > 0);
    assert.ok(status.terminalLogs.some(l => l.text.includes('headers') || l.text.includes('Headers')));
    await page.waitForSelector('#results-section:not(.hidden)', { timeout: 5000 });
    assert.equal(await page.locator('#count-total').textContent(), String(status.report.dedupSummary.total));
    await page.locator('[data-sev-filter="high"]').click();
    assert.equal(await page.locator('#findings-table-body tr').count(), status.report.dedupSummary.high);
    await page.locator('[data-sev-filter="all"]').click();
    await page.locator('#open-exec-report-results-btn').click();
    await page.waitForFunction(() => document.querySelector('#exec-findings-detail').textContent.includes('Content-Security'));
    assert.equal(await page.locator('#exec-meta-url').textContent(), target + '/');
    await page.screenshot({ path: '/tmp/vibe-shield-report-ui.png' });
    await page.emulateMedia({ media: 'print' });
    await page.pdf({ path: '/tmp/vibe-shield-executive.pdf', format: 'A4' });
    await page.emulateMedia({ media: 'screen' });
    await page.locator('#close-exec-modal-btn').click();
    await page.locator('.trend-filter-btn[data-metric="ai"]').click();
    assert.equal(await page.evaluate(() => window.trendEngine.activeMetric), 'ai');
    assert.equal(await page.evaluate(() => window.trendEngine.computedPoints.length), 0);
    assert.equal(await page.evaluate(() => window.trendEngine.points.length), 1);
    assert.ok(!(await page.evaluate(() => window.radialSiteMap.nodes.map(n => n.path))).includes('/dashboard'));
    await page.locator('#sitemap-graph-canvas').scrollIntoViewIfNeeded();
    assert.ok(await page.locator('#sitemap-graph-canvas').evaluate(canvas => canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data.some((value, i) => i % 4 === 3 && value > 0)), 'surface graph must paint visible content');
    await page.screenshot({ path: '/tmp/vibe-shield-graphs-ui.png' });
    assert.ok(await page.evaluate(() => window.radialSiteMap.nodes.length > 1));
    assert.ok(await page.locator('#findings-table-body tr').first().evaluate(row => row.getBoundingClientRect().height < 300));
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: '/tmp/vibe-shield-mobile-ui.png' });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), JSON.stringify(await page.evaluate(() => [...document.querySelectorAll('body *')].filter(el => el.getBoundingClientRect().right > innerWidth + 1 && !el.closest('table')).slice(0, 15).map(el => ({ tag: el.tagName, id: el.id, cls: el.className, right: el.getBoundingClientRect().right })))));
    await page.locator('#results-section').scrollIntoViewIfNeeded();
    await page.screenshot({ path: '/tmp/vibe-shield-mobile-ui.png' });
    const reportResponse = await fetch('http://127.0.0.1:3197' + status.reportHtmlUrl); assert.equal(reportResponse.status, 200);
    await page.goto('http://127.0.0.1:3197' + status.reportHtmlUrl);
    await page.pdf({ path: '/tmp/vibe-shield-regression-report.pdf', format: 'A4' });
    assert.equal((await fetch('http://127.0.0.1:3197/api/scan/not-a-scan/executive')).status, 404);
    const startScan = async url => {
        const response = await fetch('http://127.0.0.1:3197/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url, modules: ['security'], safetyMode: 'passive', maxPages: 1 }) });
        assert.equal(response.status, 200); return response.json();
    };
    const finish = async id => {
        for (let i = 0; i < 90; i++) {
            const state = await (await fetch(`http://127.0.0.1:3197/api/scan/${id}`)).json();
            if (state.completed) return state;
            await new Promise(r => setTimeout(r, 1000));
        }
        throw new Error('Scan did not finish');
    };
    const concurrent = await Promise.all(['/one', '/two'].map(route => startScan(target + route)));
    const completed = await Promise.all(concurrent.map(({ scanId }) => finish(scanId)));
    for (let i = 0; i < completed.length; i++) {
        assert.equal(completed[i].report.meta.target, target + ['/one', '/two'][i]);
        assert.equal(completed[i].reportHtmlUrl, `/vibe-shield-reports/${concurrent[i].scanId}/report.html`);
        assert.ok(!completed[i].report.findings.some(f => f.title.includes('Dependency')));
    }
    const failedStart = await startScan(target + '/unavailable');
    const failed = await finish(failedStart.scanId);
    assert.equal(failed.status, 'partial'); assert.equal(failed.score, null);
    assert.equal(failed.report.agents['VIBE-SHIELD-CRAWL'].status, 'error');
    assert.equal(failed.report.agents['VIBE-SHIELD-SEC'].status, 'skipped');
    const gate = await fetch('http://127.0.0.1:3197/api/webhook/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: target + '/unavailable', modules: ['security'], safetyMode: 'passive', maxPages: 1 }) });
    assert.equal(gate.status, 422); assert.equal((await gate.json()).gate.passed, false);
    assert.deepEqual(pageErrors, []);
    console.log('PASS: isolated concurrent reports, failed-crawl diagnostics, failed CI gate, mobile overflow and compact finding rows');
    console.log('PASS: full server scan, SSE live console, nonzero findings, exact report, real trends, executive report, PDF rendering; no browser errors');
} catch (err) { console.error(serverLog); throw err; }
finally { await browser?.close(); server.kill(); fixture.closeAllConnections(); fixture.close(); fs.rmSync(reportsDir, { recursive: true, force: true }); }
