import fs from 'node:fs';
import path from 'node:path';
import { calculateSecurityScore } from './security-score.js';

export function validateScanRequest(url, modules, maxPages, safetyMode) {
    const target = new URL(url);
    if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) throw new Error('Use an HTTP(S) URL without embedded credentials.');
    if (!Array.isArray(modules) || !modules.length || modules.some(m => !['qa', 'security', 'ai', 'logic', 'api'].includes(m))) throw new Error('Select valid scan modules.');
    if (!Number.isInteger(Number(maxPages)) || Number(maxPages) < 1 || Number(maxPages) > 500) throw new Error('maxPages must be an integer between 1 and 500.');
    if (!['passive', 'safe-active', 'aggressive'].includes(safetyMode)) throw new Error('Invalid safety mode.');
}

export function applyScanEvent(scan, { event, data = {} }) {
    scan.structuredEvents = true;
    const agent = scan.agents[data.agentName];
    if (agent) {
        if (event === 'agent:started') Object.assign(agent, { status: 'running', message: 'Starting…' });
        if (event === 'agent:progress') Object.assign(agent, { message: data.message, progress: data.progress });
        if (event === 'agent:completed') Object.assign(agent, { status: data.status || 'done', message: `${data.findingsCount} findings · ${(data.duration / 1000).toFixed(1)}s`, findingsCount: data.findingsCount });
        if (event === 'agent:error') Object.assign(agent, { status: 'error', message: data.error });
        if (event === 'agent:skipped') Object.assign(agent, { status: 'skipped', message: data.message });
    }
    if (event === 'finding:new') scan.liveFindingsCount = (scan.liveFindingsCount || 0) + 1;
    if (['agent:progress', 'agent:error', 'agent:skipped', 'finding:new'].includes(event)) {
        scan.terminalLogs.push({ time: new Date().toISOString().slice(11, 19), agent: (data.agentName || 'SYSTEM').replace('VIBE-SHIELD-', ''), level: event === 'agent:error' ? 'error' : 'info', text: data.message || data.error || `[${data.finding?.severity}] ${data.finding?.title}` });
        if (scan.terminalLogs.length > 1500) scan.terminalLogs.shift();
    }
}

export function completeScan(scan, exitCode, reportsDir) {
    scan.completed = true;
    scan.duration = ((Date.now() - scan.startTime) / 1000).toFixed(1);
    scan.status = 'failed';
    scan.report = null;
    scan.reportHtmlUrl = null;
    try {
        const directory = path.join(reportsDir, scan.scanId);
        const report = JSON.parse(fs.readFileSync(path.join(directory, 'report.json'), 'utf8'));
        if (report.meta?.target !== scan.url) throw new Error('Report target does not match this scan.');
        scan.report = report;
        scan.reportHtmlUrl = `/vibe-shield-reports/${scan.scanId}/report.html`;
        scan.status = exitCode === 0 && report.coverage?.status === 'complete' ? 'completed' : 'partial';
        fs.writeFileSync(path.join(directory, 'terminal.json'), JSON.stringify(scan.terminalLogs, null, 2));
    } catch (err) {
        scan.failureReason = scan.processError || `Scan exited with code ${exitCode ?? 'unknown'} without a valid report. ${err.code === 'ENOENT' ? 'See the live logs for the underlying error.' : err.message}`;
    }
    if (scan.status === 'partial') scan.failureReason = 'Scan coverage is incomplete. Review module errors before relying on these findings.';
    for (const agent of Object.values(scan.agents)) {
        if (['pending', 'running'].includes(agent.status)) Object.assign(agent, { status: 'error', message: 'Scan ended before this module completed' });
    }
    const scoreData = calculateSecurityScore(scan.status === 'completed' ? scan.report : null);
    Object.assign(scan, { score: scoreData.overallScore, grade: scoreData.grade, scoreData });
    return scoreData;
}
