import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import { nanoid } from 'nanoid';
import { generateAutoPatch } from './utils/patch-generator.js';
import { calculateSecurityScore, generateSvgBadge } from './utils/security-score.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const REPORTS_DIR = path.join(ROOT_DIR, 'vibe-shield-reports');

const PORT = process.env.PORT || 3000;

// In-memory store for scans
const activeScans = new Map();
const scanHistory = [];
const scanSseClients = new Map(); // scanId -> Set of SSE response streams

function broadcastScanProgress(scanId, data) {
    const clients = scanSseClients.get(scanId);
    if (!clients || clients.size === 0) return;
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    for (const client of clients) {
        try {
            client.write(payload);
        } catch (err) {
            clients.delete(client);
        }
    }
}

function initScanHistoryFromDisk() {
    try {
        if (!fs.existsSync(REPORTS_DIR)) return;
        const reportDirs = fs.readdirSync(REPORTS_DIR)
            .filter(d => {
                const p = path.join(REPORTS_DIR, d);
                return fs.statSync(p).isDirectory() && d !== 'logs' && d !== 'screenshots';
            })
            .sort()
            .reverse();

        for (const dir of reportDirs) {
            const jsonPath = path.join(REPORTS_DIR, dir, 'report.json');
            if (fs.existsSync(jsonPath)) {
                try {
                    const data = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
                    scanHistory.push({
                        scanId: dir,
                        url: data.meta?.target || 'Unknown',
                        timestamp: data.meta?.scannedAt || fs.statSync(jsonPath).mtime.toISOString(),
                        duration: data.meta?.duration ? (data.meta.duration / 1000).toFixed(1) : '0',
                        findingsCount: data.dedupSummary?.total ?? data.summary?.total ?? 0,
                        reportHtmlUrl: `/vibe-shield-reports/${dir}/report.html`
                    });
                } catch (e) {
                    // ignore malformed report
                }
            }
        }
    } catch (err) {
        console.error('Error reading scan history from disk:', err);
    }
}

initScanHistoryFromDisk();

function serveStaticFile(res, filePath, contentType) {
    fs.readFile(filePath, (err, content) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('404 Not Found');
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content);
        }
    });
}

function getContentType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    switch (ext) {
        case '.html': return 'text/html';
        case '.css': return 'text/css';
        case '.js': return 'text/javascript';
        case '.json': return 'application/json';
        case '.png': return 'image/png';
        case '.jpg': case '.jpeg': return 'image/jpeg';
        case '.svg': return 'image/svg+xml';
        default: return 'application/octet-stream';
    }
}

const server = http.createServer((req, res) => {
    const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
    const pathname = parsedUrl.pathname;

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    // Serve static frontend assets
    if (pathname === '/' || pathname === '/index.html') {
        return serveStaticFile(res, path.join(PUBLIC_DIR, 'index.html'), 'text/html');
    }
    if (pathname === '/styles.css') {
        return serveStaticFile(res, path.join(PUBLIC_DIR, 'styles.css'), 'text/css');
    }
    if (pathname === '/app.js') {
        return serveStaticFile(res, path.join(PUBLIC_DIR, 'app.js'), 'text/javascript');
    }

    // Serve generated scan HTML/JSON report files dynamically
    if (pathname.startsWith('/vibe-shield-reports/')) {
        const relativeReportPath = pathname.replace('/vibe-shield-reports/', '');
        const fullReportPath = path.join(REPORTS_DIR, relativeReportPath);
        if (fs.existsSync(fullReportPath) && fullReportPath.startsWith(REPORTS_DIR)) {
            return serveStaticFile(res, fullReportPath, getContentType(fullReportPath));
        }
    }

    // API: Start Scan
    if (pathname === '/api/scan' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const { url, modules = ['qa', 'security', 'ai', 'logic', 'api'], safetyMode = 'safe-active', maxPages = '25' } = JSON.parse(body);

                if (!url) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ error: 'Missing target URL' }));
                }

                let targetUrl = url.trim();
                if (!/^https?:\/\//i.test(targetUrl)) {
                    targetUrl = 'https://' + targetUrl;
                }

                const scanId = nanoid(8);
                const startTime = Date.now();

                const scanData = {
                    scanId,
                    url: targetUrl,
                    status: 'running',
                    startTime,
                    completed: false,
                    duration: 0,
                    agents: {
                        'VIBE-SHIELD-CRAWL': { status: 'pending', message: 'Starting...' },
                        'VIBE-SHIELD-QA': { status: 'pending', message: 'Waiting for crawl...' },
                        'VIBE-SHIELD-SEC': { status: 'pending', message: 'Waiting for crawl...' },
                        'VIBE-SHIELD-AI': { status: 'pending', message: 'Waiting for crawl...' },
                        'VIBE-SHIELD-LOGIC': { status: 'pending', message: 'Waiting for crawl...' },
                        'VIBE-SHIELD-API': { status: 'pending', message: 'Waiting for crawl...' },
                    },
                    terminalLogs: [
                        {
                            time: new Date().toISOString().substring(11, 19),
                            agent: 'SYSTEM',
                            level: 'info',
                            text: `[VIBE-SHIELD] Autonomous scan initiated for ${targetUrl} (modules: ${modules.join(', ')})`
                        }
                    ],
                    report: null,
                    reportHtmlUrl: null
                };

                activeScans.set(scanId, scanData);

                // Build CLI arguments
                const args = [
                    path.join(ROOT_DIR, 'src', 'cli.js'),
                    'scan',
                    targetUrl,
                    '-m', modules.join(','),
                    '--max-pages', maxPages,
                    '--prod-safe'
                ];

                const child = spawn('node', args, { cwd: ROOT_DIR });

                child.stdout.on('data', data => {
                    const text = data.toString();
                    parseScanLogs(scanData, text);
                    broadcastScanProgress(scanId, scanData);
                });

                child.stderr.on('data', data => {
                    const text = data.toString();
                    parseScanLogs(scanData, text);
                    broadcastScanProgress(scanId, scanData);
                });

                child.on('close', code => {
                    scanData.completed = true;
                    scanData.status = 'completed';
                    scanData.duration = ((Date.now() - startTime) / 1000).toFixed(1);

                    // Try reading latest generated report.json
                    try {
                        const reportDirs = fs.readdirSync(REPORTS_DIR)
                            .filter(d => fs.statSync(path.join(REPORTS_DIR, d)).isDirectory())
                            .sort()
                            .reverse();

                        if (reportDirs.length > 0) {
                            const latestDir = reportDirs[0];
                            const reportJsonPath = path.join(REPORTS_DIR, latestDir, 'report.json');
                            if (fs.existsSync(reportJsonPath)) {
                                const reportContent = JSON.parse(fs.readFileSync(reportJsonPath, 'utf-8'));
                                scanData.report = reportContent;
                                scanData.reportHtmlUrl = `/vibe-shield-reports/${latestDir}/report.html`;

                                // Persist terminal logs alongside report for future inspection
                                const terminalLogPath = path.join(REPORTS_DIR, latestDir, 'terminal.json');
                                fs.writeFileSync(terminalLogPath, JSON.stringify(scanData.terminalLogs || [], null, 2));
                            }
                        }
                    } catch (err) {
                        console.error('Error fetching report or saving logs:', err);
                    }

                    // Save to history (cap at 50 entries to prevent unbounded memory growth)
                    if (scanHistory.length >= 50) scanHistory.pop();
                    scanHistory.unshift({
                        scanId,
                        url: targetUrl,
                        timestamp: new Date().toISOString(),
                        duration: scanData.duration,
                        findingsCount: scanData.report?.summary?.total || 0,
                        reportHtmlUrl: scanData.reportHtmlUrl
                    });

                    broadcastScanProgress(scanId, scanData);
                });

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ scanId, targetUrl, status: 'started' }));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    // API: SSE Stream for Live Scan Progress
    if (pathname.startsWith('/api/scan/') && pathname.endsWith('/events') && req.method === 'GET') {
        const scanId = pathname.replace('/api/scan/', '').replace('/events', '');
        const scanData = activeScans.get(scanId);

        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache, no-transform',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*'
        });
        res.write('\n'); // keep-alive ping

        if (!scanData) {
            res.write(`data: ${JSON.stringify({ error: 'Scan ID not found', completed: true })}\n\n`);
            return res.end();
        }

        // Send initial current state immediately
        res.write(`data: ${JSON.stringify(scanData)}\n\n`);

        if (scanData.completed) {
            return res.end();
        }

        if (!scanSseClients.has(scanId)) {
            scanSseClients.set(scanId, new Set());
        }
        const clientSet = scanSseClients.get(scanId);
        clientSet.add(res);

        req.on('close', () => {
            clientSet.delete(res);
            if (clientSet.size === 0) {
                scanSseClients.delete(scanId);
            }
        });
        return;
    }

    // API: Get Terminal Logs for Scan
    if (pathname.startsWith('/api/scan/') && pathname.endsWith('/logs') && req.method === 'GET') {
        const scanId = pathname.replace('/api/scan/', '').replace('/logs', '');
        const scanData = activeScans.get(scanId);

        if (scanData && scanData.terminalLogs) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ scanId, logs: scanData.terminalLogs }));
        }

        // Try reading persisted terminal.json from report directory
        const reportPath = path.join(REPORTS_DIR, scanId, 'terminal.json');
        if (fs.existsSync(reportPath)) {
            try {
                const logs = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
                res.writeHead(200, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ scanId, logs }));
            } catch (e) {}
        }

        // Return empty logs if not found
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ scanId, logs: [] }));
    }

    // API: Get Scan Status
    if (pathname.startsWith('/api/scan/') && req.method === 'GET') {
        const scanId = pathname.replace('/api/scan/', '');
        const scanData = activeScans.get(scanId);
        if (!scanData) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Scan ID not found' }));
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(scanData));
    }

    // API: Get Scan History
    if (pathname === '/api/scans/history' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(scanHistory.slice(0, 20)));
    }

    // API: Dynamic SVG Security Badge
    if (pathname.startsWith('/api/badge') && req.method === 'GET') {
        const scanId = parsedUrl.searchParams.get('scanId') || pathname.replace('/api/badge/', '').replace('/api/badge', '');
        let grade = 'A';
        let score = 95;
        let color = '#00ff88';

        if (scanId && fs.existsSync(path.join(REPORTS_DIR, scanId, 'report.json'))) {
            try {
                const rep = JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, scanId, 'report.json'), 'utf-8'));
                const scoreData = calculateSecurityScore(rep);
                grade = scoreData.grade;
                score = scoreData.overallScore;
                color = scoreData.gradeColor;
            } catch(e) {}
        } else if (parsedUrl.searchParams.get('grade')) {
            grade = parsedUrl.searchParams.get('grade');
            score = parsedUrl.searchParams.get('score') || '90';
            color = parsedUrl.searchParams.get('color') || '#00ff88';
        }

        const svg = generateSvgBadge(grade, score, color);
        res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-cache' });
        return res.end(svg);
    }

    // API: AI Auto-Patch Generator
    if (pathname === '/api/patch' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const finding = JSON.parse(body);
                const patch = generateAutoPatch(finding);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(patch));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 Not Found');
});

function stripAnsi(str) {
    return str.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '');
}

function parseScanLogs(scanData, text) {
    for (const agentName of Object.keys(scanData.agents)) {
        if (text.includes(`[${agentName}] Complete`) || text.includes(`✔ [${agentName}]`)) {
            scanData.agents[agentName].status = 'done';
            scanData.agents[agentName].message = 'Complete ✔';
        } else if (text.includes(`[${agentName}] Starting`) || text.includes(`- [${agentName}]`)) {
            scanData.agents[agentName].status = 'running';
            scanData.agents[agentName].message = 'Active probing...';
        } else if (text.includes(`[${agentName}] Error`) || text.includes(`✘ [${agentName}]`)) {
            scanData.agents[agentName].status = 'error';
            scanData.agents[agentName].message = 'Error encountered';
        }
    }

    // Parse structured terminal log entries
    if (scanData.terminalLogs) {
        const clean = stripAnsi(text);
        const lines = clean.split('\n');
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;

            let agentTag = 'SYSTEM';
            if (trimmed.includes('VIBE-SHIELD-CRAWL')) agentTag = 'CRAWL';
            else if (trimmed.includes('VIBE-SHIELD-SEC')) agentTag = 'SEC';
            else if (trimmed.includes('VIBE-SHIELD-AI')) agentTag = 'AI';
            else if (trimmed.includes('VIBE-SHIELD-QA')) agentTag = 'QA';
            else if (trimmed.includes('VIBE-SHIELD-LOGIC')) agentTag = 'LOGIC';
            else if (trimmed.includes('VIBE-SHIELD-API')) agentTag = 'API';

            let level = 'info';
            if (trimmed.includes('Error') || trimmed.includes('✘') || trimmed.includes('CRITICAL')) level = 'error';
            else if (trimmed.includes('WARN') || trimmed.includes('HIGH')) level = 'warn';
            else if (trimmed.includes('✔') || trimmed.includes('Complete') || trimmed.includes('PASSED')) level = 'success';

            scanData.terminalLogs.push({
                time: new Date().toISOString().substring(11, 19),
                agent: agentTag,
                level,
                text: trimmed
            });

            if (scanData.terminalLogs.length > 1500) {
                scanData.terminalLogs.shift();
            }
        }
    }
}

function startServer(portToUse) {
    server.listen(portToUse)
        .on('listening', () => {
            console.log(`\n🛡️  VIBE SHIELD Web Application running at http://localhost:${portToUse}\n`);
        })
        .on('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                console.log(`Port ${portToUse} is in use, trying port ${portToUse + 1}...`);
                startServer(portToUse + 1);
            } else {
                console.error('Server error:', err);
            }
        });
}

startServer(Number(PORT));
