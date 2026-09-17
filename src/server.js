import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import { nanoid } from 'nanoid';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const REPORTS_DIR = path.join(ROOT_DIR, 'vibe-shield-reports');

const PORT = process.env.PORT || 3000;

// In-memory store for scans
const activeScans = new Map();
const scanHistory = [];

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
                });

                child.stderr.on('data', data => {
                    const text = data.toString();
                    parseScanLogs(scanData, text);
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
                            }
                        }
                    } catch (err) {
                        console.error('Error fetching report:', err);
                    }

                    // Save to history
                    scanHistory.unshift({
                        scanId,
                        url: targetUrl,
                        timestamp: new Date().toISOString(),
                        duration: scanData.duration,
                        findingsCount: scanData.report?.summary?.total || 0,
                        reportHtmlUrl: scanData.reportHtmlUrl
                    });
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

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 Not Found');
});

function parseScanLogs(scanData, text) {
    const agentRegex = /(VIBE-SHIELD-[A-Z]+):\s+(Starting\.\.\.|Complete|Running|Error|✔|✘)/g;
    let match;
    while ((match = agentRegex.exec(text)) !== null) {
        const agentName = match[1];
        if (scanData.agents[agentName]) {
            if (text.includes(`[${agentName}] Complete`) || text.includes(`✔ [${agentName}]`)) {
                scanData.agents[agentName].status = 'done';
                scanData.agents[agentName].message = 'Complete';
            } else if (text.includes(`[${agentName}] Starting`)) {
                scanData.agents[agentName].status = 'running';
                scanData.agents[agentName].message = 'Executing agent probes...';
            }
        }
    }
}

server.listen(PORT, () => {
    console.log(`\n🛡️  VIBE SHIELD Web Application running at http://localhost:${PORT}\n`);
});
