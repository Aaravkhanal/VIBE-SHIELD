import http from 'http';
import { createGoogleAuth } from './server-auth.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import { ReportGenerator } from './reporting/report-generator.js';
import { applyScanEvent, completeScan, validateScanRequest } from './utils/scan-state.js';
import { randomId } from './utils/id.js';
import { generateAutoPatch } from './utils/patch-generator.js';
import { calculateSecurityScore, generateSvgBadge } from './utils/security-score.js';
import { calculateCvss, parseCvssVector, assessedCvssForFinding } from './utils/cvss-calculator.js';
import { generateHardeningBundle } from './utils/waf-generator.js';
import { OWASP_LLM_TAXONOMY, evaluateAiThreatMatrix } from './utils/ai-threat-matrix.js';
import { normalizeVerification } from './utils/finding.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
if (fs.existsSync(path.join(ROOT_DIR, '.env'))) process.loadEnvFile?.(path.join(ROOT_DIR, '.env'));
const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const REPORTS_DIR = process.env.VIBE_SHIELD_REPORTS_DIR ? path.resolve(process.env.VIBE_SHIELD_REPORTS_DIR) : path.join(ROOT_DIR, 'vibe-shield-reports');

const PORT = process.env.PORT || 3000;
const googleAuth = createGoogleAuth();

// ─── API Key Management ───────────────────────────────────────────────────
const DATA_DIR = path.join(ROOT_DIR, 'data');
const API_KEY_FILE = path.join(DATA_DIR, 'api-key.json');

function ensureApiKey() {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    if (!fs.existsSync(API_KEY_FILE)) {
        const key = 'vs_' + randomId(40);
        fs.writeFileSync(API_KEY_FILE, JSON.stringify({ key, createdAt: new Date().toISOString() }));
        console.log(`\n🔑 VIBE SHIELD API Key generated. Manage it in Settings.`);
        return key;
    }
    return JSON.parse(fs.readFileSync(API_KEY_FILE, 'utf8')).key;
}

let VIBE_API_KEY = ensureApiKey();

function regenerateApiKey() {
    VIBE_API_KEY = 'vs_' + randomId(40);
    fs.writeFileSync(API_KEY_FILE, JSON.stringify({ key: VIBE_API_KEY, createdAt: new Date().toISOString() }));
    return VIBE_API_KEY;
}

const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');

function getSettings() {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    if (!fs.existsSync(SETTINGS_FILE)) {
        const defaults = {
            geminiApiKey: process.env.GEMINI_API_KEY || '',
            openaiApiKey: process.env.OPENAI_API_KEY || '',
            nvidiaApiKey: process.env.NVIDIA_API_KEY || ''
        };
        fs.writeFileSync(SETTINGS_FILE, JSON.stringify(defaults, null, 2));
        return defaults;
    }
    try {
        return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    } catch (e) {
        return {};
    }
}

function saveSettings(newSettings) {
    const current = getSettings();
    const updated = { ...current, ...newSettings };
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(updated, null, 2));
    return updated;
}
// ─────────────────────────────────────────────────────────────────────────

// In-memory store for scans
const activeScans = new Map();
const scanHistory = [];
const scanSseClients = new Map(); // scanId -> Set of SSE response streams

function scanOwner(req) {
    return googleAuth.required ? googleAuth.getSession(req)?.user.id || '__automation__' : 'local';
}
function canAccessScan(req, scanId) {
    if (!googleAuth.required) return true;
    if (!/^[\w-]+$/.test(scanId)) return false;
    try {
        const owner = JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, scanId, 'owner.json'), 'utf8')).id;
        const user = googleAuth.getSession(req)?.user;
        return Boolean(user && (owner === user.id || (owner === '__automation__' && user.isAdmin)));
    } catch { return false; }
}
function registerScanOwner(req, scanId) {
    const directory = path.join(REPORTS_DIR, scanId);
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, 'owner.json'), JSON.stringify({ id: scanOwner(req) }), { mode: 0o600 });
}

function broadcastScanProgress(scanId, data) {
    const clients = scanSseClients.get(scanId);
    if (!clients || clients.size === 0) return;
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    for (const client of clients) {
        try {
            client.write(payload);
            if (data.completed) client.end();
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
                    const scoreData = calculateSecurityScore(data);
                    scanHistory.push({
                        scanId: dir,
                        url: data.meta?.target || 'Unknown',
                        timestamp: data.meta?.scannedAt || fs.statSync(jsonPath).mtime.toISOString(),
                        duration: data.meta?.duration ? (data.meta.duration / 1000).toFixed(1) : '0',
                        findingsCount: data.dedupSummary?.total ?? data.summary?.total ?? 0,
                        score: scoreData.overallScore,
                        grade: scoreData.grade,
                        gradeColor: scoreData.gradeColor,
                        statusText: scoreData.statusText,
                        subscores: scoreData.subCategories,
                        summary: data.dedupSummary || data.summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
                        reportHtmlUrl: `/vibe-shield-reports/${dir}/report.html`
                    });
                } catch (e) {
                    // ignore malformed report
                }
            }
        }
        scanHistory.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
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

const server = http.createServer(async (req, res) => {
    const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
    const pathname = parsedUrl.pathname;

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    if (pathname.startsWith('/api/') || pathname.startsWith('/auth/')) res.setHeader('Cache-Control', 'no-store');
    // CORS headers
    if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}` && req.headers.origin !== `https://${req.headers.host}` && req.headers.origin !== googleAuth.origin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Cross-origin access to this local scanner is not allowed.' }));
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    if (await googleAuth.handle(req, res, pathname, parsedUrl.searchParams)) return;
    if ((pathname.startsWith('/api/') || pathname.startsWith('/vibe-shield-reports/')) && !googleAuth.authorize(req, res, VIBE_API_KEY)) return;

    if (googleAuth.required) {
        const adminRoutes = ['/api/settings', '/api/key', '/api/key/regenerate', '/api/cicd/workflow-template'];
        if (adminRoutes.includes(pathname) && !googleAuth.getSession(req)?.user.isAdmin) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Administrator access is required.' }));
        }
        let ownedScanId = pathname.startsWith('/api/scan/') ? pathname.split('/')[3] : pathname.startsWith('/vibe-shield-reports/') ? pathname.split('/')[2] : null;
        if (pathname.startsWith('/api/badge')) ownedScanId = parsedUrl.searchParams.get('scanId') || pathname.split('/')[3];
        if (ownedScanId && !canAccessScan(req, ownedScanId)) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Scan not found.' }));
        }
    }

    // Serve static frontend assets
    if (pathname === '/' || pathname === '/index.html') {
        return serveStaticFile(res, path.join(PUBLIC_DIR, 'index.html'), 'text/html');
    }
    if (['/workspace.css', '/workspace.js'].includes(pathname)) return serveStaticFile(res, path.join(PUBLIC_DIR, pathname.slice(1)), getContentType(pathname));
    if (pathname === '/styles.css') {
        return serveStaticFile(res, path.join(PUBLIC_DIR, 'styles.css'), 'text/css');
    }
    if (pathname === '/security-score.js') return serveStaticFile(res, path.join(__dirname, 'utils/security-score.js'), 'text/javascript');
    if (pathname === '/app.js') {
        return serveStaticFile(res, path.join(PUBLIC_DIR, 'app.js'), 'text/javascript');
    }

    // Serve generated scan HTML/JSON report files dynamically
    if (pathname.startsWith('/vibe-shield-reports/')) {
        const relativeReportPath = pathname.replace('/vibe-shield-reports/', '');
        if (relativeReportPath.split('/').at(-1) === 'owner.json') {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            return res.end('404 Not Found');
        }
        const fullReportPath = path.join(REPORTS_DIR, relativeReportPath);
        if (fs.existsSync(fullReportPath) && fullReportPath.startsWith(REPORTS_DIR + path.sep) && fs.statSync(fullReportPath).isFile()) {
            return serveStaticFile(res, fullReportPath, getContentType(fullReportPath));
        }

        // Only regenerate the exact HTML report; never substitute another artifact.
        const parts = relativeReportPath.split('/');
        const scanId = parts[0];
        if (/^[\w-]+$/.test(scanId) && parts.length === 2 && parts[1] === 'report.html') {
            const scanDir = path.join(REPORTS_DIR, scanId);
            const reportJsonPath = path.join(scanDir, 'report.json');
            if (fs.existsSync(reportJsonPath)) {
                try {
                    const reportData = JSON.parse(fs.readFileSync(reportJsonPath, 'utf-8'));
                    fs.writeFileSync(path.join(scanDir, 'report.html'), new ReportGenerator({})._generateHTML(reportData));
                    if (fs.existsSync(fullReportPath)) {
                        return serveStaticFile(res, fullReportPath, getContentType(fullReportPath));
                    }
                } catch(e) {
                    console.error('On-the-fly report generation error:', e);
                }
            }
        }
    }

    if (['/api/scan', '/api/webhook/scan'].includes(pathname) && req.method === 'POST') {
        const running = [...activeScans.values()].filter(scan => !scan.completed);
        if (running.length >= 4 || running.filter(scan => scan.ownerId === scanOwner(req)).length >= 2) {
            res.writeHead(429, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Your workspace already has scans running. Wait for a scan to finish.' }));
        }
    }

    // API: Start Scan
    if (pathname === '/api/scan' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const { url, modules = ['qa', 'security', 'ai', 'logic', 'api'], safetyMode = 'safe-active', maxPages = '25', auth = {}, externalSubdomains = false, organizationDomains = [] } = JSON.parse(body);

                if (!url) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ error: 'Missing target URL' }));
                }

                let targetUrl = url.trim();
                if (!/^https?:\/\//i.test(targetUrl)) {
                    targetUrl = 'https://' + targetUrl;
                }

                validateScanRequest(targetUrl, modules, maxPages, safetyMode);
                const scanId = randomId(8);
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

                if (auth.strategy || auth.bearerToken || auth.username || auth.cookies) {
                    scanData.terminalLogs.push({
                        time: new Date().toISOString().substring(11, 19),
                        agent: 'CRAWL',
                        level: 'info',
                        text: `[VIBE-SHIELD] Configured authentication: ${auth.strategy || (auth.bearerToken ? 'Bearer Token' : auth.cookies ? 'Session Cookie' : 'Form Login')} (role: ${auth.role || 'admin'})`
                    });
                }

                scanData.ownerId = scanOwner(req);
                registerScanOwner(req, scanId);
                activeScans.set(scanId, scanData);

                // Build CLI arguments
                const args = [
                    path.join(ROOT_DIR, 'src', 'cli.js'),
                    'scan',
                    targetUrl,
                    '-m', modules.join(','),
                    '--max-pages', String(maxPages),
                    '--output', path.join(REPORTS_DIR, scanId),
                    '--prod-safe'
                ];

                if (auth) {
                    if (auth.bearerToken) {
                        args.push('--bearer-token', auth.bearerToken);
                    }
                    if (auth.cookies) {
                        args.push('--auth-cookie', typeof auth.cookies === 'string' ? auth.cookies : JSON.stringify(auth.cookies));
                    }
                    if (auth.username) {
                        args.push('--username', auth.username);
                    }
                    if (auth.password) {
                        args.push('--password', auth.password);
                    }
                    if (auth.loginUrl) {
                        args.push('--login-url', auth.loginUrl);
                    }
                    if (auth.strategy) {
                        args.push('--auth-strategy', auth.strategy);
                    }
                    if (auth.role) {
                        args.push('--auth-role', auth.role);
                    }
                }

                if (externalSubdomains === true) {
                    args.push('--external-subdomains');
                    if (Array.isArray(organizationDomains) && organizationDomains.length > 0) {
                        args.push('--organization-domains', organizationDomains.map(value => String(value).trim()).filter(Boolean).join(','));
                    }
                }

                args.push('--' + safetyMode);
                const enabledAgents = ['CRAWL', ...modules.map(m => ({ security: 'SEC' }[m] || m.toUpperCase()))];
                for (const [name, agent] of Object.entries(scanData.agents)) {
                    if (!enabledAgents.includes(name.replace('VIBE-SHIELD-', ''))) Object.assign(agent, { status: 'skipped', message: 'Module not selected' });
                }
                const child = spawn(process.execPath, args, { cwd: ROOT_DIR, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
                child.on('message', event => {
                    applyScanEvent(scanData, event);
                    broadcastScanProgress(scanId, scanData);
                });
                child.on('error', err => { scanData.processError = err.message; });

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
                    const scoreData = completeScan(scanData, code, REPORTS_DIR);
                    if (scanHistory.length >= 50) scanHistory.pop();
                    scanHistory.unshift({
                        scanId,
                        url: targetUrl,
                        timestamp: new Date().toISOString(),
                        duration: scanData.duration,
                        findingsCount: scanData.report?.dedupSummary?.total ?? scanData.report?.summary?.total ?? 0,
                        score: scoreData.overallScore,
                        grade: scoreData.grade,
                        gradeColor: scoreData.gradeColor,
                        statusText: scoreData.statusText,
                        subscores: scoreData.subCategories || null,
                        summary: scanData.report?.dedupSummary || scanData.report?.summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
                        reportHtmlUrl: scanData.reportHtmlUrl
                    });

                    broadcastScanProgress(scanId, scanData);
                });

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ scanId, targetUrl, status: 'started' }));
            } catch (err) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
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
            'X-Accel-Buffering': 'no'
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

        const heartbeat = setInterval(() => res.write(': heartbeat\n\n'), 15000);
        res.on('close', () => {
            clearInterval(heartbeat);
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
    if (pathname.startsWith('/api/scan/') && req.method === 'GET' && !pathname.includes('/events') && !pathname.includes('/logs') && !pathname.includes('/executive')) {
        const scanId = pathname.replace('/api/scan/', '');
        let scanData = activeScans.get(scanId);

        if (!scanData) {
            // Check if report exists on disk
            const reportPath = path.join(REPORTS_DIR, scanId, 'report.json');
            if (fs.existsSync(reportPath)) {
                try {
                    const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
                    scanData = {
                        scanId,
                        url: report.meta?.target || 'Unknown',
                        completed: true,
                        status: report.coverage?.status === 'complete' ? 'completed' : 'partial',
                        duration: report.meta?.duration ? (report.meta.duration / 1000).toFixed(1) : '0',
                        report,
                        reportHtmlUrl: `/vibe-shield-reports/${scanId}/report.html`
                    };
                } catch (e) {}
            }
        }

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
        return res.end(JSON.stringify(scanHistory.filter(scan => canAccessScan(req, scan.scanId)).slice(0, 20)));
    }

    // API: Get Historical Score Trends
    if (pathname === '/api/scans/trends' && req.method === 'GET') {
        const targetFilter = parsedUrl.searchParams.get('url');
        let list = scanHistory.filter(scan => canAccessScan(req, scan.scanId));
        if (targetFilter) {
            list = list.filter(s => s.url === targetFilter || s.url.includes(targetFilter));
        }
        // Chronological order for time series chart (oldest to newest)
        list.reverse();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(list));
    }

    // API: Dynamic SVG Security Badge
    if (pathname.startsWith('/api/badge') && req.method === 'GET') {
        const scanId = parsedUrl.searchParams.get('scanId') || pathname.replace('/api/badge/', '').replace('/api/badge', '');
        let grade = 'N/A';
        let score = null;
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

    // API: CVSS v3.1 Quantitative Score Calculator
    if (pathname === '/api/cvss/calculate' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const payload = JSON.parse(body || '{}');
                let result;
                if (payload.vectorString) {
                    result = parseCvssVector(payload.vectorString);
                } else if (payload.metrics) {
                    result = calculateCvss(payload.metrics);
                } else if (payload.finding) {
                    result = assessedCvssForFinding(payload.finding);
                    if (!result) throw new Error('This finding has no detector-supplied CVSS assessment');
                } else {
                    result = calculateCvss(payload);
                }
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(result));
            } catch (err) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    // API: One-Click Hardening & WAF Exporter Bundle
    if (pathname === '/api/export/fix-bundle' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const payload = JSON.parse(body || '{}');
                let report = payload.report;
                
                if (!report && payload.scanId) {
                    if (!canAccessScan(req, payload.scanId)) throw new Error('Scan not found.');
                    const scanData = activeScans.get(payload.scanId);
                    if (scanData && scanData.report) {
                        report = scanData.report;
                    } else {
                        const reportPath = path.join(REPORTS_DIR, payload.scanId, 'report.json');
                        if (fs.existsSync(reportPath)) {
                            report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
                        }
                    }
                }

                if (!report && payload.finding) {
                    report = { findings: [payload.finding], meta: { target: payload.finding.affected_surface || 'app' } };
                }

                if (!report) {
                    report = { findings: [], meta: { target: payload.target || 'target-app.com' } };
                }

                const bundle = generateHardeningBundle(report);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(bundle));
            } catch (err) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    // API: AI Threat Matrix Taxonomy
    if (pathname === '/api/ai-matrix/taxonomy' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(OWASP_LLM_TAXONOMY));
    }

    // API: AI Threat Matrix Evaluate Scan Findings
    if (pathname === '/api/ai-matrix/evaluate' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const payload = JSON.parse(body || '{}');
                let report = payload.report;
                if (!report && payload.scanId) {
                    if (!canAccessScan(req, payload.scanId)) throw new Error('Scan not found.');
                    const scanData = activeScans.get(payload.scanId);
                    if (scanData && scanData.report) {
                        report = scanData.report;
                    } else {
                        const reportPath = path.join(REPORTS_DIR, payload.scanId, 'report.json');
                        if (fs.existsSync(reportPath)) {
                            report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
                        }
                    }
                }
                const matrix = evaluateAiThreatMatrix(report || {});
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(matrix));
            } catch (err) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    // API: AI Threat Matrix Interactive Adversarial Simulation
    if (pathname === '/api/ai-matrix/simulate' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const payload = JSON.parse(body || '{}');
                const vectorId = payload.vectorId || 'LLM01';
                const category = OWASP_LLM_TAXONOMY.find(c => c.id === vectorId) || OWASP_LLM_TAXONOMY[0];
                
                // Build simulation result with live metrics
                const simResult = {
                    vectorId: category.id,
                    title: category.title,
                    severity: category.severity,
                    cvss: null,
                    timestamp: new Date().toISOString(),
                    simulation: category.simulation,
                    tokensConsumed: null,
                    latencyMs: null,
                    guardrailVerdict: 'ILLUSTRATION ONLY — no probe executed',
                    guardrailRuleApplied: category.defenseMechanisms[0],
                    remediationSnippet: `// Defense Guardrail Configuration for ${category.id} (${category.shortName})
import { createGuardrail } from '@vibe-shield/ai-guard';

export const ${category.id.toLowerCase()}_shield = createGuardrail({
  threatCategory: '${category.id}',
  maxTokenBudget: 2048,
  rules: [
    ${category.defenseMechanisms.map(m => `'${m}'`).join(',\n    ')}
  ],
  onIntercept: (probe) => {
    return { action: 'BLOCK', reason: 'Adversarial ${category.shortName} probe neutralized.' };
  }
});`
                };

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(simResult));
            } catch (err) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    // API: CI/CD Webhook Trigger
    if (pathname === '/api/webhook/scan' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const payload = JSON.parse(body || '{}');
                const target = payload.url || payload.targetUrl;
                if (!target) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ error: 'Missing target URL in webhook payload (specify "url" or "targetUrl")' }));
                }

                let targetUrl = target.trim();
                if (!/^https?:\/\//i.test(targetUrl)) {
                    targetUrl = 'https://' + targetUrl;
                }

                const modules = payload.modules || ['qa', 'security', 'ai', 'logic', 'api'];
                const maxPages = payload.maxPages || '25';
                const safetyMode = payload.safetyMode || 'safe-active';
                const isAsync = payload.async === true;
                const auth = payload.auth || {};
                const externalSubdomains = payload.externalSubdomains === true;
                const organizationDomains = Array.isArray(payload.organizationDomains) ? payload.organizationDomains : [];
                const securityGate = {
                    minScore: payload.securityGate?.minScore ?? 80,
                    maxCritical: payload.securityGate?.maxCritical ?? 0,
                    maxHigh: payload.securityGate?.maxHigh ?? 2
                };

                validateScanRequest(targetUrl, modules, maxPages, safetyMode);
                const scanId = randomId(8);
                const startTime = Date.now();

                const scanData = {
                    scanId,
                    url: targetUrl,
                    status: 'running',
                    startTime,
                    completed: false,
                    duration: 0,
                    isWebhook: true,
                    securityGate,
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
                            text: `[CI/CD WEBHOOK] Triggered automated scan for ${targetUrl} (Gate: Min Score ${securityGate.minScore}, Max Critical ${securityGate.maxCritical})`
                        }
                    ],
                    report: null,
                    reportHtmlUrl: null
                };

                scanData.ownerId = scanOwner(req);
                registerScanOwner(req, scanId);
                activeScans.set(scanId, scanData);

                const args = [
                    path.join(ROOT_DIR, 'src', 'cli.js'),
                    'scan',
                    targetUrl,
                    '-m', Array.isArray(modules) ? modules.join(',') : modules,
                    '--max-pages', String(maxPages),
                    '--output', path.join(REPORTS_DIR, scanId),
                    '--prod-safe'
                ];

                if (auth) {
                    if (auth.bearerToken) args.push('--bearer-token', auth.bearerToken);
                    if (auth.cookies) args.push('--auth-cookie', typeof auth.cookies === 'string' ? auth.cookies : JSON.stringify(auth.cookies));
                    if (auth.username) args.push('--username', auth.username);
                    if (auth.password) args.push('--password', auth.password);
                    if (auth.loginUrl) args.push('--login-url', auth.loginUrl);
                    if (auth.strategy) args.push('--auth-strategy', auth.strategy);
                    if (auth.role) args.push('--auth-role', auth.role);
                }

                if (externalSubdomains) {
                    args.push('--external-subdomains');
                    if (organizationDomains.length > 0) {
                        args.push('--organization-domains', organizationDomains.map(value => String(value).trim()).filter(Boolean).join(','));
                    }
                }

                args.push('--' + safetyMode);
                const enabledAgents = ['CRAWL', ...modules.map(m => ({ security: 'SEC' }[m] || m.toUpperCase()))];
                for (const [name, agent] of Object.entries(scanData.agents)) {
                    if (!enabledAgents.includes(name.replace('VIBE-SHIELD-', ''))) Object.assign(agent, { status: 'skipped', message: 'Module not selected' });
                }
                const child = spawn(process.execPath, args, { cwd: ROOT_DIR, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
                child.on('message', event => {
                    applyScanEvent(scanData, event);
                    broadcastScanProgress(scanId, scanData);
                });
                child.on('error', err => { scanData.processError = err.message; });

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

                const onScanFinish = (code) => {
                    const scoreData = completeScan(scanData, code, REPORTS_DIR);
                    const summary = scanData.report?.dedupSummary || scanData.report?.summary || {};

                    // Evaluate CI/CD security gate
                    const violations = [];
                    if (scanData.status !== 'completed' || scoreData.overallScore === null) violations.push(scanData.failureReason || 'Scan incomplete; security gate cannot pass.');
                    if (scoreData.overallScore < securityGate.minScore) {
                        violations.push(`Security Score (${scoreData.overallScore}) fell below minimum threshold (${securityGate.minScore})`);
                    }
                    if (summary.critical > securityGate.maxCritical) {
                        violations.push(`Critical vulnerabilities count (${summary.critical}) exceeded gate limit (${securityGate.maxCritical})`);
                    }
                    if (summary.high > securityGate.maxHigh) {
                        violations.push(`High severity vulnerabilities count (${summary.high}) exceeded gate limit (${securityGate.maxHigh})`);
                    }

                    const gatePassed = violations.length === 0;

                    if (scanHistory.length >= 50) scanHistory.pop();
                    scanHistory.unshift({
                        scanId,
                        url: targetUrl,
                        timestamp: new Date().toISOString(),
                        duration: scanData.duration,
                        findingsCount: summary.total,
                        score: scoreData.overallScore,
                        grade: scoreData.grade,
                        gradeColor: scoreData.gradeColor,
                        statusText: scoreData.statusText,
                        subscores: scoreData.subCategories || null,
                        summary,
                        reportHtmlUrl: scanData.reportHtmlUrl
                    });

                    broadcastScanProgress(scanId, scanData);

                    return {
                        scanId,
                        targetUrl,
                        status: scanData.status,
                        durationSeconds: scanData.duration,
                        gate: {
                            passed: gatePassed,
                            violations,
                            thresholds: securityGate
                        },
                        posture: {
                            score: scoreData.overallScore,
                            grade: scoreData.grade,
                            statusText: scoreData.statusText,
                            summary
                        },
                        reportHtmlUrl: scanData.reportHtmlUrl,
                        executiveReportUrl: `/api/scan/${scanId}/executive`,
                        completedAt: new Date().toISOString()
                    };
                };

                if (isAsync) {
                    child.on('close', code => { onScanFinish(code); });
                    res.writeHead(202, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({
                        scanId,
                        targetUrl,
                        status: 'running',
                        message: 'Continuous scan scheduled via webhook.',
                        eventsStreamUrl: `/api/scan/${scanId}/events`,
                        executiveReportUrl: `/api/scan/${scanId}/executive`
                    }));
                } else {
                    // Synchronous CI/CD response (awaits scan completion and returns gate result)
                    child.on('close', code => {
                        const result = onScanFinish(code);
                        const statusCode = result.gate.passed ? 200 : 422;
                        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify(result, null, 2));
                    });
                }
            } catch (err) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    // API: Executive Report Generator
    if (pathname.startsWith('/api/scan/') && pathname.endsWith('/executive') && req.method === 'GET') {
        const scanId = pathname.replace('/api/scan/', '').replace('/executive', '');
        
        let targetData = activeScans.get(scanId);
        let reportJson = targetData?.report;

        if (!reportJson && /^[\w-]+$/.test(scanId)) {
            const reportPath = path.join(REPORTS_DIR, scanId, 'report.json');
            if (fs.existsSync(reportPath)) reportJson = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        }
        if (!reportJson) {
            res.writeHead(targetData && !targetData.completed ? 409 : 404, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'No report is available for this scan.' }));
        }
        const scoreData = calculateSecurityScore(reportJson);

        const targetUrl = reportJson?.meta?.target || targetData?.url || 'Unknown target';
        const scannedAt = reportJson?.meta?.scannedAt || new Date().toISOString();
        const durationSec = reportJson?.meta?.duration ? (reportJson.meta.duration / 1000).toFixed(1) : (targetData?.duration || '0');
        const summary = reportJson?.dedupSummary || reportJson?.summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
        const rawFindings = reportJson?.deduplicated || reportJson?.findings || [];

        // Build top findings
        const topFindings = rawFindings.slice(0, 8).map(f => {
            const cvss = assessedCvssForFinding(f);
            const verification = f.verification || normalizeVerification(null, f);
            return {
                id: f.id || randomId(6),
                title: f.title || f.name || 'Security Finding',
                severity: (f.severity || 'medium').toUpperCase(),
                agent: f.agent || 'VIBE-SHIELD',
                description: f.description || f.issue || 'Identified during automated surface probing.',
                impact: f.impact || 'Potential risk of unauthorized data exposure or service degradation.',
                remediation: f.remediation || f.fix || 'Implement strict input validation and least-privilege access controls.',
                cvssScore: cvss?.score ?? null,
                cvssVector: cvss?.vectorString ?? null,
                verification: {
                    level: verification.level,
                    label: verification.label,
                    reason: verification.reason,
                    method: verification.method,
                    proof: verification.proof,
                    missingEvidence: verification.missingEvidence,
                }
            };
        });

        // Generate executive briefing
        const executiveReport = {
            metadata: {
                reportTitle: 'VIBE SHIELD — Executive Security & Quality Audit Dossier',
                targetUrl,
                scannedAt,
                durationSeconds: durationSec,
                scannerVersion: '1.0.0',
                classification: 'CONFIDENTIAL / EXECUTIVE STAKEHOLDER DISTRIBUTION'
            },
            posture: {
                grade: scoreData.grade,
                score: scoreData.overallScore,
                gradeColor: scoreData.gradeColor,
                statusText: scoreData.statusText,
                summary,
                subscores: scoreData.subCategories,
                riskStatement: reportJson.coverage?.status !== 'complete'
                    ? 'Incomplete coverage. Findings remain useful, but no security grade can be established.'
                    : `${summary.total} findings in the tested scope. ${summary.critical || 0} critical and ${summary.high || 0} high. Automated scans do not establish compliance or prove the absence of vulnerabilities.`
            },
            complianceReadiness: Object.fromEntries(['owaspTop10', 'owaspLlmTop10', 'soc2Security', 'gdprDataPrivacy', 'hipaaSecurityRule'].map(key => [key, 'Not assessed by this scan'])),
            roadmap: topFindings.filter(f => f.remediation).map(f => ({ phase: f.severity, action: f.remediation, owner: 'Application team', status: 'Recommended' })),
            topFindings
        };

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(executiveReport, null, 2));
        return;
    }

    // API: CI/CD Workflow Generator Template
    if (pathname === '/api/cicd/workflow-template' && req.method === 'GET') {
        const serverUrl = googleAuth.required
            ? googleAuth.origin
            : `${req.socket.encrypted ? 'https' : 'http'}://${req.headers.host || `localhost:${PORT}`}`;

        const githubActionYaml = `name: 🛡️ VIBE SHIELD Continuous Security Scan

on:
  push:
    branches: [ main, staging, dev ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *' # Nightly continuous audit at 2:00 AM UTC

jobs:
  vibe-shield-audit:
    name: Autonomous Security & Quality Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Trigger VIBE SHIELD Continuous Scan
        id: scan
        run: |
          echo "🚀 Initiating VIBE SHIELD multi-agent security audit..."
          
          # Trigger webhook and evaluate security gate
          RESPONSE=$(curl -s -X POST "${serverUrl}/api/webhook/scan" \\
            -H "Content-Type: application/json" \\
            -H "x-api-key: \${{ secrets.VIBESHIELD_API_KEY }}" \\
            -d '{
              "targetUrl": "\${{ secrets.APP_TARGET_URL || '\''https://staging.your-app.com'\'' }}",
              "modules": ["qa", "security", "ai", "logic", "api"],
              "securityGate": {
                "minScore": 80,
                "maxCritical": 0,
                "maxHigh": 2
              },
              "auth": {
                "bearerToken": "\${{ secrets.STAGING_BEARER_TOKEN }}"
              }
            }')
          
          echo "Scan Result Payload:"
          echo "$RESPONSE" | jq .
          
          PASSED=$(echo "$RESPONSE" | jq -r '.gate.passed')
          SCORE=$(echo "$RESPONSE" | jq -r '.posture.score')
          GRADE=$(echo "$RESPONSE" | jq -r '.posture.grade')
          
          echo "======================================"
          echo "🛡️ VIBE SHIELD AUDIT SUMMARY"
          echo "Grade: $GRADE | Score: $SCORE/100"
          echo "Gate Passed: $PASSED"
          echo "======================================"
          
          if [ "$PASSED" != "true" ]; then
            echo "❌ CI/CD Security Gate Failed! Posture score or critical findings violated thresholds."
            exit 1
          fi
          
          echo "✔ Security Gate PASSED! Safe to merge."
`;

        const curlCommand = `curl -X POST "${serverUrl}/api/webhook/scan" \\
  -H "Content-Type: application/json" \\
  -H "x-api-key: YOUR_VIBESHIELD_API_KEY" \\
  -d '{
    "targetUrl": "https://your-app.com",
    "modules": ["qa", "security", "ai", "logic", "api"],
    "securityGate": {
      "minScore": 85,
      "maxCritical": 0,
      "maxHigh": 1
    }
  }'`;

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            serverUrl,
            githubActionYaml,
            curlCommand,
            gitlabCiYaml: `vibe_shield_scan:
  stage: test
  image: curlimages/curl:latest
  script:
    - |
      RESPONSE=$(curl -s -X POST "${serverUrl}/api/webhook/scan" \\
        -H "Content-Type: application/json" \\
        -H "x-api-key: $VIBESHIELD_API_KEY" \\
        -d '{"targetUrl":"'\${CI_ENVIRONMENT_URL}'", "securityGate":{"minScore":80, "maxCritical":0}}')
      echo "$RESPONSE"
  only:
    - merge_requests
    - main`
        }));
        return;
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
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    // ── GET /api/settings ──────────────────────────────────────────
    if (req.method === 'GET' && pathname === '/api/settings') {
        const settings = getSettings();
        // Mask API keys for security
        const masked = {
            geminiApiKey: settings.geminiApiKey ? '••••••••' + settings.geminiApiKey.slice(-4) : '',
            hasGeminiKey: Boolean(settings.geminiApiKey || process.env.GEMINI_API_KEY),
            openaiApiKey: settings.openaiApiKey ? '••••••••' + settings.openaiApiKey.slice(-4) : '',
            hasOpenaiKey: Boolean(settings.openaiApiKey || process.env.OPENAI_API_KEY),
            nvidiaApiKey: settings.nvidiaApiKey ? '••••••••' + settings.nvidiaApiKey.slice(-4) : '',
            hasNvidiaKey: Boolean(settings.nvidiaApiKey || process.env.NVIDIA_API_KEY)
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(masked));
        return;
    }

    // ── POST /api/settings ─────────────────────────────────────────
    if (req.method === 'POST' && pathname === '/api/settings') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const newSettings = JSON.parse(body);
                saveSettings(newSettings);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (err) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    // ── POST /api/chat — Intelligent AI Assistant Endpoint ────────
    if (req.method === 'POST' && pathname === '/api/chat') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { prompt, scanId, report } = JSON.parse(body);
                const settings = getSettings();
                const nvidiaKey = settings.nvidiaApiKey || process.env.NVIDIA_API_KEY;
                const geminiKey = settings.geminiApiKey || process.env.GEMINI_API_KEY;
                const openaiKey = settings.openaiApiKey || process.env.OPENAI_API_KEY;

                if (typeof prompt !== 'string' || !prompt.trim()) throw new Error('Enter a question.');
                const scanContext = report || (scanId && canAccessScan(req, scanId) ? activeScans.get(scanId)?.report : null);
                if (!scanContext) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    return res.end(JSON.stringify({ response: 'Run or select a scan first. No scan evidence is available for this question.', provider: 'local' }));
                }

                // 1. If NVIDIA API key is configured, call NVIDIA NIM API (Llama-3.1 70B / Nemotron)
                if (nvidiaKey) {
                    try {
                        const targetUrl = scanContext?.meta?.target || 'the scanned site';
                        const score = calculateSecurityScore(scanContext).overallScore ?? 'N/A';
                        const dedup = scanContext?.dedupSummary || scanContext?.summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
                        const findingsList = (scanContext?.findings || []).map((f, i) => `${i + 1}. [${(f.severity || 'info').toUpperCase()}] ${f.title}\n   • Surface: ${f.affectedSurface || f.url || 'N/A'}\n   • Description: ${f.description || 'No description'}\n   • Recommendation: ${f.recommendation || f.remediation || 'Apply secure coding controls'}\n   • OWASP: ${f.owasp?.id || f.owasp || 'General'}`).join('\n\n');

                        const systemInstruction = `You are VIBE SHIELD AI Security Assistant, a Principal Application Security Engineer & QA Lead powered by NVIDIA AI.\n\nCRITICAL INSTRUCTIONS:\n- You MUST base all answers strictly on the verified live security scan report provided below.\n- Do NOT invent non-existent vulnerabilities or make up random facts. Always analyze the actual scan findings first.\n- Be concise, authoritative, and actionable. Use markdown formatting (**bold**, bullet points).\n\nVERIFIED SCAN REPORT:\n• Target URL: ${targetUrl}\n• Security Score: ${score}/100\n• Findings Summary: ${dedup.total || 0} Total (${dedup.critical || 0} Critical, ${dedup.high || 0} High, ${dedup.medium || 0} Medium, ${dedup.low || 0} Low)\n\nFULL FINDINGS DETAILS:\n${findingsList || 'No findings recorded in this scan.'}`;

                        const nvRes = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${nvidiaKey}`
                            },
                            body: JSON.stringify({
                                model: 'meta/llama-3.2-11b-vision-instruct',
                                messages: [
                                    { role: 'system', content: systemInstruction },
                                    { role: 'user', content: prompt }
                                ],
                                temperature: 0.2,
                                max_tokens: 1024
                            })
                        });
                        const nvData = await nvRes.json();
                        if (!nvRes.ok) {
                            console.error('NVIDIA API Response Error:', nvRes.status, JSON.stringify(nvData));
                        }
                        const answerText = nvData?.choices?.[0]?.message?.content;
                        if (answerText) {
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            return res.end(JSON.stringify({ response: answerText, provider: 'nvidia' }));
                        }
                    } catch (e) {
                        console.error('NVIDIA API Error:', e.message);
                    }
                }

                // 1. If Gemini API key is configured, call Gemini API
                if (geminiKey) {
                    try {
                        const systemInstruction = `You are VIBE SHIELD AI Security Assistant, a elite Principal Application Security Engineer & QA Lead. You are answering a user query about a live security audit. Always be concise, direct, authoritative, and actionable. Format responses with bold text and bullet points where helpful.\n\nCurrent Audit Context:\nTarget: ${scanContext?.meta?.target || 'Not specified'}\nScore: ${scanContext?.score || 'N/A'}/100\nTotal Findings: ${scanContext?.dedupSummary?.total || scanContext?.summary?.total || 0} (${scanContext?.dedupSummary?.critical || 0} critical, ${scanContext?.dedupSummary?.high || 0} high)\nTop Findings: ${JSON.stringify((scanContext?.findings || []).slice(0, 5).map(f => ({ title: f.title, severity: f.severity, surface: f.affectedSurface })))}`;

                        const gRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${geminiKey}`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                contents: [{
                                    parts: [
                                        { text: systemInstruction },
                                        { text: `User Question: ${prompt}` }
                                    ]
                                }]
                            })
                        });
                        const gData = await gRes.json();
                        const answerText = gData?.candidates?.[0]?.content?.parts?.[0]?.text;
                        if (answerText) {
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            return res.end(JSON.stringify({ response: answerText, provider: 'gemini' }));
                        }
                    } catch (e) {
                        console.error('Gemini API Error:', e.message);
                    }
                }

                // 2. If OpenAI API key is configured, call OpenAI API
                if (openaiKey) {
                    try {
                        const oRes = await fetch('https://api.openai.com/v1/chat/completions', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${openaiKey}`
                            },
                            body: JSON.stringify({
                                model: 'gpt-4o-mini',
                                messages: [
                                    { role: 'system', content: `You are VIBE SHIELD AI Security Assistant, a elite Principal Application Security Engineer & QA Lead. Answer user queries concisely and directly based on their security scan data.\nContext: Target ${scanContext?.meta?.target || 'N/A'}, Total findings: ${scanContext?.dedupSummary?.total || 0}` },
                                    { role: 'user', content: prompt }
                                ]
                            })
                        });
                        const oData = await oRes.json();
                        const answerText = oData?.choices?.[0]?.message?.content;
                        if (answerText) {
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            return res.end(JSON.stringify({ response: answerText, provider: 'openai' }));
                        }
                    } catch (e) {
                        console.error('OpenAI API Error:', e.message);
                    }
                }

                // 3. Built-in Local Security Intelligence Engine (Comprehensive Expert Security Advisor)
                let responseText = '';
                const q = prompt.toLowerCase();
                const findings = scanContext?.findings || [];
                const summary = scanContext?.dedupSummary || scanContext?.summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
                const targetUrl = scanContext?.meta?.target || 'the website';
                const score = scanContext ? (calculateSecurityScore(scanContext.report || scanContext).overallScore ?? 'N/A') : 'N/A';

                // Top findings grouped by severity
                const crits = findings.filter(f => f.severity === 'critical');
                const highs = findings.filter(f => f.severity === 'high');
                const meds = findings.filter(f => f.severity === 'medium');

                if (q.includes('suggest') || q.includes('recommend') || q.includes('improvement') || q.includes('what to do') || q.includes('how to improve')) {
                    const topItems = [...crits, ...highs, ...meds].slice(0, 4);
                    if (topItems.length > 0) {
                        responseText = `🛡️ **Security Hardening Roadmap for ${targetUrl}:**\n\n` +
                            topItems.map((f, i) => `**${i + 1}. Fix ${f.title}** (${f.severity?.toUpperCase()})\n• **Impact**: ${f.description || 'Presents security vulnerability to web application.'}\n• **Action Required**: ${f.recommendation || f.remediation || 'Apply input validation and secure headers.'}`).join('\n\n') +
                            `\n\n📌 **General Best Practice Advice:**\n• Enforce strict Content Security Policy (\`Content-Security-Policy\`)\n• Set \`Strict-Transport-Security: max-age=31536000\`\n• Enable \`SameSite=Lax\` and \`HttpOnly\` flags on all cookies.`;
                    } else {
                        responseText = `🛡️ **Security Hardening Recommendations for ${targetUrl}:**\n\nEven with 0 critical findings, no web application is 100% secure! Here are top proactive improvements:\n\n1. **Implement Content Security Policy (CSP)** — Prevent XSS & unauthorized script execution.\n2. **HSTS & TLS Hardening** — Force HTTPS with \`Strict-Transport-Security\` header.\n3. **Cookie Flag Audit** — Ensure all session cookies use \`Secure; HttpOnly; SameSite=Strict\`.\n4. **Security Headers** — Add \`X-Frame-Options: DENY\` and \`X-Content-Type-Options: nosniff\`.`;
                    }
                } else if (q.includes('score') || q.includes('grade') || q.includes('rating')) {
                    responseText = `📊 **Security Posture Analysis for ${targetUrl}:**\n\nSecurity Score: **${score}/100**\n\n**Findings Breakdown:**\n• 🔴 Critical: ${summary.critical}\n• 🟠 High: ${summary.high}\n• 🟡 Medium: ${summary.medium}\n• 🔵 Low: ${summary.low}\n• Total Issues: ${summary.total}\n\n${summary.critical > 0 ? '⚠️ **Action Urgency**: High. Address critical findings immediately to block potential automated exploits.' : '✅ No critical findings detected. Focus on high and medium findings next.'}`;
                } else if (q.includes('critical') || q.includes('fix first') || q.includes('priority')) {
                    if (crits.length > 0) {
                        responseText = `🚨 **Priority 1 Fixes (${crits.length} Critical Issues):**\n\n${crits.map((f, i) => `${i + 1}. **${f.title}**\n   • Affected Surface: \`${f.affectedSurface || f.url || targetUrl}\`\n   • Fix: ${f.recommendation || 'Apply server-side input sanitization.'}`).join('\n\n')}`;
                    } else if (highs.length > 0) {
                        responseText = `⚠️ **No Critical Issues! Priority Focus (${highs.length} High Severity Issues):**\n\n${highs.slice(0, 3).map((f, i) => `${i + 1}. **${f.title}**\n   • Affected: \`${f.affectedSurface || targetUrl}\`\n   • Fix: ${f.recommendation || 'Enforce defense in depth controls.'}`).join('\n\n')}`;
                    } else {
                        responseText = `✅ **Great posture!** No critical or high severity issues found on **${targetUrl}**. Focus on resolving the ${summary.medium || 0} medium findings to further harden your application.`;
                    }
                } else if (q.includes('detail') || q.includes('full') || q.includes('audit') || q.includes('report') || q.includes('all')) {
                    responseText = `🔍 **Detailed Security Audit Summary for ${targetUrl}:**\n\n• **Target URL**: ${targetUrl}\n• **Total Vulnerabilities**: ${summary.total} findings\n• **Highest Severity**: ${crits.length ? 'Critical' : highs.length ? 'High' : meds.length ? 'Medium' : 'Low'}\n\n**Top Vulnerability Insights:**\n` +
                        findings.slice(0, 5).map(f => `• **[${f.severity?.toUpperCase()}]** ${f.title} — ${f.affectedSurface || f.url || ''}`).join('\n') +
                        `\n\n💡 *Click "Open Full Report ↗" or "Download JSON ⤓" in the top bar to inspect every single vulnerability trace and dynamic proof-of-concept payload.*`;
                } else {
                    responseText = `🤖 **VIBE SHIELD Security Assistant for ${targetUrl}:**\n\nI have analyzed **${targetUrl}** (${summary.total} total findings, score: ${score}/100).\n\nAsk me anything:\n• *"Give me suggestions to improve my score"* \n• *"What should I fix first?"*\n• *"Show detailed audit findings"*\n• *"How do I harden security headers?"*`;
                }

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ response: responseText, provider: 'local-engine' }));
            } catch (err) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    // ── GET /api/key — return current API key ──────────────────────────────
    if (req.method === 'GET' && pathname === '/api/key') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ key: VIBE_API_KEY }));
        return;
    }

    // ── POST /api/key/regenerate ───────────────────────────────────────────
    if (req.method === 'POST' && pathname === '/api/key/regenerate') {
        const newKey = regenerateApiKey();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ key: newKey }));
        return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 Not Found');
});


function stripAnsi(str) {
    return str.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '');
}

function parseScanLogs(scanData, text) {
    text = stripAnsi(text);
    for (const agentName of Object.keys(scanData.agents)) {
        if (scanData.structuredEvents) break;
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
    const onListening = () => {
        server.off('error', onError);
        console.log(`\n🛡️  VIBE SHIELD Web Application running at http://localhost:${portToUse}\n`);
    };
    const onError = err => {
        server.off('listening', onListening);
        if (err.code === 'EADDRINUSE') {
            if (googleAuth.required) {
                console.error(`Port ${portToUse} is already in use. APP_URL must match the listening port when Google sign-in is enabled.`);
                process.exitCode = 1;
                return;
            }
            console.log(`Port ${portToUse} is in use, trying port ${portToUse + 1}...`);
            startServer(portToUse + 1);
        } else {
            console.error('Server error:', err);
            process.exitCode = 1;
        }
    };
    server.once('listening', onListening);
    server.once('error', onError);
    server.listen(portToUse, process.env.HOST || '127.0.0.1');
}

startServer(Number(PORT));
