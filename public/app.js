import { calculateSecurityScore, generateSvgBadge } from '/security-score.js';
document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scan-form');
    const targetUrlInput = document.getElementById('target-url');
    const startBtn = document.getElementById('start-scan-btn');
    const progressSection = document.getElementById('scan-progress-section');
    const resultsSection = document.getElementById('results-section');
    const currentTargetDisplay = document.getElementById('current-target-display');
    const timerDisplay = document.getElementById('scan-timer');
    const historyList = document.getElementById('history-list');
    const viewReportBtn = document.getElementById('view-report-html-btn');

    let currentScanId = null;
    let timerInterval = null;
    let secondsElapsed = 0;
    let activeReportPath = null;

    // Load initial history
    loadHistory();

    if (viewReportBtn) {
        viewReportBtn.addEventListener('click', () => {
            const scanId = window.currentScanId || currentScanId;
            const reportUrl = activeReportPath || (scanId ? `/vibe-shield-reports/${scanId}/report.html` : null);
            if (reportUrl) {
                window.open(reportUrl, '_blank');
            } else {
                showToast('No scan report generated yet. Please run a scan first.', 'info');
            }
        });
    }

    // ── Scan config panel toggle ──────────────────────────
    const scanConfigToggleBtn = document.getElementById('scan-config-toggle-btn');
    const scanConfigPanel = document.getElementById('scan-config-panel');
    const configChevron = document.getElementById('config-chevron');
    if (scanConfigToggleBtn && scanConfigPanel) {
        scanConfigToggleBtn.addEventListener('click', () => {
            const open = scanConfigPanel.classList.toggle('visible');
            if (configChevron) configChevron.classList.toggle('open', open);
        });
    }

    // ── Module check toggles (new .module-check class) ────
    document.querySelectorAll('.module-check').forEach(label => {
        label.addEventListener('click', () => {
            label.classList.toggle('checked');
            const cb = label.querySelector('input[type="checkbox"]');
            if (cb) cb.checked = label.classList.contains('checked');
        });
    });

    // ── Auth tab switching ────────────────────────────────
    let currentAuthStrategy = 'none';
    document.querySelectorAll('.auth-tab').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.auth-tab').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentAuthStrategy = btn.dataset.auth;
            document.querySelectorAll('.auth-fields').forEach(f => f.classList.remove('active'));
            const panel = document.getElementById(`auth-panel-${currentAuthStrategy}`);
            if (panel) panel.classList.add('active');
        });
    });

    // ── Auth drawer expand ────────────────────────────────
    const authExpandBtn = document.getElementById('auth-expand-btn');
    const authExpandBody = document.getElementById('auth-expand-body');
    if (authExpandBtn && authExpandBody) {
        authExpandBtn.addEventListener('click', () => {
            authExpandBody.classList.toggle('open');
            const arrow = document.getElementById('auth-expand-arrow');
            if (arrow) arrow.textContent = authExpandBody.classList.contains('open') ? '▴' : '▾';
        });
    }

    // ── Nav panel wiring ──────────────────────────────────
    const openPanel = (id) => { const el = document.getElementById(id); if (el) el.classList.remove('hidden'); };
    const closePanel = (id) => { const el = document.getElementById(id); if (el) el.classList.add('hidden'); };

    const navMap = {
        'nav-history-btn': () => document.getElementById('history-section')?.scrollIntoView({ behavior: 'smooth' }),
        'nav-cicd-btn': () => openPanel('webhook-panel'),
        'nav-waf-btn': () => openPanel('waf-panel'),
        'nav-threat-btn': () => openPanel('ai-sim-panel'),
        'nav-report-btn': () => openPanel('executive-report-panel'),
        'nav-settings-btn': () => { openPanel('settings-panel'); loadApiKey(); }
    };
    Object.entries(navMap).forEach(([id, fn]) => {
        const btn = document.getElementById(id);
        if (btn) btn.addEventListener('click', fn);
    });

    // Close panels on backdrop click
    document.querySelectorAll('.panel-backdrop').forEach(backdrop => {
        backdrop.addEventListener('click', (e) => {
            if (e.target === backdrop) backdrop.classList.add('hidden');
        });
    });

    // Panel close buttons
    [
        ['close-patch-modal-btn', 'patch-panel'],
        ['close-cvss-modal-btn', 'cvss-panel'],
        ['close-waf-modal-btn', 'waf-panel'],
        ['close-ai-sim-modal-btn', 'ai-sim-panel'],
        ['close-webhook-modal-btn', 'webhook-panel'],
        ['close-exec-modal-btn', 'executive-report-panel'],
        ['close-settings-panel-btn', 'settings-panel']
    ].forEach(([btnId, panelId]) => {
        const btn = document.getElementById(btnId);
        if (btn) btn.addEventListener('click', () => closePanel(panelId));
    });

    // Header result-section buttons that open panels
    const btnMap = {
        'open-exec-report-results-btn': 'executive-report-panel',
        'open-exec-modal-header-btn': 'executive-report-panel',
        'open-waf-modal-header-btn': 'waf-panel',
        'open-ai-matrix-header-btn': 'ai-sim-panel',
        'open-cicd-modal-header-btn': 'webhook-panel',
        'open-cvss-lab-btn': 'cvss-panel'
    };
    Object.entries(btnMap).forEach(([btnId, panelId]) => {
        const btn = document.getElementById(btnId);
        if (btn) btn.addEventListener('click', () => openPanel(panelId));
    });

    // WAF bundle button
    const wafBundleBtn = document.getElementById('export-waf-bundle-btn');
    if (wafBundleBtn) wafBundleBtn.addEventListener('click', () => openPanel('waf-panel'));

    // ── Form Submit ───────────────────────────────────────
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = targetUrlInput.value.trim();
        if (!url) return;

        // Collect modules from new .module-check.checked labels
        const modules = Array.from(document.querySelectorAll('.module-check.checked input[type="checkbox"]')).map(cb => cb.value);
        if (!modules.length) modules.push('qa', 'security', 'ai', 'logic', 'api');

        const safetyMode = document.getElementById('safety-mode')?.value || 'safe-active';
        const maxPages = document.getElementById('max-pages')?.value || '25';

        // Auth from tab-based UI
        let authConfig = { strategy: currentAuthStrategy };
        if (currentAuthStrategy === 'form') {
            authConfig.loginUrl = document.getElementById('auth-login-url')?.value?.trim() || '';
            authConfig.username = document.getElementById('auth-username')?.value?.trim() || '';
            authConfig.password = document.getElementById('auth-password')?.value?.trim() || '';
            authConfig.role = document.getElementById('auth-role-name')?.value?.trim() || 'admin';
        } else if (currentAuthStrategy === 'token') {
            authConfig.bearerToken = document.getElementById('auth-bearer-token')?.value?.trim() || '';
            authConfig.role = document.getElementById('auth-token-role')?.value?.trim() || 'authenticated-user';
        } else if (currentAuthStrategy === 'cookie') {
            authConfig.cookies = document.getElementById('auth-cookies')?.value?.trim() || '';
            authConfig.role = document.getElementById('auth-cookie-role')?.value?.trim() || 'session-user';
        }

        // UI Transition
        startBtn.disabled = true;
        startBtn.textContent = 'Scanning...';
        startBtn.classList.add('scanning');
        progressSection.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        currentTargetDisplay.textContent = url;

        resetAgentCards();
        window.liveScanTerminal?.setLogs([]);
        window.currentScanReport = null;
        window.currentScanStatus = null;
        window.currentScanId = null;
        activeReportPath = null;
        startTimer();

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, modules, safetyMode, maxPages, auth: authConfig })
            });

            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Failed to start scan');

            currentScanId = data.scanId;
            window.currentScanId = data.scanId;
            streamScanProgress(currentScanId);
        } catch (err) {
            showToast('Scan Error: ' + err.message, 'error');
            stopTimer();
            startBtn.disabled = false;
            startBtn.textContent = 'Scan →';
            startBtn.classList.remove('scanning');
        }
    });

    // Real-Time Push Progress via Server-Sent Events (SSE)
    let activeEventSource = null;

    function streamScanProgress(scanId) {
        if (activeEventSource) {
            activeEventSource.close();
            activeEventSource = null;
        }

        const fallbackTimeout = setTimeout(() => {
            if (activeEventSource) {
                activeEventSource.close();
                activeEventSource = null;
            }
            stopTimer();
            startBtn.disabled = false;
            startBtn.textContent = 'Scan →';
            startBtn.classList.remove('scanning');
            showToast('⚠️ Scan connection timed out after 10 minutes.', 'error');
        }, 600000);

        if (typeof EventSource !== 'undefined') {
            try {
                const evtSource = new EventSource(`/api/scan/${scanId}/events`);
                activeEventSource = evtSource;

                evtSource.onmessage = (event) => {
                    try {
                        const status = JSON.parse(event.data);
                        if (status.error) {
                            showToast(`⚠️ ${status.error}`, 'error');
                            evtSource.close();
                            activeEventSource = null;
                            clearTimeout(fallbackTimeout);
                            stopTimer();
                            startBtn.disabled = false;
                            startBtn.textContent = 'Scan →';
                            startBtn.classList.remove('scanning');
                            return;
                        }

                        if (status.agents) {
                            updateAgentState('crawl', status.agents['VIBE-SHIELD-CRAWL']);
                            updateAgentState('qa', status.agents['VIBE-SHIELD-QA']);
                            updateAgentState('sec', status.agents['VIBE-SHIELD-SEC']);
                            updateAgentState('ai', status.agents['VIBE-SHIELD-AI']);
                            updateAgentState('logic', status.agents['VIBE-SHIELD-LOGIC']);
                            updateAgentState('api', status.agents['VIBE-SHIELD-API']);
                        }

                        // Feed logs into live terminal
                        if (status.terminalLogs && window.liveScanTerminal) {
                            window.liveScanTerminal.setLogs(status.terminalLogs);
                        }

                        if (status.completed) {
                            clearTimeout(fallbackTimeout);
                            evtSource.close();
                            activeEventSource = null;
                            stopTimer();
                            startBtn.disabled = false;
                            startBtn.textContent = 'Scan →';
                            startBtn.classList.remove('scanning');
                            displayResults(status);
                            loadHistory();
                            if (window.chatbotController && status.report) window.chatbotController.onScanComplete(status);
                        }
                    } catch (e) {
                        console.error('Error parsing SSE scan status:', e);
                    }
                };

                evtSource.onerror = (err) => {
                    console.warn('SSE connection interrupted, falling back to polling...', err);
                    evtSource.close();
                    activeEventSource = null;
                    pollScanProgress(scanId, fallbackTimeout);
                };
                return;
            } catch (err) {
                console.warn('EventSource initialization failed, using polling fallback', err);
            }
        }

        // Fallback to polling if SSE unavailable
        pollScanProgress(scanId, fallbackTimeout);
    }

    // Fallback Poll Progress (max 10 minutes)
    function pollScanProgress(scanId, existingTimeout) {
        let pollCount = 0;
        const MAX_POLLS = 600;
        const interval = setInterval(async () => {
            pollCount++;
            if (pollCount > MAX_POLLS) {
                clearInterval(interval);
                if (existingTimeout) clearTimeout(existingTimeout);
                stopTimer();
                startBtn.disabled = false;
                startBtn.textContent = 'Scan →';
                startBtn.classList.remove('scanning');
                showToast('Scan timed out after 10 minutes.', 'error');
                return;
            }

            try {
                const res = await fetch(`/api/scan/${scanId}`);
                if (!res.ok) return;
                const status = await res.json();

                if (status.agents) {
                    updateAgentState('crawl', status.agents['VIBE-SHIELD-CRAWL']);
                    updateAgentState('qa', status.agents['VIBE-SHIELD-QA']);
                    updateAgentState('sec', status.agents['VIBE-SHIELD-SEC']);
                    updateAgentState('ai', status.agents['VIBE-SHIELD-AI']);
                    updateAgentState('logic', status.agents['VIBE-SHIELD-LOGIC']);
                    updateAgentState('api', status.agents['VIBE-SHIELD-API']);
                }

                if (status.terminalLogs && window.liveScanTerminal) {
                    window.liveScanTerminal.setLogs(status.terminalLogs);
                }

                if (status.completed) {
                    clearInterval(interval);
                    if (existingTimeout) clearTimeout(existingTimeout);
                    stopTimer();
                    startBtn.disabled = false;
                    startBtn.textContent = 'Scan →';
                    startBtn.classList.remove('scanning');
                    displayResults(status);
                    loadHistory();
                    if (window.chatbotController && status.report) window.chatbotController.onScanComplete(status);
                }
            } catch (e) {
                console.error('Error polling status:', e);
            }
        }, 1000);
    }

    // ── Toast notification system ──────────────────────
    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        if (container) {
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 4000);
        }
    }

    function updateAgentState(key, agentData) {
        if (!agentData) return;
        const card = document.getElementById(`agent-${key}`);
        if (!card) return;
        const badge = card.querySelector('.agent-status-pill');
        const log = card.querySelector('.agent-log-text');
        const statusMap = { 'running': 'running', 'done': 'done', 'complete': 'done', 'error': 'error', 'partial': 'partial', 'skipped': 'skipped', 'pending': '', 'waiting': '' };
        if (badge) {
            badge.className = 'agent-status-pill ' + (statusMap[agentData.status] || '');
            badge.textContent = agentData.status ? agentData.status.charAt(0).toUpperCase() + agentData.status.slice(1) : 'Waiting';
        }
        if (log) log.textContent = agentData.message || agentData.status || '...';
    }

    function resetAgentCards() {
        ['crawl', 'qa', 'sec', 'ai', 'logic', 'api'].forEach(key => {
            const card = document.getElementById(`agent-${key}`);
            if (card) {
                const badge = card.querySelector('.agent-status-pill');
                const log = card.querySelector('.agent-log-text');
                if (badge) { badge.className = 'agent-status-pill'; badge.textContent = 'Waiting'; }
                if (log) log.textContent = 'Awaiting dispatch...';
            }
        });
    }

    function startTimer() {
        secondsElapsed = 0;
        clearInterval(timerInterval);
        timerInterval = setInterval(() => {
            secondsElapsed++;
            const mins = String(Math.floor(secondsElapsed / 60)).padStart(2, '0');
            const secs = String(secondsElapsed % 60).padStart(2, '0');
            timerDisplay.textContent = `${mins}:${secs}`;
        }, 1000);
    }

    function stopTimer() {
        clearInterval(timerInterval);
    }

    let currentScoreData = null;

    function renderSecurityScoreAudit(report) {
        const scoreData = calculateSecurityScore(report);
        currentScoreData = scoreData;
        window.currentScoreData = scoreData;

        const scoreGradeText = document.getElementById('score-grade-text');
        const scoreNumberText = document.getElementById('score-number-text');
        const scoreStatusText = document.getElementById('score-status-text');
        const scoreSummaryDesc = document.getElementById('score-summary-desc');
        const scoreRingArc = document.getElementById('score-ring-arc');
        const liveBadgeContainer = document.getElementById('live-badge-container');

        if (scoreGradeText) scoreGradeText.textContent = scoreData.grade;
        if (scoreNumberText) scoreNumberText.textContent = scoreData.overallScore == null ? 'Not scored' : `${scoreData.overallScore}/100`;
        if (scoreStatusText) scoreStatusText.textContent = scoreData.statusText;
        if (scoreSummaryDesc) scoreSummaryDesc.textContent = report.coverage?.note || 'Scores describe tested surfaces only.';

        // Animate the SVG ring
        if (scoreRingArc) {
            const circumference = 2 * Math.PI * 34; // r=34
            const offset = circumference - (scoreData.overallScore / 100) * circumference;
            scoreRingArc.style.strokeDashoffset = offset;
            // Color based on grade
            const color = scoreData.overallScore >= 80 ? '#16a34a' : scoreData.overallScore >= 60 ? '#d97706' : '#dc2626';
            scoreRingArc.style.stroke = color;
        }

        // Subscores
        const sub = scoreData.subCategories;
        const setSub = (key, val) => {
            const valEl = document.getElementById(`subscore-val-${key}`);
            const barEl = document.getElementById(`subscore-bar-${key}`);
            if (valEl) valEl.textContent = val == null ? 'Not assessed' : `${val}/100`;
            if (barEl) barEl.style.width = `${val ?? 0}%`;
        };

        setSub('headers', sub.headers.score);
        setSub('ai', sub.aiSafety.score);
        setSub('api', sub.apiAuth.score);
        setSub('logic', sub.logic.score);

        // Render Live Badge
        if (liveBadgeContainer) {
            liveBadgeContainer.innerHTML = generateSvgBadge(scoreData.grade, scoreData.overallScore, scoreData.gradeColor);
        }
    }

    // Badge Copy Event Listeners
    const copyBadgeMdBtn = document.getElementById('copy-badge-md-btn');
    const copyBadgeHtmlBtn = document.getElementById('copy-badge-html-btn');

    if (copyBadgeMdBtn) {
        copyBadgeMdBtn.onclick = async () => {
            if (!currentScoreData) return;
            try {
                await navigator.clipboard.writeText(currentScoreData.badgeMarkdown);
                const orig = copyBadgeMdBtn.textContent;
                copyBadgeMdBtn.textContent = 'Copied Markdown! ✓';
                copyBadgeMdBtn.style.color = 'var(--accent-green)';
                setTimeout(() => {
                    copyBadgeMdBtn.textContent = orig;
                    copyBadgeMdBtn.style.color = '';
                }, 2000);
            } catch(e) {}
        };
    }

    if (copyBadgeHtmlBtn) {
        copyBadgeHtmlBtn.onclick = async () => {
            if (!currentScoreData) return;
            try {
                await navigator.clipboard.writeText(currentScoreData.badgeHtml);
                const orig = copyBadgeHtmlBtn.textContent;
                copyBadgeHtmlBtn.textContent = 'Copied HTML! ✓';
                copyBadgeHtmlBtn.style.color = 'var(--accent-green)';
                setTimeout(() => {
                    copyBadgeHtmlBtn.textContent = orig;
                    copyBadgeHtmlBtn.style.color = '';
                }, 2000);
            } catch(e) {}
        };
    }

    function displayResults(status) {
        if (!status.report) {
            showToast(status.failureReason || 'Scan failed without a report. Review the live logs.', 'error');
            if (resultsSection) resultsSection.classList.add('hidden');
            return;
        }
        if (status.status === 'partial') showToast(status.failureReason || 'Incomplete scan coverage', 'warn');
        if (progressSection) progressSection.classList.add('hidden');
        if (resultsSection) resultsSection.classList.remove('hidden');
        const heroSection = document.getElementById('hero-section');
        if (heroSection) heroSection.classList.add('scanned-compact');
        const report = status.report || {};
        const summary = report.dedupSummary || report.summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
        const scanId = status.scanId || currentScanId;

        window.currentScanReport = report;
        window.currentScanStatus = status;
        window.currentScanId = scanId;

        document.getElementById('count-critical').textContent = summary.critical;
        document.getElementById('count-high').textContent = summary.high;
        document.getElementById('count-medium').textContent = summary.medium;
        document.getElementById('count-low').textContent = summary.low;
        document.getElementById('count-total').textContent = summary.total;

        document.getElementById('results-meta-text').textContent = `${status.status === 'partial' ? 'Incomplete scan of' : 'Scanned'} ${status.url} in ${status.duration}s · ${summary.total} findings · ${report.surfaceInventory?.totalPages || 0} pages`;

        activeReportPath = status.reportHtmlUrl;
        viewReportBtn.disabled = !activeReportPath;
        viewReportBtn.onclick = null;
        if (activeReportPath) {
            viewReportBtn.onclick = () => window.open(activeReportPath, '_blank');
        }

        const downloadJsonBtn = document.getElementById('download-json-report-btn');
        if (downloadJsonBtn) {
            downloadJsonBtn.onclick = () => {
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
                const downloadAnchor = document.createElement('a');
                downloadAnchor.setAttribute("href", dataStr);
                downloadAnchor.setAttribute("download", `vibe-shield-audit-${scanId || 'report'}.json`);
                document.body.appendChild(downloadAnchor);
                downloadAnchor.click();
                downloadAnchor.remove();
            };
        }

        // Set up results terminal logs
        const resultsScanIdSpan = document.getElementById('results-terminal-scan-id');
        if (resultsScanIdSpan) {
            resultsScanIdSpan.textContent = scanId ? `SCAN #${scanId}` : 'SCAN LOGS';
        }

        if (status.terminalLogs && window.resultsLogsTerminal) {
            window.resultsLogsTerminal.setLogs(status.terminalLogs);
        } else if (scanId && window.resultsLogsTerminal) {
            fetch(`/api/scan/${scanId}/logs`)
                .then(r => r.json())
                .then(d => {
                    if (d.logs && d.logs.length > 0) {
                        window.resultsLogsTerminal.setLogs(d.logs);
                    }
                })
                .catch(() => {});
        }

        // Render Vibe Security Score & Shield Badge
        renderSecurityScoreAudit(report);

        // Update Trend Chart
        if (window.trendEngine) {
            window.trendEngine.updateTrends(status.url);
        }

        // Render Radial Site Map & Threat Graph
        if (window.radialSiteMap) {
            window.radialSiteMap.buildFromReport(report, status.url);
        }
        if (window.threatGraph) {
            window.threatGraph.buildFromReport(report, status.url);
        }

        // Render Table Rows
        renderFindingsTable(report.findings || []);

        // Update AI Threat & Exploitation Matrix
        if (window.aiThreatMatrix) {
            window.aiThreatMatrix.updateFromReport(report);
        }
    }

    // ═══════════════════════════════════════════════
    // CVSS v3.1 Quantitative Scoring Engine & Specification
    // ═══════════════════════════════════════════════
    const CVSS_SPEC = {
        AV: {
            N: { val: 0.85, label: 'Network (N)', desc: 'Remotely exploitable across the public Internet' },
            A: { val: 0.62, label: 'Adjacent (A)', desc: 'Requires adjacent local subnet/bluetooth access' },
            L: { val: 0.55, label: 'Local (L)', desc: 'Requires local interactive shell or local script run' },
            P: { val: 0.20, label: 'Physical (P)', desc: 'Requires physical access to host hardware' }
        },
        AC: {
            L: { val: 0.77, label: 'Low (L)', desc: 'No specialized conditions; easily repeatable' },
            H: { val: 0.44, label: 'High (H)', desc: 'Requires complex prerequisites, race conditions, or bypasses' }
        },
        PR: {
            N: { valU: 0.85, valC: 0.85, label: 'None (N)', desc: 'Unauthenticated unauthorized attacker' },
            L: { valU: 0.62, valC: 0.68, label: 'Low (L)', desc: 'Standard user privileges required' },
            H: { valU: 0.27, valC: 0.50, label: 'High (H)', desc: 'Administrative / superuser privileges required' }
        },
        UI: {
            N: { val: 0.85, label: 'None (N)', desc: 'Zero victim interaction required' },
            R: { val: 0.62, label: 'Required (R)', desc: 'Victim must perform an action (click link, accept auth)' }
        },
        S: {
            U: { label: 'Unchanged (U)', desc: 'Impacts only the immediate vulnerable software component' },
            C: { label: 'Changed (C)', desc: 'Escapes security boundary (sandbox escape, SSRF, host control)' }
        },
        C: {
            N: { val: 0.0, label: 'None (N)', desc: 'Zero confidentiality impact' },
            L: { val: 0.22, label: 'Low (L)', desc: 'Minor disclosure of non-sensitive metadata' },
            H: { val: 0.56, label: 'High (H)', desc: 'Total confidentiality loss / exfiltration of credentials & DB' }
        },
        I: {
            N: { val: 0.0, label: 'None (N)', desc: 'Zero integrity impact' },
            L: { val: 0.22, label: 'Low (L)', desc: 'Modification of minor non-critical state' },
            H: { val: 0.56, label: 'High (H)', desc: 'Total compromise of state / arbitrary code/command modification' }
        },
        A: {
            N: { val: 0.0, label: 'None (N)', desc: 'Zero availability impact' },
            L: { val: 0.22, label: 'Low (L)', desc: 'Intermittent degradation or partial rate-limiting' },
            H: { val: 0.56, label: 'High (H)', desc: 'Total denial of service / host crash' }
        }
    };

    function cvssRoundup(val) {
        const intVal = Math.round(val * 100000);
        if (intVal % 10000 === 0) return intVal / 100000;
        return (Math.floor(intVal / 10000) + 1) / 10;
    }

    function calculateCvssClient(metrics) {
        const av = (metrics.AV || 'N').toUpperCase();
        const ac = (metrics.AC || 'L').toUpperCase();
        const pr = (metrics.PR || 'N').toUpperCase();
        const ui = (metrics.UI || 'N').toUpperCase();
        const s = (metrics.S || 'U').toUpperCase();
        const c = (metrics.C || 'H').toUpperCase();
        const i = (metrics.I || 'H').toUpperCase();
        const a = (metrics.A || 'N').toUpperCase();

        const avVal = CVSS_SPEC.AV[av]?.val ?? 0.85;
        const acVal = CVSS_SPEC.AC[ac]?.val ?? 0.77;
        const isChanged = s === 'C';
        const prVal = isChanged ? (CVSS_SPEC.PR[pr]?.valC ?? 0.85) : (CVSS_SPEC.PR[pr]?.valU ?? 0.85);
        const uiVal = CVSS_SPEC.UI[ui]?.val ?? 0.85;

        const cVal = CVSS_SPEC.C[c]?.val ?? 0.0;
        const iVal = CVSS_SPEC.I[i]?.val ?? 0.0;
        const aVal = CVSS_SPEC.A[a]?.val ?? 0.0;

        const exploitability = 8.22 * avVal * acVal * prVal * uiVal;
        const iss = 1 - ((1 - cVal) * (1 - iVal) * (1 - aVal));

        let impact = 0;
        if (isChanged) {
            impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
        } else {
            impact = 6.42 * iss;
        }

        let baseScore = 0.0;
        if (impact <= 0) {
            baseScore = 0.0;
        } else if (!isChanged) {
            baseScore = cvssRoundup(Math.min(impact + exploitability, 10));
        } else {
            baseScore = cvssRoundup(Math.min(1.08 * (impact + exploitability), 10));
        }
        baseScore = Math.max(0.0, Math.min(10.0, baseScore));

        let severity = 'NONE';
        let color = '#738a9c';
        let qualDesc = 'No significant security impact detected.';
        if (baseScore >= 9.0) {
            severity = 'CRITICAL';
            color = '#ff3366';
            qualDesc = 'Vulnerability is remotely exploitable with catastrophic impact across systems.';
        } else if (baseScore >= 7.0) {
            severity = 'HIGH';
            color = '#ff9900';
            qualDesc = 'Significant impact to data confidentiality, system integrity, or availability.';
        } else if (baseScore >= 4.0) {
            severity = 'MEDIUM';
            color = '#ffcc00';
            qualDesc = 'Moderate threat requiring specific preconditions or partial exposure.';
        } else if (baseScore >= 0.1) {
            severity = 'LOW';
            color = '#00f0ff';
            qualDesc = 'Minor threat requiring elevated privileges or high user interaction.';
        }

        const vectorString = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;

        return {
            score: baseScore.toFixed(1),
            numericScore: baseScore,
            severity,
            color,
            qualDesc,
            vectorString,
            exploitabilityScore: (Math.round(exploitability * 10) / 10).toFixed(1),
            impactScore: (Math.max(0, Math.round(impact * 10) / 10)).toFixed(1),
            rawMetrics: { AV: av, AC: ac, PR: pr, UI: ui, S: s, C: c, I: i, A: a }
        };
    }

    function parseCvssVectorClient(vectorString) {
        if (!vectorString || typeof vectorString !== 'string') {
            return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
        }
        const metrics = {};
        const parts = vectorString.split('/');
        for (const part of parts) {
            const [k, v] = part.split(':');
            if (k && v && ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'].includes(k.toUpperCase())) {
                metrics[k.toUpperCase()] = v.toUpperCase();
            }
        }
        return calculateCvssClient(metrics);
    }

    function inferCvssClient(finding) {
        if (finding.cvss && finding.cvss.vectorString) {
            return parseCvssVectorClient(finding.cvss.vectorString);
        }
        const title = (finding.title || '').toLowerCase();
        const desc = (finding.description || '').toLowerCase();
        const sev = (finding.severity || 'low').toLowerCase();

        if (title.includes('prompt injection') || title.includes('jailbreak') || title.includes('system prompt')) {
            return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' });
        }
        if (title.includes('sql injection') || title.includes('sqli')) {
            return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
        }
        if (title.includes('ssrf') || title.includes('server-side request forgery')) {
            return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'L', A: 'N' });
        }
        if (title.includes('cors') || title.includes('origin')) {
            return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'L', A: 'N' });
        }
        if (title.includes('api key') || title.includes('secret') || title.includes('token') || title.includes('credential')) {
            return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' });
        }
        if (title.includes('rate limit') || title.includes('dos') || title.includes('denial of service')) {
            return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'H' });
        }
        if (title.includes('content-security-policy') || title.includes('csp') || title.includes('hsts') || title.includes('header')) {
            return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' });
        }
        if (title.includes('cookie') || title.includes('httponly') || title.includes('samesite')) {
            return calculateCvssClient({ AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' });
        }
        if (title.includes('auth') || title.includes('jwt') || title.includes('bypass')) {
            return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' });
        }

        switch (sev) {
            case 'critical': return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
            case 'high': return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' });
            case 'medium': return calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' });
            case 'low': return calculateCvssClient({ AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' });
            default: return calculateCvssClient({ AV: 'N', AC: 'H', PR: 'L', UI: 'R', S: 'U', C: 'N', I: 'N', A: 'N' });
        }
    }

    // ═══════════════════════════════════════════════
    // Findings Table Rendering
    // ═══════════════════════════════════════════════

    document.getElementById('findings-filter-row')?.addEventListener('click', event => {
        const button = event.target.closest('[data-sev-filter]');
        if (!button) return;
        document.querySelectorAll('[data-sev-filter]').forEach(btn => btn.classList.toggle('active', btn === button));
        const findings = window.currentScanReport?.findings || [];
        renderFindingsTable(button.dataset.sevFilter === 'all' ? findings : findings.filter(f => f.severity === button.dataset.sevFilter));
    });

    function renderFindingsTable(findings) {
        const tbody = document.getElementById('findings-table-body');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (!findings || findings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No findings at the configured threshold. Review scan coverage before drawing conclusions.</td></tr>`;
            return;
        }

        findings.forEach((f, idx) => {
            const tr = document.createElement('tr');
            const sev = (f.severity || 'low').toLowerCase();
            const sevClass = 'pill-' + sev;
            const cvssData = f.cvss || inferCvssClient(f);
            f.cvss = cvssData; // Cache on finding object

            const cvssPillClass = 'cvss-' + (cvssData.severity ? cvssData.severity.toLowerCase() : sev);
            const scoreDisplay = cvssData.score || '0.0';
            const remediationText = f.remediation || f.description || 'Review application code and enforce strict input validation.';

            tr.innerHTML = `
                <td>
                    <button type="button" class="cvss-score-pill ${cvssPillClass} open-cvss-btn" data-finding-index="${idx}" title="Open Interactive CVSS v3.1 Calculator">
                        🎯 ${scoreDisplay}
                    </button>
                </td>
                <td><span class="badge ${sevClass}">${sev.toUpperCase()}</span></td>
                <td>
                    <strong>${escapeHtml(f.title)}</strong>
                    <span class="cvss-vector-snippet open-cvss-btn" data-finding-index="${idx}" title="Click to inspect CVSS metrics">
                        ${escapeHtml(cvssData.vectorString || 'CVSS:3.1/...')}
                    </span>
                </td>
                <td><code>${escapeHtml(f.module || f.agent || 'Unknown')}</code></td>
                <td>${escapeHtml(f.affected_surface || 'N/A')}</td>
                <td>${escapeHtml(f.owasp?.id || (typeof f.owasp === 'string' ? f.owasp : 'Not mapped'))}</td>
                <td style="max-width: 380px;">
                    <details class="finding-remediation"><summary>Remediation & evidence</summary><p>${escapeHtml(remediationText)}</p><pre>${escapeHtml(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence || {}, null, 2))}</pre></details>
                    <div class="actions-cell-wrap">
                        <button type="button" class="btn-cvss-action open-cvss-btn" data-finding-index="${idx}">
                            🎯 CVSS Calc
                        </button>
                        <button type="button" class="btn-patch-action auto-patch-btn" data-finding-index="${idx}">
                            ⚡ Auto-Patch Code
                        </button>
                        <button type="button" class="btn-waf-action open-waf-btn" data-finding-index="${idx}" style="background: rgba(112, 0, 255, 0.1); border: 1px solid rgba(112, 0, 255, 0.35); color: #a855f7; font-size: 11px; font-weight: 600; padding: 4px 8px; border-radius: 4px; cursor: pointer;">
                            🛡️ WAF Rule
                        </button>
                    </div>
                </td>
            `;

            // Wire CVSS Modal triggers
            tr.querySelectorAll('.open-cvss-btn').forEach(btn => {
                btn.onclick = () => openCvssModal(f);
            });

            // Wire Patch Modal trigger
            const patchBtn = tr.querySelector('.auto-patch-btn');
            if (patchBtn) patchBtn.onclick = () => openAutoPatchModal(f);

            // Wire WAF Modal trigger
            const wafBtn = tr.querySelector('.open-waf-btn');
            if (wafBtn) wafBtn.onclick = () => openWafModal({ finding: f });

            tbody.appendChild(tr);
        });
    }

    // ═══════════════════════════════════════════════
    // CVSS v3.1 Interactive Modal Logic
    // ═══════════════════════════════════════════════

    const cvssModal = document.getElementById('cvss-modal');
    const closeCvssModalBtn = document.getElementById('close-cvss-modal-btn');
    const openCvssLabHeaderBtn = document.getElementById('open-cvss-lab-btn');
    const cvssFindingTitle = document.getElementById('cvss-finding-title');
    const cvssScoreRing = document.getElementById('cvss-score-ring');
    const cvssScoreNum = document.getElementById('cvss-score-num');
    const cvssSeverityBadge = document.getElementById('cvss-severity-badge');
    const cvssQualitativeDesc = document.getElementById('cvss-qualitative-desc');
    const cvssExploitScore = document.getElementById('cvss-exploit-score');
    const cvssExploitBar = document.getElementById('cvss-exploit-bar');
    const cvssImpactScore = document.getElementById('cvss-impact-score');
    const cvssImpactBar = document.getElementById('cvss-impact-bar');
    const cvssVectorString = document.getElementById('cvss-vector-string');
    const cvssCopyVectorBtn = document.getElementById('cvss-copy-vector-btn');
    const cvssCopyVectorText = document.getElementById('cvss-copy-vector-text');
    const cvssCopyJsonBtn = document.getElementById('cvss-copy-json-btn');

    let currentCvssMetrics = {
        AV: 'N',
        AC: 'L',
        PR: 'N',
        UI: 'N',
        S: 'U',
        C: 'H',
        I: 'H',
        A: 'H'
    };
    let activeCvssFinding = null;

    if (closeCvssModalBtn) {
        closeCvssModalBtn.onclick = () => cvssModal.classList.add('hidden');
    }
    if (cvssModal) {
        cvssModal.addEventListener('click', (e) => {
            if (e.target === cvssModal) cvssModal.classList.add('hidden');
        });
    }
    if (openCvssLabHeaderBtn) {
        openCvssLabHeaderBtn.onclick = () => {
            openCvssModal({
                title: 'Custom Vulnerability Threat Assessment',
                cvss: calculateCvssClient({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' })
            });
        };
    }

    const CVSS_PRESETS = {
        'prompt-injection': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N', title: 'Prompt Injection / Agent Hijacking' },
        'sqli': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H', title: 'SQL Injection Data Breach' },
        'ssrf': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'L', A: 'N', title: 'SSRF Cloud Metadata Exfiltration' },
        'secrets': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N', title: 'Hardcoded API Token / Private Key Exposure' },
        'cors': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'L', A: 'N', title: 'Wildcard CORS with Authenticated Credentials' },
        'headers': { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N', title: 'Missing Content-Security-Policy & HSTS' },
        'cookie': { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N', title: 'Insecure Session Cookie (Missing HttpOnly/Secure)' }
    };

    // Attach preset buttons
    document.querySelectorAll('.btn-cvss-preset').forEach(btn => {
        btn.onclick = () => {
            const presetKey = btn.dataset.preset;
            if (CVSS_PRESETS[presetKey]) {
                const p = CVSS_PRESETS[presetKey];
                currentCvssMetrics = {
                    AV: p.AV, AC: p.AC, PR: p.PR, UI: p.UI,
                    S: p.S, C: p.C, I: p.I, A: p.A
                };
                if (cvssFindingTitle) cvssFindingTitle.textContent = p.title;
                updateCvssModalUi();
            }
        };
    });

    // Attach metric toggle buttons
    document.querySelectorAll('.cvss-metric-group').forEach(group => {
        const metric = group.dataset.metric;
        group.querySelectorAll('.btn-metric').forEach(btn => {
            btn.onclick = () => {
                const val = btn.dataset.val;
                currentCvssMetrics[metric] = val;
                updateCvssModalUi();
            };
        });
    });

    function openCvssModal(finding) {
        if (!cvssModal) return;
        activeCvssFinding = finding;
        cvssModal.classList.remove('hidden');

        if (finding && finding.title) {
            cvssFindingTitle.textContent = finding.title;
        } else {
            cvssFindingTitle.textContent = 'CVSS v3.1 Quantitative Score Calculator';
        }

        const calculated = finding?.cvss?.rawMetrics 
            ? finding.cvss 
            : inferCvssClient(finding || {});

        currentCvssMetrics = { ...calculated.rawMetrics };
        updateCvssModalUi();
    }

    function updateCvssModalUi() {
        const result = calculateCvssClient(currentCvssMetrics);

        // Update Gauge & Numbers
        if (cvssScoreNum) cvssScoreNum.textContent = result.score;
        if (cvssScoreRing) {
            cvssScoreRing.style.borderColor = result.color;
            cvssScoreRing.style.boxShadow = `0 0 25px ${result.color}55`;
            cvssScoreRing.style.background = `radial-gradient(circle, ${result.color}22 0%, rgba(13, 18, 29, 0.9) 70%)`;
        }

        if (cvssSeverityBadge) {
            cvssSeverityBadge.className = `badge badge-${result.severity.toLowerCase()}`;
            cvssSeverityBadge.textContent = result.severity;
            cvssSeverityBadge.style.borderColor = result.color;
            cvssSeverityBadge.style.color = result.color;
            cvssSeverityBadge.style.background = `${result.color}20`;
        }

        if (cvssQualitativeDesc) {
            cvssQualitativeDesc.textContent = result.qualDesc;
        }

        // Subscores
        if (cvssExploitScore) cvssExploitScore.textContent = `${result.exploitabilityScore} / 3.9`;
        if (cvssExploitBar) {
            const expPct = Math.min(100, (parseFloat(result.exploitabilityScore) / 3.9) * 100);
            cvssExploitBar.style.width = `${expPct.toFixed(0)}%`;
        }

        if (cvssImpactScore) cvssImpactScore.textContent = `${result.impactScore} / 6.0`;
        if (cvssImpactBar) {
            const impPct = Math.min(100, (parseFloat(result.impactScore) / 6.0) * 100);
            cvssImpactBar.style.width = `${impPct.toFixed(0)}%`;
        }

        // Vector String
        if (cvssVectorString) {
            cvssVectorString.textContent = result.vectorString;
        }

        // Update Metric Buttons & Active States
        document.querySelectorAll('.cvss-metric-group').forEach(group => {
            const metric = group.dataset.metric;
            const currentVal = currentCvssMetrics[metric];
            const descEl = document.getElementById(`desc-${metric}`);
            
            if (CVSS_SPEC[metric] && CVSS_SPEC[metric][currentVal] && descEl) {
                descEl.textContent = CVSS_SPEC[metric][currentVal].desc || '';
            }

            group.querySelectorAll('.btn-metric').forEach(btn => {
                if (btn.dataset.val === currentVal) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });
        });

        // If finding was active, sync back updated score
        if (activeCvssFinding) {
            activeCvssFinding.cvss = result;
        }
    }

    // Copy Vector String
    if (cvssCopyVectorBtn) {
        cvssCopyVectorBtn.onclick = async () => {
            const vec = cvssVectorString?.textContent || '';
            try {
                await navigator.clipboard.writeText(vec);
                if (cvssCopyVectorText) cvssCopyVectorText.textContent = 'Copied! ✓';
                cvssCopyVectorBtn.style.color = 'var(--accent-green)';
                setTimeout(() => {
                    if (cvssCopyVectorText) cvssCopyVectorText.textContent = 'Copy Vector';
                    cvssCopyVectorBtn.style.color = '';
                }, 2000);
            } catch(e) {}
        };
    }

    // Copy JSON Representation
    if (cvssCopyJsonBtn) {
        cvssCopyJsonBtn.onclick = async () => {
            const result = calculateCvssClient(currentCvssMetrics);
            const payload = JSON.stringify({
                version: '3.1',
                vectorString: result.vectorString,
                baseScore: parseFloat(result.score),
                baseSeverity: result.severity,
                exploitabilityScore: parseFloat(result.exploitabilityScore),
                impactScore: parseFloat(result.impactScore),
                metrics: currentCvssMetrics
            }, null, 2);

            try {
                await navigator.clipboard.writeText(payload);
                cvssCopyJsonBtn.textContent = 'JSON Copied! ✓';
                cvssCopyJsonBtn.style.color = 'var(--accent-green)';
                setTimeout(() => {
                    cvssCopyJsonBtn.textContent = '📦 Copy JSON';
                    cvssCopyJsonBtn.style.color = '';
                }, 2000);
            } catch(e) {}
        };
    }

    // ═══════════════════════════════════════════════
    // AI Auto-Patch Modal Logic
    // ═══════════════════════════════════════════════

    const patchModal = document.getElementById('patch-modal');
    const closePatchModalBtn = document.getElementById('close-patch-modal-btn');
    const patchFindingTitle = document.getElementById('patch-finding-title');
    const patchRecText = document.getElementById('patch-recommendation-text');
    const frameworkTabsContainer = document.getElementById('framework-tabs');
    const patchTargetFile = document.getElementById('patch-target-file');
    const patchCodeContent = document.getElementById('patch-code-content');
    const copyPatchBtn = document.getElementById('copy-patch-btn');
    const copyBtnText = document.getElementById('copy-btn-text');

    if (closePatchModalBtn) {
        closePatchModalBtn.onclick = () => patchModal.classList.add('hidden');
    }
    if (patchModal) {
        patchModal.addEventListener('click', (e) => {
            if (e.target === patchModal) patchModal.classList.add('hidden');
        });
    }

    async function openAutoPatchModal(finding) {
        if (!patchModal) return;
        patchModal.classList.remove('hidden');
        patchFindingTitle.textContent = finding.title || 'Security Remediation Patch';
        patchRecText.textContent = 'Analyzing vulnerability signature and synthesizing idiomatic framework guardrails...';
        patchTargetFile.textContent = '📁 Loading...';
        patchCodeContent.textContent = '// Synthesizing AI Auto-Patch...';
        frameworkTabsContainer.innerHTML = '';

        try {
            const res = await fetch('/api/patch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(finding)
            });

            const patchData = await res.json();
            renderAutoPatch(patchData);
        } catch (err) {
            patchRecText.textContent = 'Error fetching patch: ' + err.message;
        }
    }

    function renderAutoPatch(patchData) {
        patchRecText.textContent = patchData.recommendation || 'Apply the following hardened code configuration to mitigate the vulnerability.';
        frameworkTabsContainer.innerHTML = '';

        const frameworks = patchData.frameworks || {};
        const keys = Object.keys(frameworks);
        if (keys.length === 0) return;

        keys.forEach((fwKey, idx) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'tab-btn' + (idx === 0 ? ' active' : '');
            btn.textContent = fwKey;
            btn.onclick = () => {
                document.querySelectorAll('.framework-tabs .tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                displayFrameworkCode(frameworks[fwKey]);
            };
            frameworkTabsContainer.appendChild(btn);
        });

        // Display first framework by default
        displayFrameworkCode(frameworks[keys[0]]);
    }

    function displayFrameworkCode(fwData) {
        patchTargetFile.textContent = '📁 ' + (fwData.file || 'Configuration');
        patchCodeContent.textContent = fwData.code || '// No code available';
    }

    if (copyPatchBtn) {
        copyPatchBtn.onclick = async () => {
            const textToCopy = patchCodeContent.textContent;
            try {
                await navigator.clipboard.writeText(textToCopy);
                copyBtnText.textContent = 'Copied! ✓';
                copyPatchBtn.style.borderColor = 'var(--accent-green)';
                copyPatchBtn.style.color = 'var(--accent-green)';
                setTimeout(() => {
                    copyBtnText.textContent = 'Copy Patch';
                    copyPatchBtn.style.borderColor = '';
                    copyPatchBtn.style.color = '';
                }, 2000);
            } catch (err) {
                console.error('Failed to copy text:', err);
            }
        };
    }

    // ═══════════════════════════════════════════════
    // Production Hardening & WAF Exporter Logic
    // ═══════════════════════════════════════════════

    const wafModal = document.getElementById('waf-modal');
    const closeWafModalBtn = document.getElementById('close-waf-modal-btn');
    const openWafHeaderBtn = document.getElementById('open-waf-modal-header-btn');
    const exportWafResultsBtn = document.getElementById('export-waf-bundle-btn');
    const wafModalTitle = document.getElementById('waf-modal-title');
    const wafTargetDomain = document.getElementById('waf-target-domain');
    const wafFindingsCount = document.getElementById('waf-findings-count');
    const wafFilePath = document.getElementById('waf-file-path');
    const wafFileDesc = document.getElementById('waf-file-desc');
    const wafCodeContent = document.getElementById('waf-code-content');
    const wafDeployCommand = document.getElementById('waf-deploy-command');
    const wafCopyCodeBtn = document.getElementById('waf-copy-code-btn');
    const wafCopyBtnText = document.getElementById('waf-copy-btn-text');
    const wafDownloadFileBtn = document.getElementById('waf-download-file-btn');
    const wafDownloadAllBtn = document.getElementById('waf-download-all-btn');

    let currentWafBundle = null;
    let activeWafTab = 'nginx';

    const WAF_TAB_META = {
        nginx: {
            file: '📁 /etc/nginx/conf.d/vibe-shield-security.conf',
            desc: 'Production reverse proxy rate-limiting & WAF security rules',
            filename: 'vibe-shield-security.conf',
            cmd: 'sudo cp vibe-shield-security.conf /etc/nginx/conf.d/ && sudo nginx -t && sudo systemctl reload nginx',
            mime: 'text/plain'
        },
        cloudflare: {
            file: '📁 cloudflare-waf-rules.txt',
            desc: 'Cloudflare Ruleset Expressions & Response Header Transforms',
            filename: 'cloudflare-waf-rules.txt',
            cmd: 'Paste expressions into Cloudflare Dashboard -> Security -> WAF -> Custom Rules',
            mime: 'text/plain'
        },
        caddy: {
            file: '📁 /etc/caddy/Caddyfile',
            desc: 'Caddy v2 automatic HTTPS, header security & blocklists',
            filename: 'Caddyfile',
            cmd: 'sudo caddy reload --config /etc/caddy/Caddyfile',
            mime: 'text/plain'
        },
        gitPatch: {
            file: '📁 vibe-shield-hardening.patch',
            desc: 'Unified Git patch implementing defense-in-depth middleware',
            filename: 'vibe-shield-hardening.patch',
            cmd: 'git apply vibe-shield-hardening.patch',
            mime: 'text/x-diff'
        },
        env: {
            file: '📁 .env.production',
            desc: 'Hardened production environment variable template',
            filename: '.env.production',
            cmd: 'cp .env.production .env && chmod 600 .env',
            mime: 'text/plain'
        },
        docker: {
            file: '📁 Dockerfile.hardened',
            desc: 'Multi-stage non-root container with dropped capabilities',
            filename: 'Dockerfile.hardened',
            cmd: 'docker build -t app-hardened -f Dockerfile.hardened .',
            mime: 'text/plain'
        }
    };

    if (closeWafModalBtn) {
        closeWafModalBtn.onclick = () => wafModal.classList.add('hidden');
    }
    if (wafModal) {
        wafModal.addEventListener('click', (e) => {
            if (e.target === wafModal) wafModal.classList.add('hidden');
        });
    }

    if (openWafHeaderBtn) {
        openWafHeaderBtn.onclick = () => openWafModal();
    }
    if (exportWafResultsBtn) {
        exportWafResultsBtn.onclick = () => openWafModal();
    }

    // Tab buttons
    document.querySelectorAll('.waf-tab-btn').forEach(btn => {
        btn.onclick = () => {
            const tab = btn.dataset.tab;
            if (tab && WAF_TAB_META[tab]) {
                activeWafTab = tab;
                document.querySelectorAll('.waf-tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                renderWafTabContent();
            }
        };
    });

    async function openWafModal(context = {}) {
        if (!wafModal) return;
        wafModal.classList.remove('hidden');

        // Determine report context
        const report = context.report || window.currentScanReport || {};
        const scanId = context.scanId || window.currentScanId;
        const finding = context.finding;
        const target = context.target || report.meta?.target || window.currentScanStatus?.url || document.getElementById('target-url')?.value || 'target-app.com';

        wafModalTitle.textContent = `Production Hardening & WAF Bundle (${target})`;
        wafTargetDomain.textContent = target.replace(/https?:\/\//, '').split('/')[0];
        wafFindingsCount.textContent = finding ? '1 Specific Finding' : `${report.findings?.length || report.dedupSummary?.total || 0} Security Findings Mitigated`;
        wafCodeContent.textContent = '// Synthesizing production hardening & WAF configuration bundle...';

        try {
            const res = await fetch('/api/export/fix-bundle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    report,
                    scanId,
                    finding,
                    target
                })
            });

            currentWafBundle = await res.json();
            if (currentWafBundle.target) {
                wafTargetDomain.textContent = currentWafBundle.target;
            }
            if (currentWafBundle.findingsResolved !== undefined) {
                wafFindingsCount.textContent = `${currentWafBundle.findingsResolved} Findings Mitigated`;
            }
            renderWafTabContent();
        } catch (err) {
            wafCodeContent.textContent = '// Error synthesizing bundle: ' + err.message;
        }
    }

    function renderWafTabContent() {
        if (!currentWafBundle || !currentWafBundle.artifacts) return;
        const meta = WAF_TAB_META[activeWafTab] || WAF_TAB_META.nginx;
        const code = currentWafBundle.artifacts[activeWafTab] || '// No configuration available';

        if (wafFilePath) wafFilePath.textContent = meta.file;
        if (wafFileDesc) wafFileDesc.textContent = meta.desc;
        if (wafDeployCommand) wafDeployCommand.textContent = meta.cmd;
        if (wafCodeContent) wafCodeContent.textContent = code;
    }

    function downloadTextFile(filename, text, mimeType = 'text/plain') {
        const blob = new Blob([text], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Copy Current Code
    if (wafCopyCodeBtn) {
        wafCopyCodeBtn.onclick = async () => {
            const text = wafCodeContent?.textContent || '';
            try {
                await navigator.clipboard.writeText(text);
                if (wafCopyBtnText) wafCopyBtnText.textContent = 'Copied! ✓';
                wafCopyCodeBtn.style.color = 'var(--accent-green)';
                setTimeout(() => {
                    if (wafCopyBtnText) wafCopyBtnText.textContent = 'Copy Configuration';
                    wafCopyCodeBtn.style.color = '';
                }, 2000);
            } catch(e) {}
        };
    }

    // Download Active File
    if (wafDownloadFileBtn) {
        wafDownloadFileBtn.onclick = () => {
            if (!currentWafBundle || !currentWafBundle.artifacts) return;
            const meta = WAF_TAB_META[activeWafTab] || WAF_TAB_META.nginx;
            const code = currentWafBundle.artifacts[activeWafTab] || '';
            downloadTextFile(meta.filename, code, meta.mime);
        };
    }

    // Download Full Hardening Bundle (Compound Markdown / Shell Script)
    if (wafDownloadAllBtn) {
        wafDownloadAllBtn.onclick = () => {
            if (!currentWafBundle || !currentWafBundle.artifacts) return;
            const domain = currentWafBundle.target || 'target-app';
            let bundleContent = `# ==============================================================================
# VIBE SHIELD Full Hardening & WAF Bundle
# Target: ${domain}
# Generated: ${new Date().toISOString()}
# Resolves: ${currentWafBundle.findingsResolved || 0} Findings
# ==============================================================================

### 1. Nginx Security Configuration (nginx.conf)
\`\`\`nginx
${currentWafBundle.artifacts.nginx || ''}
\`\`\`

### 2. Cloudflare WAF Custom Rules
\`\`\`text
${currentWafBundle.artifacts.cloudflare || ''}
\`\`\`

### 3. Caddyfile Hardening
\`\`\`caddy
${currentWafBundle.artifacts.caddy || ''}
\`\`\`

### 4. GitHub PR Unified Patch (.patch)
\`\`\`diff
${currentWafBundle.artifacts.gitPatch || ''}
\`\`\`

### 5. Production Environment Template (.env.production)
\`\`\`env
${currentWafBundle.artifacts.env || ''}
\`\`\`

### 6. Dockerfile Multi-Stage Non-Root
\`\`\`dockerfile
${currentWafBundle.artifacts.docker || ''}
\`\`\`
`;
            downloadTextFile(`vibe-shield-hardening-${domain}.md`, bundleContent, 'text/markdown');
        };
    }

    class RadialSiteMapEngine {
        constructor(canvas, inspector) {
            this.canvas = canvas;
            this.ctx = canvas.getContext('2d');
            this.inspector = inspector;
            this.nodes = [];
            this.edges = [];
            this.particles = [];
            this.selectedNode = null;
            this.hoveredNode = null;
            this.draggedNode = null;
            this.animId = null;

            this.layoutMode = 'radial';
            this.activeFilter = 'all';
            this.searchQuery = '';

            // Performance flags
            this.isDirty = true;
            this.isVisible = true;
            this.isTabActive = !document.hidden;

            this.initVisibilityObserver();
            this.initEvents();
            this.resize();
            window.addEventListener('resize', () => {
                this.resize();
                if (this.lastReport) this.buildFromReport(this.lastReport, this.lastUrl);
            });
        }

        initVisibilityObserver() {
            if ('IntersectionObserver' in window) {
                this.observer = new IntersectionObserver((entries) => {
                    entries.forEach(entry => {
                        this.isVisible = entry.isIntersecting;
                        if (this.isVisible && this.isTabActive) {
                            this.markDirty();
                        } else {
                            this.stopAnimation();
                        }
                    });
                }, { threshold: 0.05 });
                this.observer.observe(this.canvas);
            }

            document.addEventListener('visibilitychange', () => {
                this.isTabActive = !document.hidden;
                if (this.isVisible && this.isTabActive) {
                    this.markDirty();
                } else {
                    this.stopAnimation();
                }
            });
        }

        markDirty() {
            this.isDirty = true;
            if (this.isVisible && this.isTabActive && !this.animId) {
                this.startAnimation();
            }
        }

        resize() {
            if (!this.canvas.parentElement) return;
            const rect = this.canvas.parentElement.getBoundingClientRect();
            this.canvas.width = rect.width || 1000;
            this.canvas.height = rect.height || 480;
        }

        initEvents() {
            let isDown = false;
            let dragOffset = { x: 0, y: 0 };

            this.canvas.addEventListener('mousedown', (e) => {
                const rect = this.canvas.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;

                const clicked = this.findNodeAt(x, y);
                if (clicked) {
                    this.draggedNode = clicked;
                    this.selectedNode = clicked;
                    dragOffset.x = x - clicked.x;
                    dragOffset.y = y - clicked.y;
                    isDown = true;
                    this.canvas.style.cursor = 'grabbing';
                    this.showInspector(clicked);
                    this.markDirty();
                }
            });

            this.canvas.addEventListener('mousemove', (e) => {
                const rect = this.canvas.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;

                if (isDown && this.draggedNode) {
                    this.draggedNode.x = x - dragOffset.x;
                    this.draggedNode.y = y - dragOffset.y;
                    this.canvas.style.cursor = 'grabbing';
                    this.markDirty();
                } else {
                    const hovered = this.findNodeAt(x, y);
                    if (this.hoveredNode !== hovered) {
                        this.hoveredNode = hovered;
                        this.canvas.style.cursor = hovered ? 'pointer' : 'default';
                        this.markDirty();
                    }
                }
            });

            window.addEventListener('mouseup', () => {
                if (isDown) {
                    isDown = false;
                    this.draggedNode = null;
                    if (this.canvas) this.canvas.style.cursor = this.hoveredNode ? 'pointer' : 'default';
                    this.markDirty();
                }
            });

            const closeBtn = document.getElementById('close-sitemap-inspector-btn');
            if (closeBtn) {
                closeBtn.onclick = () => {
                    this.inspector.classList.add('hidden');
                    this.selectedNode = null;
                    this.markDirty();
                };
            }

            const resetBtn = document.getElementById('btn-reset-sitemap');
            if (resetBtn) {
                resetBtn.onclick = () => {
                    if (this.lastReport) this.buildFromReport(this.lastReport, this.lastUrl);
                };
            }

            const toggleLayoutBtn = document.getElementById('btn-toggle-sitemap-layout');
            if (toggleLayoutBtn) {
                toggleLayoutBtn.onclick = () => {
                    this.layoutMode = this.layoutMode === 'radial' ? 'tree' : 'radial';
                    toggleLayoutBtn.textContent = this.layoutMode === 'radial' ? 'Mode: 🪐 Radial' : 'Mode: 🌲 Tree';
                    if (this.lastReport) this.buildFromReport(this.lastReport, this.lastUrl);
                };
            }

            const filterGroup = document.querySelector('#sitemap-container .canvas-card-controls');
            if (filterGroup) {
                filterGroup.addEventListener('click', (e) => {
                    const btn = e.target.closest('[data-sitemap-filter]');
                    if (!btn) return;
                    filterGroup.querySelectorAll('[data-sitemap-filter]').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    this.activeFilter = btn.dataset.sitemapFilter || 'all';
                    this.applyFilter();
                });
            }

            const searchInput = document.getElementById('sitemap-search-input');
            if (searchInput) {
                searchInput.addEventListener('input', (e) => {
                    this.searchQuery = e.target.value.trim().toLowerCase();
                    this.applyFilter();
                });
            }

            const filterTableBtn = document.getElementById('sitemap-filter-table-btn');
            if (filterTableBtn) {
                filterTableBtn.onclick = () => {
                    if (this.selectedNode) {
                        this.filterFindingsTableByRoute(this.selectedNode.path || this.selectedNode.label);
                    }
                };
            }
        }

        filterFindingsTableByRoute(routePath) {
            if (!this.lastReport) return;
            const findings = this.lastReport.findings || [];
            const cleanTarget = routePath.toLowerCase();

            const matched = findings.filter(f => {
                const surface = (f.affected_surface || '').toLowerCase();
                try { return new URL(surface).pathname.toLowerCase() === cleanTarget; } catch { return false; }
            });

            if (matched.length === 0) {
                showToast(`No specific finding mapped to ${routePath}, showing all findings`, 'info');
                renderFindingsTable(findings);
            } else {
                showToast(`Filtered findings for route: ${routePath} (${matched.length} findings)`, 'success');
                renderFindingsTable(matched);
                const tableWrap = document.querySelector('.table-responsive');
                if (tableWrap) tableWrap.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
        }

        applyFilter() {
            this.nodes.forEach(node => {
                let matchesType = true;
                if (this.activeFilter !== 'all') {
                    if (this.activeFilter === 'api') matchesType = node.category === 'api';
                    else if (this.activeFilter === 'auth') matchesType = node.isAuthGated;
                    else if (this.activeFilter === 'vuln') matchesType = (node.vulnCount || 0) > 0;
                    else if (this.activeFilter === 'page') matchesType = node.category === 'page';
                }

                let matchesSearch = true;
                if (this.searchQuery) {
                    matchesSearch = (node.label || '').toLowerCase().includes(this.searchQuery) ||
                                    (node.path || '').toLowerCase().includes(this.searchQuery);
                }

                node.isDimmed = !(matchesType && matchesSearch);
            });
            this.markDirty();
        }

        findNodeAt(x, y) {
            for (let i = this.nodes.length - 1; i >= 0; i--) {
                const n = this.nodes[i];
                const dist = Math.hypot(n.x - x, n.y - y);
                if (dist <= n.radius + 8) return n;
            }
            return null;
        }

        buildFromReport(report, targetUrl) {
            this.lastReport = report;
            this.lastUrl = targetUrl;
            this.resize();

            this.nodes = [];
            this.edges = [];
            this.particles = [];

            const width = this.canvas.width || 1000;
            const height = this.canvas.height || 480;

            let host = 'target-app.com';
            try { host = new URL(targetUrl).hostname; } catch(e) {}

            const findings = report.findings || [];

            // Extract discovered routes from findings & surface inventory
            const discoveredRoutesMap = new Map();

            for (const page of report.surfaceInventory?.pages || []) {
                try {
                    const parsed = new URL(page.url);
                    discoveredRoutesMap.set(parsed.pathname, { path: parsed.pathname, label: parsed.pathname, category: 'page', method: 'GET', auth: 'Not assessed', inputs: 'Not assessed' });
                } catch {}
            }
            for (const f of findings) {
                try {
                    const parsed = new URL(f.affected_surface);
                    if (parsed.origin !== new URL(targetUrl).origin) continue;
                    if (!discoveredRoutesMap.has(parsed.pathname)) discoveredRoutesMap.set(parsed.pathname, { path: parsed.pathname, label: parsed.pathname, category: 'page', method: 'Unknown', auth: 'Not assessed', inputs: 'See finding evidence' });
                } catch {}
            }

            // Count findings per route
            const routesList = Array.from(discoveredRoutesMap.values());
            routesList.forEach(r => {
                const clean = r.path.toLowerCase();
                const matchedFindings = findings.filter(f => {
                    const aff = (f.affected_surface || '').toLowerCase();
                    try { return new URL(aff).pathname.toLowerCase() === clean; } catch { return false; }
                });
                r.vulnCount = matchedFindings.length;
                r.matchedFindings = matchedFindings;
                r.isAuthGated = r.category === 'auth' || (r.auth && (r.auth.toLowerCase().includes('protect') || r.auth.toLowerCase().includes('session')));
            });

            // Update subtitle stats
            const subtitleEl = document.getElementById('sitemap-meta-subtitle');
            if (subtitleEl) {
                const totalApis = routesList.filter(r => r.category === 'api').length;
                const totalAuth = routesList.filter(r => r.isAuthGated).length;
                const totalVulns = routesList.filter(r => r.vulnCount > 0).length;
                subtitleEl.textContent = `${routesList.length} Discovered Routes · ${totalApis} APIs · ${totalAuth} Auth Walls · ${totalVulns} Vulnerable Surfaces`;
            }

            // 1. Root Node (Center)
            const centerX = width * 0.5;
            const centerY = height * 0.5;

            const rootNode = {
                id: 'sitemap-root',
                path: '/',
                label: host,
                category: 'root',
                x: this.layoutMode === 'radial' ? centerX : width * 0.12,
                y: centerY,
                radius: 24,
                color: '#00ff88',
                glow: 'rgba(0, 255, 136, 0.5)',
                icon: '🛡️',
                typeLabel: 'Target Web Origin',
                auth: 'Origin Surface',
                vulnCount: 0,
                inputs: 'All Edge Vectors'
            };
            this.nodes.push(rootNode);

            // Group routes into Branches: Pages, APIs, Auth/Boundary
            const pageRoutes = routesList.filter(r => r.category === 'page');
            const apiRoutes = routesList.filter(r => r.category === 'api');
            const authRoutes = routesList.filter(r => r.category === 'auth');

            const categories = [
                { id: 'cat-pages', label: 'Web Pages (SPA)', icon: '🌐', color: '#00ff88', glow: 'rgba(0, 255, 136, 0.4)', routes: pageRoutes },
                { id: 'cat-api', label: 'REST APIs & Endpoints', icon: '⚡', color: '#00e5ff', glow: 'rgba(0, 229, 255, 0.4)', routes: apiRoutes },
                { id: 'cat-auth', label: 'Auth & Protected Walls', icon: '🔒', color: '#ffb700', glow: 'rgba(255, 183, 0, 0.4)', routes: authRoutes }
            ].filter(c => c.routes.length > 0);

            if (this.layoutMode === 'radial') {
                // Radial Orbit Positioning
                const catOrbitRadius = Math.min(width, height) * 0.28;
                const leafOrbitRadius = Math.min(width, height) * 0.42;

                categories.forEach((cat, cIdx) => {
                    const baseAngle = (cIdx / categories.length) * Math.PI * 2 - Math.PI / 2;
                    const catX = centerX + Math.cos(baseAngle) * catOrbitRadius;
                    const catY = centerY + Math.sin(baseAngle) * catOrbitRadius;

                    const catNode = {
                        id: cat.id,
                        label: cat.label,
                        category: 'category',
                        x: catX,
                        y: catY,
                        radius: 20,
                        color: cat.color,
                        glow: cat.glow,
                        icon: cat.icon,
                        typeLabel: 'Route Cluster',
                        auth: 'Structural Branch',
                        vulnCount: cat.routes.reduce((acc, r) => acc + r.vulnCount, 0),
                        inputs: 'Route Branch'
                    };
                    this.nodes.push(catNode);
                    this.edges.push({ source: rootNode, target: catNode, color: cat.color });

                    // Layout leaf routes around category arc
                    const arcSpan = (Math.PI * 1.6) / categories.length;
                    const routeCount = cat.routes.length;

                    cat.routes.forEach((r, rIdx) => {
                        const offset = routeCount > 1 ? (rIdx / (routeCount - 1) - 0.5) * arcSpan : 0;
                        const routeAngle = baseAngle + offset;
                        const rX = centerX + Math.cos(routeAngle) * leafOrbitRadius;
                        const rY = centerY + Math.sin(routeAngle) * leafOrbitRadius;

                        const isVuln = r.vulnCount > 0;
                        const nodeColor = isVuln ? '#ff3366' : cat.color;
                        const nodeGlow = isVuln ? 'rgba(255, 51, 102, 0.5)' : cat.glow;
                        const icon = isVuln ? '🚨' : (r.category === 'api' ? '⚡' : r.isAuthGated ? '🔒' : '📄');

                        const rNode = {
                            id: `route-${cIdx}-${rIdx}`,
                            path: r.path,
                            label: r.label,
                            category: r.category,
                            isAuthGated: r.isAuthGated,
                            vulnCount: r.vulnCount,
                            matchedFindings: r.matchedFindings,
                            x: rX,
                            y: rY,
                            radius: isVuln ? 17 : 14,
                            color: nodeColor,
                            glow: nodeGlow,
                            icon: icon,
                            typeLabel: r.category === 'api' ? `REST API (${r.method})` : (r.isAuthGated ? 'Auth-Gated Route' : 'Public Web Page'),
                            auth: r.auth,
                            inputs: r.inputs
                        };
                        this.nodes.push(rNode);
                        this.edges.push({ source: catNode, target: rNode, color: nodeColor });
                    });
                });
            } else {
                // Hierarchical Tree Layout
                const col2X = width * 0.42;
                const col3X = width * 0.76;

                let leafYTracker = 40;
                const totalLeaves = routesList.length;
                const rowSpacing = Math.max(28, (height - 60) / Math.max(1, totalLeaves));

                categories.forEach((cat, cIdx) => {
                    const catStartCount = cat.routes.length;
                    const catCenterY = leafYTracker + (catStartCount * rowSpacing) / 2;

                    const catNode = {
                        id: cat.id,
                        label: cat.label,
                        category: 'category',
                        x: col2X,
                        y: catCenterY,
                        radius: 19,
                        color: cat.color,
                        glow: cat.glow,
                        icon: cat.icon,
                        typeLabel: 'Route Cluster',
                        auth: 'Structural Branch',
                        vulnCount: cat.routes.reduce((acc, r) => acc + r.vulnCount, 0),
                        inputs: 'Route Branch'
                    };
                    this.nodes.push(catNode);
                    this.edges.push({ source: rootNode, target: catNode, color: cat.color });

                    cat.routes.forEach((r, rIdx) => {
                        const rY = leafYTracker + 14;
                        leafYTracker += rowSpacing;

                        const isVuln = r.vulnCount > 0;
                        const nodeColor = isVuln ? '#ff3366' : cat.color;
                        const nodeGlow = isVuln ? 'rgba(255, 51, 102, 0.5)' : cat.glow;
                        const icon = isVuln ? '🚨' : (r.category === 'api' ? '⚡' : r.isAuthGated ? '🔒' : '📄');

                        const rNode = {
                            id: `route-${cIdx}-${rIdx}`,
                            path: r.path,
                            label: r.label,
                            category: r.category,
                            isAuthGated: r.isAuthGated,
                            vulnCount: r.vulnCount,
                            matchedFindings: r.matchedFindings,
                            x: col3X,
                            y: rY,
                            radius: isVuln ? 16 : 13,
                            color: nodeColor,
                            glow: nodeGlow,
                            icon: icon,
                            typeLabel: r.category === 'api' ? `REST API (${r.method})` : (r.isAuthGated ? 'Auth-Gated Route' : 'Public Web Page'),
                            auth: r.auth,
                            inputs: r.inputs
                        };
                        this.nodes.push(rNode);
                        this.edges.push({ source: catNode, target: rNode, color: nodeColor });
                    });
                });
            }

            this.spawnParticles();
            this.selectedNode = null;
            this.inspector?.classList.add('hidden');
            this.draw();
            this.startAnimation();
        }

        spawnParticles() {
            this.particles = [];
            this.edges.forEach((edge) => {
                for (let i = 0; i < 2; i++) {
                    this.particles.push({
                        edge,
                        progress: Math.random(),
                        speed: 0.004 + Math.random() * 0.005,
                        color: edge.color || '#00e5ff'
                    });
                }
            });
        }

        stopAnimation() {
            if (this.animId) {
                cancelAnimationFrame(this.animId);
                this.animId = null;
            }
        }

        startAnimation() {
            if (this.animId) return;
            if (!this.isVisible || !this.isTabActive) return;

            const render = () => {
                if (!this.isVisible || !this.isTabActive) {
                    this.animId = null;
                    return;
                }

                this.update();
                this.draw();
                this.isDirty = false;

                if (this.particles.length > 0 || this.draggedNode || this.isDirty) {
                    this.animId = requestAnimationFrame(render);
                } else {
                    this.animId = null;
                }
            };
            this.animId = requestAnimationFrame(render);
        }

        update() {
            for (let i = 0; i < this.nodes.length; i++) {
                for (let j = i + 1; j < this.nodes.length; j++) {
                    const n1 = this.nodes[i];
                    const n2 = this.nodes[j];
                    const dx = n2.x - n1.x;
                    const dy = n2.y - n1.y;
                    const dist = Math.hypot(dx, dy) || 1;
                    if (dist < 45) {
                        const force = (45 - dist) / dist * 0.012;
                        if (n1 !== this.draggedNode && n1.id !== 'sitemap-root') { n1.x -= dx * force; n1.y -= dy * force; }
                        if (n2 !== this.draggedNode && n2.id !== 'sitemap-root') { n2.x += dx * force; n2.y += dy * force; }
                    }
                }
            }

            this.particles.forEach(p => {
                p.progress += p.speed;
                if (p.progress >= 1) p.progress = 0;
            });
        }

        draw() {
            const ctx = this.ctx;
            const width = this.canvas.width;
            const height = this.canvas.height;
            ctx.clearRect(0, 0, width, height);

            const centerX = width * 0.5;
            const centerY = height * 0.5;

            // Concentric Orbital Rings (in Radial mode)
            if (this.layoutMode === 'radial') {
                [0.28, 0.42].forEach(ratio => {
                    ctx.beginPath();
                    ctx.arc(centerX, centerY, Math.min(width, height) * ratio, 0, Math.PI * 2);
                    ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
                    ctx.lineWidth = 1;
                    ctx.setLineDash([4, 6]);
                    ctx.stroke();
                    ctx.setLineDash([]);
                });
            }

            // Draw Edges
            this.edges.forEach(edge => {
                const isDimmed = edge.source.isDimmed || edge.target.isDimmed;
                const isHighlighted = (this.selectedNode && (edge.source === this.selectedNode || edge.target === this.selectedNode)) ||
                                      (this.hoveredNode && (edge.source === this.hoveredNode || edge.target === this.hoveredNode));

                ctx.beginPath();
                ctx.moveTo(edge.source.x, edge.source.y);

                if (this.layoutMode === 'tree') {
                    const cp1X = edge.source.x + (edge.target.x - edge.source.x) * 0.5;
                    const cp1Y = edge.source.y;
                    const cp2X = edge.source.x + (edge.target.x - edge.source.x) * 0.5;
                    const cp2Y = edge.target.y;
                    ctx.bezierCurveTo(cp1X, cp1Y, cp2X, cp2Y, edge.target.x, edge.target.y);
                } else {
                    ctx.lineTo(edge.target.x, edge.target.y);
                }

                ctx.strokeStyle = isDimmed ? 'rgba(255, 255, 255, 0.03)' : (isHighlighted ? '#00ff88' : 'rgba(51, 65, 85, 0.25)');
                ctx.lineWidth = isHighlighted ? 2.2 : 1.2;
                ctx.stroke();
            });

            // Particles
            this.particles.forEach(p => {
                if (p.edge.source.isDimmed || p.edge.target.isDimmed) return;
                const x = p.edge.source.x + (p.edge.target.x - p.edge.source.x) * p.progress;
                const y = p.edge.source.y + (p.edge.target.y - p.edge.source.y) * p.progress;

                ctx.save();
                ctx.beginPath();
                ctx.arc(x, y, 2.5, 0, Math.PI * 2);
                ctx.fillStyle = p.color;
                ctx.shadowColor = p.color;
                ctx.shadowBlur = 8;
                ctx.fill();
                ctx.restore();
            });

            // Draw Nodes
            this.nodes.forEach(node => {
                const isSelected = this.selectedNode === node;
                const isHovered = this.hoveredNode === node;
                const isDimmed = node.isDimmed;

                ctx.save();
                if (isDimmed) ctx.globalAlpha = 0.2;

                // Outer selection ring
                if (isSelected || isHovered) {
                    ctx.beginPath();
                    ctx.arc(node.x, node.y, node.radius + 6, 0, Math.PI * 2);
                    ctx.strokeStyle = isSelected ? '#00ff88' : 'rgba(255, 255, 255, 0.7)';
                    ctx.lineWidth = 2;
                    ctx.setLineDash([3, 3]);
                    ctx.stroke();
                    ctx.setLineDash([]);
                }

                // Node Glow
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.radius + (isSelected ? 8 : 4), 0, Math.PI * 2);
                ctx.fillStyle = isSelected ? 'rgba(0, 255, 136, 0.35)' : node.glow;
                ctx.fill();

                // Base Circle
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
                ctx.fillStyle = '#0a0d14';
                ctx.fill();
                ctx.lineWidth = isSelected ? 2.5 : 1.8;
                ctx.strokeStyle = isSelected ? '#00ff88' : node.color;
                ctx.stroke();

                // Inner Icon
                ctx.font = '11px sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(node.icon || '●', node.x, node.y);

                // Vulnerability count badge if > 0
                if (node.vulnCount > 0) {
                    const badgeX = node.x + node.radius - 2;
                    const badgeY = node.y - node.radius + 2;
                    ctx.beginPath();
                    ctx.arc(badgeX, badgeY, 7, 0, Math.PI * 2);
                    ctx.fillStyle = '#ff3366';
                    ctx.shadowColor = '#ff3366';
                    ctx.shadowBlur = 6;
                    ctx.fill();

                    ctx.font = 'bold 8px Inter, sans-serif';
                    ctx.fillStyle = '#ffffff';
                    ctx.fillText(String(node.vulnCount), badgeX, badgeY + 0.5);
                }

                // Label Text
                ctx.font = (isSelected || isHovered ? 'bold ' : '') + '10px Inter, sans-serif';
                ctx.fillStyle = isSelected ? '#00ff88' : '#334155';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'top';
                ctx.fillText(node.label, node.x, node.y + node.radius + 6);

                ctx.restore();
            });
        }

        showInspector(node) {
            this.selectedNode = node;
            this.inspector.classList.remove('hidden');

            const badge = document.getElementById('sitemap-inspector-badge');
            if (badge) {
                badge.textContent = (node.category || 'SURFACE').toUpperCase();
                badge.style.borderColor = node.color;
                badge.style.color = node.color;
            }

            const titleEl = document.getElementById('sitemap-inspector-title');
            const typeEl = document.getElementById('sitemap-inspector-type');
            const authEl = document.getElementById('sitemap-inspector-auth');
            const vulnsEl = document.getElementById('sitemap-inspector-vulns');
            const inputsEl = document.getElementById('sitemap-inspector-inputs');

            if (titleEl) titleEl.textContent = node.path || node.label;
            if (typeEl) typeEl.textContent = node.typeLabel || 'Web Resource';
            if (authEl) authEl.textContent = node.auth || 'Public Endpoint';
            if (vulnsEl) {
                vulnsEl.textContent = node.vulnCount > 0 ? `🚨 ${node.vulnCount} Finding(s) Correlated` : '✔ No direct vulnerability flags';
                vulnsEl.style.color = node.vulnCount > 0 ? '#ff3366' : '#00ff88';
            }
            if (inputsEl) inputsEl.textContent = node.inputs || 'None';
        }
    }

    // ═══════════════════════════════════════════════
    // Threat Graph Engine (Attack Vector Map)
    // ═══════════════════════════════════════════════

    class ThreatGraphEngine {
        constructor(canvas, inspector) {
            this.canvas = canvas;
            this.ctx = canvas.getContext('2d');
            this.inspector = inspector;
            this.nodes = [];
            this.edges = [];
            this.particles = [];
            this.selectedNode = null;
            this.hoveredNode = null;
            this.draggedNode = null;
            this.animId = null;

            // Performance flags
            this.isDirty = true;
            this.isVisible = true;
            this.isTabActive = !document.hidden;

            this.initVisibilityObserver();
            this.initEvents();
            this.resize();
            window.addEventListener('resize', () => {
                if (this.lastReport) this.buildFromReport(this.lastReport, this.lastUrl);
                else this.resize();
                this.markDirty();
            });
        }

        initVisibilityObserver() {
            if ('IntersectionObserver' in window) {
                this.observer = new IntersectionObserver((entries) => {
                    entries.forEach(entry => {
                        this.isVisible = entry.isIntersecting;
                        if (this.isVisible && this.isTabActive) {
                            this.markDirty();
                        } else {
                            this.stopAnimation();
                        }
                    });
                }, { threshold: 0.05 });
                this.observer.observe(this.canvas);
            }

            document.addEventListener('visibilitychange', () => {
                this.isTabActive = !document.hidden;
                if (this.isVisible && this.isTabActive) {
                    this.markDirty();
                } else {
                    this.stopAnimation();
                }
            });
        }

        markDirty() {
            this.isDirty = true;
            if (this.isVisible && this.isTabActive && !this.animId) {
                this.startAnimation();
            }
        }

        resize() {
            if (!this.canvas.parentElement) return;
            const rect = this.canvas.parentElement.getBoundingClientRect();
            this.canvas.width = rect.width || 1000;
            this.canvas.height = rect.height || 420;
        }

        initEvents() {
            let isDown = false;
            let dragOffset = { x: 0, y: 0 };

            this.canvas.addEventListener('mousedown', (e) => {
                const rect = this.canvas.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;

                const clicked = this.findNodeAt(x, y);
                if (clicked) {
                    this.draggedNode = clicked;
                    this.selectedNode = clicked;
                    dragOffset.x = x - clicked.x;
                    dragOffset.y = y - clicked.y;
                    isDown = true;
                    this.canvas.style.cursor = 'grabbing';
                    this.showInspector(clicked);
                    this.markDirty();
                }
            });

            this.canvas.addEventListener('mousemove', (e) => {
                const rect = this.canvas.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;

                if (isDown && this.draggedNode) {
                    this.draggedNode.x = x - dragOffset.x;
                    this.draggedNode.y = y - dragOffset.y;
                    this.canvas.style.cursor = 'grabbing';
                    this.markDirty();
                } else {
                    const hovered = this.findNodeAt(x, y);
                    if (this.hoveredNode !== hovered) {
                        this.hoveredNode = hovered;
                        this.canvas.style.cursor = hovered ? 'pointer' : 'default';
                        this.markDirty();
                    }
                }
            });

            window.addEventListener('mouseup', () => {
                if (isDown) {
                    isDown = false;
                    this.draggedNode = null;
                    if (this.canvas) this.canvas.style.cursor = this.hoveredNode ? 'pointer' : 'default';
                    this.markDirty();
                }
            });

            const closeBtn = document.getElementById('close-inspector-btn');
            if (closeBtn) {
                closeBtn.onclick = () => {
                    this.inspector.classList.add('hidden');
                    this.selectedNode = null;
                    this.markDirty();
                };
            }

            const resetBtn = document.getElementById('btn-reset-graph');
            if (resetBtn) {
                resetBtn.onclick = () => {
                    if (this.lastReport) this.buildFromReport(this.lastReport, this.lastUrl);
                };
            }

            const pulseBtn = document.getElementById('btn-pulse-paths');
            if (pulseBtn) {
                pulseBtn.onclick = () => this.pulseTrajectory();
            }
        }

        findNodeAt(x, y) {
            for (let i = this.nodes.length - 1; i >= 0; i--) {
                const n = this.nodes[i];
                const dist = Math.hypot(n.x - x, n.y - y);
                if (dist <= n.radius + 10) return n;
            }
            return null;
        }

        buildFromReport(report, targetUrl) {
            this.lastReport = report;
            this.lastUrl = targetUrl;
            this.resize();

            this.nodes = [];
            this.edges = [];
            this.particles = [];

            const findings = report.findings || [];
            const width = this.canvas.width || 900;
            const height = this.canvas.height || 420;

            let host = 'target-app.com';
            try { host = new URL(targetUrl).hostname; } catch(e) {}

            // 1. Entry Surface Node
            const rootNode = {
                id: 'node-root',
                label: host,
                type: 'surface',
                x: width * 0.12,
                y: height * 0.5,
                radius: 22,
                color: '#00e5ff',
                glow: 'rgba(0, 229, 255, 0.4)',
                stage: 'Initial Attack Surface (Web Application)',
                impact: `Publicly exposed web entry point on ${targetUrl}`,
                fix: 'Enforce strict Edge WAF, TLS 1.3, and security headers.'
            };
            this.nodes.push(rootNode);

            // 2. Vulnerability Findings
            const keyFindings = findings.slice(0, 5);
            const vulnNodes = [];

            if (keyFindings.length === 0) {
                const cleanNode = {
                    id: 'node-clean',
                    label: 'No findings recorded',
                    type: 'vuln',
                    x: width * 0.5,
                    y: height * 0.5,
                    radius: 18,
                    color: '#00ff88',
                    glow: 'rgba(0, 255, 136, 0.4)',
                    stage: 'Tested scope only',
                    impact: report.coverage?.note || 'Review scan coverage before drawing conclusions.',
                    fix: 'Continue continuous integration scanning on every deployment.'
                };
                this.nodes.push(cleanNode);
                this.edges.push({ source: rootNode, target: cleanNode, active: true, label: 'Observed' });
                this.showInspector(cleanNode);
            } else {
                keyFindings.forEach((f, idx) => {
                    const vY = height * (0.2 + (idx / Math.max(1, keyFindings.length - 1)) * 0.6);
                    const vNode = {
                        id: `node-v-${idx}`,
                        label: f.title.length > 24 ? f.title.slice(0, 24) + '...' : f.title,
                        type: 'vuln',
                        findingData: f,
                        x: width * 0.38 + (idx % 2 === 0 ? -20 : 20),
                        y: vY,
                        radius: 16,
                        color: f.severity === 'critical' ? '#ff3366' : f.severity === 'high' ? '#ffb700' : '#00e5ff',
                        glow: f.severity === 'critical' ? 'rgba(255, 51, 102, 0.5)' : 'rgba(255, 183, 0, 0.5)',
                        stage: `Vulnerability Finding (${(f.severity || 'HIGH').toUpperCase()})`,
                        impact: f.description || 'Security weakness detected on application surface.',
                        fix: f.remediation || 'Enforce defense-in-depth sanitization and strict validation.'
                    };
                    this.nodes.push(vNode);
                    vulnNodes.push(vNode);

                    this.edges.push({
                        source: rootNode,
                        target: vNode,
                        active: true,
                        label: 'Discovers'
                    });
                });

                // Auto-show inspector for the most critical/high node
                this.showInspector(vulnNodes[0]);
            }

            this.spawnParticles();
            this.draw();
            this.startAnimation();
        }

        spawnParticles() {
            this.particles = [];
            this.edges.forEach((edge) => {
                for (let i = 0; i < 2; i++) {
                    this.particles.push({
                        edge,
                        progress: Math.random(),
                        speed: 0.005 + Math.random() * 0.006,
                        color: edge.target.color
                    });
                }
            });
        }

        pulseTrajectory() {
            this.particles.forEach(p => {
                p.speed = 0.02 + Math.random() * 0.02;
            });
            this.markDirty();
            setTimeout(() => {
                this.particles.forEach(p => p.speed = 0.005 + Math.random() * 0.006);
            }, 3000);
        }

        stopAnimation() {
            if (this.animId) {
                cancelAnimationFrame(this.animId);
                this.animId = null;
            }
        }

        startAnimation() {
            if (this.animId) return;
            if (!this.isVisible || !this.isTabActive) return;

            const render = () => {
                if (!this.isVisible || !this.isTabActive) {
                    this.animId = null;
                    return;
                }

                this.update();
                this.draw();
                this.isDirty = false;

                // Animate continuously when particles exist or when dragging/animating
                if (this.particles.length > 0 || this.draggedNode || this.isDirty) {
                    this.animId = requestAnimationFrame(render);
                } else {
                    this.animId = null;
                }
            };
            this.animId = requestAnimationFrame(render);
        }

        update() {
            for (let i = 0; i < this.nodes.length; i++) {
                for (let j = i + 1; j < this.nodes.length; j++) {
                    const n1 = this.nodes[i];
                    const n2 = this.nodes[j];
                    const dx = n2.x - n1.x;
                    const dy = n2.y - n1.y;
                    const dist = Math.hypot(dx, dy) || 1;
                    if (dist < 70) {
                        const force = (70 - dist) / dist * 0.015;
                        if (n1 !== this.draggedNode) { n1.x -= dx * force; n1.y -= dy * force; }
                        if (n2 !== this.draggedNode) { n2.x += dx * force; n2.y += dy * force; }
                    }
                }
            }

            this.particles.forEach(p => {
                p.progress += p.speed;
                if (p.progress >= 1) p.progress = 0;
            });
        }

        draw() {
            const ctx = this.ctx;
            const width = this.canvas.width;
            const height = this.canvas.height;
            ctx.clearRect(0, 0, width, height);

            // Background Grid
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
            ctx.lineWidth = 1;
            const step = 30;
            for (let x = 0; x < width; x += step) {
                ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
            }
            for (let y = 0; y < height; y += step) {
                ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
            }

            // Draw Edges
            this.edges.forEach(edge => {
                const isHighlighted = (this.selectedNode && (edge.source === this.selectedNode || edge.target === this.selectedNode)) ||
                                      (this.hoveredNode && (edge.source === this.hoveredNode || edge.target === this.hoveredNode));

                ctx.beginPath();
                ctx.moveTo(edge.source.x, edge.source.y);
                ctx.lineTo(edge.target.x, edge.target.y);
                ctx.strokeStyle = isHighlighted ? 'rgba(0, 255, 136, 0.45)' : 'rgba(51, 65, 85, 0.25)';
                ctx.lineWidth = isHighlighted ? 2.5 : 1.8;
                ctx.stroke();

                // Arrow head
                const angle = Math.atan2(edge.target.y - edge.source.y, edge.target.x - edge.source.x);
                const arrowX = edge.target.x - Math.cos(angle) * (edge.target.radius + 5);
                const arrowY = edge.target.y - Math.sin(angle) * (edge.target.radius + 5);

                ctx.save();
                ctx.translate(arrowX, arrowY);
                ctx.rotate(angle);
                ctx.fillStyle = isHighlighted ? '#00ff88' : edge.target.color;
                ctx.beginPath();
                ctx.moveTo(0, 0);
                ctx.lineTo(-6, -3.5);
                ctx.lineTo(-6, 3.5);
                ctx.closePath();
                ctx.fill();
                ctx.restore();
            });

            // Glowing Particles along Edges
            this.particles.forEach(p => {
                const x = p.edge.source.x + (p.edge.target.x - p.edge.source.x) * p.progress;
                const y = p.edge.source.y + (p.edge.target.y - p.edge.source.y) * p.progress;

                ctx.save();
                ctx.beginPath();
                ctx.arc(x, y, 3.5, 0, Math.PI * 2);
                ctx.fillStyle = p.color;
                ctx.shadowColor = p.color;
                ctx.shadowBlur = 10;
                ctx.fill();
                ctx.restore();
            });

            // Draw Nodes
            this.nodes.forEach(node => {
                const isSelected = this.selectedNode === node;
                const isHovered = this.hoveredNode === node;

                ctx.save();

                // Outer selection/hover ring
                if (isSelected || isHovered) {
                    ctx.beginPath();
                    ctx.arc(node.x, node.y, node.radius + 8, 0, Math.PI * 2);
                    ctx.strokeStyle = isSelected ? '#00ff88' : 'rgba(255, 255, 255, 0.6)';
                    ctx.lineWidth = 2;
                    ctx.setLineDash([4, 4]);
                    ctx.stroke();
                    ctx.setLineDash([]);
                }

                // Glow
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.radius + (isSelected ? 10 : 5), 0, Math.PI * 2);
                ctx.fillStyle = isSelected ? 'rgba(0, 255, 136, 0.4)' : node.glow;
                ctx.fill();

                // Base circle
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
                ctx.fillStyle = '#0a0d14';
                ctx.fill();
                ctx.lineWidth = isSelected ? 3 : 2.5;
                ctx.strokeStyle = isSelected ? '#00ff88' : node.color;
                ctx.stroke();

                // Center indicator dot
                ctx.beginPath();
                ctx.arc(node.x, node.y, 4, 0, Math.PI * 2);
                ctx.fillStyle = isSelected ? '#00ff88' : node.color;
                ctx.fill();

                // Text label
                ctx.font = (isSelected || isHovered ? 'bold ' : '') + '11px Inter, sans-serif';
                ctx.fillStyle = isSelected ? '#00ff88' : '#334155';
                ctx.textAlign = 'center';
                ctx.fillText(node.label, node.x, node.y + node.radius + 14);

                ctx.restore();
            });
        }

        showInspector(node) {
            this.selectedNode = node;
            this.inspector.classList.remove('hidden');
            const badge = document.getElementById('inspector-badge');
            if (badge) {
                badge.textContent = node.type.toUpperCase();
                badge.style.borderColor = node.color;
                badge.style.color = node.color;
            }

            const titleEl = document.getElementById('inspector-title');
            const stageEl = document.getElementById('inspector-stage');
            const impactEl = document.getElementById('inspector-impact');
            const fixEl = document.getElementById('inspector-fix');
            const patchBtn = document.getElementById('inspector-patch-btn');

            if (titleEl) titleEl.textContent = node.label;
            if (stageEl) stageEl.textContent = node.stage;
            if (impactEl) impactEl.textContent = node.impact;
            if (fixEl) fixEl.textContent = node.fix;

            if (patchBtn) {
                if (node.findingData) {
                    patchBtn.classList.remove('hidden');
                    patchBtn.onclick = () => openAutoPatchModal(node.findingData);
                } else {
                    patchBtn.classList.add('hidden');
                }
            }
        }
    }

    // ═══════════════════════════════════════════════
    // Terminal Console Controller Engine
    // ═══════════════════════════════════════════════

    class TerminalConsole {
        constructor({ containerId, outputId, filterGroupId, autoScrollId, copyBtnId, clearBtnId }) {
            this.container = document.getElementById(containerId);
            this.output = document.getElementById(outputId);
            this.filterGroup = document.getElementById(filterGroupId);
            this.autoScrollToggle = autoScrollId ? document.getElementById(autoScrollId) : null;
            this.copyBtn = copyBtnId ? document.getElementById(copyBtnId) : null;
            this.clearBtn = clearBtnId ? document.getElementById(clearBtnId) : null;

            this.logs = [];
            this.currentFilter = 'all';
            this.autoScroll = true;

            this.initEvents();
        }

        initEvents() {
            if (this.filterGroup) {
                this.filterGroup.addEventListener('click', (e) => {
                    const btn = e.target.closest('.terminal-filter-btn, .console-filter-btn, .trend-filter-btn');
                    if (!btn) return;
                    this.filterGroup.querySelectorAll('.terminal-filter-btn, .console-filter-btn, .trend-filter-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    this.currentFilter = btn.dataset.filter || 'all';
                    this.render();
                });
            }

            if (this.autoScrollToggle) {
                this.autoScrollToggle.addEventListener('change', (e) => {
                    this.autoScroll = e.target.checked;
                });
            }

            if (this.copyBtn) {
                this.copyBtn.addEventListener('click', async () => {
                    if (this.logs.length === 0) {
                        showToast('No logs available to copy', 'info');
                        return;
                    }
                    const text = this.logs.map(l => `[${l.time}] [${l.agent}] ${l.text}`).join('\n');
                    try {
                        await navigator.clipboard.writeText(text);
                        showToast('📋 Terminal logs copied to clipboard!', 'success');
                    } catch(err) {
                        showToast('Failed to copy logs', 'error');
                    }
                });
            }

            if (this.clearBtn) {
                this.clearBtn.addEventListener('click', () => {
                    this.logs = [];
                    this.render();
                });
            }
        }

        setLogs(logs) {
            this.logs = Array.isArray(logs) ? logs : [];
            this.render();
        }

        appendLog(logEntry) {
            this.logs.push(logEntry);
            if (this.matchesFilter(logEntry) && this.output) {
                const lineEl = this.createLineElement(logEntry);
                this.output.appendChild(lineEl);
                if (this.autoScroll) {
                    this.output.scrollTop = this.output.scrollHeight;
                }
            }
        }

        matchesFilter(log) {
            if (this.currentFilter === 'all') return true;
            return (log.agent || '').toUpperCase() === this.currentFilter.toUpperCase();
        }

        createLineElement(log) {
            const div = document.createElement('div');
            const agent = log.agent || 'SYSTEM';
            const level = log.level || 'info';
            div.className = `log-line terminal-line agent-${agent} level-${level}`;
            div.innerHTML = `<span class="t-stamp log-time">[${log.time || '00:00:00'}]</span> <span class="t-agent log-agent">[${agent}]</span> <span class="t-msg log-msg">${escapeHtml(log.text || '')}</span>`;
            return div;
        }

        render() {
            if (!this.output) return;
            this.output.innerHTML = '';
            const filtered = this.logs.filter(l => this.matchesFilter(l));
            if (filtered.length === 0) {
                this.output.innerHTML = '<div class="terminal-line system"><span class="t-stamp log-time">[--:--:--]</span> <span class="t-msg log-msg" style="color: var(--text-muted);">No log entries match the selected filter.</span></div>';
                return;
            }

            const fragment = document.createDocumentFragment();
            filtered.forEach(log => {
                fragment.appendChild(this.createLineElement(log));
            });
            this.output.appendChild(fragment);

            if (this.autoScroll) {
                this.output.scrollTop = this.output.scrollHeight;
            }
        }
    }

    // Initialize Terminals
    window.liveScanTerminal = new TerminalConsole({
        containerId: 'terminal-feed-container',
        outputId: 'terminal-output',
        filterGroupId: 'terminal-filter-group',
        autoScrollId: 'terminal-autoscroll',
        copyBtnId: 'terminal-copy-btn',
        clearBtnId: 'terminal-clear-btn'
    });

    window.resultsLogsTerminal = new TerminalConsole({
        containerId: 'results-terminal-drawer',
        outputId: 'results-terminal-output',
        filterGroupId: 'results-terminal-filter-group',
        copyBtnId: 'results-terminal-copy-btn'
    });

    // Toggle Results Terminal Drawer
    const toggleResultsTerminalBtn = document.getElementById('toggle-results-terminal-btn');
    const resultsTerminalDrawer = document.getElementById('results-terminal-drawer');
    const resultsTerminalCloseBtn = document.getElementById('results-terminal-close-btn');

    if (toggleResultsTerminalBtn && resultsTerminalDrawer) {
        toggleResultsTerminalBtn.onclick = () => {
            const isHidden = resultsTerminalDrawer.classList.toggle('hidden');
            toggleResultsTerminalBtn.textContent = isHidden ? '📺 View Execution Logs' : '✕ Hide Execution Logs';
            if (!isHidden) {
                resultsTerminalDrawer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
        };
    }

    if (resultsTerminalCloseBtn && resultsTerminalDrawer && toggleResultsTerminalBtn) {
        resultsTerminalCloseBtn.onclick = () => {
            resultsTerminalDrawer.classList.add('hidden');
            toggleResultsTerminalBtn.textContent = '📺 View Execution Logs';
        };
    }

    // ═══════════════════════════════════════════════
    // Continuous Security Posture & Score Trend Engine
    // ═══════════════════════════════════════════════

    class SecurityScoreTrendEngine {
        constructor(canvas, tooltip) {
            this.canvas = canvas;
            this.ctx = canvas.getContext('2d');
            this.tooltip = tooltip;
            this.points = [];
            this.computedPoints = [];
            this.hoveredPoint = null;
            this.activeMetric = 'overall';

            this.isDirty = true;
            this.isVisible = true;
            this.isTabActive = !document.hidden;

            this.initVisibilityObserver();
            this.initEvents();
            this.resize();
            window.addEventListener('resize', () => {
                this.resize();
                this.draw();
            });
        }

        initVisibilityObserver() {
            if ('IntersectionObserver' in window) {
                this.observer = new IntersectionObserver((entries) => {
                    entries.forEach(entry => {
                        this.isVisible = entry.isIntersecting;
                        if (this.isVisible && this.isTabActive) {
                            this.draw();
                        }
                    });
                }, { threshold: 0.05 });
                this.observer.observe(this.canvas);
            }

            document.addEventListener('visibilitychange', () => {
                this.isTabActive = !document.hidden;
                if (this.isVisible && this.isTabActive) {
                    this.draw();
                }
            });
        }

        resize() {
            if (!this.canvas.parentElement) return;
            const rect = this.canvas.parentElement.getBoundingClientRect();
            this.canvas.width = rect.width || 1000;
            this.canvas.height = rect.height || 320;
        }

        initEvents() {
            this.canvas.addEventListener('mousemove', (e) => {
                const rect = this.canvas.getBoundingClientRect();
                const mouseX = e.clientX - rect.left;
                const mouseY = e.clientY - rect.top;

                const closest = this.findClosestPoint(mouseX, mouseY);
                if (closest !== this.hoveredPoint) {
                    this.hoveredPoint = closest;
                    this.draw();
                    if (closest) {
                        this.showTooltip(closest);
                    } else {
                        this.hideTooltip();
                    }
                }
            });

            this.canvas.addEventListener('mouseleave', () => {
                this.hoveredPoint = null;
                this.draw();
                this.hideTooltip();
            });

            const metricToggles = document.getElementById('trend-metric-toggles');
            if (metricToggles) {
                metricToggles.addEventListener('click', (e) => {
                    const btn = e.target.closest('.terminal-filter-btn, .console-filter-btn, .trend-filter-btn');
                    if (!btn) return;
                    metricToggles.querySelectorAll('.terminal-filter-btn, .console-filter-btn, .trend-filter-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    this.activeMetric = btn.dataset.metric || 'overall';
                    this.draw();
                });
            }

            const ttInspectBtn = document.getElementById('tt-inspect-btn');
            if (ttInspectBtn) {
                ttInspectBtn.onclick = () => {
                    if (this.hoveredPoint && this.hoveredPoint.data) {
                        window.loadScanById(this.hoveredPoint.data.scanId);
                    }
                };
            }
        }

        findClosestPoint(x, y) {
            if (!this.computedPoints) return null;
            let closest = null;
            let minDist = 40;
            for (const p of this.computedPoints) {
                const dist = Math.hypot(p.x - x, p.y - y);
                if (dist < minDist) {
                    minDist = dist;
                    closest = p;
                }
            }
            return closest;
        }

        showTooltip(point) {
            if (!this.tooltip || !point.data) return;
            this.tooltip.classList.remove('hidden');
            this.tooltip.style.left = `${point.x}px`;
            this.tooltip.style.top = `${point.y}px`;

            const ttDate = document.getElementById('tt-date');
            const ttGrade = document.getElementById('tt-grade');
            const ttScore = document.getElementById('tt-score-val');
            const ttTarget = document.getElementById('tt-target');
            const ttFindings = document.getElementById('tt-findings');
            const ttDuration = document.getElementById('tt-duration');

            const d = point.data;
            if (ttDate) ttDate.textContent = new Date(d.timestamp).toLocaleString();
            if (ttGrade) {
                ttGrade.textContent = `GRADE ${d.grade || 'A'}`;
                ttGrade.style.borderColor = d.gradeColor || '#00ff88';
                ttGrade.style.color = d.gradeColor || '#00ff88';
            }
            if (ttScore) {
                ttScore.textContent = point.scoreVal;
                ttScore.style.color = d.gradeColor || '#00ff88';
            }
            if (ttTarget) {
                let host = d.url || 'target';
                try { host = new URL(d.url).hostname; } catch(e) {}
                ttTarget.textContent = host;
            }
            if (ttFindings) ttFindings.textContent = `${d.findingsCount || 0} findings`;
            if (ttDuration) ttDuration.textContent = `${d.duration || 0}s`;
        }

        hideTooltip() {
            if (this.tooltip) this.tooltip.classList.add('hidden');
        }

        async updateTrends(currentUrl) {
            try {
                const res = await fetch('/api/scans/trends');
                let trends = await res.json();

                trends = Array.isArray(trends) ? trends : [];
                if (currentUrl) trends = trends.filter(scan => scan.url === currentUrl);
                trends = trends.filter(scan => Number.isFinite(scan.score)).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
                this.hoveredPoint = null;
                this.hideTooltip();
                this.points = trends;
                this.updateKPIs(trends);
                this.resize();
                this.draw();
            } catch (err) {
                console.error('Failed to update trends:', err);
            }
        }

        updateKPIs(trends) {
            if (!trends || trends.length < 2) {
                const velocity = document.getElementById('kpi-velocity');
                const status = document.getElementById('kpi-status');
                if (velocity) velocity.textContent = '—';
                if (status) status.textContent = trends?.length ? 'One recorded scan' : 'No recorded scans';
                return;
            }
            const firstScore = trends[0].score;
            const lastScore = trends[trends.length - 1].score;
            const delta = lastScore - firstScore;

            const kpiVelocity = document.getElementById('kpi-velocity');
            const kpiStatus = document.getElementById('kpi-status');
            const timelineSummary = document.getElementById('trend-timeline-summary');

            if (kpiVelocity) {
                kpiVelocity.textContent = `${delta >= 0 ? '+' : ''}${delta} pts ${delta >= 0 ? '↗' : '↘'}`;
                kpiVelocity.style.color = delta >= 0 ? 'var(--accent-green)' : 'var(--accent-red)';
            }

            if (kpiStatus) {
                if (delta >= 10) {
                    kpiStatus.textContent = 'Rapid Hardening 🚀';
                    kpiStatus.style.color = 'var(--accent-green)';
                } else if (delta >= 0) {
                    kpiStatus.textContent = 'No score regression';
                    kpiStatus.style.color = 'var(--accent-green)';
                } else {
                    kpiStatus.textContent = 'Regression Detected ⚠️';
                    kpiStatus.style.color = 'var(--accent-red)';
                }
            }

            if (timelineSummary) {
                const totalScans = trends.length;
                const meanScore = Math.round(trends.reduce((acc, t) => acc + (t.score || 0), 0) / totalScans);
                timelineSummary.textContent = `${totalScans} total scans tracked · Average Posture: ${meanScore}/100`;
            }
        }

        getMetricValue(scan, metric) {
            if (metric === 'overall') return scan.score ?? null;
            const key = { headers: 'headers', ai: 'aiSafety', api: 'apiAuth', logic: 'logic' }[metric];
            return scan.subscores?.[key]?.score ?? null;
        }

        draw() {
            if (!this.ctx || !this.canvas) return;
            const ctx = this.ctx;
            const width = this.canvas.width;
            const height = this.canvas.height;
            ctx.clearRect(0, 0, width, height);

            const padLeft = 45;
            const padRight = 35;
            const padTop = 30;
            const padBottom = 40;

            const chartW = width - padLeft - padRight;
            const chartH = height - padTop - padBottom;

            // 1. Grid Lines
            const levels = [0, 25, 50, 75, 100];
            levels.forEach(lvl => {
                const y = padTop + chartH - (lvl / 100) * chartH;
                ctx.beginPath();
                ctx.moveTo(padLeft, y);
                ctx.lineTo(width - padRight, y);
                ctx.strokeStyle = lvl === 0 ? 'rgba(51, 65, 85, 0.25)' : 'rgba(51, 65, 85, 0.1)';
                ctx.lineWidth = 1;
                ctx.stroke();

                ctx.font = '10px Fira Code, monospace';
                ctx.fillStyle = '#64748b';
                ctx.textAlign = 'right';
                ctx.textBaseline = 'middle';
                ctx.fillText(`${lvl}%`, padLeft - 8, y);
            });

            this.computedPoints = [];
            if (!this.points?.some(scan => this.getMetricValue(scan, this.activeMetric) != null)) {
                ctx.fillStyle = '#64748b'; ctx.textAlign = 'center'; ctx.font = '14px sans-serif';
                ctx.fillText('No measured data for this metric', width / 2, height / 2);
                return;
            }

            // 2. Compute Coordinates
            this.computedPoints = [];
            const count = this.points.length;
            const stepX = count > 1 ? chartW / (count - 1) : chartW / 2;

            this.points.forEach((scan, i) => {
                const x = count > 1 ? padLeft + i * stepX : padLeft + chartW / 2;
                const scoreVal = this.getMetricValue(scan, this.activeMetric);
                if (scoreVal == null) return;
                const y = padTop + chartH - (scoreVal / 100) * chartH;

                this.computedPoints.push({
                    x,
                    y,
                    scoreVal,
                    data: scan,
                    index: i
                });
            });

            // 3. Draw Spline Area Gradient
            if (this.computedPoints.length > 1) {
                ctx.save();
                ctx.beginPath();
                ctx.moveTo(this.computedPoints[0].x, this.computedPoints[0].y);

                for (let i = 0; i < this.computedPoints.length - 1; i++) {
                    const p0 = this.computedPoints[i];
                    const p1 = this.computedPoints[i + 1];
                    const cpX = (p0.x + p1.x) / 2;
                    ctx.bezierCurveTo(cpX, p0.y, cpX, p1.y, p1.x, p1.y);
                }

                const last = this.computedPoints[this.computedPoints.length - 1];
                const first = this.computedPoints[0];
                const bottomY = padTop + chartH;
                ctx.lineTo(last.x, bottomY);
                ctx.lineTo(first.x, bottomY);
                ctx.closePath();

                const grad = ctx.createLinearGradient(0, padTop, 0, bottomY);
                const themeColor = this.activeMetric === 'ai' ? '189, 0, 255' :
                                   this.activeMetric === 'api' ? '255, 183, 0' :
                                   this.activeMetric === 'headers' ? '0, 229, 255' :
                                   this.activeMetric === 'logic' ? '255, 136, 0' : '0, 255, 136';

                grad.addColorStop(0, `rgba(${themeColor}, 0.28)`);
                grad.addColorStop(0.6, `rgba(${themeColor}, 0.08)`);
                grad.addColorStop(1, `rgba(${themeColor}, 0.0)`);
                ctx.fillStyle = grad;
                ctx.fill();
                ctx.restore();

                // 4. Draw Main Spline Stroke Line
                ctx.save();
                ctx.beginPath();
                ctx.moveTo(this.computedPoints[0].x, this.computedPoints[0].y);

                for (let i = 0; i < this.computedPoints.length - 1; i++) {
                    const p0 = this.computedPoints[i];
                    const p1 = this.computedPoints[i + 1];
                    const cpX = (p0.x + p1.x) / 2;
                    ctx.bezierCurveTo(cpX, p0.y, cpX, p1.y, p1.x, p1.y);
                }

                ctx.strokeStyle = `rgb(${themeColor})`;
                ctx.lineWidth = 3;
                ctx.shadowColor = `rgba(${themeColor}, 0.6)`;
                ctx.shadowBlur = 12;
                ctx.stroke();
                ctx.restore();
            }

            // 5. Draw Crosshair if Hovered
            if (this.hoveredPoint) {
                ctx.save();
                ctx.beginPath();
                ctx.moveTo(this.hoveredPoint.x, padTop);
                ctx.lineTo(this.hoveredPoint.x, padTop + chartH);
                ctx.strokeStyle = 'rgba(0, 255, 136, 0.4)';
                ctx.lineWidth = 1.5;
                ctx.setLineDash([4, 4]);
                ctx.stroke();
                ctx.restore();
            }

            // 6. Draw Data Points
            this.computedPoints.forEach(p => {
                const isHovered = this.hoveredPoint === p;
                const strokeColor = p.data.gradeColor || '#00ff88';

                ctx.save();
                if (isHovered) {
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, 11, 0, Math.PI * 2);
                    ctx.fillStyle = 'rgba(0, 255, 136, 0.3)';
                    ctx.fill();
                }

                ctx.beginPath();
                ctx.arc(p.x, p.y, isHovered ? 6.5 : 5, 0, Math.PI * 2);
                ctx.fillStyle = '#0a0d14';
                ctx.fill();
                ctx.lineWidth = isHovered ? 3 : 2.2;
                ctx.strokeStyle = strokeColor;
                ctx.shadowColor = strokeColor;
                ctx.shadowBlur = isHovered ? 10 : 6;
                ctx.stroke();

                ctx.beginPath();
                ctx.arc(p.x, p.y, isHovered ? 3 : 2, 0, Math.PI * 2);
                ctx.fillStyle = strokeColor;
                ctx.fill();

                ctx.font = '10px Inter, sans-serif';
                ctx.fillStyle = isHovered ? '#00ff88' : '#64748b';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'top';
                const dateObj = new Date(p.data.timestamp);
                const dateStr = `${dateObj.getMonth() + 1}/${dateObj.getDate()}`;
                ctx.fillText(dateStr, p.x, padTop + chartH + 8);

                ctx.restore();
            });
        }
    }

    // Initialize Security Score Trend Canvas & Tooltip
    const trendCanvas = document.getElementById('trend-chart-canvas');
    const trendTooltip = document.getElementById('trend-chart-tooltip');
    if (trendCanvas && trendTooltip) {
        window.trendEngine = new SecurityScoreTrendEngine(trendCanvas, trendTooltip);
    }

    // Initialize Radial Site Map Canvas & Inspector
    const sitemapCanvas = document.getElementById('sitemap-graph-canvas');
    const sitemapInspector = document.getElementById('sitemap-node-inspector');
    if (sitemapCanvas && sitemapInspector) {
        window.radialSiteMap = new RadialSiteMapEngine(sitemapCanvas, sitemapInspector);
    }

    // Initialize Threat Graph Canvas & Inspector
    const graphCanvas = document.getElementById('threat-graph-canvas');
    const graphInspector = document.getElementById('threat-node-inspector');
    if (graphCanvas && graphInspector) {
        window.threatGraph = new ThreatGraphEngine(graphCanvas, graphInspector);
    }

    async function loadHistory() {
        try {
            const res = await fetch('/api/scans/history');
            const scans = await res.json();

            if (!scans || scans.length === 0) {
                historyList.innerHTML = '<div class="empty-history">No scan history recorded yet.</div>';
                return;
            }

            historyList.innerHTML = '';
            scans.forEach(scan => {
                const item = document.createElement('div');
                item.className = 'history-item';
                let hostname = scan.url;
                try { hostname = new URL(scan.url).hostname; } catch(e) {}
                item.innerHTML = `
                    <div style="cursor: pointer; display:flex; align-items:center; gap:10px;" class="history-info-click">
                        <img src="https://www.google.com/s2/favicons?domain=${escapeHtml(hostname)}&sz=16" width="16" height="16" style="border-radius:3px; opacity:0.8; flex-shrink:0;" onerror="this.style.display='none'" />
                        <div>
                            <div class="history-url">${escapeHtml(scan.url)}</div>
                            <div class="history-meta">${new Date(scan.timestamp).toLocaleString()} · ${scan.findingsCount} findings · ${scan.duration}s</div>
                        </div>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-secondary load-scan-btn" style="padding:4px 10px; font-size:11px;">Inspect Details</button>
                        ${scan.reportHtmlUrl ? `<a href="${scan.reportHtmlUrl}" target="_blank" class="btn btn-primary" style="padding:4px 10px; font-size:11px; text-decoration: none;">HTML Report ↗</a>` : ''}
                    </div>
                `;

                // Add inspect button event
                const inspectBtn = item.querySelector('.load-scan-btn');
                const infoClick = item.querySelector('.history-info-click');
                const loadScanDetails = () => window.loadScanById(scan.scanId);

                inspectBtn.onclick = loadScanDetails;
                infoClick.onclick = loadScanDetails;
                historyList.appendChild(item);
            });

            // Update Historical Score Trends
            if (window.trendEngine) {
                window.trendEngine.updateTrends(window.currentScanStatus?.url);
            }

            // Automatically auto-load the most recent scan if dashboard is idle
            if (scans.length > 0 && !startBtn.disabled && resultsSection.classList.contains('hidden')) {
                window.loadScanById(scans[0].scanId);
            }
        } catch (e) {
            console.error('Failed to load history:', e);
        }
    }

    window.loadScanById = async (scanId) => {
        try {
            let reportData = null;
            const res = await fetch(`/vibe-shield-reports/${scanId}/report.json`);
            if (res.ok) {
                reportData = await res.json();
            } else {
                const apiRes = await fetch(`/api/scan/${scanId}`);
                if (apiRes.ok) {
                    const scanObj = await apiRes.json();
                    reportData = scanObj.report;
                }
            }
            if (!reportData) return;
            displayResults({
                scanId: scanId,
                url: reportData.meta?.target || 'Unknown target',
                status: reportData.coverage?.status === 'complete' ? 'completed' : 'partial',
                duration: reportData.meta?.duration ? (reportData.meta.duration / 1000).toFixed(1) : '0',
                report: reportData,
                reportHtmlUrl: `/vibe-shield-reports/${scanId}/report.html`
            });
            resultsSection.scrollIntoView({ behavior: 'smooth' });
        } catch (err) {
            console.error('Error loading scan details for ' + scanId, err);
        }
    };

    // ═══════════════════════════════════════════════
    // AI Threat Simulation & Exploitation Matrix Manager
    // ═══════════════════════════════════════════════
    class AiThreatMatrixManager {
        constructor() {
            this.gridEl = document.getElementById('ai-matrix-grid');
            this.modalEl = document.getElementById('ai-sim-panel') || document.getElementById('ai-simulation-modal');
            this.closeBtn = document.getElementById('close-ai-sim-modal-btn');
            this.headerBtn = document.getElementById('open-ai-matrix-header-btn');
            this.batchSimBtn = document.getElementById('run-matrix-sim-btn');
            this.modalTitle = document.getElementById('sim-modal-title');
            this.threatId = document.getElementById('sim-threat-id');
            this.threatSev = document.getElementById('sim-threat-sev');
            this.threatStatus = document.getElementById('sim-threat-status');
            this.threatDesc = document.getElementById('sim-threat-desc');
            this.categoryLabel = document.getElementById('sim-category-label');
            this.dialogueStream = document.getElementById('sim-dialogue-stream');
            this.telemetryVerdict = document.getElementById('sim-telemetry-verdict');
            this.telemetryLatency = document.getElementById('sim-telemetry-latency');
            this.telemetryTokens = document.getElementById('sim-telemetry-tokens');
            this.telemetryRule = document.getElementById('sim-telemetry-rule');
            this.codeContent = document.getElementById('sim-code-content');
            this.copyCodeBtn = document.getElementById('sim-copy-code-btn');
            this.copyBtnText = document.getElementById('sim-copy-btn-text');
            this.rerunBtn = document.getElementById('sim-rerun-btn');
            this.nextBtn = document.getElementById('sim-next-btn');
            this.statusPill = document.getElementById('ai-matrix-status-pill');

            this.matrixData = [];
            this.currentVectorIndex = 0;
            this.init();
        }

        async init() {
            if (this.closeBtn) {
                this.closeBtn.onclick = () => this.modalEl.classList.add('hidden');
            }
            if (this.modalEl) {
                this.modalEl.addEventListener('click', (e) => {
                    if (e.target === this.modalEl) this.modalEl.classList.add('hidden');
                });
            }
            if (this.headerBtn) {
                this.headerBtn.onclick = () => {
                    const section = document.getElementById('ai-matrix-section');
                    if (section) section.scrollIntoView({ behavior: 'smooth' });
                };
            }
            if (this.batchSimBtn) {
                this.batchSimBtn.onclick = () => this.runBatchSimulation();
            }
            if (this.copyCodeBtn) {
                this.copyCodeBtn.onclick = async () => {
                    const text = this.codeContent?.textContent || '';
                    try {
                        await navigator.clipboard.writeText(text);
                        if (this.copyBtnText) this.copyBtnText.textContent = 'Copied! ✓';
                        this.copyCodeBtn.style.color = 'var(--accent-green)';
                        setTimeout(() => {
                            if (this.copyBtnText) this.copyBtnText.textContent = 'Copy Guardrail Code';
                            this.copyCodeBtn.style.color = '';
                        }, 2000);
                    } catch(e) {}
                };
            }
            if (this.rerunBtn) {
                this.rerunBtn.onclick = () => {
                    const vector = this.matrixData[this.currentVectorIndex];
                    if (vector) this.executeSimulation(vector.id);
                };
            }
            if (this.nextBtn) {
                this.nextBtn.onclick = () => {
                    this.currentVectorIndex = (this.currentVectorIndex + 1) % this.matrixData.length;
                    const vector = this.matrixData[this.currentVectorIndex];
                    if (vector) this.openModal(vector.id);
                };
            }

            try {
                const res = await fetch('/api/ai-matrix/taxonomy');
                if (res.ok) {
                    this.matrixData = await res.json();
                    this.render();
                }
            } catch(e) {
                console.error('Failed to load AI matrix taxonomy:', e);
            }
        }

        async updateFromReport(report) {
            try {
                const res = await fetch('/api/ai-matrix/evaluate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ report })
                });
                if (res.ok) {
                    this.matrixData = await res.json();
                    const vulnerableCount = this.matrixData.filter(m => m.status === 'VULNERABLE').length;
                    if (this.statusPill) {
                        if (vulnerableCount > 0) {
                            this.statusPill.className = 'badge badge-critical';
                            this.statusPill.textContent = `${vulnerableCount} VULNERABILITIES DETECTED`;
                        } else {
                            this.statusPill.className = 'badge badge-secondary';
                            this.statusPill.textContent = 'NO DEFENSE VERIFICATION';
                        }
                    }
                    this.render();
                }
            } catch(e) {
                console.error('Failed to evaluate AI matrix:', e);
            }
        }

        render() {
            if (!this.gridEl) return;
            this.gridEl.innerHTML = '';

            this.matrixData.forEach((vector) => {
                const isVuln = vector.status === 'VULNERABLE';
                const card = document.createElement('div');
                card.className = `matrix-card ${isVuln ? 'is-vulnerable' : ''}`;
                
                const sevClass = 'pill-' + (vector.severity || 'high');
                const statusBadgeHtml = isVuln
                    ? `<span class="badge badge-status-vulnerable">⚠️ ${vector.findingsCount || 1} VULN DETECTED</span>`
                    : `<span class="badge badge-status-defended">NOT VERIFIED</span>`;

                card.innerHTML = `
                    <div class="matrix-card-head">
                        <span class="badge-vector-code">${vector.id}</span>
                        <div style="display:flex;gap:6px;align-items:center;">
                            <span class="badge ${sevClass}">${(vector.severity || 'HIGH').toUpperCase()}</span>
                            <span class="badge" style="font-family:var(--font-mono);font-size:10px;background:rgba(255,255,255,0.05);border:1px solid var(--border-color);">CVSS ${vector.cvss}</span>
                        </div>
                    </div>
                    <div class="matrix-card-title">${escapeHtml(vector.title)}</div>
                    <div class="matrix-card-desc">${escapeHtml(vector.description)}</div>
                    <div class="matrix-status-bar">
                        ${statusBadgeHtml}
                        <span style="font-size:10px;color:var(--text-muted);font-family:var(--font-mono);">${vector.attackPrimitives?.length || 4} Primitives</span>
                    </div>
                    <button type="button" class="btn-sim-trigger" data-vector-id="${vector.id}">
                        View illustrative scenario ↗
                    </button>
                `;

                const btn = card.querySelector('.btn-sim-trigger');
                if (btn) btn.onclick = () => this.openModal(vector.id);
                this.gridEl.appendChild(card);
            });
        }

        async openModal(vectorId) {
            if (!this.modalEl) return;
            const idx = this.matrixData.findIndex(v => v.id === vectorId);
            if (idx !== -1) this.currentVectorIndex = idx;
            const vector = this.matrixData[this.currentVectorIndex] || this.matrixData[0];
            if (!vector) return;

            this.modalEl.classList.remove('hidden');
            this.modalTitle.textContent = `${vector.id}: ${vector.title}`;
            this.threatId.textContent = vector.id;
            this.threatSev.textContent = `${(vector.severity || 'HIGH').toUpperCase()} (CVSS ${vector.cvss})`;
            this.threatSev.className = `badge badge-${vector.severity || 'high'}`;
            
            const isVuln = vector.status === 'VULNERABLE';
            this.threatStatus.textContent = isVuln ? '⚠️ VULNERABILITY DETECTED' : 'NOT VERIFIED';
            this.threatStatus.className = `badge ${isVuln ? 'badge-status-vulnerable' : 'badge-status-defended'}`;
            this.threatDesc.textContent = vector.description;
            this.categoryLabel.textContent = vector.simulation?.category || 'Adversarial Probe';

            const nextIndex = (this.currentVectorIndex + 1) % this.matrixData.length;
            const nextVector = this.matrixData[nextIndex];
            if (this.nextBtn && nextVector) {
                this.nextBtn.textContent = `Next Threat Vector (${nextVector.id}) ↗`;
            }

            await this.executeSimulation(vector.id);
        }

        async executeSimulation(vectorId) {
            if (!this.dialogueStream) return;
            this.dialogueStream.innerHTML = '<div style="color:var(--text-muted);font-size:11px;font-family:var(--font-mono);">⚡ Initializing multi-turn adversarial probe simulation...</div>';

            try {
                const res = await fetch('/api/ai-matrix/simulate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ vectorId })
                });

                const sim = await res.json();
                
                // Update Telemetry
                if (this.telemetryVerdict) this.telemetryVerdict.textContent = sim.guardrailVerdict;
                if (this.telemetryLatency) this.telemetryLatency.textContent = `${sim.latencyMs}ms`;
                if (this.telemetryTokens) this.telemetryTokens.textContent = `${sim.tokensConsumed} tokens`;
                if (this.telemetryRule) this.telemetryRule.textContent = sim.guardrailRuleApplied;
                if (this.codeContent) this.codeContent.textContent = sim.remediationSnippet;

                // Animate turns
                this.dialogueStream.innerHTML = '';
                const turns = sim.simulation?.turns || [];

                for (let i = 0; i < turns.length; i++) {
                    const t = turns[i];
                    const turnDiv = document.createElement('div');
                    
                    if (t.role === 'adversary') {
                        turnDiv.className = 'sim-turn-card sim-turn-adversary';
                        turnDiv.innerHTML = `
                            <div class="sim-turn-header">
                                <span>🔴 TURN ${t.turn} — ADVERSARY PROBE</span>
                                <span>MALICIOUS INTENT</span>
                            </div>
                            <div class="sim-turn-body">${escapeHtml(t.text)}</div>
                            <div class="sim-turn-intent">🎯 Attack Vector: ${escapeHtml(t.intent || '')}</div>
                        `;
                    } else if (t.role === 'guardrail') {
                        turnDiv.className = 'sim-turn-card sim-turn-guardrail';
                        turnDiv.innerHTML = `
                            <div class="sim-turn-header">
                                <span>🟡 TURN ${t.turn} — GUARDRAIL INTERCEPTION</span>
                                <span>POLICY ENFORCEMENT</span>
                            </div>
                            <div class="sim-turn-body">${escapeHtml(t.text)}</div>
                        `;
                    } else {
                        turnDiv.className = 'sim-turn-card sim-turn-model';
                        turnDiv.innerHTML = `
                            <div class="sim-turn-header">
                                <span>🟢 TURN ${t.turn} — DEFENDED MODEL RESPONSE</span>
                                <span>OUTPUT SANITIZED</span>
                            </div>
                            <div class="sim-turn-body">${escapeHtml(t.text)}</div>
                            <div class="sim-turn-intent" style="color:var(--accent-green);font-weight:600;">✔ ${escapeHtml(t.verdict || '')}</div>
                        `;
                    }

                    this.dialogueStream.appendChild(turnDiv);
                }
            } catch(err) {
                this.dialogueStream.innerHTML = `<div style="color:#ff3366;font-size:11px;">Simulation error: ${err.message}</div>`;
            }
        }

        async runBatchSimulation() {
            if (this.matrixData.length > 0) {
                this.openModal(this.matrixData[0].id);
            }
        }
    }

    // ═══════════════════════════════════════════════════════
    // Authentication Drawer Controller
    // ═══════════════════════════════════════════════════════

    class AuthDrawerController {
        constructor() {
            this.toggleBtn = document.getElementById('toggle-auth-drawer-btn');
            this.drawerContent = document.getElementById('auth-drawer-content');
            this.drawerArrow = document.getElementById('auth-drawer-arrow');
            this.drawerBadge = document.getElementById('auth-drawer-badge');
            this.stratChips = document.querySelectorAll('.auth-tab-chip');
            this.panelForm = document.getElementById('auth-panel-form');
            this.panelToken = document.getElementById('auth-panel-token');
            this.panelCookie = document.getElementById('auth-panel-cookie');

            this.init();
        }

        init() {
            if (this.toggleBtn) {
                this.toggleBtn.addEventListener('click', () => this.toggleDrawer());
            }

            this.stratChips.forEach(chip => {
                chip.addEventListener('click', (e) => {
                    const strategy = chip.dataset.authStrategy;
                    this.setStrategy(strategy);
                });
            });

            // Listen for input changes to update badge state
            ['auth-username', 'auth-bearer-token', 'auth-cookies'].forEach(id => {
                const el = document.getElementById(id);
                if (el) {
                    el.addEventListener('input', () => this.updateBadge());
                }
            });
        }

        toggleDrawer() {
            const isHidden = this.drawerContent.classList.contains('hidden');
            if (isHidden) {
                this.drawerContent.classList.remove('hidden');
                this.drawerArrow?.classList.add('open');
            } else {
                this.drawerContent.classList.add('hidden');
                this.drawerArrow?.classList.remove('open');
            }
        }

        setStrategy(strat) {
            this.stratChips.forEach(c => {
                const isMatch = c.dataset.authStrategy === strat;
                c.classList.toggle('active', isMatch);
                const input = c.querySelector('input');
                if (input) input.checked = isMatch;
            });

            this.panelForm?.classList.toggle('hidden', strat !== 'form');
            this.panelToken?.classList.toggle('hidden', strat !== 'token');
            this.panelCookie?.classList.toggle('hidden', strat !== 'cookie');

            this.updateBadge();
        }

        updateBadge() {
            const activeStrat = document.querySelector('input[name="auth-strategy"]:checked')?.value || 'none';
            if (activeStrat === 'none') {
                this.drawerBadge.className = 'badge badge-unauth';
                this.drawerBadge.textContent = 'Public Mode';
            } else if (activeStrat === 'form') {
                const user = document.getElementById('auth-username')?.value?.trim();
                this.drawerBadge.className = 'badge badge-authed';
                this.drawerBadge.textContent = user ? `🔑 Form: ${user}` : '🔑 Form Login (Configured)';
            } else if (activeStrat === 'token') {
                const token = document.getElementById('auth-bearer-token')?.value?.trim();
                this.drawerBadge.className = 'badge badge-authed';
                this.drawerBadge.textContent = token ? '🛡️ Bearer Token (Set)' : '🛡️ Token Auth';
            } else if (activeStrat === 'cookie') {
                const cookies = document.getElementById('auth-cookies')?.value?.trim();
                this.drawerBadge.className = 'badge badge-authed';
                this.drawerBadge.textContent = cookies ? '🍪 Cookie (Set)' : '🍪 Cookie Auth';
            }
        }
    }

    // ═══════════════════════════════════════════════════════
    // CI/CD Webhook & Continuous Scan Manager
    // ═══════════════════════════════════════════════════════

    class CicdWebhookManager {
        constructor() {
            this.modal = document.getElementById('webhook-modal');
            this.openHeaderBtn = document.getElementById('open-cicd-modal-header-btn');
            this.closeBtn = document.getElementById('close-webhook-modal-btn');
            this.tabButtons = document.querySelectorAll('.webhook-tab-btn');
            this.codeContent = document.getElementById('webhook-code-content');
            this.filePath = document.getElementById('webhook-file-path');
            this.fileDesc = document.getElementById('webhook-file-desc');
            this.copyBtn = document.getElementById('webhook-copy-code-btn');
            this.copyBtnText = document.getElementById('webhook-copy-btn-text');
            this.testBtn = document.getElementById('btn-test-webhook-trigger');
            this.testResultBox = document.getElementById('webhook-test-result');

            this.minScoreInput = document.getElementById('gate-min-score');
            this.maxCritInput = document.getElementById('gate-max-critical');
            this.maxHighInput = document.getElementById('gate-max-high');

            this.currentTab = 'github';
            this.templates = {};

            this.init();
        }

        init() {
            document.getElementById('nav-report-btn')?.addEventListener('click', () => this.openReport());
            if (this.openHeaderBtn) {
                this.openHeaderBtn.addEventListener('click', () => this.openModal());
            }
            if (this.closeBtn) {
                this.closeBtn.addEventListener('click', () => this.closeModal());
            }
            if (this.modal) {
                this.modal.addEventListener('click', (e) => {
                    if (e.target === this.modal) this.closeModal();
                });
            }

            this.tabButtons.forEach(btn => {
                btn.addEventListener('click', () => {
                    this.tabButtons.forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    this.currentTab = btn.dataset.tab;
                    this.renderCurrentTab();
                });
            });

            [this.minScoreInput, this.maxCritInput, this.maxHighInput].forEach(inp => {
                if (inp) {
                    inp.addEventListener('input', () => this.renderCurrentTab());
                }
            });

            if (this.copyBtn) {
                this.copyBtn.addEventListener('click', () => this.copyCode());
            }

            if (this.testBtn) {
                this.testBtn.addEventListener('click', () => this.runTestWebhook());
            }
        }

        async openModal() {
            this.modal?.classList.remove('hidden');
            await this.fetchTemplates();
            this.renderCurrentTab();
        }

        closeModal() {
            this.modal?.classList.add('hidden');
        }

        async fetchTemplates() {
            try {
                const res = await fetch('/api/cicd/workflow-template');
                if (res.ok) {
                    this.templates = await res.json();
                }
            } catch (err) {
                console.warn('Could not fetch remote CI/CD template:', err);
            }
        }

        getGateConfig() {
            return {
                minScore: parseInt(this.minScoreInput?.value || '80', 10),
                maxCritical: parseInt(this.maxCritInput?.value || '0', 10),
                maxHigh: parseInt(this.maxHighInput?.value || '2', 10)
            };
        }

        renderCurrentTab() {
            const gate = this.getGateConfig();
            const serverUrl = window.location.origin;
            const targetUrl = document.getElementById('target-url')?.value?.trim() || 'https://staging.your-app.com';

            if (this.currentTab === 'github') {
                this.filePath.textContent = '📁 .github/workflows/vibe-shield-security-gate.yml';
                this.fileDesc.textContent = 'On-demand scan of ANY website via workflow_dispatch + auto-scan your own app on push/PR';
                this.codeContent.textContent = `name: 🛡️ VIBE SHIELD Security Gate

on:
  # ── Manual / On-Demand: scan ANY website you have permission to test ──
  workflow_dispatch:
    inputs:
      target_url:
        description: 'Target URL to scan (e.g. https://example.com)'
        required: true
        default: 'https://staging.your-app.com'
        type: string
      bearer_token:
        description: 'Bearer token for authenticated scan (optional)'
        required: false
        default: ''
        type: string

  # ── Auto-scan YOUR OWN app on every push / PR ──
  push:
    branches: [ main, staging, dev ]
  pull_request:
    branches: [ main ]

  # ── Nightly continuous audit at 2:00 AM UTC ──
  schedule:
    - cron: '0 2 * * *'

jobs:
  vibe-shield-audit:
    name: Autonomous Security & Quality Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Resolve Target URL
        id: resolve_target
        run: |
          # workflow_dispatch sets inputs.target_url
          # push/PR/schedule falls back to the STAGING_URL secret (your own app)
          TARGET="\${{ github.event.inputs.target_url }}"
          if [ -z "$TARGET" ]; then
            TARGET="\${{ secrets.STAGING_URL }}"
          fi
          echo "target=$TARGET" >> $GITHUB_OUTPUT
          echo "Scanning: $TARGET"

      - name: Run VIBE SHIELD Security Gate
        id: security_scan
        run: |
          echo "🚀 Dispatching VIBE SHIELD multi-agent security audit..."

          BEARER="\${{ github.event.inputs.bearer_token }}"
          if [ -z "$BEARER" ]; then
            BEARER="\${{ secrets.STAGING_BEARER_TOKEN }}"
          fi

          RESPONSE=$(curl -s -X POST "\${{ secrets.VIBESHIELD_URL }}/api/webhook/scan" \\
            -H "Content-Type: application/json" \\
            -H "x-api-key: \${{ secrets.VIBESHIELD_API_KEY }}" \\
            -d "{
              \\"targetUrl\\": \\"\${{ steps.resolve_target.outputs.target }}\\",
              \\"modules\\": [\\"qa\\", \\"security\\", \\"ai\\", \\"logic\\", \\"api\\"],
              \\"securityGate\\": {
                \\"minScore\\": ${gate.minScore},
                \\"maxCritical\\": ${gate.maxCritical},
                \\"maxHigh\\": ${gate.maxHigh}
              },
              \\"auth\\": {
                \\"bearerToken\\": \\"$BEARER\\"
              }
            }")

          echo "$RESPONSE" | jq .

          PASSED=$(echo "$RESPONSE" | jq -r '.gate.passed')
          SCORE=$(echo "$RESPONSE" | jq -r '.posture.score')
          GRADE=$(echo "$RESPONSE" | jq -r '.posture.grade')

          echo "======================================"
          echo "🛡️ VIBE SHIELD AUDIT SUMMARY"
          echo "Target: \${{ steps.resolve_target.outputs.target }}"
          echo "Grade: $GRADE | Score: $SCORE/100"
          echo "Gate Passed: $PASSED"
          echo "======================================"

          if [ "$PASSED" != "true" ]; then
            echo "❌ Security Gate FAILED — thresholds violated."
            exit 1
          fi

          echo "✔ Security Gate PASSED! Safe to merge."`;
            } else if (this.currentTab === 'curl') {
                this.filePath.textContent = '⚡ Webhook HTTP Request (cURL)';
                this.fileDesc.textContent = 'Scan any URL on demand — just swap the targetUrl each time';
                this.codeContent.textContent = `# Scan ANY website you have permission to test — just change targetUrl:
curl -X POST "${serverUrl}/api/webhook/scan" \\
  -H "Content-Type: application/json" \\
  -H "x-api-key: YOUR_VIBESHIELD_API_KEY" \\
  -d '{
    "targetUrl": "${targetUrl}",
    "modules": ["qa", "security", "ai", "logic", "api"],
    "securityGate": {
      "minScore": ${gate.minScore},
      "maxCritical": ${gate.maxCritical},
      "maxHigh": ${gate.maxHigh}
    },
    "auth": {
      "bearerToken": ""
    }
  }'`;
            } else if (this.currentTab === 'gitlab') {
                this.filePath.textContent = '📁 .gitlab-ci.yml';
                this.fileDesc.textContent = 'GitLab CI: scan any URL via pipeline variable $TARGET_URL or fall back to $CI_ENVIRONMENT_URL';
                this.codeContent.textContent = `stages:
  - test
  - security

# ── Usage: Pass TARGET_URL as a pipeline variable to scan any site ──
# e.g. in GitLab UI: Run Pipeline → Add variable TARGET_URL=https://any-site.com
# Falls back to CI_ENVIRONMENT_URL (your own deployed app) automatically.

vibe_shield_security_gate:
  stage: security
  image: curlimages/curl:latest
  variables:
    # Override this per-pipeline run to scan any site you have permission for:
    TARGET_URL: "\${CI_ENVIRONMENT_URL:-${targetUrl}}"
  script:
    - |
      echo "🛡️ VIBE SHIELD — Scanning: $TARGET_URL"
      RESPONSE=$(curl -s -X POST "$VIBESHIELD_URL/api/webhook/scan" \\
        -H "Content-Type: application/json" \\
        -H "x-api-key: $VIBESHIELD_API_KEY" \\
        -d "{
          \\"targetUrl\\": \\"$TARGET_URL\\",
          \\"securityGate\\": { \\"minScore\\": ${gate.minScore}, \\"maxCritical\\": ${gate.maxCritical}, \\"maxHigh\\": ${gate.maxHigh} }
        }")
      echo "$RESPONSE"
      PASSED=$(echo "$RESPONSE" | grep -o '"passed":true' || true)
      if [ -z "$PASSED" ]; then
        echo "❌ Security gate failed!"
        exit 1
      fi
      echo "✔ Security gate passed!"
  only:
    - merge_requests
    - main`;

            // Required GitLab CI/CD Variables (set under Settings → CI/CD → Variables):
            // VIBESHIELD_URL       → URL of your VIBE SHIELD server
            // VIBESHIELD_API_KEY   → Your VIBE SHIELD API key
            // TARGET_URL (optional)→ Override here OR pass per-pipeline run
            } else if (this.currentTab === 'nodejs') {
                this.filePath.textContent = '📁 scripts/vibe-shield-ci.js';
                this.fileDesc.textContent = 'Node.js runner — pass TARGET_URL as env var to scan any site on demand';
                this.codeContent.textContent = `// scripts/vibe-shield-ci.js
// Usage: TARGET_URL=https://any-site.com node scripts/vibe-shield-ci.js
import fetch from 'node-fetch';

async function runSecurityGate() {
  // TARGET_URL passed at runtime — scan any site you have permission for
  const targetUrl = process.env.TARGET_URL;
  if (!targetUrl) {
    console.error('❌ Missing TARGET_URL environment variable.');
    console.error('   Usage: TARGET_URL=https://example.com node scripts/vibe-shield-ci.js');
    process.exit(1);
  }

  console.log('🛡️ VIBE SHIELD — Scanning:', targetUrl);

  const res = await fetch(process.env.VIBESHIELD_URL + '/api/webhook/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.VIBESHIELD_API_KEY || ''
    },
    body: JSON.stringify({
      targetUrl,
      modules: ['qa', 'security', 'ai', 'logic', 'api'],
      securityGate: {
        minScore: ${gate.minScore},
        maxCritical: ${gate.maxCritical},
        maxHigh: ${gate.maxHigh}
      },
      // Optional: pass bearer token for authenticated scans
      auth: {
        bearerToken: process.env.BEARER_TOKEN || ''
      }
    })
  });

  const data = await res.json();
  console.log('Posture:', data.posture?.grade, data.posture?.score + '/100');

  if (!data.gate?.passed) {
    console.error('❌ Security Gate Violations:', data.gate?.violations);
    process.exit(1);
  }

  console.log('✔ Security Gate Passed! Report URL:', data.reportHtmlUrl);
}

runSecurityGate();`;
            }
        }

        async copyCode() {
            try {
                await navigator.clipboard.writeText(this.codeContent.textContent);
                this.copyBtnText.textContent = 'Copied!';
                showToast('📋 Configuration copied to clipboard', 'success');
                setTimeout(() => {
                    this.copyBtnText.textContent = 'Copy Workflow YAML';
                }, 2000);
            } catch (err) {
                showToast('Failed to copy configuration', 'error');
            }
        }

        async runTestWebhook() {
            this.testBtn.disabled = true;
            this.testBtn.textContent = '⏳ Executing Webhook Scan...';
            this.testResultBox.classList.remove('hidden');
            this.testResultBox.innerHTML = '<span style="color:var(--accent-cyan)">[WEBHOOK] Dispatching automated test payload to /api/webhook/scan...</span>';

            const gate = this.getGateConfig();
            const targetUrl = document.getElementById('target-url')?.value?.trim() || '';

            try {
                const res = await fetch('/api/webhook/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        targetUrl,
                        modules: ['qa', 'security', 'ai', 'logic', 'api'],
                        securityGate: gate
                    })
                });

                const data = await res.json();
                const passed = data.gate?.passed;
                const statusColor = passed ? '#00ff88' : '#ff3366';
                const statusBadge = passed ? '✔ PASSED' : '✘ FAILED (Gate Threshold Violated)';

                this.testResultBox.innerHTML = `
                    <div style="font-weight:700; color:${statusColor}; margin-bottom:8px; font-size:13px;">
                        CI/CD Security Gate: ${statusBadge}
                    </div>
                    <div style="margin-bottom:6px;">Target: <strong>${escapeHtml(data.targetUrl)}</strong> | Score: <strong>${data.posture?.score}/100</strong> (Grade ${data.posture?.grade})</div>
                    <div style="margin-bottom:6px;">Duration: <strong>${data.durationSeconds}s</strong> | Total Findings: <strong>${data.posture?.summary?.total ?? 0}</strong></div>
                    ${data.gate?.violations?.length > 0 ? `<div style="color:#ff3366; margin-top:6px;"><strong>Violations:</strong><ul style="margin:4px 0 0 16px;">${data.gate.violations.map(v => `<li>${escapeHtml(v)}</li>`).join('')}</ul></div>` : ''}
                    <div style="margin-top:8px; font-size:11px;"><a href="${data.reportHtmlUrl}" target="_blank" style="color:var(--accent-cyan);">View Full HTML Report ↗</a></div>
                `;
                showToast(`Webhook Scan Complete: ${statusBadge}`, passed ? 'success' : 'warn');
            } catch (err) {
                this.testResultBox.innerHTML = `<span style="color:#ff3366;">Webhook Error: ${err.message}</span>`;
                showToast('Webhook Execution Failed: ' + err.message, 'error');
            } finally {
                this.testBtn.disabled = false;
                this.testBtn.textContent = '🚀 Test Webhook Trigger';
            }
        }
    }

    // ═══════════════════════════════════════════════════════
    // Executive PDF Audit Report Manager
    // ═══════════════════════════════════════════════════════

    class ExecutiveReportManager {
        constructor() {
            this.modal = document.getElementById('executive-report-panel');
            this.openHeaderBtn = document.getElementById('open-exec-modal-header-btn');
            this.openResultsBtn = document.getElementById('open-exec-report-results-btn');
            this.closeBtn = document.getElementById('close-exec-modal-btn');
            this.printBtn = document.getElementById('exec-print-pdf-btn');
            this.copyMdBtn = document.getElementById('exec-copy-md-btn');

            this.reportData = null;

            this.init();
        }

        init() {
            document.getElementById('nav-report-btn')?.addEventListener('click', () => this.openReport());
            if (this.openHeaderBtn) {
                this.openHeaderBtn.addEventListener('click', () => this.openReport());
            }
            if (this.openResultsBtn) {
                this.openResultsBtn.addEventListener('click', () => this.openReport());
            }
            if (this.closeBtn) {
                this.closeBtn.addEventListener('click', () => this.closeReport());
            }
            if (this.modal) {
                this.modal.addEventListener('click', (e) => {
                    if (e.target === this.modal) this.closeReport();
                });
            }

            if (this.printBtn) {
                this.printBtn.addEventListener('click', () => {
                    window.print();
                });
            }

            if (this.copyMdBtn) {
                this.copyMdBtn.addEventListener('click', () => this.copyMarkdownBriefing());
            }
        }

        async openReport() {
            this.modal?.classList.remove('hidden');
            const scanId = window.currentScanId || currentScanId;
            await this.loadExecutiveData(scanId);
        }

        closeReport() {
            this.modal?.classList.add('hidden');
        }

        async loadExecutiveData(scanId) {
            this.reportData = null;
            if (this.printBtn) this.printBtn.disabled = true;
            if (this.copyMdBtn) this.copyMdBtn.disabled = true;
            for (const id of ['url', 'date', 'duration', 'score']) document.getElementById(`exec-meta-${id}`).textContent = '—';
            for (const severity of ['critical', 'high', 'medium', 'low']) document.getElementById(`exec-count-${severity}`).textContent = '—';
            const detail = document.getElementById('exec-findings-detail');
            detail.textContent = scanId ? 'Loading report…' : 'Run a scan before generating a report.';
            if (!scanId) return;
            try {
                const res = await fetch(`/api/scan/${encodeURIComponent(scanId)}/executive`);
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Report unavailable');
                this.reportData = data;
                this.renderReport(data);
                if (this.printBtn) this.printBtn.disabled = false;
                if (this.copyMdBtn) this.copyMdBtn.disabled = false;
            } catch (err) {
                detail.textContent = err.message;
            }
        }

        renderReport(data) {
            const meta = data.metadata || {};
            const posture = data.posture || {};
            document.getElementById('exec-meta-url').textContent = meta.targetUrl || '—';
            document.getElementById('exec-meta-date').textContent = new Date(meta.scannedAt).toLocaleString();
            document.getElementById('exec-meta-duration').textContent = `${meta.durationSeconds}s`;
            document.getElementById('exec-meta-score').textContent = posture.score == null ? 'Not scored' : `${posture.score}/100 (${posture.grade})`;
            for (const severity of ['critical', 'high', 'medium', 'low']) document.getElementById(`exec-count-${severity}`).textContent = posture.summary?.[severity] ?? 0;
            document.getElementById('exec-findings-detail').innerHTML = `<p class="report-scope">${escapeHtml(posture.riskStatement)}</p>` +
                (data.topFindings?.length ? data.topFindings.map(f => `<article class="report-finding"><span class="report-severity">${escapeHtml(f.severity)}</span><h3>${escapeHtml(f.title)}</h3><p>${escapeHtml(f.description)}</p><p><strong>Recommended fix:</strong> ${escapeHtml(f.remediation)}</p></article>`).join('') : '<p>No findings recorded at the selected threshold. Review scan coverage.</p>');
        }

        async copyMarkdownBriefing() {
            if (!this.reportData) return;
            const d = this.reportData;
            const md = `# 🛡️ VIBE SHIELD — Executive Security Audit Briefing

**Target Application:** \`${d.metadata?.targetUrl}\`  
**Audit Timestamp:** ${new Date(d.metadata?.scannedAt).toUTCString()}  
**Overall Security Grade:** **${d.posture?.grade}** (${d.posture?.score}/100) — *${d.posture?.statusText}*  
**Duration:** ${d.metadata?.durationSeconds}s  

## 🎯 Executive Risk Summary
> ${d.posture?.riskStatement}

## 📊 Vulnerability Breakdown
- **Critical (CVSS 9.0+):** ${d.posture?.summary?.critical ?? 0}
- **High (CVSS 7.0-8.9):** ${d.posture?.summary?.high ?? 0}
- **Medium (CVSS 4.0-6.9):** ${d.posture?.summary?.medium ?? 0}
- **Low (CVSS 0.1-3.9):** ${d.posture?.summary?.low ?? 0}

## 🏛️ Compliance Readiness Matrix
- **OWASP Web Top 10:** ${d.complianceReadiness?.owaspTop10}
- **OWASP LLM AI Top 10:** ${d.complianceReadiness?.owaspLlmTop10}
- **SOC 2 Type II Security:** ${d.complianceReadiness?.soc2Security}
- **GDPR Data Privacy:** ${d.complianceReadiness?.gdprDataPrivacy}

## 🗺️ Prioritized Remediation Roadmap
${(d.roadmap || []).map(r => `- **${r.phase}:** ${r.action} *(Owner: ${r.owner})*`).join('\n')}

---
*Generated by VIBE SHIELD Autonomous Multi-Agent Security Engine v1.0.0*
`;

            try {
                await navigator.clipboard.writeText(md);
                showToast('📋 Executive Markdown briefing copied to clipboard', 'success');
            } catch (err) {
                showToast('Failed to copy markdown', 'error');
            }
        }
    }


    // Initialize all new controllers
    window.authDrawer = new AuthDrawerController();
    window.cicdWebhook = new CicdWebhookManager();
    window.executiveReport = new ExecutiveReportManager();
    window.aiThreatMatrix = new AiThreatMatrixManager();

    // ═══════════════════════════════════════════════════════
    // CHATBOT CONTROLLER — Context-aware scan assistant
    // ═══════════════════════════════════════════════════════
    class ChatbotController {
        constructor() {
            this.messagesEl = document.getElementById('chatbot-messages');
            this.inputEl = document.getElementById('chatbot-input');
            this.sendBtn = document.getElementById('chatbot-send-btn');
            this.suggestionsEl = document.getElementById('chat-suggestions');
            this.scanData = null;

            if (this.sendBtn) this.sendBtn.addEventListener('click', () => this.send());
            if (this.inputEl) {
                this.inputEl.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.send(); }
                });
            }
            if (this.suggestionsEl) {
                this.suggestionsEl.querySelectorAll('.chat-suggestion-btn').forEach(btn => {
                    btn.addEventListener('click', () => {
                        if (this.inputEl) this.inputEl.value = btn.dataset.q;
                        this.send();
                    });
                });
            }
        }

        onScanComplete(status) {
            this.scanData = status;
            const report = status.report || {};
            const summary = report.dedupSummary || report.summary || {};
            const total = summary.total || 0;
            const critical = summary.critical || 0;
            const score = status.score ?? status.report?.score ?? window.currentScoreData?.overallScore ?? '—';
            const grade = status.grade || status.report?.grade || window.currentScoreData?.grade || '—';
            this.addMessage('bot',
                `Scan complete! 🔍 Found **${total} findings** (${critical} critical) on ${status.url}.\n\n` +
                `Security grade: **${grade}** (${score}/100).\n\nAsk me anything — "what should I fix first?", "explain the critical findings", or "give me suggestions to improve".`
            );
            // Update suggestions to scan-specific ones
            if (this.suggestionsEl) {
                this.suggestionsEl.innerHTML = [
                    'What should I fix first?',
                    'Explain the critical findings',
                    'How do I fix missing CSP headers?',
                    'What is my biggest risk?',
                    'Give me suggestions to improve'
                ].map(q => `<button type="button" class="chat-suggestion-btn" data-q="${q}">${q}</button>`).join('');
                this.suggestionsEl.querySelectorAll('.chat-suggestion-btn').forEach(btn => {
                    btn.addEventListener('click', () => {
                        if (this.inputEl) this.inputEl.value = btn.dataset.q;
                        this.send();
                    });
                });
            }
        }

        addMessage(role, text) {
            if (!this.messagesEl) return;
            const div = document.createElement('div');
            div.className = `chat-msg ${role}`;
            const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            
            let formattedText = escapeHtml(text || '');

            // Format code blocks ```code```
            formattedText = formattedText.replace(/```([\s\S]*?)```/g, (match, code) => {
                return `<div class="chat-code-block"><pre><code>${code.trim()}</code></pre><button type="button" class="chat-copy-code-btn" onclick="navigator.clipboard.writeText(this.previousElementSibling.innerText); this.textContent='Copied!'; setTimeout(()=>this.textContent='Copy', 2000);">Copy</button></div>`;
            });

            // Inline code `code`
            formattedText = formattedText.replace(/`([^`]+)`/g, '<code class="chat-inline-code">$1</code>');

            // Bold **text**
            formattedText = formattedText.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

            // Newlines
            formattedText = formattedText.replace(/\n/g, '<br>');

            div.innerHTML = `
                <div class="chat-bubble">${formattedText}</div>
                <span class="chat-time">${now}</span>
            `;
            this.messagesEl.appendChild(div);
            this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
        }

        showTyping() {
            if (!this.messagesEl) return null;
            const div = document.createElement('div');
            div.className = 'chat-msg bot';
            div.id = 'chat-typing-indicator';
            div.innerHTML = `<div class="chat-typing"><span></span><span></span><span></span></div>`;
            this.messagesEl.appendChild(div);
            this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
            return div;
        }

        answer(q) {
            const query = q.toLowerCase();
            const report = this.scanData?.report || {};
            const findings = report.findings || [];
            const summary = report.dedupSummary || report.summary || {};
            const score = this.scanData?.score ?? report.score ?? window.currentScoreData?.overallScore ?? '—';
            const grade = this.scanData?.grade || report.grade || window.currentScoreData?.grade || '—';
            const url = this.scanData?.url || 'the target';

            // No scan yet
            if (!this.scanData) {
                const noScanAnswers = {
                    'xss': 'XSS (Cross-Site Scripting) lets attackers inject malicious scripts into web pages. Fix: sanitize all user inputs, use Content Security Policy headers, encode output before rendering.',
                    'sql': 'SQL Injection allows attackers to manipulate your database queries. Fix: use parameterized queries/prepared statements, never concatenate user input into SQL.',
                    'cors': 'Misconfigured CORS can expose your API to unauthorized cross-origin requests. Fix: set specific allowed origins, never use wildcard (*) with credentials.',
                    'csp': 'Content Security Policy (CSP) prevents XSS by restricting what resources can load. Fix: add `Content-Security-Policy` header with a strict policy.',
                    'hsts': 'HTTP Strict Transport Security forces HTTPS connections. Fix: add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.',
                    'csrf': 'CSRF tricks authenticated users into submitting malicious requests. Fix: use CSRF tokens, SameSite cookie attribute, and verify Origin headers.',
                    'prompt injection': 'Prompt injection manipulates AI models by embedding malicious instructions in user input. Fix: separate system prompts from user input, validate and sanitize AI inputs.',
                    'ssrf': 'SSRF lets attackers make your server fetch internal resources. Fix: validate and allowlist URLs, block internal IP ranges, use a request proxy.'
                };
                for (const [keyword, ans] of Object.entries(noScanAnswers)) {
                    if (query.includes(keyword)) return ans;
                }
                return "Run a scan first and I'll give you specific, context-aware answers about the findings! You can also ask me general security questions like \"what is XSS?\" or \"how do I fix CORS issues?\".";
            }

            // Score questions
            if (query.includes('score') || query.includes('grade') || query.includes('rating')) {
                return `Your security score is **${score}/100** — Grade **${grade}**.\n\n${window.currentScoreData?.statusText || ''}.\n\nBreakdown:\n• Headers: ${document.getElementById('subscore-val-headers')?.textContent || '—'}\n• AI Defense: ${document.getElementById('subscore-val-ai')?.textContent || '—'}\n• API/Auth: ${document.getElementById('subscore-val-api')?.textContent || '—'}\n• Logic: ${document.getElementById('subscore-val-logic')?.textContent || '—'}`;
            }

            // Fix first / priority
            if (query.includes('first') || query.includes('priority') || query.includes('most important') || query.includes('what should')) {
                const crits = findings.filter(f => f.severity === 'critical');
                const highs = findings.filter(f => f.severity === 'high');
                if (crits.length > 0) {
                    return `Fix these **${crits.length} critical** findings first:\n\n${crits.slice(0, 3).map((f, i) => `${i + 1}. **${f.title}** — ${f.recommendation || f.description || 'See report for details'}`).join('\n\n')}${crits.length > 3 ? `\n\n...and ${crits.length - 3} more criticals.` : ''}`;
                } else if (highs.length > 0) {
                    return `No critical issues! Focus on these **${highs.length} high** severity findings:\n\n${highs.slice(0, 3).map((f, i) => `${i + 1}. **${f.title}**`).join('\n')}`;
                } else {
                    return `Great news — no critical or high severity issues! Your ${summary.medium || 0} medium and ${summary.low || 0} low findings are worth addressing over time.`;
                }
            }

            // Critical findings
            if (query.includes('critical')) {
                const crits = findings.filter(f => f.severity === 'critical');
                if (!crits.length) return `No critical vulnerabilities found on ${url}. ✅`;
                return `Found **${crits.length} critical** vulnerabilities:\n\n${crits.map(f => `• **${f.title}** (${f.affectedSurface || f.url || ''})`).join('\n')}`;
            }

            // What vulnerabilities
            if (query.includes('vulnerabilit') || query.includes('finding') || query.includes('issue') || query.includes('bug')) {
                if (!findings.length) return `No findings were recorded in the tested scope on ${url}. This does not establish that the site is vulnerability-free.`;
                return `Found **${summary.total}** total findings:\n• ${summary.critical || 0} Critical\n• ${summary.high || 0} High\n• ${summary.medium || 0} Medium\n• ${summary.low || 0} Low\n\nTop issues:\n${findings.slice(0, 4).map(f => `• **[${f.severity?.toUpperCase()}]** ${f.title}`).join('\n')}`;
            }

            // XSS
            if (query.includes('xss') || query.includes('cross-site scripting')) {
                const xss = findings.filter(f => (f.title || '').toLowerCase().includes('xss') || (f.title || '').toLowerCase().includes('cross-site'));
                if (xss.length) return `Found **${xss.length} XSS** issues on ${url}. Fix: sanitize all user inputs server-side, set Content-Security-Policy headers, encode output before rendering to DOM.`;
                return `No XSS issues detected on ${url}. ✅ Make sure to keep input sanitization in place.`;
            }

            // Headers / CSP / HSTS
            if (query.includes('header') || query.includes('csp') || query.includes('hsts')) {
                const hdrs = findings.filter(f => (f.title || '').toLowerCase().includes('header') || (f.title || '').toLowerCase().includes('csp'));
                if (hdrs.length) return `Found **${hdrs.length}** header-related issues. Recommended headers to add:\n• Content-Security-Policy\n• Strict-Transport-Security\n• X-Frame-Options: DENY\n• X-Content-Type-Options: nosniff`;
                return 'No header findings recorded. Check whether the security module ran and review its coverage.';
            }

            // Summary
            if (query.includes('summary') || query.includes('overview') || query.includes('tell me about') || query.includes('biggest risk')) {
                const worst = findings.sort((a, b) => {
                    const order = { critical: 4, high: 3, medium: 2, low: 1 };
                    return (order[b.severity] || 0) - (order[a.severity] || 0);
                })[0];
                return `**Scan summary for ${url}:**\n\nScore: **${score}/100** (${grade})\n\nFindings: ${summary.critical || 0} critical, ${summary.high || 0} high, ${summary.medium || 0} medium, ${summary.low || 0} low.\n\nBiggest risk: **${worst?.title || 'None found'}** — ${worst?.recommendation || worst?.description || ''}.`;
            }

            // Generic fallback
            return `I found **${summary.total || 0}** issues on ${url} (score: ${score}/100). Try asking me:\n• "What are the critical issues?"\n• "What should I fix first?"\n• "How do I fix XSS?"\n• "Explain my security score"`;
        }

        async send() {
            if (!this.inputEl) return;
            const text = this.inputEl.value.trim();
            if (!text) return;
            this.inputEl.value = '';
            this.addMessage('user', text);
            const typing = this.showTyping();

            let responseText = '';
            try {
                const res = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        prompt: text,
                        scanId: this.scanData?.scanId,
                        report: this.scanData?.report
                    })
                });
                const data = await res.json();
                if (data && data.response) {
                    responseText = data.response;
                } else {
                    responseText = this.answer(text);
                }
            } catch (err) {
                responseText = this.answer(text);
            }

            if (typing) typing.remove();
            this.addMessage('bot', responseText);
        }
    }

    window.chatbotController = new ChatbotController();

    // ═══════════════════════════════════════════════════════
    // API KEY MANAGEMENT
    // ═══════════════════════════════════════════════════════
    let apiKeyRevealed = false;
    let cachedApiKey = null;

    async function loadSettings() {
        try {
            const res = await fetch('/api/settings');
            if (res.ok) {
                const s = await res.json();
                const nInput = document.getElementById('nvidia-api-key-input');
                const gInput = document.getElementById('gemini-api-key-input');
                const oInput = document.getElementById('openai-api-key-input');
                if (nInput && s.nvidiaApiKey) nInput.placeholder = s.nvidiaApiKey;
                if (gInput && s.geminiApiKey) gInput.placeholder = s.geminiApiKey;
                if (oInput && s.openaiApiKey) oInput.placeholder = s.openaiApiKey;
            }
        } catch (e) {}
    }

    async function loadApiKey() {
        await loadSettings();
        const display = document.getElementById('api-key-display-text');
        if (!display) return;
        try {
            const res = await fetch('/api/key');
            if (res.ok) {
                const data = await res.json();
                cachedApiKey = data.key;
                display.textContent = data.key;
                display.classList.remove('revealed');
                apiKeyRevealed = false;
                const revealBtn = document.getElementById('reveal-api-key-btn');
                if (revealBtn) revealBtn.textContent = 'Reveal';
            } else {
                display.textContent = 'Could not load key';
            }
        } catch (e) {
            display.textContent = 'Server unavailable';
        }
    }

    const saveLlmBtn = document.getElementById('save-llm-settings-btn');
    if (saveLlmBtn) {
        saveLlmBtn.addEventListener('click', async () => {
            const nvidiaVal = document.getElementById('nvidia-api-key-input')?.value.trim();
            const geminiVal = document.getElementById('gemini-api-key-input')?.value.trim();
            const openaiVal = document.getElementById('openai-api-key-input')?.value.trim();
            const payload = {};
            if (nvidiaVal) payload.nvidiaApiKey = nvidiaVal;
            if (geminiVal) payload.geminiApiKey = geminiVal;
            if (openaiVal) payload.openaiApiKey = openaiVal;
            try {
                const res = await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                if (res.ok) {
                    showToast('AI Settings saved successfully!', 'success');
                    await loadSettings();
                } else {
                    showToast('Failed to save settings', 'error');
                }
            } catch (e) {
                showToast('Error saving settings', 'error');
            }
        });
    }

    const revealBtn = document.getElementById('reveal-api-key-btn');
    if (revealBtn) {
        revealBtn.addEventListener('click', () => {
            const display = document.getElementById('api-key-display-text');
            if (!display) return;
            apiKeyRevealed = !apiKeyRevealed;
            display.classList.toggle('revealed', apiKeyRevealed);
            revealBtn.textContent = apiKeyRevealed ? 'Hide' : 'Reveal';
        });
    }

    const copyApiKeyBtn = document.getElementById('copy-api-key-btn');
    if (copyApiKeyBtn) {
        copyApiKeyBtn.addEventListener('click', async () => {
            if (!cachedApiKey) return;
            try {
                await navigator.clipboard.writeText(cachedApiKey);
                copyApiKeyBtn.textContent = 'Copied!';
                setTimeout(() => { copyApiKeyBtn.textContent = 'Copy'; }, 2000);
                showToast('API key copied to clipboard', 'success');
            } catch (e) { showToast('Failed to copy', 'error'); }
        });
    }

    const regenApiKeyBtn = document.getElementById('regen-api-key-btn');
    if (regenApiKeyBtn) {
        regenApiKeyBtn.addEventListener('click', async () => {
            if (!confirm('Regenerate the API key? All existing CI/CD integrations using the old key will stop working.')) return;
            try {
                const res = await fetch('/api/key/regenerate', { method: 'POST' });
                if (res.ok) {
                    await loadApiKey();
                    showToast('API key regenerated. Update your CI/CD secrets!', 'warn');
                }
            } catch (e) { showToast('Failed to regenerate key', 'error'); }
        });
    }

    function escapeHtml(str) {
        return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }
});

