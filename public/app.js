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

    // Module checkbox chip toggles
    document.querySelectorAll('.chip input').forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            const label = e.target.closest('.chip');
            if (e.target.checked) label.classList.add('active');
            else label.classList.remove('active');
        });
    });

    // Form Submit -> Trigger Scan API
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = targetUrlInput.value.trim();
        if (!url) return;

        // Collect modules
        const modules = Array.from(document.querySelectorAll('input[name="modules"]:checked')).map(cb => cb.value);
        const safetyMode = document.getElementById('safety-mode').value;
        const maxPages = document.getElementById('max-pages').value;

        // UI Transition
        startBtn.disabled = true;
        startBtn.querySelector('.btn-text').textContent = 'Scan Initiated...';
        progressSection.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        currentTargetDisplay.textContent = url;

        resetAgentCards();
        startTimer();

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, modules, safetyMode, maxPages })
            });

            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Failed to start scan');

            currentScanId = data.scanId;
            pollScanProgress(currentScanId);
        } catch (err) {
            alert('Scan Error: ' + err.message);
            stopTimer();
            startBtn.disabled = false;
            startBtn.querySelector('.btn-text').textContent = 'Start Autonomous Scan';
        }
    });

    // Poll Progress
    function pollScanProgress(scanId) {
        const interval = setInterval(async () => {
            try {
                const res = await fetch(`/api/scan/${scanId}`);
                if (!res.ok) return;
                const status = await res.json();

                updateAgentState('crawl', status.agents['VIBE-SHIELD-CRAWL']);
                updateAgentState('qa', status.agents['VIBE-SHIELD-QA']);
                updateAgentState('sec', status.agents['VIBE-SHIELD-SEC']);
                updateAgentState('ai', status.agents['VIBE-SHIELD-AI']);
                updateAgentState('logic', status.agents['VIBE-SHIELD-LOGIC']);
                updateAgentState('api', status.agents['VIBE-SHIELD-API']);

                if (status.completed) {
                    clearInterval(interval);
                    stopTimer();
                    startBtn.disabled = false;
                    startBtn.querySelector('.btn-text').textContent = 'Start Autonomous Scan';
                    displayResults(status);
                    loadHistory();
                }
            } catch (e) {
                console.error('Error polling status:', e);
            }
        }, 1000);
    }

    function updateAgentState(key, agentData) {
        if (!agentData) return;
        const card = document.getElementById(`agent-${key}`);
        if (!card) return;

        const badge = card.querySelector('.agent-badge');
        const log = card.querySelector('.agent-log');

        badge.className = 'agent-badge badge-' + agentData.status;
        badge.textContent = agentData.status.toUpperCase();
        log.textContent = agentData.message || agentData.status;
    }

    function resetAgentCards() {
        ['crawl', 'qa', 'sec', 'ai', 'logic', 'api'].forEach(key => {
            const card = document.getElementById(`agent-${key}`);
            if (card) {
                const badge = card.querySelector('.agent-badge');
                const log = card.querySelector('.agent-log');
                badge.className = 'agent-badge badge-pending';
                badge.textContent = 'Pending';
                log.textContent = 'Waiting for execution...';
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

        const scoreCircle = document.getElementById('score-circle');
        const scoreGradeText = document.getElementById('score-grade-text');
        const scoreNumberText = document.getElementById('score-number-text');
        const scoreStatusText = document.getElementById('score-status-text');
        const liveBadgeContainer = document.getElementById('live-badge-container');

        if (scoreGradeText) {
            scoreGradeText.textContent = scoreData.grade;
            scoreGradeText.style.color = scoreData.gradeColor;
            scoreGradeText.style.textShadow = `0 0 12px ${scoreData.gradeColor}88`;
        }
        if (scoreNumberText) {
            scoreNumberText.textContent = `${scoreData.overallScore}/100`;
        }
        if (scoreStatusText) {
            scoreStatusText.textContent = scoreData.statusText;
        }
        if (scoreCircle) {
            scoreCircle.style.borderColor = scoreData.gradeColor;
            scoreCircle.style.boxShadow = `0 0 25px ${scoreData.gradeColor}44, inset 0 0 15px ${scoreData.gradeColor}22`;
        }

        // Subscores
        const sub = scoreData.subCategories;
        const setSub = (key, val) => {
            const valEl = document.getElementById(`subscore-val-${key}`);
            const barEl = document.getElementById(`subscore-bar-${key}`);
            if (valEl) valEl.textContent = `${val}%`;
            if (barEl) barEl.style.width = `${val}%`;
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

    function calculateSecurityScore(report) {
        const summary = report.dedupSummary || report.summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
        const findings = report.findings || [];

        let deductions = 0;
        deductions += (summary.critical || 0) * 25;
        deductions += (summary.high || 0) * 12;
        deductions += (summary.medium || 0) * 4;
        deductions += (summary.low || 0) * 1;

        const overallScore = Math.max(0, Math.min(100, Math.round(100 - deductions)));

        let grade = 'F';
        let gradeColor = '#ff3366';
        let statusText = 'Severe Exploitable Threats';

        if (overallScore >= 97 && summary.critical === 0 && summary.high === 0) {
            grade = 'A+';
            gradeColor = '#00ff88';
            statusText = 'Fortified & Hardened';
        } else if (overallScore >= 90 && summary.critical === 0 && summary.high === 0) {
            grade = 'A';
            gradeColor = '#00ff88';
            statusText = 'Excellent Defense Posture';
        } else if (overallScore >= 80 && summary.critical === 0) {
            grade = 'B';
            gradeColor = '#00e5ff';
            statusText = 'Good Security with Minor Gaps';
        } else if (overallScore >= 65) {
            grade = 'C';
            gradeColor = '#ffb700';
            statusText = 'Moderate Risk Exposure';
        } else if (overallScore >= 50) {
            grade = 'D';
            gradeColor = '#ff8800';
            statusText = 'High Vulnerability Risk';
        } else {
            grade = 'F';
            gradeColor = '#ff3366';
            statusText = 'Severe Exploitable Threats';
        }

        const subCategories = {
            headers: { name: 'Headers & Perimeter', score: 100 },
            aiSafety: { name: 'AI & Prompt Defense', score: 100 },
            apiAuth: { name: 'API & Auth Hardening', score: 100 },
            logic: { name: 'Logic & Surface Hygiene', score: 100 }
        };

        findings.forEach(f => {
            const title = (f.title || '').toLowerCase();
            const mod = (f.module || f.agent || '').toLowerCase();
            const sev = f.severity || 'low';
            const penalty = sev === 'critical' ? 30 : sev === 'high' ? 18 : sev === 'medium' ? 8 : 2;

            if (mod.includes('sec') || title.includes('csp') || title.includes('header') || title.includes('cors') || title.includes('tls')) {
                subCategories.headers.score = Math.max(0, subCategories.headers.score - penalty);
            } else if (mod.includes('ai') || title.includes('prompt') || title.includes('injection') || title.includes('jailbreak')) {
                subCategories.aiSafety.score = Math.max(0, subCategories.aiSafety.score - penalty);
            } else if (mod.includes('api') || title.includes('auth') || title.includes('token') || title.includes('cookie') || title.includes('graphql')) {
                subCategories.apiAuth.score = Math.max(0, subCategories.apiAuth.score - penalty);
            } else {
                subCategories.logic.score = Math.max(0, subCategories.logic.score - penalty);
            }
        });

        const badgeMarkdown = `[![VIBE SHIELD Security Grade](https://img.shields.io/badge/VIBE_SHIELD-Grade_${encodeURIComponent(grade)}_${overallScore}%2F100-${gradeColor.replace('#', '')}?style=for-the-badge&logo=shield)](https://github.com/Aaravkhanal/VIBE-SHIELD)`;
        const badgeHtml = `<a href="https://github.com/Aaravkhanal/VIBE-SHIELD"><img src="https://img.shields.io/badge/VIBE_SHIELD-Grade_${encodeURIComponent(grade)}_${overallScore}%2F100-${gradeColor.replace('#', '')}?style=for-the-badge&logo=shield" alt="VIBE SHIELD Security Grade" /></a>`;

        return { overallScore, grade, gradeColor, statusText, subCategories, badgeMarkdown, badgeHtml };
    }

    function generateSvgBadge(grade, score, color) {
        const cleanColor = color || '#00ff88';
        return `<svg xmlns="http://www.w3.org/2000/svg" width="220" height="36" viewBox="0 0 220 36" role="img" aria-label="VIBE SHIELD: Grade ${grade}">
  <defs>
    <linearGradient id="badge-grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0a0d14"/>
      <stop offset="100%" stop-color="#141c2b"/>
    </linearGradient>
    <filter id="badge-glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="2" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>
  <rect width="220" height="36" rx="8" fill="url(#badge-grad)" stroke="rgba(255,255,255,0.12)" stroke-width="1"/>
  <text x="14" y="22" fill="#8a99b5" font-family="-apple-system,BlinkMacSystemFont,'Inter',sans-serif" font-size="11" font-weight="700" letter-spacing="0.5">🛡️ VIBE SHIELD</text>
  <rect x="135" y="6" width="75" height="24" rx="5" fill="${cleanColor}" fill-opacity="0.15" stroke="${cleanColor}" stroke-opacity="0.4"/>
  <text x="172.5" y="22" fill="${cleanColor}" font-family="-apple-system,BlinkMacSystemFont,'Fira Code',monospace" font-size="12" font-weight="800" text-anchor="middle" filter="url(#badge-glow)">${grade} · ${score}</text>
</svg>`;
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
        resultsSection.classList.remove('hidden');
        const report = status.report || {};
        const summary = report.summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };

        document.getElementById('count-critical').textContent = summary.critical;
        document.getElementById('count-high').textContent = summary.high;
        document.getElementById('count-medium').textContent = summary.medium;
        document.getElementById('count-low').textContent = summary.low;
        document.getElementById('count-total').textContent = summary.total;

        document.getElementById('results-meta-text').textContent = `Scanned ${status.url} in ${status.duration}s (${summary.total} total findings)`;

        activeReportPath = status.reportHtmlUrl;
        if (activeReportPath) {
            viewReportBtn.onclick = () => window.open(activeReportPath, '_blank');
        }

        // Render Vibe Security Score & Shield Badge
        renderSecurityScoreAudit(report);

        // Render Threat Graph
        if (window.threatGraph) {
            window.threatGraph.buildFromReport(report, status.url);
        }

        // Table Rows
        const tbody = document.getElementById('findings-table-body');
        tbody.innerHTML = '';

        const findings = report.findings || [];
        if (findings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-state">🎉 Clean Scan! No findings at configured threshold.</td></tr>`;
            return;
        }

        findings.forEach((f, idx) => {
            const tr = document.createElement('tr');
            const sevClass = 'pill-' + (f.severity || 'low');
            const remediationText = f.remediation || f.description || 'Review application code and enforce strict input validation.';
            tr.innerHTML = `
                <td><span class="badge ${sevClass}">${(f.severity || 'LOW').toUpperCase()}</span></td>
                <td><strong>${escapeHtml(f.title)}</strong></td>
                <td><code>${escapeHtml(f.agent || 'VIBE-SHIELD')}</code></td>
                <td>${escapeHtml(f.affected_surface || 'N/A')}</td>
                <td>${escapeHtml(f.owasp?.id || f.owasp || 'A01:2021')}</td>
                <td style="max-width: 380px;">
                    <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 6px;">${escapeHtml(remediationText)}</div>
                    <button type="button" class="btn-patch-action auto-patch-btn" data-finding-index="${idx}">
                        ⚡ Auto-Patch Code
                    </button>
                </td>
            `;

            const patchBtn = tr.querySelector('.auto-patch-btn');
            patchBtn.onclick = () => openAutoPatchModal(f);
            tbody.appendChild(tr);
        });
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
            this.draggedNode = null;
            this.animId = null;

            this.initEvents();
            this.resize();
            window.addEventListener('resize', () => this.resize());
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
                    this.showInspector(clicked);
                }
            });

            window.addEventListener('mousemove', (e) => {
                if (isDown && this.draggedNode) {
                    const rect = this.canvas.getBoundingClientRect();
                    this.draggedNode.x = (e.clientX - rect.left) - dragOffset.x;
                    this.draggedNode.y = (e.clientY - rect.top) - dragOffset.y;
                }
            });

            window.addEventListener('mouseup', () => {
                isDown = false;
                this.draggedNode = null;
            });

            const closeBtn = document.getElementById('close-inspector-btn');
            if (closeBtn) {
                closeBtn.onclick = () => this.inspector.classList.add('hidden');
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
                    label: 'No Severe Vulnerabilities',
                    type: 'vuln',
                    x: width * 0.5,
                    y: height * 0.5,
                    radius: 18,
                    color: '#00ff88',
                    glow: 'rgba(0, 255, 136, 0.4)',
                    stage: 'Defense Verified',
                    impact: 'All evaluated security assertions passed without critical flaw.',
                    fix: 'Continue continuous integration scanning on every deployment.'
                };
                this.nodes.push(cleanNode);
                this.edges.push({ source: rootNode, target: cleanNode, active: true, label: 'Secured' });
            } else {
                keyFindings.forEach((f, idx) => {
                    const vY = height * (0.2 + (idx / Math.max(1, keyFindings.length - 1)) * 0.6);
                    const vNode = {
                        id: `node-v-${idx}`,
                        label: f.title.length > 24 ? f.title.slice(0, 24) + '...' : f.title,
                        type: 'vuln',
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

                // 3. Exploitation Primitives
                const primitives = [
                    {
                        id: 'prim-1',
                        label: 'Payload Injection / Reflection',
                        stage: 'Exploitation Primitive (Stage 2)',
                        impact: 'Adversary bypasses client validation or executes script in victim context.',
                        fix: 'Sanitize all dynamic inputs and apply strict Content-Security-Policy.'
                    },
                    {
                        id: 'prim-2',
                        label: 'Auth & Boundary Escalation',
                        stage: 'Exploitation Primitive (Stage 2)',
                        impact: 'Adversary leverages CORS / header leaks to access unauthorized resources.',
                        fix: 'Verify Origin headers against strict whitelist and enforce token signing.'
                    }
                ];

                const primNodes = primitives.map((p, idx) => {
                    const pNode = {
                        id: p.id,
                        label: p.label,
                        type: 'primitive',
                        x: width * 0.65,
                        y: height * (0.35 + idx * 0.3),
                        radius: 17,
                        color: '#bd00ff',
                        glow: 'rgba(189, 0, 255, 0.5)',
                        stage: p.stage,
                        impact: p.impact,
                        fix: p.fix
                    };
                    this.nodes.push(pNode);

                    vulnNodes.forEach(vn => {
                        this.edges.push({ source: vn, target: pNode, active: true, label: 'Enables' });
                    });
                    return pNode;
                });

                // 4. Final Compounded Impact Node
                const impactNode = {
                    id: 'impact-1',
                    label: 'Compounded Threat Impact',
                    type: 'impact',
                    x: width * 0.88,
                    y: height * 0.5,
                    radius: 22,
                    color: '#ff3366',
                    glow: 'rgba(255, 51, 102, 0.6)',
                    stage: 'Final Attack Vector Objective (Stage 3)',
                    impact: 'Full compromise of client trust, potential session hijacking, or unauthorized data exfiltration.',
                    fix: 'Apply Defense-in-Depth: HttpOnly session tokens, Strict CSP, and Least-Privilege CORS.'
                };
                this.nodes.push(impactNode);

                primNodes.forEach(pn => {
                    this.edges.push({ source: pn, target: impactNode, active: true, label: 'Compromises' });
                });
            }

            this.spawnParticles();
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
            setTimeout(() => {
                this.particles.forEach(p => p.speed = 0.005 + Math.random() * 0.006);
            }, 3000);
        }

        startAnimation() {
            if (this.animId) cancelAnimationFrame(this.animId);
            const render = () => {
                this.update();
                this.draw();
                this.animId = requestAnimationFrame(render);
            };
            render();
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
                ctx.beginPath();
                ctx.moveTo(edge.source.x, edge.source.y);
                ctx.lineTo(edge.target.x, edge.target.y);
                ctx.strokeStyle = 'rgba(255, 255, 255, 0.12)';
                ctx.lineWidth = 1.8;
                ctx.stroke();

                // Arrow head
                const angle = Math.atan2(edge.target.y - edge.source.y, edge.target.x - edge.source.x);
                const arrowX = edge.target.x - Math.cos(angle) * (edge.target.radius + 5);
                const arrowY = edge.target.y - Math.sin(angle) * (edge.target.radius + 5);

                ctx.save();
                ctx.translate(arrowX, arrowY);
                ctx.rotate(angle);
                ctx.fillStyle = edge.target.color;
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
                ctx.save();

                // Glow
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.radius + 5, 0, Math.PI * 2);
                ctx.fillStyle = node.glow;
                ctx.fill();

                // Base circle
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
                ctx.fillStyle = '#0a0d14';
                ctx.fill();
                ctx.lineWidth = 2.5;
                ctx.strokeStyle = node.color;
                ctx.stroke();

                // Center indicator dot
                ctx.beginPath();
                ctx.arc(node.x, node.y, 4, 0, Math.PI * 2);
                ctx.fillStyle = node.color;
                ctx.fill();

                // Text label
                ctx.font = '11px Inter, sans-serif';
                ctx.fillStyle = '#f0f4fc';
                ctx.textAlign = 'center';
                ctx.fillText(node.label, node.x, node.y + node.radius + 14);

                ctx.restore();
            });
        }

        showInspector(node) {
            this.inspector.classList.remove('hidden');
            const badge = document.getElementById('inspector-badge');
            badge.textContent = node.type.toUpperCase();
            badge.style.borderColor = node.color;
            badge.style.color = node.color;

            document.getElementById('inspector-title').textContent = node.label;
            document.getElementById('inspector-stage').textContent = node.stage;
            document.getElementById('inspector-impact').textContent = node.impact;
            document.getElementById('inspector-fix').textContent = node.fix;
        }
    }

    // Initialize Threat Graph instance
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
                item.innerHTML = `
                    <div style="cursor: pointer;" class="history-info-click">
                        <div class="history-url">${escapeHtml(scan.url)}</div>
                        <div class="history-meta">${new Date(scan.timestamp).toLocaleString()} · ${scan.findingsCount} findings · ${scan.duration}s</div>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-secondary load-scan-btn" style="padding:4px 10px; font-size:11px;">Inspect Details</button>
                        ${scan.reportHtmlUrl ? `<a href="${scan.reportHtmlUrl}" target="_blank" class="btn btn-primary" style="padding:4px 10px; font-size:11px; text-decoration: none;">HTML Report ↗</a>` : ''}
                    </div>
                `;

                // Add inspect button event
                const inspectBtn = item.querySelector('.load-scan-btn');
                const infoClick = item.querySelector('.history-info-click');
                const loadScanDetails = async () => {
                    try {
                        const res = await fetch(`/vibe-shield-reports/${scan.scanId}/report.json`);
                        if (!res.ok) return;
                        const reportData = await res.json();
                        displayResults({
                            url: scan.url,
                            duration: scan.duration,
                            report: reportData,
                            reportHtmlUrl: scan.reportHtmlUrl
                        });
                        resultsSection.scrollIntoView({ behavior: 'smooth' });
                    } catch (err) {
                        console.error('Error loading scan details:', err);
                    }
                };

                inspectBtn.onclick = loadScanDetails;
                infoClick.onclick = loadScanDetails;
                historyList.appendChild(item);
            });
        } catch (e) {
            console.error('Failed to load history:', e);
        }
    }

    function escapeHtml(str) {
        return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
});
