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

        // Table Rows
        const tbody = document.getElementById('findings-table-body');
        tbody.innerHTML = '';

        const findings = report.findings || [];
        if (findings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state">🎉 Clean Scan! No findings at configured threshold.</td></tr>`;
            return;
        }

        findings.forEach(f => {
            const tr = document.createElement('tr');
            const sevClass = 'pill-' + (f.severity || 'low');
            const remediationText = f.remediation || f.description || 'Review application code and enforce strict input validation.';
            tr.innerHTML = `
                <td><span class="badge ${sevClass}">${(f.severity || 'LOW').toUpperCase()}</span></td>
                <td><strong>${escapeHtml(f.title)}</strong></td>
                <td><code>${escapeHtml(f.agent || 'VIBE-SHIELD')}</code></td>
                <td>${escapeHtml(f.affected_surface || 'N/A')}</td>
                <td>${escapeHtml(f.owasp || 'N/A')}</td>
                <td style="max-width: 320px; font-size: 12px; color: var(--text-secondary);">${escapeHtml(remediationText)}</td>
            `;
            tbody.appendChild(tr);
        });
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
