/**
 * Security Score Engine — Computes 0-100 score, letter grade (A+ to F),
 * category sub-scores, and dynamic SVG / Markdown badges.
 */

export function calculateSecurityScore(report) {
    const coverage = report?.coverage?.manifest;
    if (!report || report.coverage?.status !== 'complete' || !coverage?.measured || !(coverage.pages?.discovered > 0) || !Number.isFinite(coverage.percent)) {
        return { overallScore: null, grade: 'N/A', gradeColor: '#64748b', statusText: 'Insufficient scan coverage',
            coveragePercent: coverage?.percent ?? null, riskScore: null, coverageCap: null,
            subCategories: Object.fromEntries(['headers', 'aiSafety', 'apiAuth', 'logic'].map(key => [key, { score: null, issues: 0 }])), badgeMarkdown: '', badgeHtml: '' };
    }
    const findings = report.scoringFindings || report.findings || [];
    const hasCritical = findings.some(finding => finding.severity === 'critical');
    const hasHigh = findings.some(finding => finding.severity === 'high');
    const severityPenalty = { critical: 25, high: 12, medium: 4, low: 1, info: 0 };
    const confidenceWeight = { confirmed: 1, high_confidence: 0.8, potential: 0.35, informational: 0.1, not_assessed: 0 };
    const deductions = findings.reduce((sum, finding) => {
        const level = finding.verification?.level || (finding.severity === 'info' ? 'informational' : 'potential');
        return sum + (severityPenalty[finding.severity] || 0) * (confidenceWeight[level] ?? confidenceWeight.potential);
    }, 0);
    const riskScore = Math.max(0, Math.min(100, Math.round(100 - deductions)));
    // Unknown areas cannot earn a clean bill of health. At 10% measured
    // coverage the best possible score is 46, even with zero findings.
    const coverageCap = Math.max(0, Math.min(100, Math.round(40 + 0.6 * coverage.percent)));
    const overallScore = Math.min(riskScore, coverageCap);

    // Determine Letter Grade
    let grade = 'F';
    let gradeColor = '#ff3366'; // Red
    let statusText = 'Critical Vulnerabilities Detected';

    if (overallScore >= 97 && !hasCritical && !hasHigh) {
        grade = 'A+';
        gradeColor = '#00ff88'; // Neon Green
        statusText = 'No high-severity findings in tested scope';
    } else if (overallScore >= 90 && !hasCritical && !hasHigh) {
        grade = 'A';
        gradeColor = '#00ff88';
        statusText = 'Low observed risk in tested scope';
    } else if (overallScore >= 80 && !hasCritical) {
        grade = 'B';
        gradeColor = '#00e5ff'; // Cyan
        statusText = 'Good Security with Minor Gaps';
    } else if (overallScore >= 65) {
        grade = 'C';
        gradeColor = '#ffb700'; // Amber
        statusText = 'Moderate Risk Exposure';
    } else if (overallScore >= 50) {
        grade = 'D';
        gradeColor = '#ff8800'; // Orange
        statusText = 'High Vulnerability Risk';
    } else {
        grade = 'F';
        gradeColor = '#ff3366';
        statusText = 'High risk or limited verified coverage';
    }
    if (coverageCap < riskScore) statusText = `Coverage limited this grade (${coverage.percent}% measured)`;

    // Compute Sub-Scores (0-100 each)
    const subCategories = {
        headers: { name: 'Headers & Perimeter', score: 100, weight: 25, issues: 0 },
        aiSafety: { name: 'AI & Prompt Defense', score: 100, weight: 25, issues: 0 },
        apiAuth: { name: 'API & Auth Hardening', score: 100, weight: 25, issues: 0 },
        logic: { name: 'Logic & Surface Hygiene', score: 100, weight: 25, issues: 0 }
    };

    findings.forEach(f => {
        const title = (f.title || '').toLowerCase();
        const mod = (f.module || f.agent || '').toLowerCase();
        const sev = f.severity || 'low';
        const level = f.verification?.level || (sev === 'info' ? 'informational' : 'potential');
        const penalty = (sev === 'critical' ? 30 : sev === 'high' ? 18 : sev === 'medium' ? 8 : sev === 'low' ? 2 : 0) * (confidenceWeight[level] ?? confidenceWeight.potential);

        if (mod.includes('sec') || title.includes('csp') || title.includes('header') || title.includes('cors') || title.includes('tls')) {
            subCategories.headers.score = Math.max(0, subCategories.headers.score - penalty);
            subCategories.headers.issues++;
        } else if (mod.includes('ai') || title.includes('prompt') || title.includes('injection') || title.includes('jailbreak')) {
            subCategories.aiSafety.score = Math.max(0, subCategories.aiSafety.score - penalty);
            subCategories.aiSafety.issues++;
        } else if (mod.includes('api') || title.includes('auth') || title.includes('token') || title.includes('cookie') || title.includes('graphql')) {
            subCategories.apiAuth.score = Math.max(0, subCategories.apiAuth.score - penalty);
            subCategories.apiAuth.issues++;
        } else {
            subCategories.logic.score = Math.max(0, subCategories.logic.score - penalty);
            subCategories.logic.issues++;
        }
    });

    const moduleKeys = { headers: 'security', aiSafety: 'ai', apiAuth: 'api', logic: 'logic' };
    for (const [key, module] of Object.entries(moduleKeys)) {
        const agentName = 'VIBE-SHIELD-' + ({ security: 'SEC' }[module] || module.toUpperCase());
        if (!report.meta?.modules?.includes(module) || report.agents?.[agentName]?.assessment === 'not_assessed') subCategories[key].score = null;
    }

    const badgeMarkdown = `[![VIBE SHIELD Security Grade](https://img.shields.io/badge/VIBE_SHIELD-Grade_${encodeURIComponent(grade)}_${overallScore}%2F100-${gradeColor.replace('#', '')}?style=for-the-badge&logo=shield)](https://github.com/Aaravkhanal/VIBE-SHIELD)`;
    const badgeHtml = `<a href="https://github.com/Aaravkhanal/VIBE-SHIELD"><img src="https://img.shields.io/badge/VIBE_SHIELD-Grade_${encodeURIComponent(grade)}_${overallScore}%2F100-${gradeColor.replace('#', '')}?style=for-the-badge&logo=shield" alt="VIBE SHIELD Security Grade" /></a>`;

    return {
        overallScore,
        riskScore,
        coveragePercent: coverage.percent,
        coverageCap,
        grade,
        gradeColor,
        statusText,
        subCategories,
        badgeMarkdown,
        badgeHtml
    };
}

export function generateSvgBadge(grade, score, color) {
    const cleanColor = /^#[0-9a-f]{6}$/i.test(color || '') ? color : '#64748b';
    grade = /^(A\+|[A-F]|N\/A)$/.test(grade) ? grade : 'N/A';
    score = score != null && Number.isFinite(Number(score)) ? Math.max(0, Math.min(100, Number(score))) : '—';
    return `<svg xmlns="http://www.w3.org/2000/svg" width="220" height="36" viewBox="0 0 220 36" role="img" aria-label="VIBE SHIELD: Grade ${grade}">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0a0d14"/>
      <stop offset="100%" stop-color="#141c2b"/>
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="3" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>
  <rect width="220" height="36" rx="8" fill="url(#grad)" stroke="rgba(255,255,255,0.1)" stroke-width="1"/>
  <text x="14" y="22" fill="#8a99b5" font-family="-apple-system,BlinkMacSystemFont,'Inter',sans-serif" font-size="11" font-weight="700" letter-spacing="0.5">🛡️ VIBE SHIELD</text>
  <rect x="135" y="6" width="75" height="24" rx="5" fill="${cleanColor}" fill-opacity="0.15" stroke="${cleanColor}" stroke-opacity="0.4"/>
  <text x="172.5" y="22" fill="${cleanColor}" font-family="-apple-system,BlinkMacSystemFont,'Fira Code',monospace" font-size="12" font-weight="800" text-anchor="middle" filter="url(#glow)">${grade} · ${score}</text>
</svg>`;
}
