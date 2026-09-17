/**
 * Security Score Engine — Computes 0-100 score, letter grade (A+ to F),
 * category sub-scores, and dynamic SVG / Markdown badges.
 */

export function calculateSecurityScore(report) {
    const summary = report.dedupSummary || report.summary || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    const findings = report.findings || [];

    // Base score starts at 100
    let deductions = 0;
    deductions += (summary.critical || 0) * 25;
    deductions += (summary.high || 0) * 12;
    deductions += (summary.medium || 0) * 4;
    deductions += (summary.low || 0) * 1;

    const overallScore = Math.max(0, Math.min(100, Math.round(100 - deductions)));

    // Determine Letter Grade
    let grade = 'F';
    let gradeColor = '#ff3366'; // Red
    let statusText = 'Critical Vulnerabilities Detected';

    if (overallScore >= 97 && summary.critical === 0 && summary.high === 0) {
        grade = 'A+';
        gradeColor = '#00ff88'; // Neon Green
        statusText = 'Fortified & Hardened';
    } else if (overallScore >= 90 && summary.critical === 0 && summary.high === 0) {
        grade = 'A';
        gradeColor = '#00ff88';
        statusText = 'Excellent Defense Posture';
    } else if (overallScore >= 80 && summary.critical === 0) {
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
        statusText = 'Severe Exploitable Threats';
    }

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
        const penalty = sev === 'critical' ? 30 : sev === 'high' ? 18 : sev === 'medium' ? 8 : 2;

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

    const badgeMarkdown = `[![VIBE SHIELD Security Grade](https://img.shields.io/badge/VIBE_SHIELD-Grade_${encodeURIComponent(grade)}_${overallScore}%2F100-${gradeColor.replace('#', '')}?style=for-the-badge&logo=shield)](https://github.com/Aaravkhanal/VIBE-SHIELD)`;
    const badgeHtml = `<a href="https://github.com/Aaravkhanal/VIBE-SHIELD"><img src="https://img.shields.io/badge/VIBE_SHIELD-Grade_${encodeURIComponent(grade)}_${overallScore}%2F100-${gradeColor.replace('#', '')}?style=for-the-badge&logo=shield" alt="VIBE SHIELD Security Grade" /></a>`;

    return {
        overallScore,
        grade,
        gradeColor,
        statusText,
        subCategories,
        badgeMarkdown,
        badgeHtml
    };
}

export function generateSvgBadge(grade, score, color) {
    const cleanColor = color || '#00ff88';
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
