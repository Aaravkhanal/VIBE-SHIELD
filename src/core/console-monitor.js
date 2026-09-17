import { createFinding } from '../utils/finding.js';

/**
 * Console Monitor — Captures and classifies browser console output.
 * Hooks into Playwright page events to capture errors, warnings, and failed requests.
 */
export class ConsoleMonitor {
    constructor(logger) {
        this.logger = logger;
        this.entries = [];
        this.findings = [];
    }

    /**
     * Analyze console errors and failed requests from crawled surfaces.
     */
    analyze(surfaceInventory) {
        const errorMap = new Map(); // Deduplication

        for (const page of surfaceInventory.pages) {
            // Process console errors
            for (const error of (page.consoleErrors || [])) {
                const key = `${error.type}:${error.text}`;
                if (!errorMap.has(key)) {
                    errorMap.set(key, {
                        ...error,
                        pages: [error.url],
                        count: 1,
                    });
                } else {
                    const existing = errorMap.get(key);
                    if (!existing.pages.includes(error.url)) {
                        existing.pages.push(error.url);
                    }
                    existing.count++;
                }
            }

            // Process failed network requests
            for (const req of (page.failedRequests || [])) {
                this.findings.push(
                    createFinding({
                        module: 'qa',
                        title: `Failed Network Request: ${req.method} ${this._truncateUrl(req.url)}`,
                        severity: 'medium',
                        affected_surface: req.page,
                        description: `A network request to ${req.url} failed with error: ${req.failure}. This indicates a broken resource, missing API endpoint, or connectivity issue.`,
                        reproduction: [
                            `1. Navigate to ${req.page}`,
                            `2. Observe the network panel for failed ${req.method} request to ${req.url}`,
                            `3. Error: ${req.failure}`,
                        ],
                        evidence: JSON.stringify(req, null, 2),
                        remediation: 'Verify the endpoint exists and is accessible. Check for CORS issues, missing routes, or server errors.',
                    })
                );
            }
        }

        // Convert deduplicated errors to findings
        for (const [, error] of errorMap) {
            const severity = error.type === 'exception' ? 'high' : 'medium';
            this.findings.push(
                createFinding({
                    module: 'qa',
                    title: `Console ${error.type === 'exception' ? 'Exception' : 'Error'}: ${this._truncateText(error.text, 80)}`,
                    severity,
                    affected_surface: error.pages.join(', '),
                    description: `A JavaScript ${error.type} was detected across ${error.count} occurrence(s) on ${error.pages.length} page(s):\n\n${error.text}`,
                    reproduction: [
                        `1. Navigate to ${error.pages[0]}`,
                        `2. Open browser DevTools console`,
                        `3. Observe the error: ${error.text}`,
                    ],
                    evidence: JSON.stringify({
                        type: error.type,
                        message: error.text,
                        pages: error.pages,
                        occurrences: error.count,
                    }, null, 2),
                    remediation: error.type === 'exception'
                        ? 'This is an uncaught JavaScript exception. Add try/catch blocks or fix the root cause to prevent runtime crashes.'
                        : 'Investigate and resolve the console error. Even non-critical errors can indicate underlying issues.',
                })
            );
        }

        this.logger?.info?.(`Console monitor found ${this.findings.length} issues`);
        return this.findings;
    }

    _truncateText(text, maxLen = 100) {
        if (!text) return '';
        return text.length > maxLen ? text.substring(0, maxLen) + '...' : text;
    }

    _truncateUrl(url) {
        try {
            const u = new URL(url);
            return u.pathname.length > 50 ? u.pathname.substring(0, 50) + '...' : u.pathname;
        } catch {
            return url;
        }
    }
}

export default ConsoleMonitor;
