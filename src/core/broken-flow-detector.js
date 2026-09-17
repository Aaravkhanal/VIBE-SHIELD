import { createFinding } from '../utils/finding.js';

/**
 * Broken Flow Detector — Detects common broken patterns in web applications.
 * Analyzes crawl data for dead links, empty states, unresponsive elements, etc.
 */
export class BrokenFlowDetector {
    constructor(logger) {
        this.logger = logger;
        this.findings = [];
    }

    /**
     * Analyze crawled surfaces for broken flows.
     */
    analyze(surfaceInventory) {
        this._detectDeadLinks(surfaceInventory);
        this._detectServerErrors(surfaceInventory);
        this._detectSlowPages(surfaceInventory);
        this._detectPagesWithErrors(surfaceInventory);
        this._detectMissingTitles(surfaceInventory);
        this._detectFormsWithoutSubmit(surfaceInventory);

        this.logger?.info?.(`Broken flow detector found ${this.findings.length} issues`);
        return this.findings;
    }

    /**
     * Detect pages that returned 404 or other client errors.
     */
    _detectDeadLinks(inventory) {
        for (const page of inventory.pages) {
            if (page.status >= 400 && page.status < 500) {
                this.findings.push(
                    createFinding({
                        module: 'qa',
                        title: `Dead Link: ${page.status} at ${this._shortUrl(page.url)}`,
                        severity: page.status === 404 ? 'medium' : 'low',
                        affected_surface: page.url,
                        description: `The page returned HTTP ${page.status}. This indicates a broken link or missing resource that users may encounter during navigation.`,
                        reproduction: [
                            `1. Navigate to ${page.url}`,
                            `2. Observe HTTP ${page.status} response`,
                        ],
                        remediation: page.status === 404
                            ? 'Either fix the broken link pointing here or create the missing page/resource. Consider adding a custom 404 page with navigation back to working pages.'
                            : `Investigate why the page returns ${page.status} and fix the underlying issue.`,
                    })
                );
            }
        }
    }

    /**
     * Detect pages that returned 5xx server errors.
     */
    _detectServerErrors(inventory) {
        for (const page of inventory.pages) {
            if (typeof page.status === 'number' && page.status >= 500) {
                this.findings.push(
                    createFinding({
                        module: 'qa',
                        title: `Server Error: ${page.status} at ${this._shortUrl(page.url)}`,
                        severity: 'high',
                        affected_surface: page.url,
                        description: `The page returned HTTP ${page.status} (server error). This indicates a server-side issue that completely blocks the user experience.`,
                        reproduction: [
                            `1. Navigate to ${page.url}`,
                            `2. Observe HTTP ${page.status} server error`,
                        ],
                        remediation: 'Check server logs for the root cause. This is a server-side error that needs immediate attention.',
                    })
                );
            } else if (page.status === 'error') {
                this.findings.push(
                    createFinding({
                        module: 'qa',
                        title: `Page Load Failure: ${this._shortUrl(page.url)}`,
                        severity: 'high',
                        affected_surface: page.url,
                        description: `The page failed to load entirely: ${page.error || 'Unknown error'}. This may indicate a timeout, DNS failure, or crash.`,
                        reproduction: [
                            `1. Attempt to navigate to ${page.url}`,
                            `2. Observe page load failure`,
                        ],
                        remediation: 'Investigate the page load failure. Check for timeouts, infinite redirects, or server availability.',
                    })
                );
            }
        }
    }

    /**
     * Detect pages with slow load times.
     */
    _detectSlowPages(inventory) {
        const SLOW_THRESHOLD = 5000; // 5 seconds

        for (const page of inventory.pages) {
            if (page.loadTime > SLOW_THRESHOLD) {
                this.findings.push(
                    createFinding({
                        module: 'qa',
                        title: `Slow Page Load: ${(page.loadTime / 1000).toFixed(1)}s at ${this._shortUrl(page.url)}`,
                        severity: 'low',
                        affected_surface: page.url,
                        description: `This page took ${(page.loadTime / 1000).toFixed(1)} seconds to reach network idle. Pages loading over ${SLOW_THRESHOLD / 1000}s significantly hurt user experience and SEO.`,
                        reproduction: [
                            `1. Navigate to ${page.url}`,
                            `2. Measure the time to load (observed: ${page.loadTime}ms)`,
                        ],
                        remediation: 'Optimize page load performance. Consider lazy loading, code splitting, image optimization, and caching.',
                    })
                );
            }
        }
    }

    /**
     * Detect pages that had console errors during load.
     */
    _detectPagesWithErrors(inventory) {
        for (const page of inventory.pages) {
            const errorCount = (page.consoleErrors || []).length;
            const failedCount = (page.failedRequests || []).length;

            if (errorCount + failedCount > 5) {
                this.findings.push(
                    createFinding({
                        module: 'qa',
                        title: `High Error Rate: ${errorCount + failedCount} issues on ${this._shortUrl(page.url)}`,
                        severity: 'medium',
                        affected_surface: page.url,
                        description: `This page generated ${errorCount} console errors and ${failedCount} failed network requests during load. A high error rate indicates significant quality issues.`,
                        reproduction: [
                            `1. Navigate to ${page.url}`,
                            `2. Open DevTools console`,
                            `3. Observe ${errorCount} errors and ${failedCount} failed requests`,
                        ],
                        remediation: 'Systematically address console errors and failed requests. Prioritize JavaScript exceptions and critical API failures.',
                    })
                );
            }
        }
    }

    /**
     * Detect pages with missing or empty titles.
     */
    _detectMissingTitles(inventory) {
        for (const page of inventory.pages) {
            if (typeof page.status !== 'number' || page.status >= 400) continue;
            if (!page.title || page.title.trim() === '') {
                this.findings.push(
                    createFinding({
                        module: 'qa',
                        title: `Missing Page Title: ${this._shortUrl(page.url)}`,
                        severity: 'low',
                        affected_surface: page.url,
                        description: 'This page has no <title> tag or it is empty. Page titles are critical for SEO, accessibility, and user orientation.',
                        reproduction: [
                            `1. Navigate to ${page.url}`,
                            `2. Check the browser tab — no title is displayed`,
                        ],
                        remediation: 'Add a descriptive <title> tag to the page\'s <head>. Each page should have a unique, descriptive title.',
                    })
                );
            }
        }
    }

    /**
     * Detect forms that have no submit button.
     */
    _detectFormsWithoutSubmit(inventory) {
        for (const form of inventory.forms) {
            if (!form.hasSubmitButton) {
                this.findings.push(
                    createFinding({
                        module: 'qa',
                        title: `Form Without Submit Button: ${form.id} on ${this._shortUrl(form.page)}`,
                        severity: 'low',
                        affected_surface: form.page,
                        description: `The form "${form.id}" (action: ${form.action}) has no visible submit button (no <button type="submit"> or <input type="submit">). Users may not know how to submit the form.`,
                        reproduction: [
                            `1. Navigate to ${form.page}`,
                            `2. Locate form "${form.id}"`,
                            `3. Observe no submit button is present`,
                        ],
                        remediation: 'Add a visible submit button to the form. If submission is handled via JavaScript, ensure the interaction is clear to users.',
                    })
                );
            }
        }
    }

    _shortUrl(url) {
        try {
            const u = new URL(url);
            return u.pathname === '/' ? u.hostname : u.pathname;
        } catch {
            return url;
        }
    }
}

export default BrokenFlowDetector;
