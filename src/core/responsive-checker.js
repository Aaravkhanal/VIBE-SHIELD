import { chromium } from 'playwright';
import { createFinding } from '../utils/finding.js';
import fs from 'fs';
import path from 'path';

/**
 * Responsive Checker — Tests pages across viewport breakpoints.
 * Detects horizontal overflow, overlapping elements, and captures screenshots.
 */
export class ResponsiveChecker {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.findings = [];
        this.screenshotDir = path.join(config.output_dir || 'vibe-shield-reports', 'screenshots', 'responsive');
        this.viewports = config.viewports || {
            mobile: { width: 375, height: 812 },
            tablet: { width: 768, height: 1024 },
            desktop: { width: 1440, height: 900 },
        };
    }

    /**
     * Check responsiveness of all crawled pages.
     */
    async check(surfaceInventory) {
        if (!fs.existsSync(this.screenshotDir)) {
            fs.mkdirSync(this.screenshotDir, { recursive: true });
        }

        // Only test a subset of pages for responsiveness (top-level pages, not API endpoints)
        const pagesToTest = surfaceInventory.pages
            .filter(p => typeof p.status === 'number' && p.status < 400)
            .slice(0, 20); // Cap at 20 pages

        if (pagesToTest.length === 0) {
            this.logger?.info?.('No valid pages to check responsiveness');
            return [];
        }

        const browser = await chromium.launch({ headless: true });

        for (const page of pagesToTest) {
            await this._checkPage(browser, page);
        }

        await browser.close();
        this.logger?.info?.(`Responsive checker found ${this.findings.length} issues`);
        return this.findings;
    }

    async _checkPage(browser, pageData) {
        for (const [viewportName, viewport] of Object.entries(this.viewports)) {
            const context = await browser.newContext({
                viewport,
                ignoreHTTPSErrors: true,
            });
            const page = await context.newPage();

            try {
                await page.goto(pageData.url, { waitUntil: 'networkidle', timeout: 15000 });

                // Capture screenshot
                const screenshotName = `${this._sanitizeFilename(pageData.url)}-${viewportName}.png`;
                const screenshotPath = path.join(this.screenshotDir, screenshotName);
                await page.screenshot({ path: screenshotPath, fullPage: true });

                // Check for horizontal overflow
                const overflowData = await page.evaluate(() => {
                    const docWidth = document.documentElement.scrollWidth;
                    const viewWidth = window.innerWidth;
                    const isOverflowing = docWidth > viewWidth;

                    // Find elements causing overflow
                    const overflowingElements = [];
                    if (isOverflowing) {
                        const allElements = document.querySelectorAll('*');
                        for (const el of allElements) {
                            const rect = el.getBoundingClientRect();
                            if (rect.right > viewWidth + 5) {
                                overflowingElements.push({
                                    tag: el.tagName,
                                    id: el.id,
                                    class: el.className?.toString?.()?.substring(0, 50) || '',
                                    width: Math.round(rect.width),
                                    right: Math.round(rect.right),
                                });
                                if (overflowingElements.length >= 5) break;
                            }
                        }
                    }

                    return {
                        docWidth,
                        viewWidth,
                        isOverflowing,
                        overflowingElements,
                    };
                });

                if (overflowData.isOverflowing) {
                    this.findings.push(
                        createFinding({
                            module: 'qa',
                            title: `Horizontal Overflow at ${viewportName}: ${this._shortUrl(pageData.url)}`,
                            severity: 'medium',
                            affected_surface: pageData.url,
                            description: `Page content (${overflowData.docWidth}px) exceeds ${viewportName} viewport width (${overflowData.viewWidth}px). This causes a horizontal scrollbar and breaks the responsive layout.\n\nOverflowing elements:\n${overflowData.overflowingElements.map(e => `- <${e.tag}> (${e.id || e.class || 'no id/class'}): ${e.width}px wide, extends to ${e.right}px`).join('\n')}`,
                            reproduction: [
                                `1. Open ${pageData.url}`,
                                `2. Set viewport to ${viewport.width}×${viewport.height} (${viewportName})`,
                                `3. Observe horizontal scrollbar`,
                            ],
                            evidence: JSON.stringify(overflowData, null, 2),
                            remediation: `Fix the overflow by adding max-width: 100%, overflow-x: hidden, or using responsive CSS. Check the identified elements for fixed widths.`,
                        })
                    );
                }

                // Check for overlapping interactive elements
                const overlapData = await page.evaluate(() => {
                    const interactive = Array.from(
                        document.querySelectorAll('a, button, input, select, textarea, [role="button"]')
                    );
                    const overlaps = [];

                    for (let i = 0; i < interactive.length - 1; i++) {
                        for (let j = i + 1; j < interactive.length; j++) {
                            const r1 = interactive[i].getBoundingClientRect();
                            const r2 = interactive[j].getBoundingClientRect();

                            // Skip invisible elements
                            if (r1.width === 0 || r1.height === 0 || r2.width === 0 || r2.height === 0) continue;

                            const overlap = !(r1.right < r2.left || r1.left > r2.right ||
                                r1.bottom < r2.top || r1.top > r2.bottom);

                            if (overlap) {
                                overlaps.push({
                                    el1: { tag: interactive[i].tagName, text: interactive[i].textContent?.substring(0, 30) },
                                    el2: { tag: interactive[j].tagName, text: interactive[j].textContent?.substring(0, 30) },
                                });
                                if (overlaps.length >= 3) break;
                            }
                        }
                        if (overlaps.length >= 3) break;
                    }

                    return overlaps;
                });

                if (overlapData.length > 0) {
                    this.findings.push(
                        createFinding({
                            module: 'qa',
                            title: `Overlapping Elements at ${viewportName}: ${this._shortUrl(pageData.url)}`,
                            severity: 'low',
                            affected_surface: pageData.url,
                            description: `${overlapData.length} pair(s) of interactive elements overlap at ${viewportName} (${viewport.width}×${viewport.height}). This makes them difficult or impossible to click.\n\n${overlapData.map(o => `- <${o.el1.tag}> "${o.el1.text}" overlaps with <${o.el2.tag}> "${o.el2.text}"`).join('\n')}`,
                            reproduction: [
                                `1. Open ${pageData.url}`,
                                `2. Set viewport to ${viewport.width}×${viewport.height} (${viewportName})`,
                                `3. Observe overlapping interactive elements`,
                            ],
                            evidence: JSON.stringify(overlapData, null, 2),
                            remediation: 'Use responsive CSS, media queries, or flexbox/grid to ensure interactive elements do not overlap at smaller viewports.',
                        })
                    );
                }

                // Check for tiny text (< 12px)
                const tinyText = await page.evaluate(() => {
                    const allText = document.querySelectorAll('p, span, a, li, td, th, label, div');
                    let tinyCount = 0;
                    for (const el of allText) {
                        const fontSize = parseFloat(window.getComputedStyle(el).fontSize);
                        if (fontSize < 12 && el.textContent?.trim()) {
                            tinyCount++;
                        }
                    }
                    return tinyCount;
                });

                if (viewportName === 'mobile' && tinyText > 10) {
                    this.findings.push(
                        createFinding({
                            module: 'qa',
                            title: `Tiny Text on Mobile: ${this._shortUrl(pageData.url)}`,
                            severity: 'low',
                            affected_surface: pageData.url,
                            description: `Found ${tinyText} text elements with font-size below 12px on mobile viewport. This makes content difficult to read without zooming.`,
                            reproduction: [
                                `1. Open ${pageData.url} on mobile (375×812)`,
                                `2. Observe small, hard-to-read text`,
                            ],
                            remediation: 'Use a minimum font-size of 14px on mobile viewports. Add media queries to scale text appropriately.',
                        })
                    );
                }
            } catch (err) {
                this.logger?.debug?.(`Responsive check failed for ${pageData.url} at ${viewportName}: ${err.message}`);
            } finally {
                await page.close();
                await context.close();
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

    _sanitizeFilename(url) {
        try {
            const u = new URL(url);
            return (u.hostname + u.pathname).replace(/[^a-zA-Z0-9]/g, '_').substring(0, 50);
        } catch {
            return 'page';
        }
    }
}

export default ResponsiveChecker;
