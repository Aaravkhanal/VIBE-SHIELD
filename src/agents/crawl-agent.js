import { BaseAgent } from './base-agent.js';
import { Crawler } from '../core/crawler.js';

/**
 * VIBE-SHIELD-CRAWL — Discovery Agent
 * 
 * The first agent to run. Crawls the target URL to build a complete
 * surface inventory (pages, forms, API endpoints, console errors).
 * 
 * Authentication is handled by the CLI before agents start.
 * The pre-authenticated AuthManager is available via config._authManager.
 * 
 * Crawl flow:
 *   1. Crawl unauthenticated surfaces first
 *   2. Re-crawl with each authenticated role to discover auth-gated pages
 *   3. Merge all surfaces into a unified inventory
 * 
 * Dependencies: none
 */
export class CrawlAgent extends BaseAgent {
    get name() { return 'VIBE-SHIELD-CRAWL'; }
    get dependencies() { return []; }

    async _execute(context) {
        const { config, logger } = context;

        // Auth manager is pre-initialized by the CLI
        const authManager = config._authManager || null;
        context.authManager = authManager;
        if (authManager?.loginFormInfo && !authManager.isAuthenticated) {
            context.coverageTracker?.blockedTest('missing_credentials', authManager.loginFormInfo.url || config.target_url, 'Login form detected but no authenticated session was available');
        }

        // ═══ Phase 1: Unauthenticated Crawl ═══
        this.progress('crawl', 'Starting unauthenticated crawl...', 10);

        const unauthCrawler = new Crawler(config, logger, context.coverageTracker);
        const unauthInventory = await unauthCrawler.crawl(config.target_url);

        // ═══ Phase 2: Authenticated Crawls (one per role) ═══
        const authInventories = new Map();

        if (authManager?.isAuthenticated) {
            const roles = authManager.roles;
            for (let i = 0; i < roles.length; i++) {
                const role = roles[i];
                const pct = 20 + Math.floor((i / roles.length) * 60);
                this.progress('crawl', `Crawling as "${role}"...`, pct);

                try {
                    const authState = authManager.getAuthState(role);
                    const postLoginUrl = authManager.getPostLoginUrl(role);
                    const seedLinks = authManager.getDiscoveredLinks(role);

                    // Start from the post-login URL if available (e.g., /dashboard),
                    // otherwise fall back to the target URL
                    const startUrl = postLoginUrl || config.target_url;

                    const authCrawler = new Crawler(config, logger, context.coverageTracker);
                    const authInv = await authCrawler.crawl(startUrl, authState, seedLinks);

                    authInventories.set(role, authInv);
                    logger?.info?.(`[VIBE-SHIELD-CRAWL] Authenticated crawl as "${role}": ${authInv.totalPages} pages, ${authInv.totalApis} APIs (started from ${startUrl})`);
                } catch (err) {
                    logger?.warn?.(`[VIBE-SHIELD-CRAWL] Authenticated crawl failed for "${role}": ${err.message}`);
                }
            }
        }

        // ═══ Phase 3: Merge Inventories ═══
        const mergedInventory = this._mergeInventories(unauthInventory, authInventories);
        context.coverageTracker?.seedInventory(mergedInventory);

        // Store inventory in shared context for downstream agents
        context.surfaceInventory = mergedInventory;
        if (!mergedInventory.pages.some(p => typeof p.status === 'number' && p.status >= 200 && p.status < 400)) {
            throw new Error('No accessible pages were crawled. Check the URL, authentication, network access, and target availability.');
        }

        // Broadcast discovery to all listening agents
        context.eventBus.emit('surface:discovered', {
            inventory: mergedInventory,
            agentName: this.name,
        });

        this.progress('crawl', `Discovery complete: ${mergedInventory.totalPages} pages, ${mergedInventory.totalApis} APIs, ${mergedInventory.totalForms} forms`, 100);

        this._log(`Surface inventory: ${mergedInventory.totalPages} pages, ${mergedInventory.totalApis} APIs, ${mergedInventory.totalForms} forms`);

        if (authManager?.isAuthenticated) {
            this._log(`Authenticated roles: ${authManager.roles.join(', ')}`);

            // Count auth-only surfaces
            const unauthUrls = new Set(unauthInventory.pages.map(p => p.url));
            const authOnlyPages = mergedInventory.pages.filter(p => !unauthUrls.has(p.url));
            if (authOnlyPages.length > 0) {
                this._log(`Auth-only pages discovered: ${authOnlyPages.length}`);
            }
        }
    }

    /**
     * Merge unauthenticated and authenticated inventories into one.
     * Deduplicates pages by URL, keeping the most informative version.
     */
    _mergeInventories(unauthInv, authInventories) {
        const pageMap = new Map();
        const apiMap = new Map();
        const formMap = new Map();

        const addPages = (pages, role = null) => {
            for (const page of pages) {
                const key = page.url;
                const reachedAsRole = role && Number.isInteger(page.status) && page.status >= 200 && page.status < 400;
                if (!pageMap.has(key)) {
                    pageMap.set(key, { ...page, roles: role ? [role] : ['anonymous'], authenticatedRolesReached: reachedAsRole ? [role] : [] });
                } else {
                    const existing = pageMap.get(key);
                    if (reachedAsRole && !(Number.isInteger(existing.status) && existing.status >= 200 && existing.status < 400)) {
                        const priorStatus = existing.status;
                        Object.assign(existing, page, { unauthenticatedStatus: priorStatus });
                    }
                    if (role && !existing.roles.includes(role)) {
                        existing.roles.push(role);
                    }
                    if (reachedAsRole && !existing.authenticatedRolesReached.includes(role)) existing.authenticatedRolesReached.push(role);
                }
            }
        };

        const addApis = (apis, role = null) => {
            for (const api of apis) {
                const key = `${api.method}::${api.url}`;
                if (!apiMap.has(key)) {
                    apiMap.set(key, { ...api, roles: role ? [role] : ['anonymous'] });
                } else {
                    const existing = apiMap.get(key);
                    if (role && !existing.roles.includes(role)) {
                        existing.roles.push(role);
                    }
                }
            }
        };

        const addForms = (forms, role = null) => {
            for (const form of forms) {
                const key = `${form.method}::${form.action}`;
                if (!formMap.has(key)) {
                    formMap.set(key, { ...form, roles: role ? [role] : ['anonymous'] });
                } else {
                    const existing = formMap.get(key);
                    if (role && !existing.roles.includes(role)) {
                        existing.roles.push(role);
                    }
                }
            }
        };

        addPages(unauthInv.pages);
        addApis(unauthInv.apiEndpoints || []);
        addForms(unauthInv.forms || []);

        for (const [role, inv] of authInventories) {
            addPages(inv.pages, role);
            addApis(inv.apiEndpoints || [], role);
            addForms(inv.forms || [], role);
        }

        const pages = [...pageMap.values()];
        const apiEndpoints = [...apiMap.values()];
        const forms = [...formMap.values()];

        return {
            baseUrl: unauthInv.baseUrl,
            pages,
            apiEndpoints,
            forms,
            totalPages: pages.length,
            totalApis: apiEndpoints.length,
            totalForms: forms.length,
            crawledAt: new Date().toISOString(),
            authenticated: authInventories.size > 0,
            roles: ['anonymous', ...authInventories.keys()],
        };
    }
}

export default CrawlAgent;
