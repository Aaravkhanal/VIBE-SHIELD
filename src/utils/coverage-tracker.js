import { collectParamNames } from './param-discovery.js';

function endpointKey(url, method = 'GET') {
    try { const parsed = new URL(url); return `${method.toUpperCase()} ${parsed.origin}${parsed.pathname}`; }
    catch { return null; }
}

function parameterKey(url, name) {
    if (!name) return null;
    try { const parsed = new URL(url); return `${parsed.origin}${parsed.pathname}::${name}`; }
    catch { return null; }
}

function ratio(tested, discovered) { return discovered ? Math.min(1, tested / discovered) : null; }

export async function trackedFetch(tracker, url, options = {}) {
    const response = await fetch(url, options);
    tracker?.apiTested(String(url), options.method || 'GET', response.status);
    const body = tracker && [403, 429, 503].includes(response.status)
        ? await response.clone().text().catch(() => '') : '';
    tracker?.response(String(url), response.status, Object.fromEntries(response.headers.entries()), body);
    return response;
}

export class CoverageTracker {
    constructor(targetUrl) {
        this.targetOrigin = new URL(targetUrl).origin;
        this.pagesDiscovered = new Set();
        this.pagesScanned = new Set();
        this.apisDiscovered = new Set();
        this.apisTested = new Set();
        this.formsDiscovered = new Set();
        this.formsSubmitted = new Set();
        this.parametersDiscovered = new Set();
        this.parametersEligible = new Set();
        this.parametersMutated = new Set();
        this.aiConfirmed = new Set();
        this.aiSuspected = new Set();
        this.blocked = new Map();
    }

    _sameOrigin(url) { try { return new URL(url).origin === this.targetOrigin; } catch { return false; } }
    _page(url) {
        try {
            const u = new URL(url); u.hash = '';
            const normalized = u.toString();
            return normalized.endsWith('/') && u.pathname !== '/' ? normalized.slice(0, -1) : normalized;
        } catch { return null; }
    }
    pageDiscovered(url) { if (this._sameOrigin(url)) this.pagesDiscovered.add(this._page(url)); }
    pageScanned(url, status) {
        this.pageDiscovered(url);
        if (this._sameOrigin(url) && Number.isInteger(status) && status >= 200 && status < 400) this.pagesScanned.add(this._page(url));
        this.response(url, status);
    }
    apiDiscovered(url, method) { if (this._sameOrigin(url)) this.apisDiscovered.add(endpointKey(url, method)); }
    apiTested(url, method, status) {
        if (this._sameOrigin(url) && status != null) this.apisTested.add(endpointKey(url, method));
        this.response(url, status);
    }
    formDiscovered(form) {
        const key = this._formKey(form);
        if (key) this.formsDiscovered.add(key);
    }
    formSubmitted(form) { const key = this._formKey(form); if (key) this.formsSubmitted.add(key); }
    _formKey(form) {
        const url = form?.page || form?.pageUrl || form?.action;
        if (!this._sameOrigin(url)) return null;
        return `${form?.method || 'GET'} ${this._page(url)}::${form?.id || form?.action || ''}`;
    }
    parameterDiscovered(url, name, eligible = true) {
        const key = parameterKey(url, name);
        if (key && this._sameOrigin(url)) {
            this.parametersDiscovered.add(key);
            if (eligible) this.parametersEligible.add(key);
        }
    }
    parameterMutated(url, name) { const key = parameterKey(url, name); if (key && this._sameOrigin(url)) this.parametersMutated.add(key); }
    mutation(baseline, payload) {
        if (!baseline?.url || !payload?.url || !this._sameOrigin(payload.url)) return;
        try {
            const left = new URL(baseline.url), right = new URL(payload.url);
            if (left.origin + left.pathname === right.origin + right.pathname) {
                for (const [name, value] of right.searchParams) if (left.searchParams.get(name) !== value) this.parameterMutated(right.toString(), name);
            }
            const oldBody = JSON.parse(baseline.body || '{}'), newBody = JSON.parse(payload.body || '{}');
            for (const [name, value] of Object.entries(newBody)) if (JSON.stringify(oldBody[name]) !== JSON.stringify(value)) this.parameterMutated(right.toString(), name);
        } catch { /* A browser or non-JSON probe may record its field directly. */ }
    }
    aiSurface(surface) {
        if (!this._sameOrigin(surface?.url)) return;
        (surface.confidence === 'confirmed' ? this.aiConfirmed : this.aiSuspected).add(endpointKey(surface.url, surface.method));
    }
    blockedTest(reason, url, detail = '') {
        if (!this._sameOrigin(url)) return;
        const key = `${reason}::${url}`;
        this.blocked.set(key, { reason, url, detail: String(detail).slice(0, 200) });
    }
    response(url, status, headers = {}, body = '') {
        if (!this._sameOrigin(url)) return;
        if (status === 429) this.blockedTest('rate_limit', url, 'HTTP 429');
        if (status === 401) this.blockedTest('missing_credentials', url, 'HTTP 401');
        const headerText = JSON.stringify(headers).toLowerCase();
        const sample = String(body).slice(0, 1000).toLowerCase();
        if ((status === 403 || status === 503) && /cf-mitigated|x-sucuri|x-akamai|x-waf|access denied|web application firewall/i.test(headerText + sample)) this.blockedTest('waf', url, `HTTP ${status}`);
        if (/captcha|hcaptcha|recaptcha|turnstile/i.test(sample) && [401, 403, 429, 503].includes(status)) this.blockedTest('captcha', url, `HTTP ${status}`);
    }
    seedInventory(inventory = {}) {
        inventory ||= {};
        const firstPage = inventory.pages?.find(page => page?.url);
        if (firstPage) {
            try { this.targetOrigin = new URL(firstPage.url).origin; } catch { /* keep configured origin */ }
        }
        for (const page of inventory.pages || []) {
            this.pageDiscovered(page.url);
            this.pageScanned(page.url, page.status);
            this.response(page.url, page.status, page.headers, page.bodySnippet);
            for (const link of page.links || []) this.pageDiscovered(link);
            try { for (const [name] of new URL(page.url).searchParams) this.parameterDiscovered(page.url, name); } catch { /* invalid URL */ }
        }
        for (const api of inventory.apiEndpoints || []) {
            this.apiDiscovered(api.url, api.method);
            try { for (const [name] of new URL(api.url).searchParams) this.parameterDiscovered(api.url, name); } catch { /* invalid URL */ }
        }
        for (const form of inventory.forms || []) {
            this.formDiscovered(form);
            for (const field of form.fields || []) this.parameterDiscovered(form.action || form.page, field.name, !['hidden', 'submit', 'button', 'file'].includes(field.type));
        }
        // Keep the discovery helper in sync with crawler changes. Endpoint keys
        // above are the measurable denominator; this list is diagnostic only.
        this.discoveredParameterNames = collectParamNames(inventory);
    }
    manifest(agents = {}, inventory = {}) {
        inventory ||= {};
        const modules = Object.fromEntries(Object.entries(agents).map(([name, agent]) => [name, {
            status: agent.status === 'done' && agent.assessment === 'not_assessed' ? 'unsupported'
                : agent.status === 'partial' || agent.status === 'error' ? 'failed'
                    : agent.status === 'done' && agent.skippedChecks?.length ? 'partial'
                    : agent.status === 'done' ? 'completed' : agent.status,
            assessment: agent.assessment || null,
            errors: agent.errors || [],
            skippedChecks: agent.skippedChecks || [],
        }]));
        const eligible = Object.values(modules);
        const counted = (set, discovered) => [...set].filter(key => discovered.has(key)).length;
        const metrics = {
            pages: { discovered: this.pagesDiscovered.size, scanned: counted(this.pagesScanned, this.pagesDiscovered) },
            apiEndpoints: { discovered: this.apisDiscovered.size, tested: counted(this.apisTested, this.apisDiscovered) },
            forms: { discovered: this.formsDiscovered.size, submitted: counted(this.formsSubmitted, this.formsDiscovered) },
            parameters: { discovered: this.parametersDiscovered.size, eligible: this.parametersEligible.size, mutated: counted(this.parametersMutated, this.parametersEligible) },
            authenticatedRoutesReached: (inventory.pages || []).filter(page => page.authenticatedRolesReached?.length > 0).length,
            userRolesTested: [...new Set((inventory.roles || []).filter(Boolean))],
            modules,
            moduleCounts: Object.fromEntries(['completed', 'partial', 'skipped', 'failed', 'unsupported'].map(status => [status, eligible.filter(module => module.status === status).length])),
            blockedTests: [...this.blocked.values()],
            aiEndpoints: { confirmed: this.aiConfirmed.size, suspected: this.aiSuspected.size },
        };
        const components = [
            [metrics.pages, 'scanned', 30], [metrics.apiEndpoints, 'tested', 20],
            [metrics.forms, 'submitted', 15], [metrics.parameters, 'mutated', 15],
        ].filter(([item]) => (item.eligible ?? item.discovered) > 0);
        if (eligible.length) components.push([{ discovered: eligible.length, completed: metrics.moduleCounts.completed }, 'completed', 20]);
        const weight = components.reduce((sum, [, , value]) => sum + value, 0);
        const percent = weight ? Math.round(100 * components.reduce((sum, [item, key, value]) => sum + value * ratio(item[key], item.eligible ?? item.discovered), 0) / weight) : null;
        return { ...metrics, percent, measured: percent !== null, denominator: 'Discovered in-scope surfaces and selected modules; parameter coverage excludes non-testable hidden, submit, button, and file fields. Exercised means a recorded request, browser submit event, or controlled mutation.' };
    }
}
