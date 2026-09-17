/**
 * Parameter discovery helpers.
 *
 * Derives real, application-specific parameter names from a SurfaceInventory so
 * injection scanners can test what the app actually uses instead of relying on
 * a fixed guess-list. Sources:
 *   - form fields (per-page forms and the global forms list)
 *   - query-string params on discovered page URLs and links
 *   - query-string params on intercepted API endpoint URLs
 */

function _addUrlParams(url, set) {
    if (!url || typeof url !== 'string') return;
    try {
        const u = new URL(url);
        for (const key of u.searchParams.keys()) {
            if (key) set.add(key);
        }
    } catch {
        // not a parseable URL — ignore
    }
}

function _addFormFields(form, set) {
    for (const field of (form?.fields || [])) {
        const name = field?.name || field?.id;
        if (name) set.add(name);
    }
}

/**
 * Collect a de-duplicated list of candidate parameter names from an inventory.
 * @param {object} inventory - SurfaceInventory ({ pages, forms, apiEndpoints })
 * @returns {string[]} discovered parameter names
 */
export function collectParamNames(inventory) {
    const names = new Set();
    if (!inventory) return [];

    for (const page of (inventory.pages || [])) {
        _addUrlParams(page?.url || page, names);
        for (const link of (page?.links || [])) {
            _addUrlParams(link, names);
        }
        for (const form of (page?.forms || [])) {
            _addFormFields(form, names);
        }
    }

    for (const form of (inventory.forms || [])) {
        _addFormFields(form, names);
    }

    for (const api of (inventory.apiEndpoints || [])) {
        _addUrlParams(api?.url || api, names);
    }

    return [...names];
}

/**
 * Collect, per discovered page/link/api URL, the set of query params that
 * already appear on that exact URL. Useful for scanners that want to test the
 * parameters that a given endpoint genuinely accepts.
 * @returns {Map<string, string[]>} url → param names present on that url
 */
export function collectUrlParamMap(inventory) {
    const map = new Map();
    if (!inventory) return map;

    const record = (url) => {
        if (!url || typeof url !== 'string') return;
        try {
            const u = new URL(url);
            const keys = [...u.searchParams.keys()].filter(Boolean);
            if (keys.length > 0) map.set(url, keys);
        } catch {
            /* ignore */
        }
    };

    for (const page of (inventory.pages || [])) {
        record(page?.url || page);
        for (const link of (page?.links || [])) record(link);
    }
    for (const api of (inventory.apiEndpoints || [])) {
        record(api?.url || api);
    }

    return map;
}

export default { collectParamNames, collectUrlParamMap };
