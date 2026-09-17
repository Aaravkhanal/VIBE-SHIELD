import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

/**
 * Centralized version resolver.
 *
 * Reads the version from package.json once and caches it, so the version
 * string is never duplicated/hardcoded across the codebase. Use getVersion()
 * everywhere a version is needed (CLI banner, reports, SARIF, webhooks, etc.).
 */
let _cachedVersion = null;

export function getVersion() {
    if (_cachedVersion) return _cachedVersion;

    try {
        const __dirname = path.dirname(fileURLToPath(import.meta.url));
        // src/utils/version.js → ../../package.json
        const pkgPath = path.join(__dirname, '..', '..', 'package.json');
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        _cachedVersion = pkg.version || '0.0.0';
    } catch {
        _cachedVersion = '0.0.0';
    }

    return _cachedVersion;
}

export default getVersion;
