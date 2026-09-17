import fs from 'fs';
import path from 'path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { chromium } from 'playwright';

const require = createRequire(import.meta.url);

/**
 * Returns the path to the Chromium build Playwright expects, or null if it
 * cannot be resolved.
 */
function resolveChromiumPath() {
    try {
        const p = chromium.executablePath();
        return p || null;
    } catch {
        return null;
    }
}

/** True if the Chromium build is actually present on disk. */
export function isChromiumInstalled() {
    const p = resolveChromiumPath();
    return Boolean(p && fs.existsSync(p));
}

/**
 * Resolve the Playwright CLI that ships with our own dependency. Running it via
 * `node <cli> install chromium` (instead of `npx playwright ...`) guarantees we
 * use the installed Playwright version and never trigger npx to fetch a
 * separate copy — which matters most when VIBE SHIELD is installed globally.
 */
function resolvePlaywrightCli() {
    for (const spec of ['playwright', 'playwright-core']) {
        try {
            const pkgPath = require.resolve(`${spec}/package.json`);
            const bin = JSON.parse(fs.readFileSync(pkgPath, 'utf8')).bin;
            const rel = typeof bin === 'string' ? bin : bin && Object.values(bin)[0];
            if (!rel) continue;
            const cli = path.join(path.dirname(pkgPath), rel);
            if (fs.existsSync(cli)) return cli;
        } catch {
            // try the next candidate
        }
    }
    return null;
}

function runChromiumInstall() {
    const cli = resolvePlaywrightCli();
    if (cli) {
        return spawnSync(process.execPath, [cli, 'install', 'chromium'], { stdio: 'inherit' });
    }
    // Last resort if resolution fails for some reason.
    return spawnSync('npx', ['playwright', 'install', 'chromium'], {
        stdio: 'inherit',
        shell: process.platform === 'win32',
    });
}

/**
 * Ensure Chromium is available before a scan. If it is missing (or a previous
 * download was interrupted/left partial), install it once — with clear
 * messaging so the silent extraction step doesn't look like a hang — then
 * re-check.
 *
 * Throws a friendly Error if Chromium is required but unavailable so the CLI
 * can print actionable guidance instead of a raw Playwright stack trace.
 */
export function ensureChromium(logger) {
    if (isChromiumInstalled()) return true;

    const skip =
        process.env.VIBE_SHIELD_SKIP_BROWSER_DOWNLOAD ||
        process.env.PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD;
    if (skip) {
        throw new Error(
            'Chromium is not installed and a skip flag is set. Run: npx playwright install chromium'
        );
    }

    logger?.info?.('Chromium not found — installing Playwright Chromium (one-time).');
    console.log('  Chromium not found — setting it up now (one-time).');
    console.log('  Downloading + extracting (~170 MB). The extraction step shows no progress');
    console.log('  bar and can take a minute — please wait, do not interrupt...');

    runChromiumInstall();

    if (!isChromiumInstalled()) {
        throw new Error(
            'Chromium is required but could not be installed automatically. Run: npx playwright install chromium'
        );
    }

    console.log('  \u2714 Chromium ready.\n');
    return true;
}
