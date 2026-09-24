import fs from 'fs';
import path from 'path';

/**
 * Safety mode tiers control how aggressive VIBE SHIELD is allowed to be.
 *
 *   passive     — recon/observation + static analysis only. No probing requests
 *                 that send attack payloads, no state-changing requests.
 *   safe-active — (default) active but non-destructive probing (XSS/SQLi probes,
 *                 enumeration checks, etc.). Never issues state-changing/mutating
 *                 requests. Destructive logic tests are skipped.
 *   aggressive  — everything, including destructive/state-changing tests
 *                 (race conditions, pricing/checkout mutation, etc.).
 */
export const SAFETY_MODES = ['passive', 'safe-active', 'aggressive'];
export const DEFAULT_SAFETY_MODE = 'safe-active';

const DEFAULTS = {
    target_url: null,
    project_root: null,
    credentials: [],
    modules_enabled: ['qa'],
    severity_threshold: 'low',
    halt_on_critical: false,
    notify_webhook: null,
    safety_mode: DEFAULT_SAFETY_MODE,
    // LLM augmentation is OFF by default and strictly additive. The API key is
    // NEVER stored here — it is read from the environment at runtime only.
    llm: {
        enabled: false,
        provider: 'openai',          // openai | anthropic
        model: null,                 // null → provider default (cheap model)
        max_tokens: 1024,            // per-call output cap
        max_calls: 50,               // per-scan call budget
        token_budget: 100000,        // per-scan total token budget
        timeout_seconds: 30,
        consent: false,              // must be true before any data egress
        base_url: null,              // optional override (self-hosted/proxy)
    },
    crawler: {
        max_depth: 5,
        max_pages: 50,
        timeout: 30000,
        concurrency: 4,
    },
    subdomains: {
        external_enumeration: false,
        organization_domains: [],
        max_candidates: 100,
    },
    viewports: {
        mobile: { width: 375, height: 812 },
        tablet: { width: 768, height: 1024 },
        desktop: { width: 1440, height: 900 },
    },
};

/**
 * Scan Profile Presets
 *
 *   quick — Fast recon: fewer pages, shallow depth, best for development feedback loops
 *   deep  — Thorough: more pages, deep crawling, lower concurrency to avoid rate limits
 *   ci    — CI/CD optimized: moderate scope, fail-fast on critical findings
 */
const SCAN_PROFILES = {
    quick: {
        crawler: { max_pages: 10, max_depth: 2, concurrency: 4, timeout: 15000 },
        modules_enabled: ['qa', 'security'],
    },
    deep: {
        crawler: { max_pages: 200, max_depth: 10, concurrency: 2, timeout: 60000 },
        modules_enabled: ['qa', 'security', 'ai', 'logic', 'api'],
    },
    ci: {
        crawler: { max_pages: 30, max_depth: 3, concurrency: 4, timeout: 20000 },
        modules_enabled: ['qa', 'security', 'ai', 'logic', 'api'],
        halt_on_critical: true,
    },
};

// ── Lightweight config schema (for validation) ──────────────
const KNOWN_TOP_LEVEL_KEYS = new Set([
    'target_url', 'project_root', 'credentials', 'modules_enabled', 'severity_threshold',
    'halt_on_critical', 'prod_safe', 'notify_webhook', 'safety_mode',
    'crawler', 'viewports', 'auth', 'business_context', 'output_dir', 'subdomains',
    'llm', '_profile', '_authManager',
]);
const KNOWN_CRAWLER_KEYS = new Set(['max_depth', 'max_pages', 'timeout', 'concurrency']);
const KNOWN_SUBDOMAIN_KEYS = new Set(['external_enumeration', 'organization_domains', 'max_candidates']);
const KNOWN_LLM_KEYS = new Set([
    'enabled', 'provider', 'model', 'max_tokens', 'max_calls',
    'token_budget', 'timeout_seconds', 'consent', 'base_url',
]);
// Secret-bearing keys must NEVER live in the config file.
const LLM_SECRET_KEYS = new Set(['api_key', 'apiKey', 'key', 'openai_api_key', 'anthropic_api_key', 'token']);
const VALID_LLM_PROVIDERS = new Set(['openai', 'anthropic']);
const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

// Keys that have been removed/deprecated. Mapped to a short reason so we can
// warn and drop them cleanly rather than silently honoring drifted config.
const DEPRECATED_KEYS = {
    respect_robots: 'VIBE SHIELD is a security scanner and intentionally does not honor robots.txt',
    respect_robots_txt: 'VIBE SHIELD is a security scanner and intentionally does not honor robots.txt',
};

/**
 * Validate a parsed vibe-shield.config.json. Warns (does not throw) on unknown keys,
 * bad types, and deprecated keys, and returns a cleaned copy.
 */
export function validateConfig(fileConfig) {
    const warnings = [];
    const cfg = { ...fileConfig };

    // Alias drift: README historically documented `modules`; canonical is `modules_enabled`.
    if (cfg.modules !== undefined && cfg.modules_enabled === undefined) {
        cfg.modules_enabled = cfg.modules;
        warnings.push('Config key "modules" is deprecated — use "modules_enabled". Aliased for now.');
    }
    delete cfg.modules;

    // Top-level deprecated keys (e.g. respect_robots).
    for (const key of Object.keys(DEPRECATED_KEYS)) {
        if (cfg[key] !== undefined) {
            warnings.push(`Config key "${key}" is no longer supported (${DEPRECATED_KEYS[key]}). Ignoring it.`);
            delete cfg[key];
        }
    }

    // Unknown top-level keys.
    for (const key of Object.keys(cfg)) {
        if (!KNOWN_TOP_LEVEL_KEYS.has(key) && key !== 'modules') {
            warnings.push(`Unknown config key "${key}" — ignoring.`);
        }
    }

    // Type checks (light).
    if (cfg.severity_threshold !== undefined && !VALID_SEVERITIES.has(cfg.severity_threshold)) {
        warnings.push(`Invalid severity_threshold "${cfg.severity_threshold}" — expected one of ${[...VALID_SEVERITIES].join(', ')}.`);
    }
    if (cfg.safety_mode !== undefined && !SAFETY_MODES.includes(cfg.safety_mode)) {
        warnings.push(`Invalid safety_mode "${cfg.safety_mode}" — expected one of ${SAFETY_MODES.join(', ')}. Falling back to "${DEFAULT_SAFETY_MODE}".`);
        delete cfg.safety_mode;
    }
    if (cfg.halt_on_critical !== undefined && typeof cfg.halt_on_critical !== 'boolean') {
        warnings.push('Config key "halt_on_critical" should be a boolean.');
    }
    if (cfg.modules_enabled !== undefined && !Array.isArray(cfg.modules_enabled)) {
        warnings.push('Config key "modules_enabled" should be an array of module names.');
    }

    // Crawler sub-keys.
    if (cfg.crawler !== undefined) {
        if (typeof cfg.crawler !== 'object' || cfg.crawler === null) {
            warnings.push('Config key "crawler" should be an object.');
        } else {
            for (const key of Object.keys(cfg.crawler)) {
                if (key in DEPRECATED_KEYS) {
                    warnings.push(`Config key "crawler.${key}" is no longer supported (${DEPRECATED_KEYS[key]}). Ignoring it.`);
                    delete cfg.crawler[key];
                } else if (!KNOWN_CRAWLER_KEYS.has(key)) {
                    warnings.push(`Unknown crawler config key "crawler.${key}" — ignoring.`);
                }
            }
        }
    }

    if (cfg.subdomains !== undefined) {
        if (typeof cfg.subdomains !== 'object' || cfg.subdomains === null || Array.isArray(cfg.subdomains)) {
            warnings.push('Config key "subdomains" should be an object.');
            delete cfg.subdomains;
        } else {
            cfg.subdomains = { ...cfg.subdomains };
            for (const key of Object.keys(cfg.subdomains)) {
                if (!KNOWN_SUBDOMAIN_KEYS.has(key)) {
                    warnings.push(`Unknown subdomains config key "subdomains.${key}" — ignoring.`);
                    delete cfg.subdomains[key];
                }
            }
            if (cfg.subdomains.external_enumeration !== undefined && typeof cfg.subdomains.external_enumeration !== 'boolean') {
                warnings.push('Config key "subdomains.external_enumeration" should be a boolean.');
                delete cfg.subdomains.external_enumeration;
            }
            if (cfg.subdomains.organization_domains !== undefined && !Array.isArray(cfg.subdomains.organization_domains)) {
                warnings.push('Config key "subdomains.organization_domains" should be an array of authorized domains or DNS zones.');
                delete cfg.subdomains.organization_domains;
            }
            if (cfg.subdomains.max_candidates !== undefined && (!Number.isInteger(cfg.subdomains.max_candidates) || cfg.subdomains.max_candidates < 1 || cfg.subdomains.max_candidates > 500)) {
                warnings.push('Config key "subdomains.max_candidates" should be an integer between 1 and 500.');
                delete cfg.subdomains.max_candidates;
            }
        }
    }

    // LLM sub-keys.
    if (cfg.llm !== undefined) {
        if (typeof cfg.llm !== 'object' || cfg.llm === null) {
            warnings.push('Config key "llm" should be an object.');
            delete cfg.llm;
        } else {
            cfg.llm = { ...cfg.llm };
            // SECURITY: warn-and-drop any API key placed in the config file.
            for (const key of Object.keys(cfg.llm)) {
                if (LLM_SECRET_KEYS.has(key)) {
                    warnings.push(`Config key "llm.${key}" is not allowed — API keys must come from the environment (OPENAI_API_KEY / ANTHROPIC_API_KEY), never the config file. Dropping it.`);
                    delete cfg.llm[key];
                } else if (!KNOWN_LLM_KEYS.has(key)) {
                    warnings.push(`Unknown llm config key "llm.${key}" — ignoring.`);
                }
            }
            if (cfg.llm.enabled !== undefined && typeof cfg.llm.enabled !== 'boolean') {
                warnings.push('Config key "llm.enabled" should be a boolean.');
            }
            if (cfg.llm.consent !== undefined && typeof cfg.llm.consent !== 'boolean') {
                warnings.push('Config key "llm.consent" should be a boolean.');
            }
            if (cfg.llm.provider !== undefined && !VALID_LLM_PROVIDERS.has(cfg.llm.provider)) {
                warnings.push(`Invalid llm.provider "${cfg.llm.provider}" — expected one of ${[...VALID_LLM_PROVIDERS].join(', ')}.`);
            }
            for (const numKey of ['max_tokens', 'max_calls', 'token_budget', 'timeout_seconds']) {
                if (cfg.llm[numKey] !== undefined && (typeof cfg.llm[numKey] !== 'number' || cfg.llm[numKey] <= 0)) {
                    warnings.push(`Config key "llm.${numKey}" should be a positive number.`);
                }
            }
        }
    }

    for (const w of warnings) {
        console.warn(`⚠ VIBE SHIELD config: ${w}`);
    }

    return cfg;
}

/**
 * Resolve the safety mode from CLI flags / file config / default.
 * Precedence: explicit CLI flag > config file > default (safe-active).
 */
/**
 * Resolve LLM settings. Precedence: CLI flags > config file > defaults.
 * NOTE: the API key is NEVER part of this object — it is read from env at
 * runtime by LLMClient. Any stray secret keys are stripped for defense in depth.
 */
function resolveLLM(cliOptions, fileLLM) {
    const llm = { ...DEFAULTS.llm, ...(fileLLM || {}) };

    if (cliOptions.llm) llm.enabled = true;
    if (cliOptions.llmProvider) llm.provider = cliOptions.llmProvider;
    if (cliOptions.llmModel) llm.model = cliOptions.llmModel;
    if (cliOptions.llmConsent) llm.consent = true;

    // Defense in depth: never let a secret survive into the merged config.
    for (const key of Object.keys(llm)) {
        if (LLM_SECRET_KEYS.has(key)) delete llm[key];
    }
    return llm;
}

function resolveSafetyMode(cliOptions, fileMode) {
    if (cliOptions.aggressive) return 'aggressive';
    if (cliOptions.passive) return 'passive';
    if (cliOptions.safeActive) return 'safe-active';
    if (cliOptions.safety && SAFETY_MODES.includes(cliOptions.safety)) return cliOptions.safety;
    if (fileMode && SAFETY_MODES.includes(fileMode)) return fileMode;
    return DEFAULT_SAFETY_MODE;
}

export function loadConfig(cliOptions = {}) {
    let fileConfig = {};

    // Load from config file if specified or default path exists
    const configPath = cliOptions.config || path.join(process.cwd(), 'vibe-shield.config.json');
    if (fs.existsSync(configPath)) {
        try {
            const raw = fs.readFileSync(configPath, 'utf-8');
            fileConfig = JSON.parse(raw);
        } catch (e) {
            console.warn(`⚠ Warning: Could not parse config file at ${configPath}`);
        }
    }

    // Validate + clean file config (warn on unknown/deprecated/bad-typed keys)
    fileConfig = validateConfig(fileConfig);

    // Merge: defaults < file config < CLI options
    const config = {
        ...DEFAULTS,
        ...fileConfig,
        crawler: { ...DEFAULTS.crawler, ...(fileConfig.crawler || {}) },
        subdomains: { ...DEFAULTS.subdomains, ...(fileConfig.subdomains || {}) },
        viewports: { ...DEFAULTS.viewports, ...(fileConfig.viewports || {}) },
        llm: { ...DEFAULTS.llm, ...(fileConfig.llm || {}) },
    };

    // Apply scan profile (overrides default settings)
    const profileName = cliOptions.profile;
    if (profileName && SCAN_PROFILES[profileName]) {
        const profile = SCAN_PROFILES[profileName];
        if (profile.crawler) {
            Object.assign(config.crawler, profile.crawler);
        }
        if (profile.modules_enabled) {
            config.modules_enabled = profile.modules_enabled;
        }
        if (profile.halt_on_critical !== undefined) {
            config.halt_on_critical = profile.halt_on_critical;
        }
        config._profile = profileName;
    }

    // CLI overrides (take priority over profiles)
    if (cliOptions.projectDir) config.project_root = path.resolve(cliOptions.projectDir);
    if (cliOptions.targetUrl) config.target_url = cliOptions.targetUrl;
    if (cliOptions.severity) config.severity_threshold = cliOptions.severity;
    if (cliOptions.output) config.output_dir = cliOptions.output;
    if (cliOptions.verbose !== undefined) config.verbose = cliOptions.verbose;
    if (cliOptions.json) config.output_json = true;
    if (cliOptions.html) config.output_html = true;
    if (cliOptions.maxPages) config.crawler.max_pages = parseInt(cliOptions.maxPages);
    if (cliOptions.maxDepth) config.crawler.max_depth = parseInt(cliOptions.maxDepth);
    if (cliOptions.externalSubdomains) config.subdomains.external_enumeration = true;
    if (cliOptions.organizationDomains) {
        config.subdomains.organization_domains = String(cliOptions.organizationDomains).split(',').map(item => item.trim()).filter(Boolean);
    }

    // Resolve safety mode (CLI flag > file > default)
    config.safety_mode = resolveSafetyMode(cliOptions, config.safety_mode);

    // Resolve LLM settings (CLI flag > file > default). Key stays in env only.
    config.llm = resolveLLM(cliOptions, config.llm);

    return config;
}

export { SCAN_PROFILES };
export default loadConfig;
