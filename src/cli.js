#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { loadConfig } from './utils/config.js';
import { createLogger } from './utils/logger.js';
import { Orchestrator } from './agents/orchestrator.js';
import { CrawlAgent } from './agents/crawl-agent.js';
import { QAAgent } from './agents/qa-agent.js';
import { SecurityAgent } from './agents/security-agent.js';
import { AIAgent } from './agents/ai-agent.js';
import { LogicAgent } from './agents/logic-agent.js';
import { APIAgent } from './agents/api-agent.js';
import { ReportGenerator } from './reporting/report-generator.js';
import { ComplianceReporter } from './reporting/compliance-reporter.js';
import { AuthManager } from './core/auth-manager.js';
import { getVersion } from './utils/version.js';
import { LLMClient } from './core/llm/llm-client.js';
import { ensureChromium } from './utils/browser.js';

const VERSION = getVersion();

const BANNER = `
${chalk.hex('#00ff88').bold('  🛡️  V I B E   S H I E L D')}
${chalk.dim('  Autonomous Security & Quality Intelligence')}
${chalk.dim(`  v${VERSION} · Multi-Agent`)}
`;

const program = new Command();

program
    .name('vibe-shield')
    .description('VIBE SHIELD — Autonomous QA & Security scanning agent for vibe-coded apps')
    .version(VERSION);

// ═══════════════════════════════════════════════
// Multi-Agent Scan Runner
// ═══════════════════════════════════════════════

async function runScan(url, options, modulesToRun) {
    console.log(BANNER);

    const config = loadConfig({ ...options, targetUrl: url });
    config.target_url = url;

    // CLI --max-pages / --max-depth override profile settings only when explicitly set
    // (Commander gives us the string defaults, so we check against those)
    if (options.maxPages && options.maxPages !== '50') {
        config.crawler.max_pages = parseInt(options.maxPages);
    }
    if (options.maxDepth && options.maxDepth !== '5') {
        config.crawler.max_depth = parseInt(options.maxDepth);
    }

    // Propagate CLI flags to config
    if (options.haltOnCritical) config.halt_on_critical = true;
    if (options.webhook) config.notify_webhook = options.webhook;

    // Propagate auth flags from CLI
    if (options.username || options.password || options.loginUrl || options.authStrategy) {
        config.auth = config.auth || {};
        if (options.authStrategy) config.auth.strategy = options.authStrategy;
        if (options.loginUrl) config.auth.login_url = options.loginUrl;
        if (options.username && options.password) {
            config.credentials = config.credentials || [];
            // Add CLI credentials as a "cli" role if not already present
            const hasCliRole = config.credentials.some(c => c.role === 'cli');
            if (!hasCliRole) {
                config.credentials.push({
                    role: 'cli',
                    username: options.username,
                    password: options.password,
                });
            }
        }
    }

    // ── prod_safe guard ──
    const prodIndicators = /\b(prod|production|live|www\.)\b/i;
    const isLikelyProd = prodIndicators.test(url) && !/\b(staging|dev|test|local|sandbox)\b/i.test(url);
    if (isLikelyProd && !options.prodSafe && !config.prod_safe) {
        console.error(chalk.red('\n  ⛔ PRODUCTION TARGET DETECTED'));
        console.error(chalk.red(`  URL "${url}" looks like a production environment.`));
        console.error(chalk.red('  Add --prod-safe flag to confirm you have authorization to test.'));
        console.error(chalk.dim('  Example: vibe-shield scan https://prod.example.com --prod-safe\n'));
        process.exit(1);
    }

    const logger = createLogger({ verbose: options.verbose });
    const startTime = Date.now();

    const runQA = modulesToRun.includes('qa');
    const runSecurity = modulesToRun.includes('security');
    const runAI = modulesToRun.includes('ai');
    const runLogic = modulesToRun.includes('logic');
    const runAPI = modulesToRun.includes('api');
    const moduleLabel = modulesToRun.join(' + ').toUpperCase();

    const safetyLabels = {
        passive: 'Passive (recon + static analysis only)',
        'safe-active': 'Safe-Active (non-destructive probing)',
        aggressive: 'Aggressive (includes destructive tests)',
    };

    console.log(chalk.hex('#00ff88')('  Target:  ') + chalk.white(url));
    console.log(chalk.hex('#00ff88')('  Modules: ') + chalk.white(moduleLabel));
    console.log(chalk.hex('#00ff88')('  Mode:    ') + chalk.white('Multi-Agent Orchestration'));
    console.log(chalk.hex('#00ff88')('  Safety:  ') + chalk.white(safetyLabels[config.safety_mode] || config.safety_mode));
    console.log(chalk.hex('#00ff88')('  Severity:') + chalk.white(` ≥ ${config.severity_threshold}`));

    // Single startup line stating whether LLM augmentation is active (no secrets).
    const llmStatus = LLMClient.describe(config);
    const llmActive = llmStatus.startsWith('enabled');
    console.log(
        chalk.hex('#00ff88')('  LLM:     ') +
        (llmActive ? chalk.cyan(llmStatus) : chalk.dim(llmStatus))
    );
    console.log();

    // ═══════════════════════════════════════
    // Preflight: ensure the browser engine is available
    // ═══════════════════════════════════════
    try {
        ensureChromium(logger);
    } catch (err) {
        console.error(chalk.red(`\n  ⛔ ${err.message}\n`));
        process.exit(1);
    }

    // ═══════════════════════════════════════
    // Phase 0: Authentication (before spinners)
    // ═══════════════════════════════════════
    const authManager = new AuthManager(config, logger);
    const authSpinner = ora({ text: chalk.dim('Detecting login forms...'), color: 'yellow' }).start();

    // Pause spinner before prompting (so readline works cleanly)
    authManager._onBeforePrompt = () => authSpinner.stop();
    authManager._onAfterPrompt = () => { }; // don't restart — prompt handles its own output

    await authManager.authenticate();

    if (authManager.isAuthenticated) {
        authSpinner.succeed(chalk.dim('Authenticated: ') + authManager.roles.map(r => chalk.hex('#00ff88')(r)).join(', '));
    } else if (authManager.loginFormInfo) {
        const info = authManager.loginFormInfo;
        const typeLabel = { phone: '📱 Phone/OTP', otp: '🔢 OTP', social: '🔗 Social/OAuth', email: '📧 Email', password: '🔑 Password' }[info.type] || info.type;
        const locationLabel = info.isModal ? 'modal' : 'page';
        authSpinner.info(chalk.dim(`Login detected (${typeLabel} via ${locationLabel}) — scanning unauthenticated`));
    } else {
        authSpinner.info(chalk.dim('No credentials — scanning unauthenticated'));
    }

    // Inject auth manager into config for agents to access
    config._authManager = authManager;

    // ═══════════════════════════════════════
    // Build the agent constellation
    // ═══════════════════════════════════════
    const orchestrator = new Orchestrator(config, logger);

    // VIBE-SHIELD-CRAWL always runs (all modules depend on it)
    orchestrator.register(new CrawlAgent());

    // Register module agents
    let qaAgent = null;
    let secAgent = null;

    if (runQA) {
        qaAgent = new QAAgent();
        orchestrator.register(qaAgent);
    }
    if (runSecurity) {
        secAgent = new SecurityAgent();
        orchestrator.register(secAgent);
    }
    if (runAI) {
        orchestrator.register(new AIAgent());
    }
    if (runLogic) {
        orchestrator.register(new LogicAgent());
    }
    if (runAPI) {
        orchestrator.register(new APIAgent());
    }

    // ═══════════════════════════════════════
    // Wire up CLI progress display
    // ═══════════════════════════════════════
    const spinners = {};
    let activeAgentCount = 0;
    const parallelIndicator = () => activeAgentCount > 1 ? chalk.cyan(' ⚡parallel') : '';

    orchestrator.on('agent:started', ({ agentName }) => {
        activeAgentCount++;
        const color = agentName === 'VIBE-SHIELD-SEC' ? 'yellow' : agentName === 'VIBE-SHIELD-AI' ? 'magenta' : agentName === 'VIBE-SHIELD-LOGIC' ? 'cyan' : agentName === 'VIBE-SHIELD-API' ? 'red' : 'green';
        spinners[agentName] = ora({
            text: chalk.dim(`[${agentName}] `) + 'Starting...' + parallelIndicator(),
            color,
        }).start();
    });

    orchestrator.on('agent:progress', ({ agentName, phase, message }) => {
        if (spinners[agentName]) {
            spinners[agentName].text = chalk.dim(`[${agentName}] `) + message + parallelIndicator();
        }
    });

    orchestrator.on('agent:completed', ({ agentName, duration, findingsCount }) => {
        activeAgentCount--;
        if (spinners[agentName]) {
            spinners[agentName].succeed(
                chalk.dim(`[${agentName}] `) +
                `Complete — ${chalk.hex('#00ff88').bold(findingsCount)} findings in ${(duration / 1000).toFixed(1)}s`
            );
        }
    });

    orchestrator.on('agent:error', ({ agentName, error }) => {
        activeAgentCount--;
        if (spinners[agentName]) {
            spinners[agentName].fail(chalk.dim(`[${agentName}] `) + chalk.red(`Error: ${error}`));
        }
    });

    // ═══════════════════════════════════════
    // Execute the multi-agent pipeline
    // ═══════════════════════════════════════
    let results;
    try {
        results = await orchestrator.run();
    } catch (err) {
        console.error(chalk.red(`\n  Orchestrator failed: ${err.message}`));
        process.exit(1);
    }

    // ═══════════════════════════════════════
    // Report Generation
    // ═══════════════════════════════════════
    const reportSpinner = ora({
        text: 'Generating reports...',
        color: 'green',
    }).start();

    try {
        const duration = Date.now() - startTime;
        const reporter = new ReportGenerator(config, logger, orchestrator.llmClient);

        const testSummary = qaAgent?.testSummary || {};

        const { reportDir, summary, dedupSummary } = await reporter.generate({
            findings: results.findings,
            deduplicated: results.deduplicated,
            dedupStats: results.dedupStats,
            testSummary: { ...testSummary, duration },
            surfaceInventory: results.surfaceInventory,
            outputDir: config.output_dir,
            modules: modulesToRun,
        });

        // Generate compliance report if requested
        let complianceResult = null;
        if (options.compliance) {
            const complianceReporter = new ComplianceReporter(config, logger);
            complianceResult = complianceReporter.generate(
                options.compliance,
                results.findings,
                reportDir,
                { target: url, version: VERSION, scannedAt: new Date().toISOString() }
            );
        }

        reportSpinner.succeed(`Reports saved to ${chalk.underline(reportDir)}`);

        // ═══════════════════════════════════════
        // Final Summary
        // ═══════════════════════════════════════
        console.log();
        console.log(chalk.hex('#00ff88').bold('  ═══ SCAN COMPLETE ═══'));
        console.log();
        console.log(`  ${chalk.dim('Duration:')}    ${(duration / 1000).toFixed(1)}s`);
        console.log(`  ${chalk.dim('Modules:')}     ${moduleLabel}`);
        console.log(`  ${chalk.dim('Agents:')}      ${Object.keys(results.agents).length} agents executed`);

        // Agent breakdown
        for (const [name, agent] of Object.entries(results.agents)) {
            const statusIcon = agent.status === 'done' ? chalk.hex('#00ff88')('✔') : chalk.red('✘');
            console.log(`  ${chalk.dim('  ' + name + ':')}  ${statusIcon} ${agent.findingsCount} findings (${(agent.duration / 1000).toFixed(1)}s)`);
        }

        console.log();
        const displaySummary = dedupSummary || summary;
        const dedupStats = results.dedupStats;
        if (dedupStats && dedupStats.duplicatesRemoved > 0) {
            console.log(`  ${chalk.dim('Findings:')}    ${displaySummary.total} unique ${chalk.dim(`(from ${dedupStats.rawCount} raw, ${dedupStats.reductionPercent}% deduped)`)}`);
        } else {
            console.log(`  ${chalk.dim('Findings:')}    ${summary.total}`);
        }
        if (displaySummary.critical > 0) console.log(`  ${chalk.red('  Critical:')}  ${displaySummary.critical}`);
        if (displaySummary.high > 0) console.log(`  ${chalk.hex('#ff6d00')('  High:')}      ${displaySummary.high}`);
        if (displaySummary.medium > 0) console.log(`  ${chalk.yellow('  Medium:')}    ${displaySummary.medium}`);
        if (displaySummary.low > 0) console.log(`  ${chalk.blue('  Low:')}       ${displaySummary.low}`);
        if (displaySummary.info > 0) console.log(`  ${chalk.gray('  Info:')}      ${displaySummary.info}`);

        // Correlations
        if (results.correlations?.length > 0) {
            console.log();
            console.log(chalk.hex('#ff6d00').bold('  ═══ CORRELATIONS ═══'));
            for (const c of results.correlations) {
                console.log(`  ${chalk.hex('#ff6d00')('⚡')} ${c.title}`);
            }
        }

        // OWASP Compliance Summary
        if (complianceResult?.compliance) {
            const c = complianceResult.compliance;
            console.log();
            console.log(chalk.hex('#00ff88').bold('  ═══ OWASP TOP 10 COMPLIANCE ═══'));
            console.log();
            const scoreColor = c.percentage >= 80 ? '#00e676' : c.percentage >= 50 ? '#ffd600' : '#ff1744';
            console.log(`  ${chalk.dim('Score:')}       ${chalk.hex(scoreColor).bold(`${c.score}/${c.total}`)} (${c.percentage}%)`);
            console.log();
            for (const cat of c.categories) {
                const icon = cat.status === 'pass' ? chalk.hex('#00e676')('✔') : cat.status === 'fail' ? chalk.red('✘') : chalk.yellow('⚠');
                const label = `${cat.id} ${cat.name}`;
                const count = cat.findingsCount > 0 ? chalk.dim(` (${cat.findingsCount} findings)`) : '';
                console.log(`  ${icon} ${label}${count}`);
            }
        }

        console.log();

        if (summary.critical > 0) {
            console.log(chalk.red.bold('  ⚠ CRITICAL findings detected — immediate action required!'));
            if (config.halt_on_critical) process.exit(1);
        } else if (summary.high > 0) {
            console.log(chalk.hex('#ff6d00')('  ⚠ HIGH severity findings detected — review recommended.'));
        } else if (summary.total === 0) {
            console.log(chalk.hex('#00ff88')('  ✔ No findings at the configured severity threshold. Clean scan!'));
        }

        console.log();
    } catch (err) {
        reportSpinner.fail('Report generation failed: ' + err.message);
        logger.error('Report generation failed', err);
        process.exit(1);
    }
}

// ═══════════════════════════════════════════════
// Commands
// ═══════════════════════════════════════════════

program
    .command('scan')
    .description('Run VIBE SHIELD scan with selected modules (default: qa + security + ai + logic + api)')
    .argument('<url>', 'Target URL to scan')
    .option('-c, --config <path>', 'Path to vibe-shield.config.json')
    .option('-o, --output <dir>', 'Output directory for reports')
    .option('-m, --modules <list>', 'Comma-separated modules to run (qa,security,ai,logic,api)', 'qa,security,ai,logic,api')
    .option('-s, --severity <level>', 'Minimum severity threshold (critical|high|medium|low|info)', 'low')
    .option('--profile <type>', 'Scan profile: quick|deep|ci (overrides crawl settings)')
    .option('--compliance <framework>', 'Generate compliance report (owasp)')
    .option('--json', 'Output JSON report')
    .option('--html', 'Output HTML report')
    .option('--max-pages <n>', 'Maximum pages to crawl', '50')
    .option('--max-depth <n>', 'Maximum crawl depth', '5')
    .option('--halt-on-critical', 'Abort scan immediately on critical finding')
    .option('--webhook <url>', 'POST findings to webhook URL on completion')
    .option('--prod-safe', 'Confirm authorization to scan production targets')
    .option('--passive', 'Safety mode: recon + static analysis only (no attack probing)')
    .option('--safe-active', 'Safety mode: non-destructive active probing (default)')
    .option('--aggressive', 'Safety mode: enable destructive/state-changing tests')
    .option('--llm', 'Enable optional LLM augmentation (key from env; default off)')
    .option('--llm-provider <name>', 'LLM provider: openai|anthropic')
    .option('--llm-model <id>', 'LLM model id (provider default if omitted)')
    .option('--llm-consent', 'Consent to send minimal finding/target data to the LLM provider')
    .option('--auth-strategy <type>', 'Auth strategy: auto|form|api|cookie (default: auto)')
    .option('--login-url <url>', 'Login page URL for form-based auth')
    .option('--username <user>', 'Username/email for authenticated scanning')
    .option('--password <pass>', 'Password for authenticated scanning')
    .option('-v, --verbose', 'Enable verbose logging')
    .action(async (url, options) => {
        const modules = options.modules.split(',').map(m => m.trim().toLowerCase());
        await runScan(url, options, modules);
    });

program
    .command('qa')
    .description('Run Module 01 only: Quality Assurance & Functional Testing')
    .argument('<url>', 'Target URL to scan')
    .option('-c, --config <path>', 'Path to vibe-shield.config.json')
    .option('-o, --output <dir>', 'Output directory for reports')
    .option('-s, --severity <level>', 'Severity threshold', 'low')
    .option('--max-pages <n>', 'Maximum pages to crawl', '50')
    .option('--max-depth <n>', 'Maximum crawl depth', '5')
    .option('--passive', 'Safety mode: recon + static analysis only (no attack probing)')
    .option('--safe-active', 'Safety mode: non-destructive active probing (default)')
    .option('--aggressive', 'Safety mode: enable destructive/state-changing tests')
    .option('--llm', 'Enable optional LLM augmentation (key from env; default off)')
    .option('--llm-provider <name>', 'LLM provider: openai|anthropic')
    .option('--llm-model <id>', 'LLM model id (provider default if omitted)')
    .option('--llm-consent', 'Consent to send minimal finding/target data to the LLM provider')
    .option('-v, --verbose', 'Enable verbose logging')
    .action(async (url, options) => {
        await runScan(url, options, ['qa']);
    });

program
    .command('security')
    .description('Run Module 02 only: Security Vulnerability Scanning')
    .argument('<url>', 'Target URL to scan')
    .option('-c, --config <path>', 'Path to vibe-shield.config.json')
    .option('-o, --output <dir>', 'Output directory for reports')
    .option('-s, --severity <level>', 'Severity threshold', 'low')
    .option('--max-pages <n>', 'Maximum pages to crawl', '50')
    .option('--max-depth <n>', 'Maximum crawl depth', '5')
    .option('--passive', 'Safety mode: recon + static analysis only (no attack probing)')
    .option('--safe-active', 'Safety mode: non-destructive active probing (default)')
    .option('--aggressive', 'Safety mode: enable destructive/state-changing tests')
    .option('--llm', 'Enable optional LLM augmentation (key from env; default off)')
    .option('--llm-provider <name>', 'LLM provider: openai|anthropic')
    .option('--llm-model <id>', 'LLM model id (provider default if omitted)')
    .option('--llm-consent', 'Consent to send minimal finding/target data to the LLM provider')
    .option('-v, --verbose', 'Enable verbose logging')
    .action(async (url, options) => {
        await runScan(url, options, ['security']);
    });

program
    .command('ai')
    .description('Run Module 04 only: Prompt Injection & AI Abuse Detection')
    .argument('<url>', 'Target URL to scan')
    .option('-c, --config <path>', 'Path to vibe-shield.config.json')
    .option('-o, --output <dir>', 'Output directory for reports')
    .option('-s, --severity <level>', 'Severity threshold', 'low')
    .option('--max-pages <n>', 'Maximum pages to crawl', '50')
    .option('--max-depth <n>', 'Maximum crawl depth', '5')
    .option('--passive', 'Safety mode: recon + static analysis only (no attack probing)')
    .option('--safe-active', 'Safety mode: non-destructive active probing (default)')
    .option('--aggressive', 'Safety mode: enable destructive/state-changing tests')
    .option('--llm', 'Enable optional LLM augmentation (key from env; default off)')
    .option('--llm-provider <name>', 'LLM provider: openai|anthropic')
    .option('--llm-model <id>', 'LLM model id (provider default if omitted)')
    .option('--llm-consent', 'Consent to send minimal finding/target data to the LLM provider')
    .option('-v, --verbose', 'Enable verbose logging')
    .action(async (url, options) => {
        await runScan(url, options, ['ai']);
    });

program
    .command('logic')
    .description('Run Module 03 only: Business Logic Validation')
    .argument('<url>', 'Target URL to scan')
    .option('-c, --config <path>', 'Path to vibe-shield.config.json')
    .option('-o, --output <dir>', 'Output directory for reports')
    .option('-s, --severity <level>', 'Severity threshold', 'low')
    .option('--max-pages <n>', 'Maximum pages to crawl', '50')
    .option('--max-depth <n>', 'Maximum crawl depth', '5')
    .option('--passive', 'Safety mode: recon + static analysis only (no attack probing)')
    .option('--safe-active', 'Safety mode: non-destructive active probing (default)')
    .option('--aggressive', 'Safety mode: enable destructive/state-changing tests')
    .option('--llm', 'Enable optional LLM augmentation (key from env; default off)')
    .option('--llm-provider <name>', 'LLM provider: openai|anthropic')
    .option('--llm-model <id>', 'LLM model id (provider default if omitted)')
    .option('--llm-consent', 'Consent to send minimal finding/target data to the LLM provider')
    .option('-v, --verbose', 'Enable verbose logging')
    .action(async (url, options) => {
        await runScan(url, options, ['logic']);
    });

program
    .command('api')
    .description('Run Module 05 only: API & Auth Flow Verification')
    .argument('<url>', 'Target URL to scan')
    .option('-c, --config <path>', 'Path to vibe-shield.config.json')
    .option('-o, --output <dir>', 'Output directory for reports')
    .option('-s, --severity <level>', 'Severity threshold', 'low')
    .option('--max-pages <n>', 'Maximum pages to crawl', '50')
    .option('--max-depth <n>', 'Maximum crawl depth', '5')
    .option('--passive', 'Safety mode: recon + static analysis only (no attack probing)')
    .option('--safe-active', 'Safety mode: non-destructive active probing (default)')
    .option('--aggressive', 'Safety mode: enable destructive/state-changing tests')
    .option('--llm', 'Enable optional LLM augmentation (key from env; default off)')
    .option('--llm-provider <name>', 'LLM provider: openai|anthropic')
    .option('--llm-model <id>', 'LLM model id (provider default if omitted)')
    .option('--llm-consent', 'Consent to send minimal finding/target data to the LLM provider')
    .option('-v, --verbose', 'Enable verbose logging')
    .action(async (url, options) => {
        await runScan(url, options, ['api']);
    });

program.parse();
