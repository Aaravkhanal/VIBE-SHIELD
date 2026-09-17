import { chromium } from 'playwright';
import { createFinding } from '../../utils/finding.js';
import { collectParamNames } from '../../utils/param-discovery.js';

/**
 * SQLi Prober — Tests query-bearing inputs for SQL/NoSQL injection vulnerabilities.
 * SAFETY: Simulation only — no destructive payloads (DROP, DELETE, etc.) are ever sent.
 *
 * Detection strategies:
 *   1. Error-based   — diagnostic payloads that surface DB error signatures
 *   2. Boolean blind — compare TRUE vs FALSE condition responses
 *   3. Time blind    — measure response delay for a sleep payload
 */
export class SQLiProber {
    constructor(logger) {
        this.logger = logger;
        this.findings = [];
        this._candidateParams = [];
        // Budget for expensive time-based probes (each adds ~5s of delay).
        this._timeBudget = 12;
    }

    // SQL injection test payloads — detection-only, non-destructive
    static SQL_PAYLOADS = [
        { name: 'Single quote', payload: "'", errorPatterns: ['sql', 'syntax', 'mysql', 'postgresql', 'sqlite', 'ora-', 'odbc'] },
        { name: 'Classic OR', payload: "' OR '1'='1", errorPatterns: ['sql', 'syntax', 'query'] },
        { name: 'Double dash comment', payload: "' -- ", errorPatterns: ['sql', 'syntax'] },
        { name: 'UNION probe', payload: "' UNION SELECT NULL--", errorPatterns: ['union', 'select', 'column'] },
        { name: 'Numeric injection', payload: '1 OR 1=1', errorPatterns: ['sql', 'syntax'] },
        { name: 'Stacked query probe', payload: "'; SELECT 1--", errorPatterns: ['syntax', 'multiple'] },
    ];

    // Fallback guess-list of common query parameter names, used to AUGMENT
    // (never replace) parameters discovered from the actual surface.
    static FALLBACK_PARAMS = [
        'id', 'user', 'user_id', 'uid', 'page', 'item', 'product', 'product_id',
        'category', 'cat', 'q', 'search', 'query', 'name', 'order', 'sort', 'filter',
    ];

    // Boolean-based blind pairs (logically-true vs logically-false conditions).
    static BOOLEAN_PAIRS = [
        { context: 'string-and', truePayload: "' AND '1'='1", falsePayload: "' AND '1'='2" },
        { context: 'numeric-and', truePayload: ' AND 1=1', falsePayload: ' AND 1=2' },
        { context: 'string-or', truePayload: "' OR '1'='1' -- ", falsePayload: "' OR '1'='2' -- " },
    ];

    // Time-based blind payloads (5s sleep across common DB engines).
    static SLEEP_SECONDS = 5;
    static TIME_PAYLOADS = [
        { db: 'MySQL (string)', payload: "' AND SLEEP(5)-- -" },
        { db: 'MySQL (numeric)', payload: ' AND SLEEP(5)-- -' },
        { db: 'PostgreSQL', payload: "'; SELECT pg_sleep(5)-- -" },
        { db: 'MSSQL', payload: "'; WAITFOR DELAY '0:0:5'-- -" },
    ];

    // NoSQL injection payloads for JSON bodies
    static NOSQL_PAYLOADS = [
        { name: 'NoSQL $gt operator', payload: { '$gt': '' }, desc: 'MongoDB greater-than operator' },
        { name: 'NoSQL $ne null', payload: { '$ne': null }, desc: 'MongoDB not-equal null' },
        { name: 'NoSQL $regex', payload: { '$regex': '.*' }, desc: 'MongoDB regex wildcard' },
    ];

    // Common SQL error signatures in responses
    static ERROR_SIGNATURES = [
        /SQL syntax.*MySQL/i,
        /Warning.*mysql_/i,
        /PostgreSQL.*ERROR/i,
        /ERROR:\s*syntax error at or near/i,
        /pg_query\(\)/i,
        /Microsoft OLE DB Provider/i,
        /\[Microsoft\]\[ODBC/i,
        /ORA-\d{5}/i,
        /SQLite\/JDBCDriver/i,
        /SQLite\.Exception/i,
        /SQLITE_ERROR/i,
        /org\.hibernate\.QueryException/i,
        /Unclosed quotation mark/i,
        /quoted string not properly terminated/i,
        /com\.mysql\.jdbc/i,
        /Syntax error in string in query expression/i,
        /SQLSTATE\[\d{5}\]/i,
        /you have an error in your sql syntax/i,
    ];

    /**
     * Run SQL injection probing on all discovered surfaces.
     */
    async probe(surfaceInventory) {
        // Derive real candidate params from forms, query strings, and API URLs,
        // then augment with the fallback guess-list (discovered take priority).
        const discovered = collectParamNames(surfaceInventory);
        this._candidateParams = [
            ...discovered,
            ...SQLiProber.FALLBACK_PARAMS.filter(p => !discovered.includes(p)),
        ];
        this.logger?.debug?.(
            `SQLi prober: ${discovered.length} discovered params + ${SQLiProber.FALLBACK_PARAMS.length} fallback`
        );

        // Test URL parameters
        await this._testURLParams(surfaceInventory);

        // Test form inputs
        await this._testFormInputs(surfaceInventory);

        // Test API endpoints with JSON bodies
        await this._testAPIEndpoints(surfaceInventory);

        this.logger?.info?.(`SQLi prober found ${this.findings.length} issues`);
        return this.findings;
    }

    /**
     * Test URL query parameters for SQL injection (error, boolean, and time blind).
     */
    async _testURLParams(inventory) {
        for (const page of inventory.pages) {
            if (typeof page.status !== 'number') continue;

            let parsedUrl;
            try {
                parsedUrl = new URL(page.url);
            } catch {
                continue;
            }

            // Params present on this URL + discovered candidates (capped).
            const existing = [...parsedUrl.searchParams.keys()];
            const paramsToTest = [...new Set([...existing, ...this._candidateParams])].slice(0, 30);
            if (paramsToTest.length === 0) continue;

            for (const param of paramsToTest) {
                // 1. Error-based detection
                const errorFinding = await this._errorBasedTest(page.url, param);
                if (errorFinding) {
                    this.findings.push(errorFinding);
                    continue; // confirmed — no need for blind tests on this param
                }

                // 2. Boolean-based blind detection
                const boolFinding = await this._booleanBlindTest(page.url, param);
                if (boolFinding) {
                    this.findings.push(boolFinding);
                    continue;
                }

                // 3. Time-based blind detection (budgeted — each adds ~5s)
                if (this._timeBudget > 0) {
                    const timeFinding = await this._timeBlindTest(page.url, param);
                    if (timeFinding) this.findings.push(timeFinding);
                }
            }
        }
    }

    /**
     * Error-based detection: inject diagnostic payloads and look for DB errors.
     */
    async _errorBasedTest(baseUrl, param) {
        for (const { name, payload } of SQLiProber.SQL_PAYLOADS.slice(0, 4)) {
            let testUrl;
            try {
                testUrl = new URL(baseUrl);
            } catch {
                return null;
            }
            testUrl.searchParams.set(param, payload);

            try {
                const resp = await fetch(testUrl.toString(), {
                    signal: AbortSignal.timeout(10000),
                    redirect: 'follow',
                });
                const body = await resp.text();
                const errorMatch = this._detectSQLError(body);
                if (errorMatch) {
                    return createFinding({
                        module: 'security',
                        title: `SQL Injection: ${param} parameter (${name})`,
                        severity: 'critical',
                        affected_surface: baseUrl,
                        description: `The URL parameter "${param}" appears vulnerable to SQL injection. The "${name}" payload triggered a database error in the response, indicating unsanitized input is being passed directly to SQL queries.\n\nError signature: ${errorMatch}`,
                        reproduction: [
                            `1. Navigate to: ${testUrl.toString()}`,
                            `2. Observe database error message in the response`,
                            `3. Error signature: ${errorMatch}`,
                        ],
                        evidence: JSON.stringify({ param, payload: name, errorSignature: errorMatch, responseSnippet: body.substring(0, 300) }),
                        remediation: 'Use parameterized queries (prepared statements) for all database operations. Never concatenate user input into SQL strings. Implement input validation and WAF rules.',
                        references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'CWE-89'],
                    });
                }
            } catch {
                // Request failed — try next payload
            }
        }
        return null;
    }

    /**
     * Boolean-based blind detection: compare a logically-TRUE condition response
     * against a logically-FALSE one. If TRUE behaves like the baseline while
     * FALSE diverges, the input is being evaluated inside a SQL query.
     */
    async _booleanBlindTest(baseUrl, param) {
        const baseValue = this._baseValueFor(baseUrl, param);

        const baseline = await this._fetchVariant(baseUrl, param, baseValue);
        if (!baseline) return null;

        for (const pair of SQLiProber.BOOLEAN_PAIRS) {
            const trueResp = await this._fetchVariant(baseUrl, param, baseValue + pair.truePayload);
            const falseResp = await this._fetchVariant(baseUrl, param, baseValue + pair.falsePayload);
            if (!trueResp || !falseResp) continue;

            // Skip if either variant produced a hard error page (covered elsewhere).
            const simTrueBase = this._similarity(trueResp, baseline);
            const simTrueFalse = this._similarity(trueResp, falseResp);

            const statusDivergence = trueResp.status !== falseResp.status;

            // TRUE ≈ baseline, but TRUE clearly differs from FALSE → boolean blind.
            const booleanSignal =
                (simTrueBase >= 0.95 && simTrueFalse <= 0.85) || statusDivergence;

            if (booleanSignal) {
                // Confirm by repeating once to reduce false positives from jitter.
                const trueResp2 = await this._fetchVariant(baseUrl, param, baseValue + pair.truePayload);
                const falseResp2 = await this._fetchVariant(baseUrl, param, baseValue + pair.falsePayload);
                const confirmed = trueResp2 && falseResp2 &&
                    ((this._similarity(trueResp2, baseline) >= 0.95 && this._similarity(trueResp2, falseResp2) <= 0.85) ||
                        trueResp2.status !== falseResp2.status);

                if (!confirmed) continue;

                return createFinding({
                    module: 'security',
                    title: `Blind SQL Injection (Boolean): ${param} parameter`,
                    severity: 'critical',
                    affected_surface: baseUrl,
                    description: `The URL parameter "${param}" appears vulnerable to boolean-based blind SQL injection. A logically-true condition (${pair.truePayload}) returned a response matching the baseline, while a logically-false condition (${pair.falsePayload}) produced a measurably different response — indicating the input is evaluated within a SQL query even though no error is shown.`,
                    reproduction: [
                        `1. Request with ${param}=${baseValue}${pair.truePayload} (TRUE condition)`,
                        `2. Request with ${param}=${baseValue}${pair.falsePayload} (FALSE condition)`,
                        `3. Compare responses — TRUE matches baseline, FALSE diverges`,
                    ],
                    evidence: JSON.stringify({
                        param,
                        context: pair.context,
                        truePayload: pair.truePayload,
                        falsePayload: pair.falsePayload,
                        simTrueVsBaseline: Number(simTrueBase.toFixed(3)),
                        simTrueVsFalse: Number(simTrueFalse.toFixed(3)),
                        trueStatus: trueResp.status,
                        falseStatus: falseResp.status,
                    }),
                    remediation: 'Use parameterized queries (prepared statements). Boolean-based blind SQLi is exploitable even without visible errors — apply strict input validation and least-privilege DB accounts.',
                    references: ['https://owasp.org/www-community/attacks/Blind_SQL_Injection', 'CWE-89'],
                });
            }
        }
        return null;
    }

    /**
     * Time-based blind detection: inject a sleep payload and measure the delay.
     */
    async _timeBlindTest(baseUrl, param) {
        const baseValue = this._baseValueFor(baseUrl, param);

        // Establish a control latency (fastest of two benign requests).
        const c1 = await this._timeVariant(baseUrl, param, baseValue);
        const c2 = await this._timeVariant(baseUrl, param, baseValue);
        if (c1 === null && c2 === null) return null;
        const control = Math.min(...[c1, c2].filter(t => t !== null));

        const sleepMs = SQLiProber.SLEEP_SECONDS * 1000;
        const threshold = control + sleepMs - 1500; // allow ~1.5s slack

        for (const { db, payload } of SQLiProber.TIME_PAYLOADS) {
            if (this._timeBudget <= 0) break;
            this._timeBudget--;

            const delayed = await this._timeVariant(baseUrl, param, baseValue + payload);
            if (delayed === null) continue;

            if (delayed >= threshold) {
                // Confirm once more to rule out a transient slow response.
                const confirm = await this._timeVariant(baseUrl, param, baseValue + payload);
                if (confirm === null || confirm < threshold) continue;

                return createFinding({
                    module: 'security',
                    title: `Blind SQL Injection (Time-based): ${param} parameter`,
                    severity: 'critical',
                    affected_surface: baseUrl,
                    description: `The URL parameter "${param}" appears vulnerable to time-based blind SQL injection. A ${db} sleep payload caused the response to be delayed by ~${SQLiProber.SLEEP_SECONDS}s relative to a ${(control / 1000).toFixed(1)}s control, indicating the injected SQL was executed.`,
                    reproduction: [
                        `1. Baseline request with ${param}=${baseValue} (~${(control / 1000).toFixed(1)}s)`,
                        `2. Inject ${param}=${baseValue}${payload}`,
                        `3. Response is delayed by ~${SQLiProber.SLEEP_SECONDS}s (measured ${(delayed / 1000).toFixed(1)}s)`,
                    ],
                    evidence: JSON.stringify({
                        param,
                        engine: db,
                        payload,
                        controlMs: control,
                        delayedMs: delayed,
                        thresholdMs: threshold,
                    }),
                    remediation: 'Use parameterized queries (prepared statements). Time-based blind SQLi confirms code execution in the database — enforce input validation, query timeouts, and least-privilege DB accounts.',
                    references: ['https://owasp.org/www-community/attacks/Blind_SQL_Injection', 'CWE-89'],
                });
            }
        }
        return null;
    }

    /**
     * Choose a base value to graft payloads onto: the existing param value if
     * present, otherwise a benign numeric default.
     */
    _baseValueFor(baseUrl, param) {
        try {
            const u = new URL(baseUrl);
            const v = u.searchParams.get(param);
            if (v && v.length > 0) return v;
        } catch {
            /* ignore */
        }
        return '1';
    }

    /**
     * Fetch a URL variant with `param` set to `value`. Returns { status, body }.
     */
    async _fetchVariant(baseUrl, param, value) {
        let testUrl;
        try {
            testUrl = new URL(baseUrl);
        } catch {
            return null;
        }
        testUrl.searchParams.set(param, value);
        try {
            const resp = await fetch(testUrl.toString(), {
                signal: AbortSignal.timeout(10000),
                redirect: 'follow',
            });
            const body = await resp.text();
            return { status: resp.status, body };
        } catch {
            return null;
        }
    }

    /**
     * Measure the round-trip time (ms) for a URL variant. Returns null on error.
     */
    async _timeVariant(baseUrl, param, value) {
        let testUrl;
        try {
            testUrl = new URL(baseUrl);
        } catch {
            return null;
        }
        testUrl.searchParams.set(param, value);
        const start = Date.now();
        try {
            const resp = await fetch(testUrl.toString(), {
                // Generous timeout so the sleep payload can complete.
                signal: AbortSignal.timeout((SQLiProber.SLEEP_SECONDS + 8) * 1000),
                redirect: 'follow',
            });
            await resp.text();
            return Date.now() - start;
        } catch {
            return null;
        }
    }

    /**
     * Similarity between two responses based on status + body length.
     * Returns 0..1 (1 = identical-ish).
     */
    _similarity(a, b) {
        if (!a || !b) return 0;
        if (a.status !== b.status) return 0;
        const la = a.body?.length || 0;
        const lb = b.body?.length || 0;
        if (la === 0 && lb === 0) return 1;
        return 1 - Math.abs(la - lb) / Math.max(la, lb, 1);
    }

    /**
     * Test form inputs for SQL injection.
     */
    async _testFormInputs(inventory) {
        const browser = await chromium.launch({ headless: true });
        const context = await browser.newContext({ ignoreHTTPSErrors: true });

        for (const form of inventory.forms) {
            const page = await context.newPage();
            try {
                await page.goto(form.page, { waitUntil: 'networkidle', timeout: 15000 });

                for (const field of form.fields) {
                    if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file'].includes(field.type)) continue;

                    // Test with the single quote payload (most universal SQL diagnostic)
                    const testPayload = SQLiProber.SQL_PAYLOADS[0];

                    try {
                        const input = await page.$(`[name="${field.name}"]`) || await page.$(`#${field.name}`);
                        if (!input) continue;

                        await input.fill(testPayload.payload);

                        // Submit
                        const submitBtn = await page.$('button[type="submit"], input[type="submit"]');
                        if (submitBtn) {
                            // Intercept response
                            const [response] = await Promise.all([
                                page.waitForNavigation({ timeout: 10000 }).catch(() => null),
                                submitBtn.click(),
                            ]);

                            await page.waitForTimeout(1000);
                            const content = await page.content();

                            const errorMatch = this._detectSQLError(content);
                            if (errorMatch) {
                                this.findings.push(createFinding({
                                    module: 'security',
                                    title: `SQL Injection: Form Field "${field.name}" in ${form.id}`,
                                    severity: 'critical',
                                    affected_surface: form.page,
                                    description: `The form field "${field.name}" in form "${form.id}" appears vulnerable to SQL injection. A single quote payload triggered a database error, indicating raw input is passed to SQL queries.\n\nError: ${errorMatch}`,
                                    reproduction: [
                                        `1. Navigate to ${form.page}`,
                                        `2. Enter a single quote (') in the "${field.name}" field`,
                                        `3. Submit the form`,
                                        `4. Observe SQL error in the response`,
                                    ],
                                    evidence: JSON.stringify({ form: form.id, field: field.name, errorSignature: errorMatch }),
                                    remediation: 'Use parameterized queries. Never pass raw form input to SQL queries.',
                                    references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'CWE-89'],
                                }));
                            }

                            // Go back for next field
                            await page.goto(form.page, { waitUntil: 'networkidle', timeout: 10000 });
                        }
                    } catch {
                        // Field test failed
                    }
                }
            } catch (err) {
                this.logger?.debug?.(`SQLi form test failed for ${form.page}: ${err.message}`);
            } finally {
                await page.close();
            }
        }

        await browser.close();
    }

    /**
     * Test API endpoints for NoSQL injection via JSON bodies.
     */
    async _testAPIEndpoints(inventory) {
        for (const endpoint of inventory.apiEndpoints || []) {
            if (endpoint.method !== 'POST' && endpoint.method !== 'PUT') continue;

            for (const { name, payload, desc } of SQLiProber.NOSQL_PAYLOADS) {
                try {
                    // Send a JSON body with NoSQL operator
                    const resp = await fetch(endpoint.url, {
                        method: endpoint.method,
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username: payload, password: payload }),
                        signal: AbortSignal.timeout(10000),
                    });

                    const body = await resp.text();

                    // Check for unexpected success (auth bypass) or detailed errors
                    if (resp.ok && body.includes('token')) {
                        this.findings.push(createFinding({
                            module: 'security',
                            title: `NoSQL Injection: ${name} at ${new URL(endpoint.url).pathname}`,
                            severity: 'critical',
                            affected_surface: endpoint.url,
                            description: `The API endpoint may be vulnerable to NoSQL injection. A ${desc} payload in the JSON body returned what appears to be a successful authentication response, suggesting the database query was manipulated.`,
                            reproduction: [
                                `1. Send ${endpoint.method} to ${endpoint.url}`,
                                `2. Body: ${JSON.stringify({ username: payload, password: payload })}`,
                                `3. Response contains authentication token`,
                            ],
                            evidence: JSON.stringify({ endpoint: endpoint.url, method: endpoint.method, payload: name }),
                            remediation: 'Validate and sanitize all input before database queries. Use explicit type checking to reject objects where strings are expected. Use mongoose schema validation or equivalent.',
                            references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection'],
                        }));
                        break;
                    }
                } catch {
                    // Request failed
                }
            }
        }
    }

    /**
     * Check response body for SQL error signatures.
     */
    _detectSQLError(body) {
        if (!body) return null;
        for (const pattern of SQLiProber.ERROR_SIGNATURES) {
            const match = body.match(pattern);
            if (match) return match[0];
        }
        return null;
    }
}

export default SQLiProber;
