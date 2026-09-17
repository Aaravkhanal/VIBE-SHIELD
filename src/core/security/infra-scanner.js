import { createFinding } from '../../utils/finding.js';

/**
 * Infrastructure Scanner — Scans for infrastructure exposure and misconfigurations.
 * Checks debug endpoints, directory listing, error disclosure, and common misconfigs.
 */
export class InfraScanner {
    constructor(logger) {
        this.logger = logger;
        this.findings = [];
    }

    // Common admin/debug/sensitive endpoints to probe
    static PROBE_PATHS = [
        { path: '/admin', desc: 'Admin panel', severity: 'high' },
        { path: '/administrator', desc: 'Admin panel', severity: 'high' },
        { path: '/admin/login', desc: 'Admin login', severity: 'medium' },
        { path: '/wp-admin', desc: 'WordPress admin', severity: 'high' },
        { path: '/wp-login.php', desc: 'WordPress login', severity: 'medium' },
        { path: '/debug', desc: 'Debug endpoint', severity: 'high' },
        { path: '/_debug', desc: 'Debug endpoint', severity: 'high' },
        { path: '/__debug', desc: 'Debug endpoint', severity: 'high' },
        { path: '/debug/vars', desc: 'Go debug vars', severity: 'critical' },
        { path: '/debug/pprof', desc: 'Go profiler', severity: 'critical' },
        { path: '/status', desc: 'Status page', severity: 'low' },
        { path: '/health', desc: 'Health check', severity: 'info' },
        { path: '/healthz', desc: 'Kubernetes health', severity: 'info' },
        { path: '/readyz', desc: 'Kubernetes readiness', severity: 'info' },
        { path: '/metrics', desc: 'Prometheus metrics', severity: 'high' },
        { path: '/api-docs', desc: 'API documentation', severity: 'low' },
        { path: '/swagger', desc: 'Swagger UI', severity: 'medium' },
        { path: '/swagger-ui.html', desc: 'Swagger UI', severity: 'medium' },
        { path: '/swagger.json', desc: 'Swagger spec', severity: 'medium' },
        { path: '/openapi.json', desc: 'OpenAPI spec', severity: 'medium' },
        { path: '/graphql', desc: 'GraphQL endpoint', severity: 'low' },
        { path: '/graphiql', desc: 'GraphQL IDE', severity: 'high' },
        { path: '/__graphql', desc: 'GraphQL endpoint', severity: 'low' },
        { path: '/actuator', desc: 'Spring Boot actuator', severity: 'high' },
        { path: '/actuator/env', desc: 'Spring environment', severity: 'critical' },
        { path: '/actuator/heapdump', desc: 'Spring heap dump', severity: 'critical' },
        { path: '/actuator/beans', desc: 'Spring beans', severity: 'high' },
        { path: '/console', desc: 'Console endpoint', severity: 'high' },
        { path: '/server-info', desc: 'Server info', severity: 'medium' },
        { path: '/info', desc: 'Info endpoint', severity: 'low' },
        { path: '/trace', desc: 'Trace endpoint', severity: 'high' },
        { path: '/api/v1', desc: 'API v1 root', severity: 'info' },
        { path: '/robots.txt', desc: 'Robots.txt', severity: 'info' },
        { path: '/sitemap.xml', desc: 'Sitemap', severity: 'info' },
        { path: '/crossdomain.xml', desc: 'Flash crossdomain', severity: 'medium' },
        { path: '/elmah.axd', desc: '.NET error logs', severity: 'high' },
        { path: '/phpinfo.php', desc: 'PHP info', severity: 'high' },
        { path: '/test', desc: 'Test page', severity: 'low' },
        { path: '/backup', desc: 'Backup directory', severity: 'high' },
        { path: '/dump', desc: 'Data dump', severity: 'critical' },
    ];

    // Patterns in error pages that reveal internal details
    static ERROR_DISCLOSURE_PATTERNS = [
        { regex: /at [\w.]+\([\w/.]+:\d+:\d+\)/i, name: 'Stack trace (Node.js)', severity: 'medium' },
        { regex: /Traceback \(most recent call/i, name: 'Stack trace (Python)', severity: 'medium' },
        { regex: /at [\w.]+\.[\w]+\([\w]+\.java:\d+\)/i, name: 'Stack trace (Java)', severity: 'medium' },
        { regex: /Fatal error:.*in \/[\w/]+\.php on line \d+/i, name: 'PHP fatal error with path', severity: 'high' },
        { regex: /DOCUMENT_ROOT.*\/[\w/]+/i, name: 'Document root path disclosure', severity: 'medium' },
        { regex: /\/home\/[\w]+\/|\/var\/www\/|\/usr\/local\//i, name: 'Server path disclosure', severity: 'medium' },
        { regex: /DB_HOST|DB_PASSWORD|DATABASE_URL/i, name: 'Database config disclosure', severity: 'critical' },
        { regex: /MongoServerError|mongoose.*Error/i, name: 'MongoDB error disclosure', severity: 'medium' },
        { regex: /ECONNREFUSED|ETIMEDOUT.*\d+\.\d+\.\d+\.\d+/i, name: 'Internal IP disclosure', severity: 'medium' },
    ];

    /**
     * Run infrastructure scanning.
     */
    async scan(surfaceInventory) {
        const baseUrl = surfaceInventory.baseUrl;

        // 1. Probe known sensitive endpoints
        await this._probeEndpoints(baseUrl);

        // 2. Check for directory listing
        await this._checkDirectoryListing(baseUrl);

        // 3. Check error page information disclosure
        await this._checkErrorDisclosure(baseUrl);

        // 4. Check for GraphQL introspection
        await this._checkGraphQLIntrospection(baseUrl);

        this.logger?.info?.(`Infrastructure scanner found ${this.findings.length} issues`);
        return this.findings;
    }

    /**
     * Probe known sensitive/admin endpoints.
     */
    async _probeEndpoints(baseUrl) {
        const results = await Promise.allSettled(
            InfraScanner.PROBE_PATHS.map(async ({ path, desc, severity }) => {
                const url = new URL(path, baseUrl).toString();
                try {
                    const resp = await fetch(url, {
                        method: 'GET',
                        redirect: 'follow',
                        signal: AbortSignal.timeout(5000),
                    });

                    if (resp.ok && resp.status === 200) {
                        const contentType = resp.headers.get('content-type') || '';
                        const body = await resp.text();

                        // Skip if it's a generic 200 HTML page (SPA catch-all)
                        if (this._isGenericSPAPage(body, path)) return null;
                        // Skip very small responses (likely empty)
                        if (body.trim().length < 20) return null;

                        return { path, desc, severity, url, contentType, bodyLength: body.length, body };
                    }
                } catch {
                    // Not accessible
                }
                return null;
            })
        );

        for (const result of results) {
            if (result.status !== 'fulfilled' || !result.value) continue;
            const { path, desc, severity, url, contentType, bodyLength, body } = result.value;

            // Determine actual severity based on content
            let actualSeverity = severity;
            if (this._containsSensitiveData(body)) {
                actualSeverity = 'critical';
            }

            this.findings.push(createFinding({
                module: 'security',
                title: `Exposed Endpoint: ${path} (${desc})`,
                severity: actualSeverity,
                affected_surface: url,
                description: `The endpoint "${path}" (${desc}) is publicly accessible and returned HTTP 200 with ${bodyLength} bytes.\n\nContent-Type: ${contentType}\n\nExposed management, debug, or admin endpoints can leak sensitive information and provide attack vectors.`,
                reproduction: [
                    `1. Navigate to ${url}`,
                    `2. Endpoint returns HTTP 200 with ${bodyLength} bytes`,
                    `3. Content-Type: ${contentType}`,
                ],
                evidence: body.substring(0, 500),
                remediation: `Restrict access to "${path}" via authentication, IP whitelisting, or remove it entirely from production. Use environment-based configuration to disable debug endpoints in production.`,
            }));
        }
    }

    /**
     * Check if common directories have directory listing enabled.
     */
    async _checkDirectoryListing(baseUrl) {
        const dirs = ['/static/', '/assets/', '/uploads/', '/images/', '/files/', '/media/', '/public/'];

        for (const dir of dirs) {
            try {
                const url = new URL(dir, baseUrl).toString();
                const resp = await fetch(url, { signal: AbortSignal.timeout(5000) });

                if (resp.ok) {
                    const body = await resp.text();
                    // Check for directory listing patterns
                    if (body.includes('Index of') || body.includes('Directory listing') ||
                        body.includes('<pre>') && (body.includes('Parent Directory') || body.match(/<a href="[^"]+\/">/g)?.length > 3)) {
                        this.findings.push(createFinding({
                            module: 'security',
                            title: `Directory Listing Enabled: ${dir}`,
                            severity: 'medium',
                            affected_surface: url,
                            description: `Directory listing is enabled at "${dir}". This allows anyone to browse the directory contents, potentially revealing sensitive files, backup files, or internal structure.`,
                            reproduction: [
                                `1. Navigate to ${url}`,
                                '2. Observe the directory listing showing file names and sizes',
                            ],
                            remediation: 'Disable directory listing in your web server configuration. Apache: `Options -Indexes`. Nginx: remove `autoindex on`.',
                        }));
                    }
                }
            } catch {
                // Not accessible
            }
        }
    }

    /**
     * Check error pages for information disclosure.
     */
    async _checkErrorDisclosure(baseUrl) {
        // Trigger error pages with various paths
        const errorPaths = [
            '/this-page-definitely-does-not-exist-vibe-shield-test-404',
            '/api/nonexistent-endpoint-vibe-shield-test',
            "/%00",  // Null byte
            '/..%2f..%2f..%2fetc/passwd', // Path traversal
        ];

        for (const errorPath of errorPaths) {
            try {
                const url = new URL(errorPath, baseUrl).toString();
                const resp = await fetch(url, {
                    signal: AbortSignal.timeout(10000),
                    redirect: 'follow',
                });

                const body = await resp.text();

                for (const { regex, name, severity } of InfraScanner.ERROR_DISCLOSURE_PATTERNS) {
                    const match = body.match(regex);
                    if (match) {
                        this.findings.push(createFinding({
                            module: 'security',
                            title: `Error Information Disclosure: ${name}`,
                            severity,
                            affected_surface: url,
                            description: `The error page reveals internal information: ${name}.\n\nMatched pattern: "${match[0]}"\n\nDetailed error messages help attackers understand the technology stack, internal paths, and potential vulnerabilities.`,
                            reproduction: [
                                `1. Navigate to ${url}`,
                                `2. Error response contains: ${match[0]}`,
                            ],
                            evidence: `Matched: ${match[0]}\n\nFull response excerpt:\n${body.substring(Math.max(0, match.index - 100), match.index + match[0].length + 100)}`,
                            remediation: 'Configure custom error pages that do not reveal stack traces, file paths, or technology details. Set NODE_ENV=production or equivalent for your framework.',
                        }));
                    }
                }
            } catch {
                // Request failed
            }
        }
    }

    /**
     * Check if GraphQL introspection is enabled.
     */
    async _checkGraphQLIntrospection(baseUrl) {
        const graphqlPaths = ['/graphql', '/api/graphql', '/__graphql', '/graphql/v1'];

        for (const gqlPath of graphqlPaths) {
            try {
                const url = new URL(gqlPath, baseUrl).toString();
                const resp = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        query: '{ __schema { types { name } } }',
                    }),
                    signal: AbortSignal.timeout(5000),
                });

                if (resp.ok) {
                    const data = await resp.json().catch(() => null);
                    if (data?.data?.__schema) {
                        const typeCount = data.data.__schema.types?.length || 0;
                        this.findings.push(createFinding({
                            module: 'security',
                            title: `GraphQL Introspection Enabled: ${gqlPath}`,
                            severity: 'medium',
                            affected_surface: url,
                            description: `GraphQL introspection is enabled at "${gqlPath}", exposing the entire API schema (${typeCount} types discovered). Attackers can use this to map all queries, mutations, and types to find sensitive operations.`,
                            reproduction: [
                                `1. Send POST to ${url}`,
                                `2. Body: {"query": "{ __schema { types { name } } }"}`,
                                `3. Response contains full schema with ${typeCount} types`,
                            ],
                            remediation: 'Disable GraphQL introspection in production. Most GraphQL servers have a configuration option for this.',
                            references: ['https://www.apollographql.com/docs/apollo-server/security/introspection/'],
                        }));
                    }
                }
            } catch {
                // Not a GraphQL endpoint
            }
        }
    }

    /**
     * Check if a response is a generic SPA catch-all page.
     */
    _isGenericSPAPage(body, path) {
        // SPAs often serve the same index.html for all routes
        if (!body.includes('<!DOCTYPE html') && !body.includes('<!doctype html')) return false;
        // Check if it looks like a generic app shell (no path-specific content)
        if (body.includes('id="root"') || body.includes('id="app"') || body.includes('id="__next"')) {
            // Likely a SPA — check if the path text doesn't appear in the body
            const pathName = path.replace(/[/._-]/g, '');
            return !body.toLowerCase().includes(pathName.toLowerCase());
        }
        return false;
    }

    _containsSensitiveData(body) {
        const sensitivePatterns = [
            /password/i, /secret/i, /private.*key/i, /access.*token/i,
            /database/i, /DB_HOST/i, /api.?key/i,
        ];
        return sensitivePatterns.some(p => p.test(body));
    }
}

export default InfraScanner;
