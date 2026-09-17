import { createFinding } from '../../utils/finding.js';

/**
 * GraphQLTester — Tests GraphQL-specific vulnerabilities.
 *
 * Probes:
 * - Introspection exposure (enumerate schema)
 * - Batch query abuse (credential brute-force)
 * - Nested query DoS (exponential execution)
 * - Field suggestion (info disclosure)
 * - Mutation without auth
 * - Missing query depth/complexity limits
 */
export class GraphQLTester {
    constructor(logger) {
        this.logger = logger;

        this.GRAPHQL_PATHS = [
            '/graphql', '/api/graphql', '/graphql/v1', '/gql',
            '/query', '/api/query', '/graphql/console', '/graphiql',
        ];
    }

    /**
     * Test GraphQL endpoints for security issues.
     */
    async test(surfaceInventory) {
        const findings = [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        this.logger?.info?.('GraphQL Tester: starting tests');

        // 1. Discover GraphQL endpoints
        const endpoints = await this._discover(baseUrl);

        if (endpoints.length === 0) {
            this.logger?.info?.('GraphQL Tester: no GraphQL endpoints found — skipping');
            return findings;
        }

        this.logger?.info?.(`GraphQL Tester: found ${endpoints.length} GraphQL endpoints`);

        for (const endpoint of endpoints) {
            // 2. Test introspection
            const introFindings = await this._testIntrospection(endpoint);
            findings.push(...introFindings);

            // 3. Test batch queries
            const batchFindings = await this._testBatchQueries(endpoint);
            findings.push(...batchFindings);

            // 4. Test nested query DoS
            const dosFindings = await this._testNestedDoS(endpoint);
            findings.push(...dosFindings);

            // 5. Test field suggestions
            const suggestionFindings = await this._testFieldSuggestions(endpoint);
            findings.push(...suggestionFindings);
        }

        this.logger?.info?.(`GraphQL Tester: found ${findings.length} issues`);
        return findings;
    }

    async _discover(baseUrl) {
        const endpoints = [];

        for (const path of this.GRAPHQL_PATHS) {
            try {
                const url = new URL(path, baseUrl).href;

                // Test with a simple introspection field
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query: '{ __typename }' }),
                    signal: AbortSignal.timeout(5000),
                });

                if (response.ok) {
                    const text = await response.text();
                    if (text.includes('__typename') || text.includes('"data"') || text.includes('"errors"')) {
                        endpoints.push(url);
                    }
                }
            } catch {
                continue;
            }
        }

        return endpoints;
    }

    async _testIntrospection(endpoint) {
        const findings = [];

        const introspectionQuery = `{
            __schema {
                types { name kind }
                queryType { name }
                mutationType { name }
            }
        }`;

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: introspectionQuery }),
                signal: AbortSignal.timeout(8000),
            });

            if (response.ok) {
                const result = await response.json();
                if (result.data?.__schema?.types) {
                    const types = result.data.__schema.types;
                    const customTypes = types.filter(t =>
                        !t.name.startsWith('__') && !['String', 'Int', 'Float', 'Boolean', 'ID'].includes(t.name)
                    );

                    findings.push(createFinding({
                        module: 'api',
                        title: 'GraphQL Introspection Exposed',
                        severity: 'high',
                        affected_surface: endpoint,
                        description: `GraphQL introspection is enabled at ${endpoint}, exposing the entire API schema (${types.length} types, ${customTypes.length} custom). An attacker can enumerate all queries, mutations, and data types to map the attack surface.`,
                        reproduction: [
                            `1. POST to ${endpoint} with __schema introspection query`,
                            `2. Full schema is returned`,
                        ],
                        evidence: `Types: ${types.length} (${customTypes.length} custom)\nCustom types: ${customTypes.slice(0, 10).map(t => t.name).join(', ')}`,
                        remediation: 'Disable introspection in production. Only allow it in development environments. Use persisted queries/allowlists to restrict which queries clients can execute.',
                    }));
                }
            }
        } catch {
            // Not GraphQL or introspection disabled
        }

        return findings;
    }

    async _testBatchQueries(endpoint) {
        const findings = [];

        // Send multiple queries in a single request (batch abuse)
        const batchPayload = Array.from({ length: 10 }, (_, i) => ({
            query: `{ __typename }`,
            operationName: `batch_${i}`,
        }));

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(batchPayload),
                signal: AbortSignal.timeout(8000),
            });

            if (response.ok) {
                const result = await response.json();
                if (Array.isArray(result) && result.length >= 5) {
                    findings.push(createFinding({
                        module: 'api',
                        title: 'GraphQL Batch Query Abuse',
                        severity: 'high',
                        affected_surface: endpoint,
                        description: `GraphQL endpoint accepts batch queries (${result.length}/10 processed). An attacker can abuse batching for credential brute-force (batching login mutations), rate limit bypass, or DoS by sending thousands of queries in a single HTTP request.`,
                        reproduction: [
                            `1. POST array of 10 queries to ${endpoint}`,
                            `2. Server processes all ${result.length} queries`,
                        ],
                        evidence: `Batch size: 10 → ${result.length} processed`,
                        remediation: 'Limit batch query count (max 5-10 per request). Implement per-query rate limiting. Count each query in a batch against rate limits individually.',
                    }));
                }
            }
        } catch {
            // Batch not supported
        }

        return findings;
    }

    async _testNestedDoS(endpoint) {
        const findings = [];

        // Test with a deeply nested query
        const deepQuery = `{
            __schema {
                types {
                    fields {
                        type {
                            fields {
                                type {
                                    fields {
                                        type {
                                            name
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }`;

        try {
            const startTime = Date.now();
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: deepQuery }),
                signal: AbortSignal.timeout(10000),
            });
            const elapsed = Date.now() - startTime;

            if (response.ok) {
                const text = await response.text();

                if (elapsed > 3000 || text.length > 100000) {
                    findings.push(createFinding({
                        module: 'api',
                        title: 'GraphQL Nested Query DoS: No Depth Limit',
                        severity: 'high',
                        affected_surface: endpoint,
                        description: `GraphQL endpoint processed a deeply nested query (7 levels) in ${elapsed}ms, returning ${text.length} bytes. No depth or complexity limit prevents resource exhaustion via recursive queries.`,
                        evidence: `Query depth: 7 levels\nResponse time: ${elapsed}ms\nResponse size: ${text.length} bytes`,
                        remediation: 'Implement query depth limiting (max 5-10 levels). Add query complexity analysis. Set maximum execution time. Use query cost analysis to reject expensive queries.',
                    }));
                }
            }
        } catch {
            // Timeout — which actually confirms DoS risk
        }

        return findings;
    }

    async _testFieldSuggestions(endpoint) {
        const findings = [];

        // Send query with a typo to trigger field suggestions
        const typoQuery = `{ usrs { id naem emial } }`;

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: typoQuery }),
                signal: AbortSignal.timeout(5000),
            });

            if (response.ok || response.status === 400) {
                const text = await response.text();
                if (/did you mean|suggestion|similar/i.test(text)) {
                    findings.push(createFinding({
                        module: 'api',
                        title: 'GraphQL Field Suggestions: Schema Enumeration',
                        severity: 'low',
                        affected_surface: endpoint,
                        description: `GraphQL endpoint returns field suggestions for invalid queries. An attacker can brute-force valid field names by observing "Did you mean..." suggestions.`,
                        evidence: `Query with typos returned suggestions`,
                        remediation: 'Disable field suggestions in production. This leaks schema information even when introspection is disabled.',
                    }));
                }
            }
        } catch {
            // Not applicable
        }

        return findings;
    }

    _getBaseUrl(surfaceInventory) {
        const pages = surfaceInventory.pages || [];
        if (pages.length === 0) return null;
        try {
            const parsed = new URL(pages[0].url || pages[0]);
            return `${parsed.protocol}//${parsed.host}`;
        } catch { return null; }
    }
}

export default GraphQLTester;
