import { createFinding } from '../../utils/finding.js';
import dns from 'dns/promises';

/**
 * SubdomainScanner — Discovers related subdomains via DNS bruteforce
 * and Certificate Transparency logs.
 *
 * Methods:
 *   1. Common prefix DNS bruteforce (80+ prefixes)
 *   2. crt.sh Certificate Transparency log query
 *   3. HTTP probe discovered subdomains for status + title
 */
export class SubdomainScanner {
    constructor(logger) {
        this.logger = logger;
    }

    async scan(surfaceInventory) {
        this.logger?.info?.('Subdomain Scanner: starting enumeration');
        const findings = [];
        const baseUrl = new URL(surfaceInventory.baseUrl);
        const domain = this._extractRootDomain(baseUrl.hostname);

        if (!domain) {
            this.logger?.info?.('Subdomain Scanner: could not extract root domain — skipping');
            return findings;
        }

        // Discover subdomains from both methods
        const discovered = new Map(); // hostname → { source, status, title }

        // Method 1: Common prefix bruteforce
        const bruteforceResults = await this._bruteforceScan(domain);
        for (const sub of bruteforceResults) {
            discovered.set(sub, { source: 'dns-bruteforce' });
        }

        // Method 2: Certificate Transparency logs
        const ctResults = await this._ctLogScan(domain);
        for (const sub of ctResults) {
            if (!discovered.has(sub)) {
                discovered.set(sub, { source: 'ct-log' });
            }
        }

        this.logger?.info?.(
            `Subdomain Scanner: found ${discovered.size} subdomains ` +
            `(${bruteforceResults.length} DNS, ${ctResults.length} CT)`
        );

        // HTTP probe each discovered subdomain
        const probed = await this._probeSubdomains(discovered);

        // Classify and create findings
        const interestingPatterns = {
            admin: { label: 'Admin Panel', severity: 'medium' },
            staging: { label: 'Staging Environment', severity: 'medium' },
            stage: { label: 'Staging Environment', severity: 'medium' },
            dev: { label: 'Development Environment', severity: 'medium' },
            test: { label: 'Test Environment', severity: 'medium' },
            internal: { label: 'Internal Service', severity: 'medium' },
            jenkins: { label: 'CI/CD Server (Jenkins)', severity: 'high' },
            gitlab: { label: 'GitLab Instance', severity: 'high' },
            grafana: { label: 'Monitoring Dashboard', severity: 'medium' },
            kibana: { label: 'Log Dashboard', severity: 'medium' },
            prometheus: { label: 'Metrics Server', severity: 'medium' },
            phpmyadmin: { label: 'Database Admin', severity: 'high' },
            mysql: { label: 'Database Server', severity: 'high' },
            postgres: { label: 'Database Server', severity: 'high' },
            redis: { label: 'Cache Server', severity: 'medium' },
            mongo: { label: 'Database Server', severity: 'high' },
            elastic: { label: 'Elasticsearch', severity: 'medium' },
            vpn: { label: 'VPN Endpoint', severity: 'low' },
            mail: { label: 'Mail Server', severity: 'low' },
            ftp: { label: 'FTP Server', severity: 'medium' },
            backup: { label: 'Backup Server', severity: 'high' },
        };

        for (const [hostname, info] of probed) {
            if (!info.alive) continue;

            // Check if this is an interesting subdomain
            const prefix = hostname.replace('.' + domain, '').split('.')[0];
            const match = interestingPatterns[prefix];

            if (match) {
                findings.push(createFinding({
                    module: 'security',
                    title: `Exposed ${match.label}: ${hostname}`,
                    severity: match.severity,
                    affected_surface: `https://${hostname}`,
                    description:
                        `Discovered ${match.label.toLowerCase()} at ${hostname} ` +
                        `(HTTP ${info.status}). Title: "${info.title || 'N/A'}". ` +
                        `Source: ${info.source}. ` +
                        `This may expose sensitive configuration, internal tools, or unprotected environments.`,
                    evidence: {
                        hostname,
                        status: info.status,
                        title: info.title,
                        source: info.source,
                        ip: info.ip,
                    },
                    remediation:
                        'Restrict access to internal subdomains via VPN or IP allowlisting. ' +
                        'Ensure staging/dev environments require authentication. ' +
                        'Remove DNS records for decommissioned services.',
                    references: [
                        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
                    ],
                }));
            } else {
                // Informational finding for any live subdomain
                findings.push(createFinding({
                    module: 'security',
                    title: `Subdomain Discovered: ${hostname}`,
                    severity: 'info',
                    affected_surface: `https://${hostname}`,
                    description:
                        `Live subdomain at ${hostname} (HTTP ${info.status}). ` +
                        `Title: "${info.title || 'N/A'}". Source: ${info.source}.`,
                    evidence: {
                        hostname,
                        status: info.status,
                        title: info.title,
                        source: info.source,
                    },
                    remediation: 'Review all subdomains and ensure they are intentionally public.',
                }));
            }
        }

        this.logger?.info?.(`Subdomain Scanner: ${findings.length} findings (${probed.size} alive)`);
        return findings;
    }

    // ── DNS Bruteforce ──────────────────────────────────

    async _bruteforceScan(domain) {
        const prefixes = [
            'api', 'app', 'admin', 'staging', 'stage', 'dev', 'test',
            'beta', 'alpha', 'internal', 'intranet', 'portal', 'dashboard',
            'cms', 'blog', 'docs', 'doc', 'help', 'support',
            'mail', 'email', 'smtp', 'imap', 'pop',
            'cdn', 'static', 'assets', 'media', 'images', 'img',
            'status', 'monitor', 'health', 'metrics',
            'grafana', 'kibana', 'prometheus', 'elasticsearch', 'elastic',
            'jenkins', 'ci', 'cd', 'gitlab', 'github', 'bitbucket',
            'jira', 'confluence', 'wiki',
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
            'cache', 'queue', 'rabbitmq', 'kafka',
            'vpn', 'remote', 'gateway', 'proxy',
            'ftp', 'sftp', 'backup', 'bak',
            'phpmyadmin', 'adminer', 'pgadmin',
            'www', 'web', 'shop', 'store', 'checkout',
            'sandbox', 'demo', 'preview', 'uat',
            'auth', 'login', 'sso', 'oauth', 'id', 'identity',
            'ws', 'websocket', 'socket', 'realtime',
            'graphql', 'rest', 'rpc',
            'v1', 'v2', 'v3',
            'new', 'old', 'legacy', 'next',
        ];

        const found = [];
        const batchSize = 20;

        for (let i = 0; i < prefixes.length; i += batchSize) {
            const batch = prefixes.slice(i, i + batchSize);
            const results = await Promise.allSettled(
                batch.map(prefix => this._dnsLookup(`${prefix}.${domain}`))
            );

            results.forEach((result, idx) => {
                if (result.status === 'fulfilled' && result.value) {
                    found.push(`${batch[idx]}.${domain}`);
                }
            });
        }

        return found;
    }

    async _dnsLookup(hostname) {
        try {
            const addresses = await dns.resolve4(hostname);
            return addresses.length > 0 ? addresses[0] : null;
        } catch {
            return null;
        }
    }

    // ── Certificate Transparency ─────────────────────────

    async _ctLogScan(domain) {
        const found = [];

        try {
            const response = await fetch(
                `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
                {
                    headers: { 'User-Agent': 'VIBE SHIELD-SecurityScanner/1.0' },
                    signal: AbortSignal.timeout(15000),
                }
            );

            if (!response.ok) return found;

            const entries = await response.json();
            const seen = new Set();

            for (const entry of entries) {
                const names = (entry.name_value || '').split('\n');
                for (let name of names) {
                    name = name.trim().toLowerCase();
                    if (name.startsWith('*.')) name = name.slice(2);
                    if (name.endsWith('.' + domain) && !seen.has(name)) {
                        seen.add(name);
                        found.push(name);
                    }
                }
            }
        } catch (err) {
            this.logger?.debug?.(`CT log query failed: ${err.message}`);
        }

        // Cap at 100 to avoid excessive probing
        return found.slice(0, 100);
    }

    // ── HTTP Probing ─────────────────────────────────────

    async _probeSubdomains(discovered) {
        const probed = new Map();
        const entries = [...discovered.entries()];
        const batchSize = 10;

        for (let i = 0; i < entries.length; i += batchSize) {
            const batch = entries.slice(i, i + batchSize);
            const results = await Promise.allSettled(
                batch.map(([hostname, info]) => this._probeHost(hostname, info))
            );

            results.forEach((result, idx) => {
                if (result.status === 'fulfilled' && result.value) {
                    probed.set(batch[idx][0], result.value);
                }
            });
        }

        return probed;
    }

    async _probeHost(hostname, info) {
        // Try HTTPS first, fall back to HTTP
        for (const proto of ['https', 'http']) {
            try {
                const response = await fetch(`${proto}://${hostname}`, {
                    redirect: 'follow',
                    headers: { 'User-Agent': 'VIBE SHIELD-SecurityScanner/1.0' },
                    signal: AbortSignal.timeout(8000),
                });

                // Extract title from HTML
                let title = '';
                const contentType = response.headers.get('content-type') || '';
                if (contentType.includes('text/html')) {
                    const body = await response.text();
                    const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i);
                    if (titleMatch) title = titleMatch[1].trim().slice(0, 100);
                }

                // DNS lookup for IP
                let ip = null;
                try {
                    const addresses = await dns.resolve4(hostname);
                    ip = addresses[0] || null;
                } catch { /* ignore */ }

                return {
                    ...info,
                    alive: true,
                    status: response.status,
                    title,
                    protocol: proto,
                    ip,
                };
            } catch {
                // Try next protocol
            }
        }

        return { ...info, alive: false };
    }

    // ── Helpers ──────────────────────────────────────────

    _extractRootDomain(hostname) {
        // Handle cases like api.example.com → example.com
        // Simple heuristic: take last 2 parts (or 3 for co.uk etc.)
        const parts = hostname.split('.');
        if (parts.length <= 2) return hostname;

        // Common TLDs with two parts
        const twoPartTLDs = ['co.uk', 'co.in', 'com.au', 'co.jp', 'co.kr', 'com.br', 'co.za'];
        const lastTwo = parts.slice(-2).join('.');
        if (twoPartTLDs.includes(lastTwo)) {
            return parts.slice(-3).join('.');
        }

        return parts.slice(-2).join('.');
    }
}

export default SubdomainScanner;
