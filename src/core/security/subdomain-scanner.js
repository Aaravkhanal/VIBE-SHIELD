import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import tls from 'node:tls';
import { createFinding } from '../../utils/finding.js';
import { domainMetadata, isHostnameInScope, organizationScopes } from '../../utils/domain-scope.js';
import { responseSimilarity } from '../../utils/response-similarity.js';

const PREFIXES = [
    'api', 'app', 'admin', 'staging', 'stage', 'dev', 'test', 'beta', 'internal',
    'portal', 'dashboard', 'status', 'monitor', 'grafana', 'kibana', 'prometheus',
    'jenkins', 'ci', 'gitlab', 'db', 'mysql', 'postgres', 'mongo', 'redis', 'vpn',
    'backup', 'phpmyadmin', 'adminer', 'auth', 'login', 'sso', 'graphql', 'www',
];

const SERVICE_FINGERPRINTS = [
    { id: 'jenkins', label: 'Jenkins', severity: 'high', headers: [['x-jenkins']], body: [/jenkins/i, /adjuncts\//i] },
    { id: 'gitlab', label: 'GitLab', severity: 'high', headers: [['x-gitlab-meta']], body: [/gitlab/i, /gon\.gitlab/i] },
    { id: 'grafana', label: 'Grafana', severity: 'medium', headers: [['x-grafana-org-id']], body: [/grafana/i, /public\/build\/.*grafana/i] },
    { id: 'kibana', label: 'Kibana', severity: 'medium', headers: [['kbn-name'], ['x-kibana-request-id']], body: [/kibana/i, /kbn-injected-metadata/i] },
    { id: 'prometheus', label: 'Prometheus', severity: 'medium', body: [/prometheus time series collection/i, /<title>prometheus/i] },
    { id: 'phpmyadmin', label: 'phpMyAdmin', severity: 'high', body: [/phpmyadmin/i, /pmahomme/i] },
    { id: 'elasticsearch', label: 'Elasticsearch', severity: 'medium', body: [/"cluster_name"\s*:/i, /"tagline"\s*:\s*"you know, for search"/i] },
];

function dnsSignature(record) {
    if (!record) return '';
    return [...(record.addresses || []), ...(record.cnames || []).map(item => `cname:${item}`)].sort().join('|');
}

/**
 * Discovers subdomains only inside an authorized organization scope. External
 * DNS/CT enumeration is disabled by default and private PSL entries (for
 * example vercel.app) are treated as suffixes, never as tenant ownership.
 */
export class SubdomainScanner {
    constructor(config = {}, logger = null) {
        if (config && typeof config.info === 'function' && !logger) {
            this.logger = config;
            this.config = {};
        } else {
            this.config = config || {};
            this.logger = logger;
        }
    }

    async scan(surfaceInventory) {
        const settings = this.config.subdomains || {};
        if (settings.external_enumeration !== true) {
            this.logger?.info?.('Subdomain Scanner: external enumeration disabled (enable subdomains.external_enumeration explicitly)');
            return [];
        }

        const baseUrl = new URL(surfaceInventory.baseUrl);
        if (!domainMetadata(baseUrl.hostname)) return [];
        const scopes = organizationScopes(baseUrl.hostname, settings.organization_domains || []);
        if (scopes.length === 0) return [];

        const findings = [];
        const baseDns = await this._resolveDns(baseUrl.hostname);
        const baseProbe = await this._probeHost(baseUrl.hostname, { source: 'scan-target' });
        const maxCandidates = Math.min(Math.max(Number(settings.max_candidates) || 100, 1), 500);

        for (const scope of scopes) {
            this.logger?.info?.(`Subdomain Scanner: enumerating authorized scope ${scope.domain} (${scope.source})`);
            const wildcard = await this._detectWildcard(scope.domain);
            const discovered = new Map();

            for (const item of await this._bruteforceScan(scope.domain)) discovered.set(item.hostname, { source: 'dns-bruteforce', dns: item.dns });
            for (const hostname of await this._ctLogScan(scope.domain)) {
                if (isHostnameInScope(hostname, scope.domain) && !discovered.has(hostname)) discovered.set(hostname, { source: 'ct-log' });
            }

            const limited = new Map([...discovered].slice(0, maxCandidates));
            const probed = await this._probeSubdomains(limited);
            for (const [hostname, info] of probed) {
                if (!info.alive || !isHostnameInScope(hostname, scope.domain)) continue;
                const candidateDns = info.dns || await this._resolveDns(hostname);
                const wildcardDnsMatch = Boolean(wildcard.detected && dnsSignature(candidateDns) === wildcard.signature);
                const wildcardResponseSimilarity = wildcard.probe?.alive ? responseSimilarity(info.body, wildcard.probe.body) : 0;
                if (wildcardDnsMatch && (info.source === 'dns-bruteforce' || wildcardResponseSimilarity >= 0.85)) {
                    this.logger?.debug?.(`Subdomain Scanner: ignored wildcard response ${hostname}`);
                    continue;
                }

                const tlsCertificate = await this._inspectCertificate(hostname);
                const sharedAddresses = (candidateDns.addresses || []).filter(address => baseDns.addresses?.includes(address));
                const sharedCnames = (candidateDns.cnames || []).filter(name => baseDns.cnames?.includes(name));
                const targetSimilarity = baseProbe.alive ? responseSimilarity(info.body, baseProbe.body) : 0;
                const ownership = {
                    verified: true,
                    scope: scope.domain,
                    scopeSource: scope.source,
                    dnsNamespaceControl: true,
                    sharedAddresses,
                    sharedCnames,
                    tlsNames: tlsCertificate.names,
                    tlsMatchesScope: tlsCertificate.names.some(name => isHostnameInScope(name.replace(/^\*\./, ''), scope.domain)),
                    targetResponseSimilarity: Number(targetSimilarity.toFixed(3)),
                    wildcardDnsMatch,
                    wildcardResponseSimilarity: Number(wildcardResponseSimilarity.toFixed(3)),
                };

                const fingerprint = this._fingerprintService(info);
                if (fingerprint) findings.push(this._serviceFinding(hostname, info, fingerprint, ownership));
                else findings.push(this._assetFinding(hostname, info, ownership));
            }
        }

        this.logger?.info?.(`Subdomain Scanner: ${findings.length} scoped findings`);
        return findings;
    }

    async _bruteforceScan(domain) {
        const found = [];
        for (let i = 0; i < PREFIXES.length; i += 10) {
            const batch = PREFIXES.slice(i, i + 10);
            const results = await Promise.all(batch.map(async prefix => {
                const hostname = `${prefix}.${domain}`;
                const record = await this._resolveDns(hostname);
                return dnsSignature(record) ? { hostname, dns: record } : null;
            }));
            found.push(...results.filter(Boolean));
        }
        return found;
    }

    async _resolveDns(hostname) {
        const [v4, v6, cname] = await Promise.allSettled([dns.resolve4(hostname), dns.resolve6(hostname), dns.resolveCname(hostname)]);
        return {
            addresses: [...(v4.status === 'fulfilled' ? v4.value : []), ...(v6.status === 'fulfilled' ? v6.value : [])].sort(),
            cnames: (cname.status === 'fulfilled' ? cname.value : []).map(item => item.toLowerCase().replace(/\.$/, '')).sort(),
        };
    }

    async _detectWildcard(domain) {
        const hosts = Array.from({ length: 3 }, () => `${crypto.randomBytes(8).toString('hex')}.${domain}`);
        const records = await Promise.all(hosts.map(hostname => this._resolveDns(hostname)));
        const signatures = records.map(dnsSignature).filter(Boolean);
        const signature = signatures.find(item => signatures.filter(candidate => candidate === item).length >= 2) || '';
        const index = records.findIndex(record => dnsSignature(record) === signature);
        return {
            detected: Boolean(signature),
            signature,
            samples: hosts.map((hostname, sampleIndex) => ({ hostname, signature: dnsSignature(records[sampleIndex]) })),
            probe: signature ? await this._probeHost(hosts[index], { source: 'wildcard-control', dns: records[index] }) : null,
        };
    }

    async _ctLogScan(domain) {
        try {
            const response = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
                headers: { 'User-Agent': 'VIBE-SHIELD-SecurityScanner/1.0' },
                signal: AbortSignal.timeout(15000),
            });
            if (!response.ok) return [];
            const names = new Set();
            for (const entry of await response.json()) {
                for (let name of String(entry.name_value || '').split('\n')) {
                    name = name.trim().toLowerCase().replace(/^\*\./, '');
                    if (isHostnameInScope(name, domain) && name !== domain) names.add(name);
                }
            }
            return [...names].slice(0, 100);
        } catch (error) {
            this.logger?.debug?.(`CT log query failed: ${error.message}`);
            return [];
        }
    }

    async _probeSubdomains(discovered) {
        const probed = new Map();
        const entries = [...discovered.entries()];
        for (let i = 0; i < entries.length; i += 10) {
            const batch = entries.slice(i, i + 10);
            const results = await Promise.all(batch.map(([hostname, info]) => this._probeHost(hostname, info)));
            results.forEach((result, index) => probed.set(batch[index][0], result));
        }
        return probed;
    }

    async _probeHost(hostname, info = {}) {
        for (const protocol of ['https', 'http']) {
            try {
                const response = await fetch(`${protocol}://${hostname}`, {
                    redirect: 'follow',
                    headers: { 'User-Agent': 'VIBE-SHIELD-SecurityScanner/1.0' },
                    signal: AbortSignal.timeout(8000),
                });
                const body = (await response.text()).slice(0, 250000);
                const title = body.match(/<title[^>]*>([^<]+)<\/title>/i)?.[1]?.trim().slice(0, 120) || '';
                return {
                    ...info, alive: true, status: response.status, title, protocol, body,
                    headers: Object.fromEntries(response.headers.entries()),
                    dns: info.dns || await this._resolveDns(hostname),
                };
            } catch { /* try the next protocol */ }
        }
        return { ...info, alive: false, body: '', headers: {}, dns: info.dns || await this._resolveDns(hostname) };
    }

    _inspectCertificate(hostname) {
        return new Promise(resolve => {
            let settled = false;
            const finish = value => {
                if (settled) return;
                settled = true;
                resolve(value || { names: [], issuer: null, validTo: null });
            };
            const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: false });
            socket.setTimeout(4000);
            socket.once('secureConnect', () => {
                const certificate = socket.getPeerCertificate();
                const names = String(certificate.subjectaltname || '').split(',').map(item => item.trim().replace(/^DNS:/, '').toLowerCase()).filter(Boolean);
                socket.destroy();
                finish({ names, issuer: certificate.issuer?.O || certificate.issuer?.CN || null, validTo: certificate.valid_to || null });
            });
            socket.once('timeout', () => { socket.destroy(); finish(); });
            socket.once('error', () => finish());
        });
    }

    _fingerprintService(info) {
        const headers = info.headers || {};
        for (const fingerprint of SERVICE_FINGERPRINTS) {
            const headerMatch = fingerprint.headers?.some(group => group.every(name => headers[name])) || false;
            const bodyMatches = fingerprint.body?.filter(pattern => pattern.test(`${info.title}\n${info.body}`)).length || 0;
            if (headerMatch || bodyMatches >= Math.min(2, fingerprint.body?.length || 2)) return { ...fingerprint, signals: { headerMatch, bodyMatches } };
        }
        return null;
    }

    _assetFinding(hostname, info, ownership) {
        return createFinding({
            module: 'security',
            title: `Owned Subdomain Discovered: ${hostname}`,
            severity: 'info',
            affected_surface: `${info.protocol}://${hostname}`,
            description: `A live hostname was verified inside organization scope ${ownership.scope}. No exposed product or sensitive service was inferred from the hostname alone.`,
            evidence: { hostname, status: info.status, title: info.title, source: info.source, ownership },
            verification: { level: 'informational', reason: 'DNS and scope evidence establish an owned attack-surface host; no vulnerability fingerprint was observed.', method: 'scoped-asset-discovery' },
            remediation: 'Review whether this hostname is intentionally public and keep its software, authentication, and DNS lifecycle managed.',
        });
    }

    _serviceFinding(hostname, info, fingerprint, ownership) {
        const url = `${info.protocol}://${hostname}`;
        return createFinding({
            module: 'security',
            title: `Verified ${fingerprint.label} Service: ${hostname}`,
            severity: info.status === 200 ? fingerprint.severity : 'low',
            affected_surface: url,
            description: `${fingerprint.label} was identified from response fingerprints at an ownership-verified hostname. The classification is based on response content or headers, not the hostname label. HTTP status: ${info.status}.`,
            reproduction: [`Request ${url}`, `Confirm the ${fingerprint.label} response fingerprints recorded in evidence`],
            evidence: { hostname, status: info.status, title: info.title, source: info.source, fingerprint: fingerprint.signals, ownership },
            verification: {
                level: 'high_confidence',
                reason: `The hostname is in verified organization scope and its HTTP response matches ${fingerprint.label} fingerprints.`,
                method: 'ownership-and-service-fingerprint',
                proof: {
                    originalRequest: { method: 'GET', url },
                    mutatedRequest: { method: 'GET', url, purpose: 'service fingerprint verification' },
                    baselineResponse: { targetResponseSimilarity: ownership.targetResponseSimilarity },
                    vulnerableResponse: { status: info.status, title: info.title, fingerprint: fingerprint.signals },
                    responseDifference: { productIdentified: fingerprint.label, wildcardRejected: !ownership.wildcardDnsMatch },
                    reproductionCommand: `curl -i ${JSON.stringify(url)}`,
                    accountRole: 'anonymous',
                },
            },
            remediation: 'Require authentication and network restrictions where appropriate, update the service, and remove public DNS when external reachability is unnecessary.',
        });
    }
}

export default SubdomainScanner;
