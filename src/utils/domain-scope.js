import { parse } from 'tldts';
import { isIP } from 'node:net';

export function normalizeHostname(value) {
    if (!value) return null;
    try {
        const input = String(value).trim().toLowerCase();
        const hostname = input.includes('://') ? new URL(input).hostname : input.split('/')[0].split(':')[0];
        return hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '') || null;
    } catch {
        return null;
    }
}

export function domainMetadata(value) {
    const hostname = normalizeHostname(value);
    if (!hostname || isIP(hostname) || hostname === 'localhost' || hostname.endsWith('.localhost')) return null;
    const result = parse(hostname, { allowPrivateDomains: true });
    if (!result.domain || !result.publicSuffix) return null;
    return {
        hostname,
        registrableDomain: result.domain,
        publicSuffix: result.publicSuffix,
        subdomain: result.subdomain || '',
        privateSuffix: result.isPrivate === true,
    };
}

export function organizationScopes(targetHostname, configuredDomains = []) {
    const configured = (Array.isArray(configuredDomains) ? configuredDomains : [configuredDomains])
        .map(normalizeHostname)
        .filter(Boolean)
        .filter(hostname => {
            const metadata = domainMetadata(hostname);
            return metadata && hostname !== metadata.publicSuffix;
        });

    if (configured.length > 0) {
        return [...new Set(configured)].map(domain => ({ domain, source: 'configured' }));
    }

    const metadata = domainMetadata(targetHostname);
    return metadata ? [{
        domain: metadata.registrableDomain,
        source: metadata.privateSuffix ? 'psl-private-domain' : 'psl-registrable-domain',
        publicSuffix: metadata.publicSuffix,
    }] : [];
}

export function isHostnameInScope(hostname, scopeDomain) {
    const host = normalizeHostname(hostname);
    const scope = normalizeHostname(scopeDomain);
    return Boolean(host && scope && (host === scope || host.endsWith(`.${scope}`)));
}
