import { createFinding } from '../../utils/finding.js';
import https from 'https';
import http from 'http';

/**
 * TLS Checker — Reviews TLS/SSL configuration.
 * Checks certificate validity, protocol version, HTTPS enforcement, and mixed content.
 */
export class TLSChecker {
    constructor(logger) {
        this.logger = logger;
        this.findings = [];
    }

    /**
     * Run TLS checks on the target.
     */
    async check(surfaceInventory) {
        const baseUrl = surfaceInventory.baseUrl;

        // Check HTTPS/TLS
        await this._checkCertificate(baseUrl);
        await this._checkHTTPSEnforcement(baseUrl);
        await this._checkMixedContent(surfaceInventory);

        this.logger?.info?.(`TLS checker found ${this.findings.length} issues`);
        return this.findings;
    }

    /**
     * Check TLS certificate details.
     */
    async _checkCertificate(baseUrl) {
        try {
            const url = new URL(baseUrl);
            if (url.protocol !== 'https:') {
                this.findings.push(createFinding({
                    module: 'security',
                    title: 'Site Not Using HTTPS',
                    severity: 'high',
                    affected_surface: baseUrl,
                    description: `The target site is served over HTTP (${baseUrl}). All data including credentials, session tokens, and personal information is transmitted in plaintext, making it vulnerable to eavesdropping and man-in-the-middle attacks.`,
                    reproduction: [
                        `1. Navigate to ${baseUrl}`,
                        '2. Note the URL uses http:// not https://',
                    ],
                    remediation: 'Enable HTTPS with a valid TLS certificate. Use services like Let\'s Encrypt for free certificates. Redirect all HTTP traffic to HTTPS.',
                    references: ['https://letsencrypt.org/'],
                }));
                return;
            }

            // Check certificate details
            await new Promise((resolve) => {
                const req = https.get(baseUrl, { rejectUnauthorized: false, timeout: 10000 }, (res) => {
                    const cert = res.socket.getPeerCertificate();

                    if (!cert || Object.keys(cert).length === 0) {
                        this.findings.push(createFinding({
                            module: 'security',
                            title: 'TLS Certificate Not Available',
                            severity: 'high',
                            affected_surface: baseUrl,
                            description: 'Could not retrieve the TLS certificate for this site.',
                            reproduction: [`1. Attempt to inspect TLS certificate for ${baseUrl}`],
                            remediation: 'Ensure a valid TLS certificate is installed and configured correctly.',
                        }));
                        resolve();
                        return;
                    }

                    // Check expiration
                    if (cert.valid_to) {
                        const expiryDate = new Date(cert.valid_to);
                        const now = new Date();
                        const daysUntilExpiry = Math.floor((expiryDate - now) / (1000 * 86400));

                        if (daysUntilExpiry < 0) {
                            this.findings.push(createFinding({
                                module: 'security',
                                title: 'TLS Certificate Expired',
                                severity: 'critical',
                                affected_surface: baseUrl,
                                description: `The TLS certificate expired on ${cert.valid_to} (${Math.abs(daysUntilExpiry)} days ago). Browsers will show security warnings and users cannot trust the connection.`,
                                reproduction: [
                                    `1. Navigate to ${baseUrl}`,
                                    `2. Browser shows certificate expired warning`,
                                    `3. Certificate expired: ${cert.valid_to}`,
                                ],
                                remediation: 'Immediately renew the TLS certificate. Set up auto-renewal to prevent future expirations.',
                            }));
                        } else if (daysUntilExpiry < 30) {
                            this.findings.push(createFinding({
                                module: 'security',
                                title: `TLS Certificate Expiring Soon (${daysUntilExpiry} days)`,
                                severity: 'medium',
                                affected_surface: baseUrl,
                                description: `The TLS certificate expires on ${cert.valid_to} (${daysUntilExpiry} days from now). Renew it before expiration to avoid service disruption.`,
                                reproduction: [
                                    `1. Inspect certificate for ${baseUrl}`,
                                    `2. Expiry: ${cert.valid_to} (${daysUntilExpiry} days remaining)`,
                                ],
                                remediation: 'Renew the TLS certificate before it expires. Set up auto-renewal with your certificate provider.',
                            }));
                        }
                    }

                    // Check if self-signed
                    if (cert.issuer && cert.subject &&
                        JSON.stringify(cert.issuer) === JSON.stringify(cert.subject)) {
                        this.findings.push(createFinding({
                            module: 'security',
                            title: 'Self-Signed TLS Certificate',
                            severity: 'medium',
                            affected_surface: baseUrl,
                            description: `The TLS certificate appears to be self-signed (issuer matches subject). Browsers will show security warnings and users won't trust the connection.\n\nSubject: ${cert.subject?.CN || 'unknown'}\nIssuer: ${cert.issuer?.CN || 'unknown'}`,
                            reproduction: [
                                `1. Navigate to ${baseUrl}`,
                                '2. Browser shows "Not Secure" or certificate warning',
                            ],
                            remediation: 'Replace with a certificate from a trusted Certificate Authority. Use Let\'s Encrypt for free certificates.',
                        }));
                    }

                    resolve();
                });

                req.on('error', () => resolve());
                req.setTimeout(10000, () => { req.destroy(); resolve(); });
            });
        } catch (err) {
            this.logger?.debug?.(`TLS certificate check failed: ${err.message}`);
        }
    }

    /**
     * Check if HTTP redirects to HTTPS.
     */
    async _checkHTTPSEnforcement(baseUrl) {
        try {
            const url = new URL(baseUrl);
            if (url.protocol !== 'https:') return; // Already flagged

            // Try HTTP version
            const httpUrl = baseUrl.replace('https://', 'http://');

            await new Promise((resolve) => {
                const req = http.get(httpUrl, { timeout: 10000 }, (res) => {
                    if (res.statusCode >= 300 && res.statusCode < 400) {
                        const location = res.headers.location || '';
                        if (location.startsWith('https://')) {
                            // Good — redirects to HTTPS
                            resolve();
                            return;
                        }
                    }

                    // HTTP served without redirect to HTTPS
                    if (res.statusCode === 200) {
                        this.findings.push(createFinding({
                            module: 'security',
                            title: 'HTTP Not Redirecting to HTTPS',
                            severity: 'medium',
                            affected_surface: httpUrl,
                            description: `The HTTP version of the site (${httpUrl}) serves content instead of redirecting to HTTPS. Users who navigate to the HTTP version are not automatically upgraded to a secure connection.`,
                            reproduction: [
                                `1. Navigate to ${httpUrl} (note: http not https)`,
                                `2. Page loads over HTTP with status ${res.statusCode}`,
                                '3. No redirect to HTTPS occurs',
                            ],
                            remediation: 'Configure your web server to redirect all HTTP requests to HTTPS (301 permanent redirect). Add HSTS header to prevent future HTTP access.',
                        }));
                    }

                    resolve();
                });

                req.on('error', () => resolve()); // HTTP may not be listening — that's fine
                req.setTimeout(10000, () => { req.destroy(); resolve(); });
            });
        } catch (err) {
            this.logger?.debug?.(`HTTPS enforcement check failed: ${err.message}`);
        }
    }

    /**
     * Check for mixed content (HTTP resources on HTTPS pages).
     */
    async _checkMixedContent(surfaceInventory) {
        const baseUrl = surfaceInventory.baseUrl;
        if (!baseUrl.startsWith('https://')) return;

        // Check crawled page data for HTTP resources
        for (const page of surfaceInventory.pages) {
            if (typeof page.status !== 'number') continue;

            // Look for HTTP URLs in links that should be HTTPS
            for (const link of (page.links || [])) {
                if (link.startsWith('http://') && !link.includes('localhost')) {
                    // Only flag if the link is to a resource (js, css, img) not navigation
                    const ext = link.split('.').pop()?.toLowerCase();
                    if (['js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'woff', 'woff2'].includes(ext)) {
                        this.findings.push(createFinding({
                            module: 'security',
                            title: `Mixed Content: HTTP Resource on HTTPS Page`,
                            severity: 'medium',
                            affected_surface: page.url,
                            description: `An HTTPS page loads a resource over HTTP: ${link}. Mixed content can be intercepted and modified by attackers, potentially injecting malicious code.`,
                            reproduction: [
                                `1. Navigate to ${page.url} (HTTPS)`,
                                `2. Resource loaded over HTTP: ${link}`,
                            ],
                            remediation: 'Change all resource URLs to use HTTPS or protocol-relative URLs (//).',
                        }));
                        break; // One finding per page
                    }
                }
            }
        }
    }
}

export default TLSChecker;
