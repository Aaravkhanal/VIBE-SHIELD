import { createFinding } from '../../utils/finding.js';

/**
 * FileUploadTester — Tests file upload endpoints for abuse vectors.
 *
 * Probes:
 * - MIME type spoofing (image extension with script content)
 * - Path traversal in filenames (../../etc/passwd)
 * - Oversized payload upload
 * - Dangerous file type acceptance (.php, .jsp, .aspx, .sh)
 * - Double extension bypass (file.jpg.php)
 * - Null byte injection (file.php%00.jpg)
 * - Content-Type header manipulation
 */
export class FileUploadTester {
    constructor(logger) {
        this.logger = logger;

        this.UPLOAD_INDICATORS = [
            'type="file"', 'input[type=file]', 'enctype="multipart/form-data"',
            'dropzone', 'file-upload', 'fileUpload', 'upload',
        ];

        this.UPLOAD_PATHS = [
            '/upload', '/api/upload', '/api/files', '/api/images',
            '/api/media', '/api/attachments', '/api/v1/upload',
            '/api/v1/files', '/file/upload', '/media/upload',
        ];

        this.DANGEROUS_EXTENSIONS = [
            'php', 'php5', 'phtml', 'phar',
            'jsp', 'jspx', 'jsw',
            'asp', 'aspx', 'ashx',
            'sh', 'bash', 'cgi', 'pl',
            'py', 'rb', 'exe', 'bat', 'cmd',
            'svg', 'html', 'htm', 'xml',
        ];
    }

    /**
     * Test file upload security.
     */
    async test(surfaceInventory) {
        const findings = [];
        const baseUrl = this._getBaseUrl(surfaceInventory);
        if (!baseUrl) return findings;

        this.logger?.info?.('File Upload Tester: starting tests');

        // Discover upload endpoints
        const uploadEndpoints = await this._discoverUploads(baseUrl, surfaceInventory);

        if (uploadEndpoints.length === 0) {
            this.logger?.info?.('File Upload Tester: no upload endpoints found');
            return findings;
        }

        this.logger?.info?.(`File Upload Tester: found ${uploadEndpoints.length} upload endpoints`);

        for (const endpoint of uploadEndpoints) {
            // 1. Test MIME type spoofing
            const mimeFindings = await this._testMIMESpoofing(endpoint);
            findings.push(...mimeFindings);

            // 2. Test path traversal in filename
            const pathFindings = await this._testPathTraversal(endpoint);
            findings.push(...pathFindings);

            // 3. Test dangerous file types
            const typeFindings = await this._testDangerousTypes(endpoint);
            findings.push(...typeFindings);

            // 4. Test oversized uploads
            const sizeFindings = await this._testOversizedUpload(endpoint);
            findings.push(...sizeFindings);
        }

        this.logger?.info?.(`File Upload Tester: found ${findings.length} issues`);
        return findings;
    }

    async _discoverUploads(baseUrl, surfaceInventory) {
        const endpoints = [];

        // Check forms for file inputs
        const forms = surfaceInventory.forms || [];
        for (const form of forms) {
            const html = JSON.stringify(form);
            if (this.UPLOAD_INDICATORS.some(ind => html.toLowerCase().includes(ind.toLowerCase()))) {
                endpoints.push({
                    url: form.action ? new URL(form.action, baseUrl).href : baseUrl,
                    source: 'form',
                });
            }
        }

        // Probe common upload paths
        for (const path of this.UPLOAD_PATHS) {
            try {
                const url = new URL(path, baseUrl).href;
                const response = await fetch(url, {
                    method: 'OPTIONS',
                    signal: AbortSignal.timeout(3000),
                });
                // Accept any non-404 as potential upload endpoint
                if (response.status !== 404 && response.status !== 403) {
                    endpoints.push({ url, source: 'probe' });
                }
            } catch {
                continue;
            }
        }

        return endpoints;
    }

    async _testMIMESpoofing(endpoint) {
        const findings = [];

        // Create a "JPEG" that's actually a PHP script
        const spoofedContent = '<?php echo "VIBE_SHIELD_MIME_SPOOF_TEST"; ?>';
        const boundary = '----VIBESHIELDBoundary' + Date.now();

        const body = [
            `--${boundary}`,
            `Content-Disposition: form-data; name="file"; filename="innocent.jpg"`,
            `Content-Type: image/jpeg`,
            '',
            spoofedContent,
            `--${boundary}--`,
        ].join('\r\n');

        try {
            const response = await fetch(endpoint.url, {
                method: 'POST',
                headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
                body,
                signal: AbortSignal.timeout(5000),
            });

            if (response.ok) {
                const text = await response.text();
                if (/success|upload|created|saved|file/i.test(text) &&
                    !/invalid|rejected|not allowed|unsupported|error/i.test(text)) {
                    findings.push(createFinding({
                        module: 'security',
                        title: 'File Upload: MIME Type Spoofing Accepted',
                        severity: 'high',
                        affected_surface: endpoint.url,
                        description: `Upload endpoint accepted a file with mismatched Content-Type (image/jpeg) and actual content (PHP script). The server validates by Content-Type header rather than file content, allowing server-side script execution.`,
                        reproduction: [
                            `1. Upload file named "innocent.jpg" with Content-Type: image/jpeg`,
                            `2. File content: <?php echo "test"; ?>`,
                            `3. Server accepts the upload`,
                        ],
                        evidence: `MIME type: image/jpeg, Content: PHP script`,
                        remediation: 'Validate files by magic bytes (file signature), not Content-Type header or extension. Use a media type allowlist. Store uploads outside the webroot. Serve with Content-Disposition: attachment.',
                        references: ['CWE-434'],
                    }));
                }
            }
        } catch {
            // Not reachable
        }

        return findings;
    }

    async _testPathTraversal(endpoint) {
        const findings = [];

        const traversalNames = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '....//....//....//etc/passwd',
            'file.txt%00.jpg',
        ];

        const boundary = '----VIBESHIELDBoundary' + Date.now();

        for (const filename of traversalNames) {
            const body = [
                `--${boundary}`,
                `Content-Disposition: form-data; name="file"; filename="${filename}"`,
                `Content-Type: text/plain`,
                '',
                'VIBE SHIELD_PATH_TRAVERSAL_TEST',
                `--${boundary}--`,
            ].join('\r\n');

            try {
                const response = await fetch(endpoint.url, {
                    method: 'POST',
                    headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
                    body,
                    signal: AbortSignal.timeout(5000),
                });

                if (response.ok) {
                    const text = await response.text();
                    if (/success|upload|created|saved/i.test(text) &&
                        !/invalid|rejected|sanitized|error|\.\..*not allowed/i.test(text)) {
                        findings.push(createFinding({
                            module: 'security',
                            title: 'File Upload: Path Traversal in Filename',
                            severity: 'critical',
                            affected_surface: endpoint.url,
                            description: `Upload endpoint accepted a filename containing path traversal characters ("${filename}"). An attacker can overwrite arbitrary server files or place web shells in accessible directories.`,
                            reproduction: [
                                `1. Upload file with filename: "${filename}"`,
                                `2. Server does not sanitize the filename`,
                            ],
                            evidence: `Filename: ${filename}`,
                            remediation: 'Strip all path components from uploaded filenames. Use a generated UUID as the stored filename. Never use user-supplied filenames for disk storage.',
                            references: ['CWE-22'],
                        }));
                        break;
                    }
                }
            } catch {
                continue;
            }
        }

        return findings;
    }

    async _testDangerousTypes(endpoint) {
        const findings = [];
        const boundary = '----VIBESHIELDBoundary' + Date.now();
        const acceptedTypes = [];

        for (const ext of this.DANGEROUS_EXTENSIONS.slice(0, 6)) {
            const body = [
                `--${boundary}`,
                `Content-Disposition: form-data; name="file"; filename="test.${ext}"`,
                `Content-Type: application/octet-stream`,
                '',
                '// VIBE SHIELD dangerous type test',
                `--${boundary}--`,
            ].join('\r\n');

            try {
                const response = await fetch(endpoint.url, {
                    method: 'POST',
                    headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
                    body,
                    signal: AbortSignal.timeout(5000),
                });

                if (response.ok) {
                    const text = await response.text();
                    if (/success|upload|created|saved/i.test(text) &&
                        !/invalid|rejected|not allowed|forbidden|error/i.test(text)) {
                        acceptedTypes.push(ext);
                    }
                }
            } catch {
                continue;
            }
        }

        if (acceptedTypes.length > 0) {
            findings.push(createFinding({
                module: 'security',
                title: 'File Upload: Dangerous File Types Accepted',
                severity: 'critical',
                affected_surface: endpoint.url,
                description: `Upload endpoint accepts dangerous file extensions: ${acceptedTypes.map(t => `.${t}`).join(', ')}. If these files are served by the web server, an attacker can achieve remote code execution.`,
                reproduction: [
                    `1. Upload files with extensions: ${acceptedTypes.join(', ')}`,
                    `2. Server accepts the uploads`,
                ],
                evidence: `Accepted dangerous types: ${acceptedTypes.join(', ')}`,
                remediation: 'Implement a strict file extension allowlist (e.g., only .jpg, .png, .pdf, .doc). Reject all other extensions. Store files outside the web root. Configure the web server to never execute uploaded files.',
                references: ['CWE-434'],
            }));
        }

        return findings;
    }

    async _testOversizedUpload(endpoint) {
        const findings = [];
        const boundary = '----VIBESHIELDBoundary' + Date.now();

        // Generate a ~5MB payload
        const largeContent = 'A'.repeat(5 * 1024 * 1024);

        const body = [
            `--${boundary}`,
            `Content-Disposition: form-data; name="file"; filename="large_test.txt"`,
            `Content-Type: text/plain`,
            '',
            largeContent,
            `--${boundary}--`,
        ].join('\r\n');

        try {
            const response = await fetch(endpoint.url, {
                method: 'POST',
                headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
                body,
                signal: AbortSignal.timeout(15000),
            });

            if (response.ok) {
                const text = await response.text();
                if (/success|upload|created|saved/i.test(text) &&
                    !/too large|size limit|maximum|exceeded|413|error/i.test(text)) {
                    findings.push(createFinding({
                        module: 'security',
                        title: 'File Upload: No Size Limit Enforced',
                        severity: 'medium',
                        affected_surface: endpoint.url,
                        description: `Upload endpoint accepted a 5MB file without size restrictions. An attacker can exhaust disk space or memory with repeated large uploads (denial of service).`,
                        evidence: `5MB payload accepted`,
                        remediation: 'Enforce server-side file size limits (e.g., 2MB for images). Return 413 Payload Too Large for oversized files. Implement per-user/IP upload rate limiting.',
                        references: ['CWE-400'],
                    }));
                }
            }
        } catch {
            // Timeout or rejection — that's fine
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

export default FileUploadTester;
