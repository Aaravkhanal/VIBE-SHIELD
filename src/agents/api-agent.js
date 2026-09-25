import { BaseAgent } from './base-agent.js';
import { allows, getSafetyMode } from '../utils/safety.js';
import { AuthFlowTester } from '../core/api/auth-flow-tester.js';
import { OAuthProber } from '../core/api/oauth-prober.js';
import { APIKeyAuditor } from '../core/api/api-key-auditor.js';
import { GraphQLTester } from '../core/api/graphql-tester.js';
import { CORSWSTester } from '../core/api/cors-ws-tester.js';

/**
 * VIBE-SHIELD-API — API & Auth Flow Verification Agent
 *
 * Pipeline:
 * 1. Test authentication flows (JWT, sessions, passwords, MFA)
 * 2. Probe OAuth/SSO security
 * 3. Audit API key management
 * 4. Test GraphQL-specific vulnerabilities
 * 5. Validate CORS and WebSocket security
 *
 * Dependencies: VIBE-SHIELD-CRAWL (runs in Wave 2, parallel with QA + SEC + AI + LOGIC)
 */
export class APIAgent extends BaseAgent {
    get name() { return 'VIBE-SHIELD-API'; }
    get dependencies() { return ['VIBE-SHIELD-CRAWL']; }

    async _execute(context) {
        const { config, logger, surfaceInventory } = context;

        if (!surfaceInventory) {
            throw new Error('No surface inventory available — VIBE-SHIELD-CRAWL must run first');
        }

        // API/auth flow verification sends live requests, so it requires at
        // least safe-active. In passive mode it is skipped.
        if (!allows(config, 'safe-active')) {
            this.assessment = 'not_assessed';
            this._log(`API & auth flow verification skipped — requires active probing (current: ${getSafetyMode(config)} mode)`);
            this.progress('complete', 'API testing skipped (passive mode)', 100);
            return;
        }

        // Phase 1: Auth flow testing
        this.progress('auth', 'Testing authentication flows...', 0);
        try {
            const authTester = new AuthFlowTester(logger, context.coverageTracker);
            const authFindings = await authTester.test(surfaceInventory);
            this.addFindings(authFindings);
            this._log(`Auth flows: ${authFindings.length} issues`);
        } catch (err) {
            this._log(`Auth flow testing failed: ${err.message}`, 'error');
        }
        this.progress('auth', 'Auth flow testing complete', 20);

        // Phase 2: OAuth probing
        this.progress('oauth', 'Probing OAuth/SSO flows...', 20);
        try {
            const oauthProber = new OAuthProber(logger, context.coverageTracker);
            const oauthFindings = await oauthProber.probe(surfaceInventory);
            this.addFindings(oauthFindings);
            this._log(`OAuth: ${oauthFindings.length} issues`);
        } catch (err) {
            this._log(`OAuth probing failed: ${err.message}`, 'error');
        }
        this.progress('oauth', 'OAuth probing complete', 40);

        // Phase 3: API key audit
        this.progress('apikeys', 'Auditing API key management...', 40);
        try {
            const keyAuditor = new APIKeyAuditor(logger, context.coverageTracker);
            const keyFindings = await keyAuditor.audit(surfaceInventory);
            this.addFindings(keyFindings);
            this._log(`API keys: ${keyFindings.length} issues`);
        } catch (err) {
            this._log(`API key audit failed: ${err.message}`, 'error');
        }
        this.progress('apikeys', 'API key audit complete', 60);

        // Phase 4: GraphQL testing
        this.progress('graphql', 'Testing GraphQL endpoints...', 60);
        try {
            const gqlTester = new GraphQLTester(logger, context.coverageTracker);
            const gqlFindings = await gqlTester.test(surfaceInventory);
            this.addFindings(gqlFindings);
            this._log(`GraphQL: ${gqlFindings.length} issues`);
        } catch (err) {
            this._log(`GraphQL testing failed: ${err.message}`, 'error');
        }
        this.progress('graphql', 'GraphQL testing complete', 80);

        // Phase 5: CORS & WebSocket testing
        this.progress('cors-ws', 'Testing CORS and WebSocket security...', 80);
        try {
            const corsTester = new CORSWSTester(logger, context.coverageTracker);
            const corsFindings = await corsTester.test(surfaceInventory);
            this.addFindings(corsFindings);
            this._log(`CORS/WS: ${corsFindings.length} issues`);
        } catch (err) {
            this._log(`CORS/WS testing failed: ${err.message}`, 'error');
        }
        this.progress('cors-ws', 'CORS/WS testing complete', 100);

        this.progress('complete', `API scan complete — ${this._findings.length} total findings`, 100);
    }
}

export default APIAgent;
