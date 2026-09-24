import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { createGoogleAuth, verifyGoogleIdToken } from '../src/server-auth.js';

const now = Date.UTC(2026, 8, 24, 12);
const clientId = 'test-client.apps.googleusercontent.com';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test-key', use: 'sig', alg: 'RS256' };

function idToken(overrides = {}) {
    const encoded = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    const claims = {
        iss: 'https://accounts.google.com', aud: clientId, sub: 'google-user-123',
        email: 'member@example.com', email_verified: true, name: 'Vibe Member',
        nonce: 'expected-nonce', iat: now / 1000 - 5, exp: now / 1000 + 3600,
        ...overrides
    };
    const input = `${encoded({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' })}.${encoded(claims)}`;
    return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}

function response() {
    return {
        status: null, headers: {}, body: '',
        setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
        writeHead(status, headers = {}) { this.status = status; for (const [name, value] of Object.entries(headers)) this.setHeader(name, value); },
        end(value = '') { this.body += value; }
    };
}

function cookieValue(setCookie, name) {
    const values = Array.isArray(setCookie) ? setCookie : [setCookie];
    const item = values.find(value => value?.startsWith(`${name}=`));
    return item?.split(';')[0];
}

test('Google ID tokens require a valid signature, audience, nonce, and verified email', () => {
    const user = verifyGoogleIdToken(idToken(), [jwk], { clientId, nonce: 'expected-nonce', now });
    assert.deepEqual(user, { id: 'google-user-123', email: 'member@example.com', name: 'Vibe Member' });
    assert.throws(() => verifyGoogleIdToken(idToken({ aud: 'other-client' }), [jwk], { clientId, nonce: 'expected-nonce', now }));
    assert.throws(() => verifyGoogleIdToken(idToken({ nonce: 'replayed' }), [jwk], { clientId, nonce: 'expected-nonce', now }));
    assert.throws(() => verifyGoogleIdToken(idToken({ exp: now / 1000 - 1 }), [jwk], { clientId, nonce: 'expected-nonce', now }));
    assert.throws(() => verifyGoogleIdToken(idToken({ email_verified: false }), [jwk], { clientId, nonce: 'expected-nonce', now }));
});

test('authorization-code flow creates and clears a private session for any verified Google account', async () => {
    let nonce;
    const fetchImpl = async url => {
        if (url === 'https://oauth2.googleapis.com/token') return { ok: true, json: async () => ({ id_token: idToken({ nonce }) }) };
        if (url === 'https://www.googleapis.com/oauth2/v3/certs') return { ok: true, json: async () => ({ keys: [jwk] }) };
        throw new Error(`Unexpected request: ${url}`);
    };
    const auth = createGoogleAuth({
        env: { GOOGLE_CLIENT_ID: clientId, GOOGLE_CLIENT_SECRET: 'test-secret', APP_URL: 'http://localhost:3000' },
        fetchImpl, now: () => now
    });

    const start = response();
    await auth.handle({ method: 'GET', headers: {} }, start, '/auth/google', new URLSearchParams());
    assert.equal(start.status, 302);
    const authorizationUrl = new URL(start.headers.location);
    nonce = authorizationUrl.searchParams.get('nonce');
    assert.equal(authorizationUrl.searchParams.get('code_challenge_method'), 'S256');
    assert.ok(authorizationUrl.searchParams.get('state'));
    const flowCookie = cookieValue(start.headers['set-cookie'], 'vs_oauth');

    const callback = response();
    await auth.handle(
        { method: 'GET', headers: { cookie: flowCookie } }, callback, '/auth/google/callback',
        new URLSearchParams({ state: authorizationUrl.searchParams.get('state'), code: 'one-time-code' })
    );
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.location, '/');
    const sessionCookie = cookieValue(callback.headers['set-cookie'], 'vs_session');
    assert.ok(sessionCookie);

    const session = response();
    await auth.handle({ method: 'GET', headers: { cookie: sessionCookie } }, session, '/auth/session', new URLSearchParams());
    const sessionPayload = JSON.parse(session.body);
    assert.equal(sessionPayload.user.email, 'member@example.com');
    assert.equal(sessionPayload.user.isAdmin, false);

    const webhookRequest = { url: '/api/webhook/scan', headers: { 'x-api-key': 'ci-secret' } };
    assert.equal(auth.authorize(webhookRequest, response(), 'ci-secret'), true);

    const logout = response();
    await auth.handle({ method: 'POST', headers: { cookie: sessionCookie, origin: 'http://localhost:3000' } }, logout, '/auth/logout', new URLSearchParams());
    assert.equal(logout.status, 200);
    assert.equal(auth.getSession({ headers: { cookie: sessionCookie } }), null);
});
