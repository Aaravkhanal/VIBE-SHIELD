import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';

const hash = value => createHash('sha256').update(value).digest('hex');
const token = () => randomBytes(32).toString('base64url');
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(part => { const i = part.indexOf('='); return [part.slice(0, i).trim(), part.slice(i + 1).trim()]; }));

export function verifyGoogleIdToken(jwt, keys, { clientId, nonce, now = Date.now() }) {
    if (typeof jwt !== 'string' || jwt.length > 16384) throw new Error('Invalid identity token');
    const parts = jwt.split('.');
    if (parts.length !== 3) throw new Error('Invalid identity token');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
    const key = keys.find(key => key.kid === header.kid && key.kty === 'RSA' && (!key.use || key.use === 'sig'));
    if (header.alg !== 'RS256' || !key || !verify('RSA-SHA256', Buffer.from(parts.slice(0, 2).join('.')), createPublicKey({ key, format: 'jwk' }), Buffer.from(parts[2], 'base64url'))) throw new Error('Invalid token signature');
    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!['accounts.google.com', 'https://accounts.google.com'].includes(claims.iss) || !audience.includes(clientId) || (audience.length > 1 && claims.azp !== clientId) || (claims.azp && claims.azp !== clientId)) throw new Error('Invalid token issuer or audience');
    if (!Number.isFinite(claims.exp) || claims.exp * 1000 <= now || !Number.isFinite(claims.iat) || claims.iat * 1000 > now + 60000 || !same(claims.nonce, nonce)) throw new Error('Expired or replayed token');
    if (!claims.sub || typeof claims.email !== 'string' || claims.email_verified !== true) throw new Error('A verified Google email is required');
    return { id: claims.sub, email: claims.email.toLowerCase(), name: typeof claims.name === 'string' ? claims.name : claims.email.split('@')[0] };
}

export function createGoogleAuth({ env = process.env, fetchImpl = fetch, now = Date.now } = {}) {
    const clientId = env.GOOGLE_CLIENT_ID;
    const clientSecret = env.GOOGLE_CLIENT_SECRET;
    const enabled = Boolean(clientId && clientSecret);
    const required = enabled || Boolean(clientId || clientSecret) || env.NODE_ENV === 'production' || env.AUTH_REQUIRED === 'true';
    const base = new URL(env.APP_URL || `http://localhost:${env.PORT || 3000}`);
    if (base.pathname !== '/' || base.search || base.hash || base.username || base.password) throw new Error('APP_URL must be an origin without a path or credentials');
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname);
    if (base.protocol !== 'https:' && !(base.protocol === 'http:' && local && env.NODE_ENV !== 'production')) throw new Error('Google sign-in requires HTTPS outside local development');
    const secure = base.protocol === 'https:';
    const prefix = secure ? '__Host-' : '';
    const sessionCookie = prefix + 'vs_session';
    const flowCookie = prefix + 'vs_oauth';
    const admins = new Set((env.AUTH_ADMIN_EMAILS || '').split(',').map(email => email.trim().toLowerCase()).filter(Boolean));
    const allowed = new Set((env.AUTH_ALLOWED_EMAILS || '').split(',').map(email => email.trim().toLowerCase()).filter(Boolean));
    const sessions = new Map();
    const flows = new Map();
    let jwks = { keys: [], expires: 0 };
    const json = (res, status, data) => { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(data)); };
    const cookie = (name, value, seconds) => `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${seconds}${secure ? '; Secure' : ''}`;
    const prune = () => { for (const map of [sessions, flows]) for (const [id, item] of map) if (item.expires <= now()) map.delete(id); };
    const getSession = req => { prune(); const value = cookies(req)[sessionCookie]; return value ? sessions.get(hash(value)) || null : null; };
    const redirect = (res, location) => { res.writeHead(302, { Location: location, 'Cache-Control': 'no-store' }); res.end(); };
    async function handle(req, res, pathname, searchParams) {
        prune();
        if (pathname === '/auth/session' && req.method === 'GET') {
            json(res, 200, { enabled, required, user: getSession(req)?.user || null, mode: required ? 'google' : 'local', configured: enabled }); return true;
        }
        if (pathname === '/auth/logout' && req.method === 'POST') {
            if (req.headers.origin !== base.origin) { json(res, 403, { error: 'Invalid request origin' }); return true; }
            const sid = cookies(req)[sessionCookie]; if (sid) sessions.delete(hash(sid));
            res.setHeader('Set-Cookie', cookie(sessionCookie, '', 0)); json(res, 200, { ok: true }); return true;
        }
        if (pathname === '/auth/google' && req.method === 'GET') {
            if (!enabled) { redirect(res, '/?auth_error=not_configured'); return true; }
            if (flows.size >= 1000) { json(res, 429, { error: 'Too many sign-in requests. Try again shortly.' }); return true; }
            const state = token(), binding = token(), verifier = token(), nonce = token();
            flows.set(hash(state), { binding: hash(binding), verifier, nonce, expires: now() + 600000 });
            res.setHeader('Set-Cookie', cookie(flowCookie, binding, 600));
            const params = new URLSearchParams({ client_id: clientId, redirect_uri: `${base.origin}/auth/google/callback`, response_type: 'code', scope: 'openid email profile', state, nonce, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', prompt: 'select_account' });
            redirect(res, `https://accounts.google.com/o/oauth2/v2/auth?${params}`); return true;
        }
        if (pathname === '/auth/google/callback' && req.method === 'GET') {
            const state = searchParams.get('state') || '';
            const flow = flows.get(hash(state)); flows.delete(hash(state));
            res.setHeader('Set-Cookie', cookie(flowCookie, '', 0));
            if (!flow || !same(flow.binding, hash(cookies(req)[flowCookie] || '')) || !searchParams.get('code') || searchParams.has('error')) { redirect(res, '/?auth_error=sign_in_failed'); return true; }
            try {
                const response = await fetchImpl('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code: searchParams.get('code'), client_id: clientId, client_secret: clientSecret, redirect_uri: `${base.origin}/auth/google/callback`, grant_type: 'authorization_code', code_verifier: flow.verifier }), signal: AbortSignal.timeout(15000) });
                if (!response.ok) throw new Error('Token exchange failed');
                const result = await response.json();
                if (jwks.expires <= now()) {
                    const response = await fetchImpl('https://www.googleapis.com/oauth2/v3/certs', { signal: AbortSignal.timeout(10000) });
                    if (!response.ok) throw new Error('Verification keys unavailable');
                    jwks = { keys: (await response.json()).keys || [], expires: now() + 3600000 };
                }
                const user = verifyGoogleIdToken(result.id_token, jwks.keys, { clientId, nonce: flow.nonce, now: now() });
                if (allowed.size && !allowed.has(user.email)) { redirect(res, '/?auth_error=access_denied'); return true; }
                if (sessions.size >= 1000) throw new Error('Session limit reached');
                const existing = cookies(req)[sessionCookie]; if (existing) sessions.delete(hash(existing));
                user.isAdmin = admins.has(user.email);
                const sid = token(); sessions.set(hash(sid), { user, expires: now() + 28800000 });
                res.setHeader('Set-Cookie', [cookie(flowCookie, '', 0), cookie(sessionCookie, sid, 28800)]);
                redirect(res, '/');
            } catch { redirect(res, '/?auth_error=sign_in_failed'); }
            return true;
        }
        return false;
    }
    return { enabled, required, origin: base.origin, handle, getSession,
        authorize(req, res, apiKey) {
            if (!required) return true;
            if (getSession(req)) return true;
            // Machine access is explicit and limited to the CI scan endpoint.
            const bearer = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : '';
            const presentedKey = req.headers['x-api-key'] || bearer;
            if (req.url?.split('?')[0] === '/api/webhook/scan' && same(presentedKey, apiKey)) return true;
            json(res, 401, { error: 'Sign in with Google to access this workspace.', code: 'AUTH_REQUIRED' }); return false;
        }
    };
}
