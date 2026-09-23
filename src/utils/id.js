import { randomBytes } from 'node:crypto';

/** Cryptographically random, URL-safe identifiers using Node's built-in CSPRNG. */
export function randomId(size = 21) {
    if (!Number.isInteger(size) || size < 1 || size > 1024) throw new RangeError('ID size must be an integer between 1 and 1024');
    return randomBytes(Math.ceil(size * 3 / 4)).toString('base64url').slice(0, size);
}
