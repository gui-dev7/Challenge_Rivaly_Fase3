/**
 * password-hasher.mjs — como a senha é guardada NO SERVIDOR.
 *
 * argon2id (vencedor da Password Hashing Competition e 1ª recomendação
 * da OWASP Password Storage Cheat Sheet) com a configuração mínima da
 * OWASP: 19 MiB de memória, 2 passadas, paralelismo 1. Gastar memória é
 * o que torna o ataque com GPU caro: cada palpite precisa de 19 MiB.
 *
 * Usa o argon2 nativo do Node (node:crypto, desde a versão 24.7), sem
 * dependências. Em Node mais antigo, cai para scrypt (N=2^17, r=8, p=1),
 * a 2ª opção da OWASP.
 *
 * Formato PHC (o mesmo das bibliotecas argon2 de Python, PHP, Go…):
 *   $argon2id$v=19$m=19456,t=2,p=1$<sal>$<hash>
 *   $scrypt$ln=17,r=8,p=1$<sal>$<hash>
 * Os parâmetros ficam no próprio hash: dá para subir o custo no futuro
 * e rehashear cada conta no próximo login (needsRehash).
 */

import crypto from 'node:crypto';

export const ARGON2ID = Object.freeze({ memory: 19_456, passes: 2, parallelism: 1, tagLength: 32 });
export const SCRYPT = Object.freeze({ ln: 17, r: 8, p: 1, keyLength: 32 });
const SALT_BYTES = 16;

export const hasArgon2 = typeof crypto.argon2 === 'function';
export const preferredAlgorithm = hasArgon2 ? 'argon2id' : 'scrypt';

const b64 = (buffer) => buffer.toString('base64').replace(/=+$/, '');
const unb64 = (text) => Buffer.from(text, 'base64');
const encode = (password) => Buffer.from(String(password ?? '').normalize('NFKC'), 'utf8');

function argon2id(password, salt, { memory, passes, parallelism, tagLength }) {
    return new Promise((resolve, reject) => {
        crypto.argon2('argon2id', { message: encode(password), nonce: salt, memory, passes, parallelism, tagLength },
            (error, key) => (error ? reject(error) : resolve(key)));
    });
}

function scrypt(password, salt, { ln, r, p, keyLength }) {
    const N = 2 ** ln;
    return new Promise((resolve, reject) => {
        crypto.scrypt(encode(password), salt, keyLength, { N, r, p, maxmem: 256 * N * r },
            (error, key) => (error ? reject(error) : resolve(key)));
    });
}

/** @returns {Promise<string>} hash no formato PHC */
export async function hashPassword(password, { algorithm = preferredAlgorithm } = {}) {
    const salt = crypto.randomBytes(SALT_BYTES);
    if (algorithm === 'argon2id') {
        const { memory, passes, parallelism } = ARGON2ID;
        const key = await argon2id(password, salt, ARGON2ID);
        return `$argon2id$v=19$m=${memory},t=${passes},p=${parallelism}$${b64(salt)}$${b64(key)}`;
    }
    const key = await scrypt(password, salt, SCRYPT);
    return `$scrypt$ln=${SCRYPT.ln},r=${SCRYPT.r},p=${SCRYPT.p}$${b64(salt)}$${b64(key)}`;
}

/** "$argon2id$v=19$m=19456,t=2,p=1$sal$hash" → partes. */
export function parsePhc(stored) {
    const parts = String(stored ?? '').split('$');
    if (parts[1] === 'argon2id' && parts.length === 6) {
        const params = Object.fromEntries(parts[3].split(',').map((pair) => pair.split('=')).map(([k, v]) => [k, Number(v)]));
        return { id: 'argon2id', params, salt: unb64(parts[4]), hash: unb64(parts[5]) };
    }
    if (parts[1] === 'scrypt' && parts.length === 5) {
        const params = Object.fromEntries(parts[2].split(',').map((pair) => pair.split('=')).map(([k, v]) => [k, Number(v)]));
        return { id: 'scrypt', params, salt: unb64(parts[3]), hash: unb64(parts[4]) };
    }
    return null;
}

/** @returns {Promise<{ok:boolean, needsRehash:boolean}>} */
export async function verifyPassword(password, stored) {
    const parsed = parsePhc(stored);
    if (!parsed) return { ok: false, needsRehash: false };

    let key;
    if (parsed.id === 'argon2id') {
        if (!hasArgon2) return { ok: false, needsRehash: false };
        key = await argon2id(password, parsed.salt, {
            memory: parsed.params.m, passes: parsed.params.t, parallelism: parsed.params.p, tagLength: parsed.hash.length,
        });
    } else {
        key = await scrypt(password, parsed.salt, { ...parsed.params, keyLength: parsed.hash.length });
    }

    const ok = key.length === parsed.hash.length && crypto.timingSafeEqual(key, parsed.hash);
    const weaker = parsed.id !== preferredAlgorithm
        || (parsed.id === 'argon2id' && (parsed.params.m < ARGON2ID.memory || parsed.params.t < ARGON2ID.passes))
        || (parsed.id === 'scrypt' && parsed.params.ln < SCRYPT.ln);
    return { ok, needsRehash: ok && weaker };
}
