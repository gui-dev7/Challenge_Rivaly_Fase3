/**
 * password-hash.js — como a senha é guardada NO NAVEGADOR.
 *
 * Antes (V3.0): SHA-256 com um sal FIXO, igual para todo mundo. Duas
 * contas com a mesma senha tinham o mesmo hash, e o SHA-256 é rápido
 * demais: uma GPU testa bilhões por segundo.
 *
 * Agora: PBKDF2-HMAC-SHA256 com 600.000 iterações (valor da OWASP
 * Password Storage Cheat Sheet) e um sal aleatório de 16 bytes POR CONTA.
 * É o melhor KDF que o Web Crypto oferece no navegador. No servidor da
 * demo (server/password-hasher.mjs) o algoritmo é o argon2id, a primeira
 * recomendação da OWASP.
 *
 * Formato guardado (inspirado no PHC string format):
 *   pbkdf2-sha256$600000$<sal base64>$<hash base64>
 *
 * Contas antigas continuam entrando: o hash legado é conferido uma vez
 * e trocado pelo novo no mesmo login (needsRehash).
 *
 * Lembrete honesto: no navegador isto protege a senha de quem abre o
 * DevTools, mas não substitui um servidor. Ver docs/padrao-de-senha.md.
 */

export const PBKDF2 = Object.freeze({
    algorithm: 'pbkdf2-sha256',
    iterations: 600_000,
    saltBytes: 16,
    keyBits: 256,
});

const LEGACY_SALT = 'rivaly::academic-demo';

const subtle = () => globalThis.crypto?.subtle ?? null;

/** O Web Crypto só existe em contexto seguro (https:// ou localhost). */
export const isCryptoAvailable = () => Boolean(subtle() && globalThis.crypto?.getRandomValues);

const toBase64 = (bytes) => {
    let binary = '';
    new Uint8Array(bytes).forEach((byte) => { binary += String.fromCharCode(byte); });
    return btoa(binary);
};

const fromBase64 = (text) => Uint8Array.from(atob(text), (char) => char.charCodeAt(0));

const encode = (text) => new TextEncoder().encode(String(text ?? '').normalize('NFKC'));

/** Comparação em tempo constante: não para no primeiro byte diferente. */
export function timingSafeEqual(a, b) {
    const left = new Uint8Array(a);
    const right = new Uint8Array(b);
    let diff = left.length ^ right.length;
    const length = Math.max(left.length, right.length);
    for (let i = 0; i < length; i += 1) diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
    return diff === 0;
}

async function derive(password, salt, iterations) {
    const key = await subtle().importKey('raw', encode(password), 'PBKDF2', false, ['deriveBits']);
    return subtle().deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, PBKDF2.keyBits);
}

/**
 * @param {string} password
 * @param {{iterations?:number, salt?:Uint8Array}} options (o sal fixo só existe para testes)
 * @returns {Promise<string>} pbkdf2-sha256$600000$sal$hash
 */
export async function hashPassword(password, { iterations = PBKDF2.iterations, salt } = {}) {
    if (!isCryptoAvailable()) {
        throw new Error('Web Crypto indisponível: abra a RIVALY por https:// ou http://localhost.');
    }
    const useSalt = salt ?? globalThis.crypto.getRandomValues(new Uint8Array(PBKDF2.saltBytes));
    const bits = await derive(password, useSalt, iterations);
    return `${PBKDF2.algorithm}$${iterations}$${toBase64(useSalt)}$${toBase64(bits)}`;
}

/** Lê "pbkdf2-sha256$600000$sal$hash". */
export function parseHash(stored) {
    const [algorithm, iterations, salt, hash] = String(stored ?? '').split('$');
    if (algorithm !== PBKDF2.algorithm || !salt || !hash) return null;
    return { algorithm, iterations: Number(iterations), salt: fromBase64(salt), hash: fromBase64(hash) };
}

/* ---------- formatos antigos (só para migrar) ---------- */

async function legacySha256(password) {
    const digest = await subtle().digest('SHA-256', new TextEncoder().encode(`${LEGACY_SALT}|${password}`));
    return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function legacyDjb2(password) {
    let hash = 5381;
    const text = `${LEGACY_SALT}|${password}`;
    for (let i = 0; i < text.length; i += 1) hash = ((hash << 5) + hash + text.charCodeAt(i)) | 0;
    return `djb2:${Math.abs(hash).toString(16)}`;
}

/** É um hash da V3.0 (SHA-256 com sal fixo ou djb2)? */
export const isLegacyHash = (stored) => /^[0-9a-f]{64}$/.test(String(stored ?? '')) || String(stored ?? '').startsWith('djb2:');

/**
 * Confere uma senha contra o que está guardado.
 * @returns {Promise<{ok:boolean, needsRehash:boolean}>}
 */
export async function verifyPassword(password, stored) {
    const parsed = parseHash(stored);
    if (parsed) {
        const bits = await derive(password, parsed.salt, parsed.iterations);
        const ok = timingSafeEqual(bits, parsed.hash);
        return { ok, needsRehash: ok && parsed.iterations < PBKDF2.iterations };
    }

    if (isLegacyHash(stored)) {
        const candidate = String(stored).startsWith('djb2:') ? legacyDjb2(password) : await legacySha256(password);
        const ok = timingSafeEqual(new TextEncoder().encode(candidate), new TextEncoder().encode(String(stored)));
        return { ok, needsRehash: ok };
    }

    return { ok: false, needsRehash: false };
}

/**
 * Gasta o mesmo tempo de um login de verdade quando o e-mail não existe.
 * Sem isso, a resposta mais rápida entregaria quais e-mails têm conta.
 */
export async function burnVerifyTime(password) {
    const fakeSalt = new Uint8Array(PBKDF2.saltBytes);
    await derive(password, fakeSalt, PBKDF2.iterations);
    return { ok: false, needsRehash: false };
}

/** O hash do formato antigo, para a comparação na página de segurança. */
export const legacyHashForDemo = (password) => legacySha256(password);
