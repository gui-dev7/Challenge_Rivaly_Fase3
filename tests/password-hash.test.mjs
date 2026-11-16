/**
 * password-hash.test.mjs — PBKDF2 do navegador e a migração do hash antigo.
 * (O Node 18+ tem o mesmo Web Crypto do navegador em globalThis.crypto.)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
    hashPassword, verifyPassword, parseHash, isLegacyHash, timingSafeEqual, legacyHashForDemo, PBKDF2,
} from '../js/core/password-hash.js';

const SECRET = 'pizza de quinta com o squad';

test('formato pbkdf2-sha256$600000$sal$hash', async () => {
    const stored = await hashPassword(SECRET);
    const parsed = parseHash(stored);
    assert.equal(parsed.algorithm, 'pbkdf2-sha256');
    assert.equal(parsed.iterations, 600_000);
    assert.equal(parsed.salt.length, PBKDF2.saltBytes);
    assert.equal(parsed.hash.length, 32);
});

test('sal por conta: a mesma senha gera hashes diferentes', async () => {
    const [a, b] = await Promise.all([hashPassword(SECRET), hashPassword(SECRET)]);
    assert.notEqual(a, b);
    assert.equal((await verifyPassword(SECRET, a)).ok, true);
    assert.equal((await verifyPassword(SECRET, b)).ok, true);
});

test('senha errada não confere', async () => {
    const stored = await hashPassword(SECRET);
    assert.equal((await verifyPassword('pizza de quinta com o squaD', stored)).ok, false);
    assert.equal((await verifyPassword('', stored)).ok, false);
});

test('hash com menos iterações confere, mas pede rehash', async () => {
    const weak = await hashPassword(SECRET, { iterations: 1000 });
    assert.deepEqual(await verifyPassword(SECRET, weak), { ok: true, needsRehash: true });
});

test('hash da V3.0 (SHA-256 + sal fixo) ainda entra e pede migração', async () => {
    const legacy = await legacyHashForDemo('senha-antiga');
    assert.equal(isLegacyHash(legacy), true);
    // O defeito que motivou a troca: sempre o mesmo hash.
    assert.equal(legacy, await legacyHashForDemo('senha-antiga'));
    assert.deepEqual(await verifyPassword('senha-antiga', legacy), { ok: true, needsRehash: true });
    assert.equal((await verifyPassword('outra', legacy)).ok, false);
});

test('a conta demo ("demo") nunca confere com senha nenhuma', async () => {
    assert.equal((await verifyPassword('demo', 'demo')).ok, false);
});

test('comparação em tempo constante', () => {
    assert.equal(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
    assert.equal(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
    assert.equal(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])), false);
});
