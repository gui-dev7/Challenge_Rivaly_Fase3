/**
 * pwned.test.mjs — consulta ao Have I Been Pwned com k-anonimato.
 * A rede é falsa: o teste confere o que SAI do aparelho e como a
 * resposta é lida, sem depender da internet.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha1Hex, checkPwnedPassword, countInRangeResponse, pwnedMessage } from '../js/core/pwned.js';

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
const PASSWORD_SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

test('SHA-1 no formato do HIBP (hex maiúsculo)', async () => {
    assert.equal(await sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
});

test('k-anonimato: só os 5 primeiros caracteres do hash vão na URL', async () => {
    const seen = [];
    const fakeFetch = async (url, options) => {
        seen.push({ url, options });
        return { ok: true, text: async () => `0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n${PASSWORD_SUFFIX}:9659365\r\n` };
    };
    const result = await checkPwnedPassword('password', { fetchImpl: fakeFetch });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].url, 'https://api.pwnedpasswords.com/range/5BAA6');
    // nem a senha nem o resto do hash saem do aparelho
    assert.ok(!seen[0].url.includes(PASSWORD_SUFFIX));
    assert.ok(!seen[0].url.endsWith('password'));
    assert.deepEqual({ status: result.status, count: result.count, prefix: result.prefix }, { status: 'pwned', count: 9659365, prefix: '5BAA6' });
    assert.match(pwnedMessage(result), /9\.659\.365 vezes/);
});

test('padding só quando pedido (no navegador ele quebraria o CORS)', async () => {
    let headers;
    const fakeFetch = async (_url, options) => { headers = options.headers; return { ok: true, text: async () => '' }; };
    await checkPwnedPassword('x', { fetchImpl: fakeFetch });
    assert.equal(headers, undefined);
    await checkPwnedPassword('x', { fetchImpl: fakeFetch, padding: true });
    assert.deepEqual(headers, { 'Add-Padding': 'true' });
});

test('linhas de padding (contagem 0) não contam como vazamento', () => {
    assert.equal(countInRangeResponse(`${PASSWORD_SUFFIX}:0\n`, PASSWORD_SUFFIX), 0);
    assert.equal(countInRangeResponse('AAAA:3\n', PASSWORD_SUFFIX), 0);
});

test('rede fora ou erro HTTP vira "unavailable", nunca exceção', async () => {
    const down = await checkPwnedPassword('x', { fetchImpl: async () => { throw new Error('offline'); } });
    assert.equal(down.status, 'unavailable');
    const error = await checkPwnedPassword('x', { fetchImpl: async () => ({ ok: false, status: 503 }) });
    assert.equal(error.status, 'unavailable');
    assert.equal(pwnedMessage(error), '');
});
