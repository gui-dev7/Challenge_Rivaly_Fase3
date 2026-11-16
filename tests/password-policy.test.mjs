/**
 * password-policy.test.mjs — o padrão de senha (o mesmo no cliente e no servidor).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
    evaluatePassword, estimateStrength, commonPasswordMatch, personalInfoMatch, contextTokens,
    passwordLength, formatDuration, PASSWORD_POLICY, BLOCKLIST,
} from '../js/core/password-policy.js';

const ctx = { nickname: 'Nova_7', email: 'nova.silva@fiap.com.br' };
const codes = (password, context = ctx) => evaluatePassword(password, context).errors.map((error) => error.code);

test('tamanho: mínimo de 15 e máximo de 128, contando caracteres de verdade', () => {
    assert.equal(PASSWORD_POLICY.minLength, 15);
    assert.ok(codes('xk7#qz').includes('too_short'));
    assert.ok(!codes('xk7#qz9!vbm2@rt').includes('too_short')); // 15
    assert.ok(codes('xk7#qz9!vbm2@r'.padEnd(129, 'w')).includes('too_long'));
    // emoji conta 1, não 2 (code points, não UTF-16)
    assert.equal(passwordLength('🎮🎮🎮'), 3);
    // NFKC: "é" composto e decomposto viram a mesma senha
    assert.equal(passwordLength('é'), 1);
});

test('sem regra de composição: frase só com minúsculas e espaços é aceita', () => {
    const result = evaluatePassword('pizza de quinta com o squad', ctx);
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    assert.ok(result.strength.score >= 3);
});

test('composição "clássica" não garante nada: Senha@2026forte é recusada', () => {
    const result = evaluatePassword('Senha@2026forte', ctx);
    assert.equal(result.ok, false);
    assert.ok(result.strength.score < PASSWORD_POLICY.minScore);
});

test('lista de bloqueio: senhas comuns e variações com números, símbolos e leet', () => {
    assert.ok(BLOCKLIST.has('123456'));
    assert.equal(commonPasswordMatch('minecraft2024!!!'), 'minecraft');
    assert.equal(commonPasswordMatch('M1necr@ft2024!!!'), 'minecraft');
    assert.match(commonPasswordMatch('p@ssw0rd123456789'), /^password/);
    assert.equal(commonPasswordMatch('valorantvalorant'), 'valorant');
    assert.equal(commonPasswordMatch('rivaly2026!!!!!!'), 'rivaly');
    assert.ok(commonPasswordMatch('dragon pokemon batman 2026'));
    assert.ok(codes('Flamengo1234567!').includes('common'));
    // uma palavra comum DENTRO de uma frase própria não bloqueia
    assert.equal(commonPasswordMatch('eu jogo valorant toda noite'), null);
});

test('dados pessoais: apelido e partes do e-mail não podem aparecer', () => {
    // o domínio também entra quando não é um provedor comum (fiap.com.br)
    assert.deepEqual(contextTokens(ctx).sort(), ['fiap', 'nova', 'nova7', 'novasilva', 'silva'].sort());
    assert.equal(personalInfoMatch('NovaSilva2026!!!xyz', ctx) !== null, true);
    assert.equal(personalInfoMatch('n0v4 joga demais hoje', ctx), 'nova'); // leet também
    assert.ok(codes('silva joga lol a noite toda').includes('personal_info'));
    // provedores de e-mail comuns não viram palavra proibida
    assert.ok(!contextTokens({ email: 'ze@gmail.com' }).includes('gmail'));
});

test('padrões previsíveis: repetição, sequência e teclado ficam fracos', () => {
    for (const password of ['aaaaaaaaaaaaaaa', '123456789012345', 'qwertyuiopasdfg', 'abcabcabcabcabcabc']) {
        const result = evaluatePassword(password, ctx);
        assert.equal(result.ok, false, password);
        assert.ok(result.strength.score <= 1, `${password}: ${result.strength.bits} bits`);
    }
});

test('força cresce com o tamanho e com a imprevisibilidade', () => {
    const short = estimateStrength('kqzvmtbx').bits;
    const long = estimateStrength('kqzvmtbxwplrfghn').bits;
    assert.ok(long > short);
    assert.ok(estimateStrength('kqzvmtbxwplrfgh').score >= 3);
    assert.ok(estimateStrength('minecraft').bits < estimateStrength('kqzvmtbxw').bits);
});

test('checklist: um item por regra, todos verdes numa senha boa', () => {
    const good = evaluatePassword('MeuCachorroRex#7 late', ctx);
    assert.equal(good.ok, true, JSON.stringify(good.errors));
    assert.deepEqual(good.checks.map((check) => check.id), ['length', 'common', 'personal', 'strength']);
    assert.ok(good.checks.every((check) => check.ok));

    const empty = evaluatePassword('', ctx);
    assert.equal(empty.empty, true);
    assert.equal(empty.ok, false);
});

test('caracteres de controle são recusados', () => {
    assert.ok(codes('uma frase bem longa\tcom tab').includes('control_chars'));
});

test('formatDuration escreve tempos legíveis', () => {
    assert.equal(formatDuration(0.2), 'menos de 1 segundo');
    assert.equal(formatDuration(90), '1 minuto');
    assert.equal(formatDuration(60 * 60 * 24 * 3), '3 dias');
    assert.equal(formatDuration(1e30), 'mais que a idade do universo');
});
