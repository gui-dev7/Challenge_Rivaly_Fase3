/**
 * auth-local.test.mjs — cadastro e login do navegador (auth.js) com o
 * padrão de senha, PBKDF2, mensagem genérica e bloqueio por tentativas.
 */
import { resetStorage } from './setup.mjs';
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { register, login, logout, GENERIC_LOGIN_ERROR, loginThrottleStatus } from '../js/core/auth.js';
import { initStorage, getAccounts, saveAccounts } from '../js/core/storage.js';
import { legacyHashForDemo } from '../js/core/password-hash.js';

const GOOD = 'pizza de quinta com o squad';

beforeEach(() => {
    resetStorage();
    initStorage();
});

test('cadastro recusa senha fora do padrão, mesmo sem passar pelo formulário', async () => {
    const short = await register({ nickname: 'Nova_7', email: 'nova@exemplo.com', password: 'abc123' });
    assert.equal(short.ok, false);
    assert.equal(short.field, 'password');

    const personal = await register({ nickname: 'Nova_7', email: 'nova@exemplo.com', password: 'nova joga demais toda noite' });
    assert.equal(personal.ok, false);
    assert.match(personal.error, /apelido/);
});

test('cadastro guarda PBKDF2 com sal, nunca a senha', async () => {
    const result = await register({ nickname: 'Nova_7', email: 'nova@exemplo.com', password: GOOD });
    assert.equal(result.ok, true, result.error);
    const [account] = getAccounts();
    assert.match(account.passwordHash, /^pbkdf2-sha256\$600000\$/);
    assert.ok(!JSON.stringify(account).includes(GOOD));
});

test('mensagem genérica: e-mail inexistente e senha errada respondem igual', async () => {
    await register({ nickname: 'Nova_7', email: 'nova@exemplo.com', password: GOOD });
    logout();
    const wrongPassword = await login({ email: 'nova@exemplo.com', password: 'outra frase qualquer aqui' });
    const unknownEmail = await login({ email: 'ninguem@exemplo.com', password: GOOD });
    assert.equal(wrongPassword.error, GENERIC_LOGIN_ERROR);
    assert.equal(unknownEmail.error, GENERIC_LOGIN_ERROR);
    assert.equal(wrongPassword.code, unknownEmail.code);
});

test('5 erros seguidos pausam o login, até para a senha certa', async () => {
    await register({ nickname: 'Nova_7', email: 'nova@exemplo.com', password: GOOD });
    logout();
    let last;
    for (let i = 0; i < 5; i += 1) last = await login({ email: 'nova@exemplo.com', password: `errada numero ${i} xyz` });
    assert.equal(last.code, 'locked');
    assert.ok(loginThrottleStatus('nova@exemplo.com').locked);

    const right = await login({ email: 'nova@exemplo.com', password: GOOD });
    assert.equal(right.ok, false);
    assert.equal(right.code, 'locked');
});

test('login com hash da V3.0 funciona e migra para PBKDF2', async () => {
    saveAccounts([{
        id: 'acc-legacy', nickname: 'Antigo', email: 'antigo@exemplo.com',
        passwordHash: await legacyHashForDemo('senha123'), createdAt: new Date().toISOString(),
    }]);
    const result = await login({ email: 'antigo@exemplo.com', password: 'senha123' });
    assert.equal(result.ok, true);
    assert.equal(result.upgradedHash, true);
    assert.match(getAccounts()[0].passwordHash, /^pbkdf2-sha256\$/);
});
