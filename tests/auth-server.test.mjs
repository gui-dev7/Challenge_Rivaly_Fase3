/**
 * auth-server.test.mjs — o servidor da demo: argon2id, padrão de senha,
 * vazamentos, bloqueio por e-mail e IP, respostas sem enumeração e as
 * defesas do transporte HTTP (Content-Type, tamanho, cookie).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createAuthService, GENERIC_LOGIN_ERROR } from '../server/auth-service.mjs';
import { createRequestHandler } from '../server/http-handler.mjs';
import { hashPassword, verifyPassword, parsePhc, preferredAlgorithm } from '../server/password-hasher.mjs';

const GOOD = 'pizza de quinta com o squad';
const notPwned = async () => ({ status: 'clean', count: 0 });

function clock(start = 5_000_000) {
    let time = start;
    return { now: () => time, advance: (ms) => { time += ms; } };
}

test('hasher: formato PHC, sal por hash e verificação', async () => {
    const a = await hashPassword(GOOD);
    const b = await hashPassword(GOOD);
    assert.notEqual(a, b);
    if (preferredAlgorithm === 'argon2id') {
        assert.match(a, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    }
    assert.equal(parsePhc(a).salt.length, 16);
    assert.deepEqual(await verifyPassword(GOOD, a), { ok: true, needsRehash: false });
    assert.equal((await verifyPassword('errada', a)).ok, false);
});

test('hasher: hash scrypt antigo confere e pede rehash para argon2id', { skip: preferredAlgorithm !== 'argon2id' }, async () => {
    const old = await hashPassword(GOOD, { algorithm: 'scrypt' });
    assert.match(old, /^\$scrypt\$ln=17,r=8,p=1\$/);
    assert.deepEqual(await verifyPassword(GOOD, old), { ok: true, needsRehash: true });
});

test('servidor aplica o mesmo padrão do cliente', async () => {
    const service = createAuthService({ pwnedCheck: notPwned });
    const weak = await service.register({ nickname: 'Nova_7', email: 'nova@x.com', password: 'Senha@2026' });
    assert.equal(weak.status, 422);
    assert.equal(weak.body.field, 'password');

    const check = await service.checkPassword({ password: GOOD });
    assert.equal(check.status, 200);
    assert.equal(check.body.checkedBy, 'servidor');
});

test('servidor recusa senha vazada', async () => {
    const service = createAuthService({ pwnedCheck: async () => ({ status: 'pwned', count: 42 }) });
    const result = await service.register({ nickname: 'Nova_7', email: 'nova@x.com', password: GOOD });
    assert.equal(result.status, 422);
    assert.ok(result.body.errors.some((error) => error.code === 'pwned'));
});

test('cadastro responde igual para e-mail novo e repetido', async () => {
    const service = createAuthService({ pwnedCheck: notPwned });
    const first = await service.register({ nickname: 'Nova_7', email: 'nova@x.com', password: GOOD });
    const again = await service.register({ nickname: 'Zeca_9', email: 'nova@x.com', password: 'cachorro latiu na chuva de domingo' });
    assert.deepEqual(first, again);
    // e a senha original continua valendo
    assert.equal((await service.login({ email: 'nova@x.com', password: GOOD })).status, 200);
});

test('login: mensagem genérica para e-mail inexistente e senha errada', async () => {
    const service = createAuthService({ pwnedCheck: notPwned });
    await service.register({ nickname: 'Nova_7', email: 'nova@x.com', password: GOOD });
    const wrong = await service.login({ email: 'nova@x.com', password: 'nada a ver com a senha' }, { ip: '1.1.1.1' });
    const unknown = await service.login({ email: 'zz@x.com', password: GOOD }, { ip: '2.2.2.2' });
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.equal(wrong.body.error, GENERIC_LOGIN_ERROR);
    assert.equal(unknown.body.error, GENERIC_LOGIN_ERROR);
});

test('login: 5º erro devolve 429 com Retry-After, e a pausa acaba', async () => {
    const time = clock();
    const service = createAuthService({ pwnedCheck: notPwned, now: time.now });
    await service.register({ nickname: 'Nova_7', email: 'nova@x.com', password: GOOD });

    let result;
    for (let i = 0; i < 5; i += 1) result = await service.login({ email: 'nova@x.com', password: `errada ${i}` }, { ip: '9.9.9.9' });
    assert.equal(result.status, 429);
    assert.equal(result.headers['Retry-After'], '30');

    // Durante a pausa, nem a senha certa.
    assert.equal((await service.login({ email: 'nova@x.com', password: GOOD }, { ip: '9.9.9.9' })).status, 429);

    time.advance(30_000);
    const ok = await service.login({ email: 'nova@x.com', password: GOOD }, { ip: '9.9.9.9' });
    assert.equal(ok.status, 200);
    assert.match(ok.headers['Set-Cookie'], /HttpOnly; SameSite=Strict/);
});

test('login: o mesmo IP testando muitos e-mails também é bloqueado', async () => {
    const service = createAuthService({ pwnedCheck: notPwned });
    let result;
    for (let i = 0; i < 20; i += 1) result = await service.login({ email: `vitima${i}@x.com`, password: 'senha123' }, { ip: '6.6.6.6' });
    assert.equal(result.status, 429);
    // outro IP segue livre
    assert.equal((await service.login({ email: 'a@x.com', password: 'senha123' }, { ip: '7.7.7.7' })).status, 401);
});

test('HTTP: rotas, Content-Type obrigatório, limite de corpo e no-store', async () => {
    const service = createAuthService({ pwnedCheck: notPwned });
    const server = http.createServer(createRequestHandler(service));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;

    try {
        const health = await fetch(`${base}/api/health`);
        assert.equal(health.status, 200);
        assert.equal(health.headers.get('cache-control'), 'no-store');
        assert.equal((await health.json()).passwordPolicy.minLength, 15);

        // Um <form> de outro site manda text/plain ou form-urlencoded: recusado.
        const form = await fetch(`${base}/api/login`, { method: 'POST', body: 'email=a&password=b', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
        assert.equal(form.status, 415);

        const huge = await fetch(`${base}/api/password-check`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: 'x'.repeat(20_000) }),
        });
        assert.equal(huge.status, 413);

        const register = await fetch(`${base}/api/register`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nickname: 'Nova_7', email: 'nova@x.com', password: GOOD }),
        });
        assert.equal(register.status, 202);

        const login = await fetch(`${base}/api/login`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'nova@x.com', password: GOOD }),
        });
        assert.equal(login.status, 200);
        assert.match(login.headers.get('set-cookie'), /rv_session=.+; HttpOnly; SameSite=Strict/);

        assert.equal((await fetch(`${base}/api/login`)).status, 405);
        assert.equal((await fetch(`${base}/api/nada`)).status, 404);
    } finally {
        server.close();
    }
});

test('Vercel: só as rotas liberadas respondem', async () => {
    const service = createAuthService({ pwnedCheck: notPwned });
    const server = http.createServer(createRequestHandler(service, { routes: ['password-check'] }));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
        const register = await fetch(`${base}/api/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        assert.equal(register.status, 404);
        const check = await fetch(`${base}/api/password-check`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: GOOD }) });
        assert.equal(check.status, 200);
    } finally {
        server.close();
    }
});
