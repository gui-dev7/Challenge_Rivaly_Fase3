/**
 * throttle.test.mjs — bloqueio progressivo, com relógio falso.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createThrottle, lockDurationFor, formatWait, THROTTLE_POLICY } from '../js/core/throttle.js';

function clock(start = 1_000_000) {
    let time = start;
    return { now: () => time, advance: (ms) => { time += ms; } };
}

test('escala: sem pausa até o 4º erro; 30 s no 5º, dobrando até 15 min', () => {
    assert.deepEqual([1, 2, 3, 4].map((n) => lockDurationFor(n)), [0, 0, 0, 0]);
    assert.equal(lockDurationFor(5), 30_000);
    assert.equal(lockDurationFor(6), 60_000);
    assert.equal(lockDurationFor(7), 120_000);
    assert.equal(lockDurationFor(9), 480_000);
    assert.equal(lockDurationFor(10), THROTTLE_POLICY.maxLockMs);
    assert.equal(lockDurationFor(50), THROTTLE_POLICY.maxLockMs);
});

test('o 5º erro seguido bloqueia e a pausa termina sozinha', () => {
    const time = clock();
    const throttle = createThrottle({ now: time.now });
    for (let i = 1; i <= 4; i += 1) assert.equal(throttle.registerFailure('a@x.com').locked, false);
    const fifth = throttle.registerFailure('a@x.com');
    assert.equal(fifth.locked, true);
    assert.equal(fifth.retryAfterMs, 30_000);

    time.advance(29_000);
    assert.equal(throttle.status('a@x.com').locked, true);
    time.advance(1_000);
    assert.equal(throttle.status('a@x.com').locked, false);

    // O próximo erro já vem com pausa dobrada.
    assert.equal(throttle.registerFailure('a@x.com').retryAfterMs, 60_000);
});

test('acerto zera a contagem; chaves diferentes não se misturam', () => {
    const throttle = createThrottle({ now: clock().now });
    throttle.registerFailure('a@x.com');
    throttle.registerFailure('a@x.com');
    throttle.registerFailure('b@x.com');
    throttle.registerSuccess('a@x.com');
    assert.equal(throttle.status('a@x.com').failures, 0);
    assert.equal(throttle.status('b@x.com').failures, 1);
});

test('attemptsBeforeLock e nextLockMs dizem quando e quanto vem a pausa', () => {
    const time = clock();
    const throttle = createThrottle({ now: time.now });
    const first = throttle.registerFailure('k');
    assert.equal(first.attemptsBeforeLock, 4);
    assert.equal(first.nextLockMs, 30_000); // a pausa que vem é a do 5º erro
    throttle.registerFailure('k');
    throttle.registerFailure('k');
    assert.equal(throttle.registerFailure('k').attemptsBeforeLock, 1);
    throttle.registerFailure('k'); // 5º: pausa de 30 s
    time.advance(30_000);
    assert.equal(throttle.status('k').nextLockMs, 60_000); // a próxima já dobra
});

test('entradas paradas há mais de 24 h são esquecidas', () => {
    const time = clock();
    const throttle = createThrottle({ now: time.now });
    throttle.registerFailure('k');
    time.advance(THROTTLE_POLICY.forgetAfterMs + 1);
    assert.equal(throttle.status('k').failures, 0);
});

test('load/save: o estado pode morar fora (localStorage no navegador)', () => {
    let stored = {};
    const throttle = createThrottle({ load: () => stored, save: (state) => { stored = state; }, now: clock().now });
    throttle.registerFailure('k');
    assert.equal(stored.k.failures, 1);
});

test('formatWait', () => {
    assert.equal(formatWait(30_000), '30 s');
    assert.equal(formatWait(120_000), '2 min');
    assert.equal(formatWait(90_000), '1 min 30 s');
});
