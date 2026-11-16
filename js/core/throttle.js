/**
 * throttle.js — bloqueio progressivo depois de muitas tentativas erradas.
 *
 * Puro e com relógio injetável: o mesmo código roda no navegador
 * (auth.js, guardando no localStorage), no servidor da demo
 * (server/auth-service.mjs, em memória) e nos testes (relógio falso).
 *
 * Política (OWASP Authentication Cheat Sheet / ASVS 5.0 V6.3):
 *   - 5 erros seguidos liberam sem espera;
 *   - a partir do 5º erro, pausa de 30 s, que dobra a cada novo erro
 *     (30 s, 1 min, 2 min, 4 min, 8 min) até o teto de 15 min;
 *   - um acerto zera a contagem;
 *   - entradas paradas há 24 h são esquecidas.
 * Bloqueio TEMPORÁRIO, nunca permanente: um bloqueio permanente deixaria
 * qualquer pessoa trancar a conta de outra só errando a senha dela.
 */

export const THROTTLE_POLICY = Object.freeze({
    freeAttempts: 5,
    baseLockMs: 30_000,
    maxLockMs: 15 * 60_000,
    forgetAfterMs: 24 * 60 * 60_000,
});

/** Duração da pausa depois do n-ésimo erro seguido (0 = sem pausa). */
export function lockDurationFor(failures, policy = THROTTLE_POLICY) {
    if (failures < policy.freeAttempts) return 0;
    return Math.min(policy.baseLockMs * 2 ** (failures - policy.freeAttempts), policy.maxLockMs);
}

/** "30 s", "2 min", "1 min 30 s". */
export function formatWait(ms) {
    const total = Math.max(1, Math.ceil(ms / 1000));
    const minutes = Math.floor(total / 60);
    const seconds = total % 60;
    if (!minutes) return `${seconds} s`;
    return seconds ? `${minutes} min ${seconds} s` : `${minutes} min`;
}

/**
 * @param {{
 *   load?: () => Record<string, {failures:number, lockedUntil:number, lastAt:number}>,
 *   save?: (state:object) => void,
 *   now?: () => number,
 *   policy?: typeof THROTTLE_POLICY,
 * }} options
 */
export function createThrottle({ load, save, now = () => Date.now(), policy = THROTTLE_POLICY } = {}) {
    let memory = {};
    const read = () => (load ? (load() ?? {}) : memory);
    const write = (state) => { if (save) save(state); else memory = state; };

    function prune(state) {
        const cutoff = now() - policy.forgetAfterMs;
        return Object.fromEntries(Object.entries(state).filter(([, entry]) => entry && entry.lastAt >= cutoff));
    }

    function describe(entry) {
        const failures = entry?.failures ?? 0;
        const retryAfterMs = Math.max(0, (entry?.lockedUntil ?? 0) - now());
        return {
            locked: retryAfterMs > 0,
            retryAfterMs,
            failures,
            /** Quantos erros ainda cabem; o último deles já inicia a pausa. */
            attemptsBeforeLock: Math.max(0, policy.freeAttempts - failures),
            /** Duração da próxima pausa que vier (no 5º erro, se ainda não chegou lá). */
            nextLockMs: lockDurationFor(Math.max(failures + 1, policy.freeAttempts), policy),
        };
    }

    return {
        policy,

        /** Situação atual de uma chave (e-mail, IP…). */
        status(key) {
            return describe(prune(read())[key]);
        },

        /** Registra um erro e devolve a situação depois dele. */
        registerFailure(key) {
            const state = prune(read());
            const failures = (state[key]?.failures ?? 0) + 1;
            const lockMs = lockDurationFor(failures, policy);
            state[key] = { failures, lockedUntil: lockMs ? now() + lockMs : 0, lastAt: now() };
            write(state);
            return describe(state[key]);
        },

        /** Acertou: a contagem volta a zero. */
        registerSuccess(key) {
            const state = prune(read());
            delete state[key];
            write(state);
        },

        reset() {
            write({});
        },
    };
}
