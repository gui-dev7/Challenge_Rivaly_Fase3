/**
 * auth-service.mjs — as regras de conta do servidor da demo.
 *
 * Nada de HTTP aqui: cada função recebe dados e devolve
 * { status, body, headers? }. O transporte fica em http-handler.mjs.
 * Isso deixa o serviço testável direto (tests/auth-server.test.mjs) e
 * reaproveitável numa Vercel Function (api/).
 *
 * O que este servidor faz e o navegador não consegue garantir sozinho:
 *   - é a validação que VALE: o mesmo password-policy.js do cliente,
 *     rodando onde o usuário não consegue desligar;
 *   - argon2id com sal por conta (password-hasher.mjs);
 *   - consulta ao Have I Been Pwned com padding;
 *   - bloqueio por e-mail E por IP (credential stuffing usa muitos
 *     e-mails a partir de poucas máquinas);
 *   - resposta e tempo iguais para e-mail inexistente e senha errada;
 *   - cadastro com resposta igual para e-mail novo e repetido;
 *   - sessão em cookie HttpOnly + SameSite=Strict, guardada como hash.
 *
 * Os dados ficam em memória: reiniciar o servidor apaga as contas.
 * Banco de dados, e-mail de confirmação e MFA estão em docs/ como proposta.
 */

import crypto from 'node:crypto';
import { evaluatePassword, PASSWORD_POLICY } from '../js/core/password-policy.js';
import { checkPwnedPassword, pwnedMessage } from '../js/core/pwned.js';
import { createThrottle, formatWait, THROTTLE_POLICY } from '../js/core/throttle.js';
import { validateNickname, validateEmail, normaliseEmail } from '../js/core/account-rules.js';
import * as hasher from './password-hasher.mjs';

export const GENERIC_LOGIN_ERROR = 'E-mail ou senha incorretos.';

/** Por IP o limite é maior: uma casa ou uma escola dividem o mesmo IP. */
export const IP_THROTTLE_POLICY = Object.freeze({ ...THROTTLE_POLICY, freeAttempts: 20 });

export const SESSION_TTL_SECONDS = 60 * 60;

/** Entradas absurdas são recusadas antes de gastar CPU com hash. */
const MAX_FIELD = 1024;

const isText = (value) => typeof value === 'string' && value.length <= MAX_FIELD;

const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');

/**
 * @param {{
 *   now?: () => number,
 *   pwnedCheck?: (password:string) => Promise<{status:string, count:number}>,
 *   log?: (message:string) => void,
 *   secureCookies?: boolean,
 * }} options
 */
export function createAuthService({
    now = () => Date.now(),
    pwnedCheck = (password) => checkPwnedPassword(password, { padding: true }),
    log = () => {},
    secureCookies = false,
} = {}) {
    const users = new Map();     // e-mail → conta
    const sessions = new Map();  // sha256(token) → sessão
    const byEmail = createThrottle({ now });
    const byIp = createThrottle({ now, policy: IP_THROTTLE_POLICY });

    let dummyHash = null;
    const getDummyHash = async () => (dummyHash ??= await hasher.hashPassword(crypto.randomBytes(24).toString('hex')));

    function lockedResponse(status) {
        const seconds = Math.ceil(status.retryAfterMs / 1000);
        return {
            status: 429,
            headers: { 'Retry-After': String(seconds) },
            body: {
                ok: false,
                code: 'locked',
                error: `Muitas tentativas erradas. Espere ${formatWait(status.retryAfterMs)} para tentar de novo.`,
                retryAfterSeconds: seconds,
            },
        };
    }

    /** Avalia a senha sem criar nada (usado pelo cadastro e pelo formulário). */
    async function checkPassword({ password, nickname = '', email = '' } = {}) {
        if (!isText(password)) {
            return { status: 400, body: { ok: false, error: 'Envie a senha como texto.' } };
        }
        const evaluation = evaluatePassword(password, { nickname: String(nickname), email: String(email) });
        const pwned = evaluation.length >= PASSWORD_POLICY.minLength ? await pwnedCheck(password) : { status: 'skipped', count: 0 };

        const errors = [...evaluation.errors];
        if (pwned.status === 'pwned') errors.push({ code: 'pwned', message: pwnedMessage(pwned) });

        return {
            status: errors.length ? 422 : 200,
            body: {
                ok: errors.length === 0,
                checkedBy: 'servidor',
                errors,
                checks: evaluation.checks,
                strength: { score: evaluation.strength.score, label: evaluation.strength.label, bits: evaluation.strength.bits },
                pwned: { status: pwned.status, count: pwned.count ?? 0 },
            },
        };
    }

    async function register({ nickname, email, password } = {}) {
        if (!isText(nickname) || !isText(email) || !isText(password)) {
            return { status: 400, body: { ok: false, error: 'Envie apelido, e-mail e senha como texto.' } };
        }
        const nicknameError = validateNickname(nickname);
        if (nicknameError) return { status: 400, body: { ok: false, field: 'nickname', error: nicknameError } };
        const emailError = validateEmail(email);
        if (emailError) return { status: 400, body: { ok: false, field: 'email', error: emailError } };

        const check = await checkPassword({ password, nickname, email });
        if (!check.body.ok) {
            return { status: 422, body: { ok: false, field: 'password', error: check.body.errors[0].message, errors: check.body.errors } };
        }

        const key = normaliseEmail(email);
        const passwordHash = await hasher.hashPassword(password); // calculado nos dois casos: mesmo tempo
        if (!users.has(key)) {
            users.set(key, { id: crypto.randomUUID(), nickname: nickname.trim(), email: key, passwordHash, createdAt: new Date(now()).toISOString() });
            log(`cadastro: conta criada para ${key}`);
        } else {
            log(`cadastro: ${key} já existia. Resposta igual; em produção, o dono receberia um aviso por e-mail.`);
        }

        // Mesma resposta para e-mail novo ou repetido: o cadastro não vira
        // um jeito de descobrir quem tem conta.
        return {
            status: 202,
            body: { ok: true, message: 'Cadastro recebido. Em produção, a confirmação chegaria por e-mail.' },
        };
    }

    async function login({ email, password } = {}, { ip = 'desconhecido' } = {}) {
        const key = normaliseEmail(isText(email) ? email : '');

        const blocked = [byIp.status(ip), byEmail.status(key)].find((status) => status.locked);
        if (blocked) return lockedResponse(blocked);

        const user = users.get(key);
        const candidate = isText(password) ? password : '';
        const check = user
            ? await hasher.verifyPassword(candidate, user.passwordHash)
            : (await hasher.verifyPassword(candidate, await getDummyHash()), { ok: false, needsRehash: false });

        if (!check.ok) {
            const afterEmail = byEmail.registerFailure(key);
            const afterIp = byIp.registerFailure(ip);
            const lockedNow = [afterIp, afterEmail].find((status) => status.locked);
            log(`login: falha para ${key || '(vazio)'} (${afterEmail.failures} seguidas)`);
            if (lockedNow) return lockedResponse(lockedNow);
            return {
                status: 401,
                body: { ok: false, code: 'invalid', error: GENERIC_LOGIN_ERROR, attemptsBeforeLock: afterEmail.attemptsBeforeLock },
            };
        }

        byEmail.registerSuccess(key);
        if (check.needsRehash) {
            user.passwordHash = await hasher.hashPassword(candidate);
            log(`login: hash de ${key} atualizado para ${hasher.preferredAlgorithm}`);
        }

        // O token vai para o navegador; o servidor guarda só o hash dele.
        const token = crypto.randomBytes(32).toString('base64url');
        sessions.set(sha256(token), { email: key, expiresAt: now() + SESSION_TTL_SECONDS * 1000 });
        log(`login: sucesso para ${key}`);

        const cookie = [
            `rv_session=${token}`, 'HttpOnly', 'SameSite=Strict', 'Path=/', `Max-Age=${SESSION_TTL_SECONDS}`,
            ...(secureCookies ? ['Secure'] : []),
        ].join('; ');

        return {
            status: 200,
            headers: { 'Set-Cookie': cookie },
            body: { ok: true, nickname: user.nickname, message: `Login aprovado pelo servidor. Bem-vindo, ${user.nickname}.` },
        };
    }

    /** SÓ PARA A DEMO: mostra como cada senha ficou guardada. */
    function listAccounts() {
        return {
            status: 200,
            body: {
                ok: true,
                warning: 'Rota de demonstração. Não existe em produção.',
                accounts: [...users.values()].map(({ nickname, email, passwordHash, createdAt }) => ({ nickname, email, passwordHash, createdAt })),
            },
        };
    }

    return { checkPassword, register, login, listAccounts, sessionCount: () => sessions.size };
}
