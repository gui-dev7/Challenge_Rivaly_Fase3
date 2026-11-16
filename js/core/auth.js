/**
 * auth.js — autenticação LOCAL da RIVALY (navegador).
 *
 * ┌────────────────────────────────────────────────────────────┐
 * │  AINDA NÃO É AUTENTICAÇÃO DE PRODUÇÃO.                     │
 * │                                                            │
 * │  As contas vivem no localStorage deste navegador. Quem     │
 * │  tem o dispositivo nas mãos consegue ler e editar tudo.    │
 * │  O que este arquivo faz de verdade desde a V3.1:           │
 * │    - padrão de senha (password-policy.js), igual ao do     │
 * │      servidor;                                             │
 * │    - PBKDF2-SHA256, 600 mil iterações, sal por conta       │
 * │      (password-hash.js), com migração dos hashes antigos;  │
 * │    - bloqueio progressivo após 5 erros (throttle.js);      │
 * │    - mensagem de erro genérica e tempo igual para e-mail   │
 * │      inexistente (sem enumeração de contas).               │
 * │  A versão com servidor (argon2id, bloqueio por IP, cookie  │
 * │  HttpOnly) está em server/ e na página seguranca.html.     │
 * └────────────────────────────────────────────────────────────┘
 */

import {
    getAccounts, saveAccounts, getSession, saveSession, clearSession,
    getUser, saveUser, resetAll, read, write, KEYS,
} from './storage.js';
import { createUser } from '../domain/profile.js';
import {
    VALIDATION as ACCOUNT_RULES, normaliseEmail, validateNickname, validateEmail,
} from './account-rules.js';
import { PASSWORD_POLICY, passwordError } from './password-policy.js';
import { hashPassword, verifyPassword, burnVerifyTime, isCryptoAvailable } from './password-hash.js';
import { createThrottle, formatWait } from './throttle.js';

export { validateNickname, validateEmail };

/* ============================================================
   VALIDAÇÃO
   Apelido e e-mail: account-rules.js. Senha: password-policy.js.
   Os dois módulos também rodam no servidor da demo.
   ============================================================ */

export const VALIDATION = {
    ...ACCOUNT_RULES,
    password: { min: PASSWORD_POLICY.minLength, max: PASSWORD_POLICY.maxLength },
};

/** @param {{nickname?:string, email?:string}} context dados que não podem estar na senha */
export const validatePassword = (value, context = {}) => passwordError(value, context);

export const GENERIC_LOGIN_ERROR = 'E-mail ou senha incorretos.';

const CRYPTO_UNAVAILABLE = 'Abra a RIVALY por https:// ou http://localhost: o navegador só libera a criptografia (Web Crypto) em contexto seguro.';

/* ============================================================
   BLOQUEIO POR TENTATIVAS
   No navegador ele é uma camada de experiência: quem apaga o
   localStorage zera a contagem. O bloqueio que vale é o do servidor.
   ============================================================ */

const throttle = createThrottle({
    load: () => read(KEYS.authThrottle, {}),
    save: (state) => write(KEYS.authThrottle, state),
});

export const loginThrottleStatus = (email) => throttle.status(normaliseEmail(email));

function lockedResult(status) {
    return {
        ok: false,
        code: 'locked',
        field: 'password',
        retryAfterMs: status.retryAfterMs,
        error: `Muitas tentativas erradas. Por segurança, espere ${formatWait(status.retryAfterMs)} para tentar de novo.`,
    };
}

/* ============================================================
   CONTAS
   ============================================================ */

export const findAccountByEmail = (email) =>
    getAccounts().find((account) => account.email === normaliseEmail(email)) ?? null;

/**
 * Cria a conta E o Passaporte que pertence a ela.
 * @returns {Promise<{ok:boolean, field?:string, error?:string, account?:object}>}
 */
export async function register({ nickname, email, password }) {
    const nicknameError = validateNickname(nickname);
    if (nicknameError) return { ok: false, field: 'nickname', error: nicknameError };

    const emailError = validateEmail(email);
    if (emailError) return { ok: false, field: 'email', error: emailError };

    // Revalida aqui mesmo que o formulário já tenha validado: quem chama
    // register() pode não ser o formulário.
    const passwordProblem = validatePassword(password, { nickname, email });
    if (passwordProblem) return { ok: false, field: 'password', error: passwordProblem };

    if (!isCryptoAvailable()) return { ok: false, field: 'password', error: CRYPTO_UNAVAILABLE };

    // Numa conta com servidor, esta resposta seria igual à de sucesso e o
    // aviso iria por e-mail (ver docs/padrao-de-senha.md). Aqui a conta é
    // local, deste navegador, então avisar não revela nada a terceiros.
    if (findAccountByEmail(email)) {
        return { ok: false, field: 'email', error: 'Já existe uma conta com este e-mail neste navegador. Entre por ela ou use outro e-mail.' };
    }

    const account = {
        id: `acc-${globalThis.crypto.randomUUID?.() ?? Date.now().toString(36)}`,
        nickname: String(nickname).trim(),
        email: normaliseEmail(email),
        passwordHash: await hashPassword(password),
        createdAt: new Date().toISOString(),
    };

    saveAccounts([...getAccounts(), account]);
    saveUser(createUser({ nickname: account.nickname, email: account.email }));
    saveSession({ accountId: account.id, startedAt: new Date().toISOString() });

    return { ok: true, account };
}

/**
 * @returns {Promise<{ok:boolean, code?:string, error?:string, field?:string,
 *   retryAfterMs?:number, attemptsBeforeLock?:number,
 *   account?:object, needsProfileSwitch?:boolean, upgradedHash?:boolean}>}
 */
export async function login({ email, password }) {
    const key = normaliseEmail(email);

    const status = throttle.status(key);
    if (status.locked) return lockedResult(status);

    if (!isCryptoAvailable()) return { ok: false, code: 'crypto', field: 'password', error: CRYPTO_UNAVAILABLE };

    const account = findAccountByEmail(key);
    // E-mail inexistente gasta o mesmo tempo e devolve a mesma mensagem.
    const check = account ? await verifyPassword(password, account.passwordHash) : await burnVerifyTime(password);

    if (!check.ok) {
        const after = throttle.registerFailure(key);
        if (after.locked) return lockedResult(after);
        const hint = after.attemptsBeforeLock <= 2
            ? ` Mais ${after.attemptsBeforeLock} ${after.attemptsBeforeLock === 1 ? 'erro' : 'erros'} e o login pausa por ${formatWait(after.nextLockMs)}.`
            : '';
        return {
            ok: false,
            code: 'invalid',
            field: 'password',
            attemptsBeforeLock: after.attemptsBeforeLock,
            error: `${GENERIC_LOGIN_ERROR}${hint}`,
        };
    }

    throttle.registerSuccess(key);

    // Migração silenciosa: o hash antigo vira PBKDF2 com sal próprio.
    let upgradedHash = false;
    if (check.needsRehash) {
        const passwordHash = await hashPassword(password);
        saveAccounts(getAccounts().map((item) => (item.id === account.id ? { ...item, passwordHash, hashUpgradedAt: new Date().toISOString() } : item)));
        upgradedHash = true;
    }

    const storedUser = getUser();

    // Um Passaporte por navegador: entrar com outra conta substitui o
    // atual, então quem chamou precisa confirmar.
    if (storedUser && storedUser.email !== account.email) {
        return { ok: true, account, needsProfileSwitch: true, upgradedHash };
    }

    if (!storedUser) {
        saveUser(createUser({ nickname: account.nickname, email: account.email }));
    }

    saveSession({ accountId: account.id, startedAt: new Date().toISOString() });
    return { ok: true, account, upgradedHash };
}

/** Conclui um login que precisa substituir o Passaporte local. */
export function switchProfile(account) {
    resetAll({ keepAccounts: true });
    saveUser(createUser({ nickname: account.nickname, email: account.email }));
    saveSession({ accountId: account.id, startedAt: new Date().toISOString() });
}

export function logout() {
    clearSession();
}

/* ============================================================
   SESSÃO
   ============================================================ */

export function currentAccount() {
    const session = getSession();
    if (!session?.accountId) return null;
    return getAccounts().find((account) => account.id === session.accountId) ?? null;
}

export const isAuthenticated = () => Boolean(currentAccount());

/**
 * Guarda de rota usada por toda página do app.
 * @param {{requireOnboarding?: boolean}} options
 * @returns {boolean} true quando a página pode continuar.
 */
export function requireAuth({ requireOnboarding = true } = {}) {
    if (!isAuthenticated()) {
        window.location.replace('login.html?redirect=' + encodeURIComponent(currentPageName()));
        return false;
    }

    const user = getUser();
    if (!user) {
        window.location.replace('login.html');
        return false;
    }

    if (requireOnboarding && !user.onboardingComplete) {
        window.location.replace('onboarding.html');
        return false;
    }

    return true;
}

/** Guarda de login/onboarding: manda quem já entrou para o lugar certo. */
export function redirectIfAuthenticated() {
    if (!isAuthenticated()) return false;
    const user = getUser();
    if (user && !user.onboardingComplete) {
        window.location.replace('onboarding.html');
    } else {
        window.location.replace('dashboard.html');
    }
    return true;
}

function currentPageName() {
    const parts = window.location.pathname.split('/');
    return parts[parts.length - 1] || 'dashboard.html';
}
