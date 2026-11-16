/**
 * account-rules.js — regras de apelido e e-mail, sem DOM.
 *
 * Saiu de auth.js para que o navegador (login.html) e o servidor da demo
 * (server/auth-service.mjs) validem com exatamente o mesmo código. A regra
 * de senha mora em password-policy.js pelo mesmo motivo.
 */

export const VALIDATION = {
    nickname: { min: 3, max: 18, pattern: /^[a-zA-Z0-9_À-ÿ][a-zA-Z0-9_ À-ÿ-]{1,16}[a-zA-Z0-9_À-ÿ]$/ },
    email: { pattern: /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/, max: 254 },
};

export const normaliseEmail = (email) => String(email ?? '').trim().toLowerCase();

export function validateNickname(value) {
    const nickname = String(value ?? '').trim();
    if (nickname.length < VALIDATION.nickname.min) return 'O apelido precisa de pelo menos 3 caracteres.';
    if (nickname.length > VALIDATION.nickname.max) return 'O apelido pode ter no máximo 18 caracteres.';
    if (!VALIDATION.nickname.pattern.test(nickname)) return 'Use letras, números, espaços, hífen ou sublinhado. Ex.: Nova_7.';
    return '';
}

export function validateEmail(value) {
    const email = normaliseEmail(value);
    if (!email) return 'Digite um e-mail.';
    if (email.length > VALIDATION.email.max) return 'Este e-mail é longo demais.';
    if (!VALIDATION.email.pattern.test(email)) return 'Digite um e-mail no formato nome@exemplo.com.';
    return '';
}
