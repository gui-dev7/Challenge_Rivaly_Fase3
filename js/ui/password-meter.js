/**
 * password-meter.js — medidor de força + checklist do padrão de senha.
 *
 * Usado no cadastro (login.html) e no laboratório (seguranca.html).
 * Toda a regra vem de password-policy.js; aqui só tem desenho.
 *
 *   const meter = mountPasswordMeter(container, { input, getContext });
 *   const pwned = await meter.checkPwned(); // no envio do formulário
 *
 * A consulta de vazamento (pwned.js) roda sozinha 700 ms depois que a
 * pessoa para de digitar, e só quando a senha já tem o tamanho mínimo.
 * Ela envia apenas 5 caracteres do SHA-1 (k-anonimato).
 */

import { evaluatePassword, PASSWORD_POLICY } from '../core/password-policy.js';
import { checkPwnedPassword } from '../core/pwned.js';
import { icon, escapeHtml } from './ui.js';

const PWNED_TEXT = {
    idle: `Não aparece em vazamentos conhecidos (confere ao chegar em ${PASSWORD_POLICY.minLength} caracteres)`,
    checking: 'Conferindo vazamentos conhecidos…',
    clean: 'Não aparece em vazamentos conhecidos',
    pwned: 'Apareceu em vazamentos conhecidos',
    unavailable: 'Não deu para consultar vazamentos agora (sem rede?)',
};

/**
 * @param {HTMLElement} container
 * @param {{input:HTMLInputElement, getContext?:() => object, onChange?:(state:object) => void, showDetails?:boolean}} options
 */
export function mountPasswordMeter(container, { input, getContext = () => ({}), onChange, showDetails = false }) {
    container.classList.add('pw-meter');
    container.innerHTML = `
        <div class="pw-meter__bar" aria-hidden="true">${'<span></span>'.repeat(5)}</div>
        <p class="pw-meter__label"><span class="pw-meter__label-key">Força</span> <strong data-meter-label>—</strong> <span class="pw-meter__bits" data-meter-bits></span></p>
        <ul class="pw-meter__checks" data-meter-checks></ul>
        <p class="pw-meter__time" data-meter-time hidden></p>
        <p class="pw-meter__tip" data-meter-tip hidden></p>
        <p class="visually-hidden" aria-live="polite" data-meter-live></p>`;

    const nodes = {
        label: container.querySelector('[data-meter-label]'),
        bits: container.querySelector('[data-meter-bits]'),
        checks: container.querySelector('[data-meter-checks]'),
        time: container.querySelector('[data-meter-time]'),
        tip: container.querySelector('[data-meter-tip]'),
        live: container.querySelector('[data-meter-live]'),
    };

    let pwned = { status: 'idle', count: 0, prefix: '', for: null };
    let pwnedTimer = null;
    let liveTimer = null;
    let latest = evaluatePassword('', {});

    const checkItem = (state, label) => {
        const glyph = state === 'ok' ? 'check-circle' : state === 'bad' ? 'x-circle' : state === 'wait' ? 'clock' : 'info';
        return `<li class="pw-meter__check" data-state="${state}">${icon(glyph, { size: 15 })}<span>${label}</span></li>`;
    };

    function paint() {
        const value = input.value;
        latest = evaluatePassword(value, getContext());
        const { strength, empty } = latest;

        container.dataset.score = empty ? '-1' : String(strength.score);
        nodes.label.textContent = empty ? '—' : strength.label;
        nodes.bits.textContent = empty || !showDetails ? '' : `≈ ${Math.round(strength.bits)} bits`;

        const pwnedCurrent = pwned.for === value ? pwned.status : (latest.length >= PASSWORD_POLICY.minLength ? 'checking' : 'idle');
        const pwnedState = { clean: 'ok', pwned: 'bad', checking: 'wait', unavailable: 'info', idle: 'neutral' }[pwnedCurrent];
        let pwnedLabel = PWNED_TEXT[pwnedCurrent];
        if (pwnedCurrent === 'pwned') pwnedLabel = `Apareceu ${pwned.count.toLocaleString('pt-BR')} ${pwned.count === 1 ? 'vez' : 'vezes'} em vazamentos conhecidos`;

        nodes.checks.innerHTML = [
            ...latest.checks.map((check) => checkItem(empty ? 'neutral' : check.ok ? 'ok' : 'bad', escapeHtml(check.label))),
            checkItem(pwnedState, escapeHtml(pwnedLabel)),
        ].join('');

        if (!empty) {
            const times = strength.crackTimes;
            nodes.time.innerHTML = showDetails
                ? `Se o banco vazar: <strong>${escapeHtml(times.offlineSlow.text)}</strong> com argon2id · <strong>${escapeHtml(times.offlineFast.text)}</strong> com SHA-256 rápido`
                : `Tempo estimado para quebrar se o banco vazar: <strong>${escapeHtml(times.offlineSlow.text)}</strong>`;
        }
        nodes.time.hidden = empty;

        const tip = latest.errors[0]?.message ?? (strength.score < 4 ? strength.feedback[0] : '');
        nodes.tip.textContent = empty ? '' : tip ?? '';
        nodes.tip.hidden = empty || !tip;

        clearTimeout(liveTimer);
        liveTimer = setTimeout(() => {
            nodes.live.textContent = empty ? '' : `Força da senha: ${strength.label}. ${latest.ok ? 'Atende ao padrão.' : 'Ainda não atende ao padrão.'}`;
        }, 900);

        onChange?.({ evaluation: latest, pwned: pwned.for === value ? pwned : null });
    }

    async function runPwned(value) {
        const result = await checkPwnedPassword(value);
        if (input.value !== value) return pwned; // a pessoa já digitou outra coisa
        pwned = { ...result, for: value };
        paint();
        return pwned;
    }

    function schedulePwned() {
        clearTimeout(pwnedTimer);
        const value = input.value;
        if (Array.from(value).length < PASSWORD_POLICY.minLength || pwned.for === value) return;
        pwnedTimer = setTimeout(() => runPwned(value), 700);
    }

    input.addEventListener('input', () => { paint(); schedulePwned(); });
    paint();

    return {
        /** Reavalia (ex.: quando o apelido ou o e-mail mudam). */
        refresh: paint,
        evaluation: () => latest,
        /** Garante a consulta de vazamento da senha atual (para o envio). */
        async checkPwned() {
            const value = input.value;
            if (pwned.for === value && pwned.status !== 'unavailable') return pwned;
            clearTimeout(pwnedTimer);
            pwned = { status: 'checking', count: 0, prefix: '', for: null };
            paint();
            return runPwned(value);
        },
        lastPwned: () => (pwned.for === input.value ? pwned : null),
    };
}
