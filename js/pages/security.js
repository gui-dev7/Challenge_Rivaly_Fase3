/**
 * security.js — controller do laboratório de segurança (seguranca.html).
 *
 * Quatro demonstrações, todas usando os mesmos módulos do login de
 * verdade, para que o que aparece aqui seja o que o produto faz:
 *   1. medidor de força + vazamentos  → password-policy.js, pwned.js
 *   2. hash antigo × hash novo         → password-hash.js
 *   3. bloqueio por tentativas         → throttle.js
 *   4. cadastro e login no servidor    → server-api.js → server/
 */

import { bootHybrid } from '../core/app.js';
import { mountPasswordMeter } from '../ui/password-meter.js';
import { hashPassword, legacyHashForDemo, isCryptoAvailable, PBKDF2 } from '../core/password-hash.js';
import { createThrottle, lockDurationFor, formatWait, THROTTLE_POLICY } from '../core/throttle.js';
import { serverHealth, serverRegister, serverLogin, serverAccounts } from '../core/server-api.js';
import { icon, escapeHtml, $ } from '../ui/ui.js';

bootHybrid({ page: 'security', title: 'Segurança', subtitle: 'O padrão de senha da RIVALY, ao vivo.' });

/* ============================================================
   MOSTRAR / OCULTAR SENHA
   ============================================================ */

function paintReveal(button, input) {
    const shown = input.type === 'text';
    button.innerHTML = icon(shown ? 'eye-off' : 'eye', { size: 16 });
    button.setAttribute('aria-label', shown ? 'Ocultar senha' : 'Mostrar senha');
    button.setAttribute('aria-pressed', String(shown));
}

document.querySelectorAll('[data-reveal-password]').forEach((button) => {
    const input = document.getElementById(button.dataset.revealPassword);
    paintReveal(button, input);
    button.addEventListener('click', () => {
        input.type = input.type === 'password' ? 'text' : 'password';
        paintReveal(button, input);
        input.focus();
    });
});

/* ============================================================
   1. TESTAR UMA SENHA
   ============================================================ */

const labPassword = $('#labPassword');
const labContext = () => ({ nickname: $('#labNickname').value, email: $('#labEmail').value });

function paintPwned(pwned) {
    const node = $('#pwnedDetail');
    if (!pwned?.prefix) {
        node.hidden = true;
        return;
    }
    const outcome = {
        pwned: `Resultado: apareceu ${pwned.count.toLocaleString('pt-BR')} ${pwned.count === 1 ? 'vez' : 'vezes'} em vazamentos. O cadastro recusa.`,
        clean: 'Resultado: não aparece nos vazamentos conhecidos.',
        unavailable: 'A consulta não respondeu agora. O cadastro segue com as outras regras e o servidor tenta de novo.',
    }[pwned.status] ?? '';
    node.innerHTML = `${icon('shield', { size: 16 })}<span>Para conferir vazamentos, saíram do seu navegador só <code>${escapeHtml(pwned.prefix)}</code>: 5 dos 40 caracteres do SHA-1 da senha. O Have I Been Pwned devolveu todos os hashes que começam assim, e a comparação foi feita aqui. ${escapeHtml(outcome)}</span>`;
    node.dataset.state = pwned.status;
    node.hidden = false;
}

const meter = mountPasswordMeter($('#labMeter'), {
    input: labPassword,
    getContext: labContext,
    showDetails: true,
    onChange: ({ pwned }) => paintPwned(pwned),
});

['#labNickname', '#labEmail'].forEach((selector) => $(selector).addEventListener('input', () => meter.refresh()));

document.querySelectorAll('[data-sample]').forEach((chip) => {
    chip.addEventListener('click', () => {
        labPassword.value = chip.dataset.sample;
        labPassword.type = 'text';
        const reveal = document.querySelector('[data-reveal-password="labPassword"]');
        if (reveal) paintReveal(reveal, labPassword);
        labPassword.dispatchEvent(new Event('input', { bubbles: true }));
        labPassword.focus();
    });
});

/* ============================================================
   2. HASH: ANTES × AGORA
   ============================================================ */

$('#hashRun').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    const password = labPassword.value;
    $('#hashEmpty').hidden = Boolean(password);
    if (!password) {
        labPassword.focus();
        return;
    }
    if (!isCryptoAvailable()) {
        $('#hashEmpty').textContent = 'O navegador só libera o Web Crypto em https:// ou http://localhost.';
        $('#hashEmpty').hidden = false;
        return;
    }

    button.disabled = true;
    button.classList.add('is-loading');
    try {
        const old1 = await legacyHashForDemo(password);
        const old2 = await legacyHashForDemo(password);

        const started = performance.now();
        const new1 = await hashPassword(password);
        const elapsed = Math.round(performance.now() - started);
        const new2 = await hashPassword(password);

        $('#hashOld1').textContent = old1;
        $('#hashOld2').textContent = old2;
        $('#hashNew1').textContent = new1;
        $('#hashNew2').textContent = new2;

        $('#hashOldVerdict').textContent = old1 === old2
            ? 'Iguais. Quem vazar o banco vê quem usa a mesma senha, e uma GPU testa bilhões de SHA-256 por segundo.'
            : 'Diferentes.';
        $('#hashNewVerdict').textContent = new1 !== new2
            ? `Diferentes, por causa do sal. Cada palpite custa ${PBKDF2.iterations.toLocaleString('pt-BR')} rodadas: ${elapsed} ms neste aparelho.`
            : 'Iguais (não deveria acontecer).';
        $('#hashCompare').hidden = false;
    } finally {
        button.disabled = false;
        button.classList.remove('is-loading');
    }
});

/* ============================================================
   3. BLOQUEIO POR TENTATIVAS (simulador, relógio real)
   ============================================================ */

const sim = createThrottle(); // em memória: some ao recarregar
const SIM_KEY = 'simulador';
let message = '';

$('#lockTable').innerHTML = Array.from({ length: 10 }, (_, index) => {
    const failures = index + 1;
    const wait = lockDurationFor(failures);
    const label = failures === 10 ? '10º ou mais' : `${failures}º`;
    return `<tr data-failures="${failures}"><td>${label}</td><td>${wait ? formatWait(wait) : 'sem pausa'}</td></tr>`;
}).join('');

function paintLock() {
    const status = sim.status(SIM_KEY);
    const plural = status.failures === 1 ? 'erro seguido' : 'erros seguidos';
    let text = status.failures ? `${status.failures} ${plural}. ` : 'Nenhum erro ainda. ';
    if (status.locked) {
        text += `Login pausado por mais ${formatWait(status.retryAfterMs)}.`;
    } else if (status.failures) {
        text += status.attemptsBeforeLock > 0
            ? `Mais ${status.attemptsBeforeLock} ${status.attemptsBeforeLock === 1 ? 'erro' : 'erros'} e começa uma pausa de ${formatWait(lockDurationFor(THROTTLE_POLICY.freeAttempts))}.`
            : `O próximo erro pausa por ${formatWait(status.nextLockMs)}.`;
    }
    $('#lockStatus').textContent = `${text}${message ? ` ${message}` : ''}`;
    $('#lockStatus').dataset.state = status.locked ? 'locked' : status.failures ? 'warn' : 'idle';

    const active = Math.min(status.failures, 10);
    document.querySelectorAll('#lockTable tr').forEach((row) => {
        row.toggleAttribute('data-active', Number(row.dataset.failures) === active);
    });
}

$('#lockFail').addEventListener('click', () => {
    message = '';
    if (sim.status(SIM_KEY).locked) message = 'Durante a pausa, nenhuma tentativa é conferida.';
    else sim.registerFailure(SIM_KEY);
    paintLock();
});

$('#lockOk').addEventListener('click', () => {
    if (sim.status(SIM_KEY).locked) {
        message = 'Nem a senha certa entra até a pausa acabar: é isso que segura um robô.';
    } else {
        sim.registerSuccess(SIM_KEY);
        message = 'Acertou: a contagem voltou a zero.';
    }
    paintLock();
});

$('#lockReset').addEventListener('click', () => {
    sim.reset();
    message = '';
    paintLock();
});

setInterval(() => { if (sim.status(SIM_KEY).locked || $('#lockStatus').dataset.state === 'locked') paintLock(); }, 500);
paintLock();

/* ============================================================
   4. SERVIDOR
   ============================================================ */

const OFFLINE_HELP = 'Rode "npm run demo" na pasta do projeto e recarregue esta página.';
let serverMode = 'offline';

async function detectServer() {
    const node = $('#serverStatus');
    const health = await serverHealth();

    if (!health.available) {
        serverMode = 'offline';
        node.dataset.state = 'offline';
        node.textContent = `Servidor da demo desligado. ${OFFLINE_HELP}`;
        return;
    }

    const { hashing, throttle, routes = [] } = health.body;
    if (!routes.includes('register')) {
        serverMode = 'partial';
        node.dataset.state = 'partial';
        node.textContent = 'No site publicado, o servidor faz a checagem de senha do cadastro (/api/password-check). Cadastro e login no servidor, com argon2id, rodam na demo local: npm run demo.';
        return;
    }

    serverMode = 'online';
    node.dataset.state = 'online';
    const hashText = hashing.algorithm === 'argon2id'
        ? `argon2id (${Math.round(hashing.memoryKiB / 1024)} MiB, ${hashing.passes} passadas)`
        : `scrypt (N=${hashing.N})`;
    node.textContent = `Servidor da demo no ar. Hash: ${hashText}. Bloqueio a partir do ${throttle.freeAttempts}º erro seguido, por e-mail e por IP.`;
}

function printResponse(result) {
    const node = $('#srvResponse');
    if (!result.available) {
        node.dataset.state = 'error';
        node.textContent = serverMode === 'partial'
            ? 'Esta rota existe só no servidor local. Rode "npm run demo".'
            : `Sem resposta do servidor. ${OFFLINE_HELP}`;
        return;
    }
    const header = `HTTP ${result.status}${result.retryAfter ? ` · Retry-After: ${result.retryAfter} s` : ''}`;
    node.dataset.state = result.status < 300 ? 'ok' : 'error';
    node.textContent = `${header}\n${JSON.stringify(result.body, null, 2)}`;
}

async function withBusy(form, task) {
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    button.classList.add('is-loading');
    try {
        return await task();
    } finally {
        button.disabled = false;
        button.classList.remove('is-loading');
    }
}

$('#srvRegister').addEventListener('submit', (event) => {
    event.preventDefault();
    withBusy(event.currentTarget, async () => {
        printResponse(await serverRegister({
            nickname: $('#srvRegNickname').value,
            email: $('#srvRegEmail').value,
            password: $('#srvRegPassword').value,
        }));
    });
});

$('#srvLogin').addEventListener('submit', (event) => {
    event.preventDefault();
    withBusy(event.currentTarget, async () => {
        printResponse(await serverLogin({ email: $('#srvLogEmail').value, password: $('#srvLogPassword').value }));
    });
});

$('#srvAccounts').addEventListener('click', async () => {
    const list = $('#srvAccountsList');
    const result = await serverAccounts();
    if (!result.available) {
        printResponse(result);
        list.innerHTML = '';
        return;
    }
    const accounts = result.body.accounts ?? [];
    list.innerHTML = accounts.length
        ? `<p class="sec-note">${escapeHtml(result.body.warning ?? '')}</p><ul class="sec-accounts">${accounts.map((account) => `
            <li>
                <span class="sec-accounts__who"><strong>${escapeHtml(account.nickname)}</strong> ${escapeHtml(account.email)}</span>
                <code class="sec-hash">${escapeHtml(account.passwordHash)}</code>
            </li>`).join('')}</ul>`
        : '<p class="sec-note">Nenhuma conta no servidor ainda. Crie uma no formulário ao lado.</p>';
});

detectServer();
