/**
 * password-policy.js — o PADRÃO DE SENHA da RIVALY.
 *
 * Um módulo puro (sem DOM, sem rede) importado nos dois lados:
 *   - no navegador, por login.html e seguranca.html (feedback ao vivo);
 *   - no servidor, por server/auth-service.mjs (a validação que vale).
 * Mesma regra, mesmo texto de erro: o cliente ajuda, o servidor decide.
 *
 * Base: NIST SP 800-63B-4 (2025), seção de senhas, e OWASP ASVS 5.0, V6.
 *   - Mínimo de 15 caracteres quando a senha é o único fator (NIST).
 *   - Máximo de 128: frases-senha cabem, e o servidor não vira alvo de
 *     negação de serviço por hash de textos gigantes.
 *   - Espaços, acentos e emoji são aceitos; o texto é normalizado em NFKC
 *     para "é" digitado de dois jeitos virar a mesma senha.
 *   - SEM regra de composição ("1 maiúscula, 1 símbolo..."): a NIST proíbe,
 *     porque empurra as pessoas para "Senha@2026", que todo ataque testa.
 *   - Lista de bloqueio: senhas comuns, nomes de jogos e times, o nome do
 *     serviço e dados da própria pessoa (apelido, e-mail).
 *   - Estimativa de força: precisa chegar a "Forte" (cerca de 55 bits).
 *   - Senha vazada (Have I Been Pwned) é verificada à parte, em pwned.js,
 *     porque depende de rede.
 *
 * O estimador é uma versão simplificada da ideia do zxcvbn (Dropbox):
 * quebra a senha em padrões que um atacante adivinha rápido (palavras de
 * dicionário, sequências, teclado, repetições, anos) e soma o custo de
 * cada pedaço em bits. Em produção, o recomendado é o zxcvbn-ts completo.
 */

export const PASSWORD_POLICY = Object.freeze({
    minLength: 15,
    maxLength: 128,
    /** Pontuação mínima na escala 0–4 (3 = "Forte"). */
    minScore: 3,
    /** Partes do apelido/e-mail com menos que isso não são procuradas. */
    contextMinLength: 4,
});

export const STRENGTH_LABELS = ['Muito fraca', 'Fraca', 'Razoável', 'Forte', 'Muito forte'];

/** Limites em bits entre uma faixa e a próxima. */
export const SCORE_THRESHOLDS = [28, 40, 55, 70];

/* ============================================================
   LISTA DE BLOQUEIO
   Senhas mais vazadas do mundo e do Brasil, mais o vocabulário de quem
   joga: nomes de jogos, personagens, times e o próprio nome do serviço.
   Tudo minúsculo e sem acento; a busca entende leet (p@ssw0rd).
   ============================================================ */

const COMMON_PASSWORDS = [
    '123456', '1234567', '12345678', '123456789', '1234567890', '12345', '1234', '123123', '111111',
    '000000', '654321', '666666', '121212', '112233', '159753', '147258', '102030', '123321', '987654321',
    'password', 'passw0rd', 'password1', 'qwerty', 'qwerty123', 'qwertyuiop', 'asdfgh', 'asdfghjkl',
    'zxcvbnm', '1q2w3e4r', '1q2w3e', '1qaz2wsx', 'zaq12wsx', 'abc123', 'abcdef', 'iloveyou', 'admin',
    'administrator', 'welcome', 'monkey', 'dragon', 'letmein', 'football', 'baseball', 'soccer',
    'sunshine', 'princess', 'master', 'shadow', 'superman', 'batman', 'spiderman', 'ironman',
    'trustno1', 'whatever', 'freedom', 'starwars', 'hello', 'charlie', 'michael', 'jordan', 'killer',
    'access', 'secret', 'computer', 'internet', 'login', 'guest', 'default', 'changeme', 'test',
    'senha', 'senha123', 'mudar123', 'mudar', 'trocar', 'teste', 'brasil', 'amor', 'teamo', 'amorzinho',
    'jesus', 'deus', 'deusefiel', 'familia', 'saudade', 'felicidade', 'estrela', 'chocolate',
    'flamengo', 'corinthians', 'palmeiras', 'saopaulo', 'vasco', 'gremio', 'santos', 'cruzeiro',
    'internacional', 'botafogo', 'fluminense', 'atletico', 'bahia', 'sport',
    'gabriel', 'lucas', 'mateus', 'matheus', 'pedro', 'joao', 'maria', 'ana', 'julia', 'beatriz',
    'guilherme', 'rafael', 'bruno', 'felipe', 'carlos', 'daniel', 'fernanda', 'amanda', 'leticia',
];

const GAMING_WORDS = [
    'gamer', 'gaming', 'player', 'noob', 'pro', 'hacker', 'hack', 'gg', 'ggwp', 'clutch', 'headshot',
    'squad', 'clan', 'rank', 'ranked', 'ranqueada', 'elo', 'arena', 'rival', 'ally', 'rivaly', 'happygame',
    'minecraft', 'fortnite', 'valorant', 'roblox', 'freefire', 'leagueoflegends', 'league', 'lol',
    'csgo', 'counterstrike', 'overwatch', 'dota', 'dota2', 'gta', 'gtav', 'fifa', 'pubg', 'apex',
    'warzone', 'callofduty', 'cod', 'zelda', 'mario', 'luigi', 'sonic', 'pokemon', 'pikachu',
    'naruto', 'goku', 'vegeta', 'dragonball', 'onepiece', 'kratos', 'halo', 'masterchief',
    'steam', 'xbox', 'playstation', 'ps4', 'ps5', 'nintendo', 'switch', 'twitch', 'discord',
    'youtube', 'tiktok', 'skin', 'skins', 'vbucks', 'robux', 'diamante', 'mestre', 'desafiante',
    'fiap', 'palo', 'paloalto',
];

/** Lista de bloqueio completa (exportada para os testes e para a página de segurança). */
export const BLOCKLIST = Object.freeze(new Set([...COMMON_PASSWORDS, ...GAMING_WORDS]));

/**
 * Palavras usadas só pelo ESTIMADOR (não bloqueiam sozinhas): ficam
 * baratas na conta de força porque estão em qualquer dicionário de ataque.
 */
const EXTRA_DICTIONARY = [
    'love', 'game', 'games', 'jogo', 'jogos', 'jogar', 'casa', 'vida', 'time', 'gol', 'bola', 'azul',
    'verde', 'preto', 'branco', 'vermelho', 'amarelo', 'gato', 'cachorro', 'flor', 'lua', 'sol',
    'feliz', 'forte', 'lindo', 'linda', 'gostoso', 'querida', 'querido', 'princesa', 'principe',
    'king', 'queen', 'boss', 'legend', 'lenda', 'ninja', 'sniper', 'killer', 'dark', 'light',
    'blue', 'red', 'green', 'black', 'white', 'happy', 'super', 'mega', 'ultra', 'master',
];

const DICTIONARY = [...new Set([...BLOCKLIST, ...EXTRA_DICTIONARY])]
    .filter((word) => /[a-z]/.test(word) && word.length >= 3)
    .sort((a, b) => b.length - a.length);

/* ============================================================
   NORMALIZAÇÃO
   ============================================================ */

/** NFKC: "é" composto e "e + ´" viram o mesmo caractere. */
export const normalizePassword = (value) => String(value ?? '').normalize('NFKC');

/** Tamanho em caracteres de verdade (um emoji conta 1, não 2). */
export const passwordLength = (value) => Array.from(normalizePassword(value)).length;

/** Substituições "leet" que não enganam ninguém: p@ssw0rd = password. */
const LEET = {
    '4': ['a'], '@': ['a'], '3': ['e'], '1': ['i', 'l'], '!': ['i', 'l'], '|': ['i', 'l'],
    '0': ['o'], '$': ['s'], '5': ['s'], '7': ['t'], '+': ['t'], '8': ['b'], '9': ['g'], '6': ['g'],
};

const sameLetter = (char, letter) => char === letter || (LEET[char]?.includes(letter) ?? false);

const stripAccents = (text) => text.normalize('NFD').replace(/[̀-ͯ]/g, '');

/* ============================================================
   CONTEXTO: dados da própria pessoa
   ============================================================ */

const EMAIL_PROVIDERS = new Set(['gmail', 'hotmail', 'outlook', 'yahoo', 'icloud', 'live', 'bol', 'uol', 'terra']);

/**
 * Pedaços do apelido e do e-mail que não podem aparecer na senha.
 * "Nova_7" + "nova.silva@fiap.com.br" → ["nova", "nova7", "silva", "novasilva"].
 */
export function contextTokens({ nickname = '', email = '' } = {}) {
    const min = PASSWORD_POLICY.contextMinLength;
    const tokens = new Set();
    const add = (value) => {
        const clean = stripAccents(String(value ?? '').toLowerCase()).replace(/[^a-z0-9]/g, '');
        if (clean.length >= min) tokens.add(clean);
    };

    const nick = String(nickname ?? '');
    add(nick);
    nick.split(/[\s_\-.]+/).forEach(add);

    const [local = '', domain = ''] = String(email ?? '').toLowerCase().split('@');
    add(local);
    local.split(/[._\-+\d]+/).forEach(add);
    const domainName = domain.split('.')[0];
    if (!EMAIL_PROVIDERS.has(domainName)) add(domainName);

    return [...tokens].sort((a, b) => b.length - a.length);
}

/* ============================================================
   DETECÇÃO DE PADRÕES
   Tudo trabalha sobre um array de caracteres (code points).
   ============================================================ */

/**
 * Procura palavras do dicionário (com leet) na senha.
 * @returns {{word:string, start:number, end:number, leet:boolean, kind:string}[]}
 */
function findWords(lowerChars, words, kind) {
    const found = [];
    for (const word of words) {
        const letters = Array.from(word);
        for (let start = 0; start + letters.length <= lowerChars.length; start += 1) {
            let leet = false;
            let ok = true;
            for (let k = 0; k < letters.length; k += 1) {
                const char = lowerChars[start + k];
                if (char === letters[k]) continue;
                if (sameLetter(char, letters[k])) { leet = true; continue; }
                ok = false;
                break;
            }
            if (ok) found.push({ kind, word, start, end: start + letters.length, leet });
        }
    }
    return found;
}

/** Escolhe matches sem sobreposição, os mais longos primeiro. */
function pickNonOverlapping(matches) {
    const taken = [];
    [...matches]
        .sort((a, b) => (b.end - b.start) - (a.end - a.start) || a.start - b.start)
        .forEach((match) => {
            if (taken.every((other) => match.end <= other.start || match.start >= other.end)) taken.push(match);
        });
    return taken.sort((a, b) => a.start - b.start);
}

const charClass = (char) => (/[0-9]/.test(char) ? 'digit' : /[a-z]/i.test(char) ? 'letter' : 'other');

/** abc, 4321, zyx… (passo +1 ou −1, mesma classe). */
function findSequences(lowerChars) {
    const found = [];
    let i = 0;
    while (i < lowerChars.length - 2) {
        const cls = charClass(lowerChars[i]);
        const delta = lowerChars[i + 1].codePointAt(0) - lowerChars[i].codePointAt(0);
        if (cls === 'other' || Math.abs(delta) !== 1 || charClass(lowerChars[i + 1]) !== cls) { i += 1; continue; }
        let j = i + 1;
        while (j + 1 < lowerChars.length
            && charClass(lowerChars[j + 1]) === cls
            && lowerChars[j + 1].codePointAt(0) - lowerChars[j].codePointAt(0) === delta) j += 1;
        if (j - i + 1 >= 3) found.push({ kind: 'sequence', start: i, end: j + 1 });
        i = j + 1;
    }
    return found;
}

const KEYBOARD_ROWS = ['1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p'];
const KEYBOARD_PATHS = [...KEYBOARD_ROWS, ...KEYBOARD_ROWS.map((row) => [...row].reverse().join(''))];

/** qwerty, asdf, 1qaz2wsx… (4 teclas vizinhas ou mais). */
function findKeyboard(lowerChars) {
    const found = [];
    const text = lowerChars.join('');
    if (text.length !== lowerChars.length) return found; // só ASCII
    for (let start = 0; start < text.length - 3; start += 1) {
        for (let len = text.length - start; len >= 4; len -= 1) {
            const slice = text.slice(start, start + len);
            if (KEYBOARD_PATHS.some((path) => path.includes(slice))) {
                found.push({ kind: 'keyboard', start, end: start + len });
                break;
            }
        }
    }
    return found;
}

/** aaa, 1111… (mesmo caractere três vezes ou mais). */
function findRepeats(chars) {
    const found = [];
    let i = 0;
    while (i < chars.length) {
        let j = i;
        while (j + 1 < chars.length && chars[j + 1] === chars[i]) j += 1;
        if (j - i + 1 >= 3) found.push({ kind: 'repeat', start: i, end: j + 1 });
        i = j + 1;
    }
    return found;
}

/** 1990, 2026… */
function findYears(chars) {
    const found = [];
    const text = chars.join('');
    if (text.length !== chars.length) return found;
    const regex = /(19\d\d|20[0-4]\d)/g;
    let match;
    while ((match = regex.exec(text))) found.push({ kind: 'year', start: match.index, end: match.index + 4 });
    return found;
}

/** "abcabcabc" → "abc"; null quando a senha não é uma repetição inteira. */
function repeatedUnit(text) {
    const match = /^(.+?)\1+$/su.exec(text);
    return match ? match[1] : null;
}

function charsetSize(chars) {
    let size = 0;
    if (chars.some((c) => /[a-z]/.test(c))) size += 26;
    if (chars.some((c) => /[A-Z]/.test(c))) size += 26;
    if (chars.some((c) => /[0-9]/.test(c))) size += 10;
    if (chars.some((c) => c === ' ')) size += 1;
    if (chars.some((c) => /[^a-zA-Z0-9 ]/.test(c) && c.codePointAt(0) < 128)) size += 33;
    // Acentos e emoji: um atacante cobre os comuns (á, ç, ã…) sem esforço.
    if (chars.some((c) => c.codePointAt(0) >= 128)) size += 30;
    return Math.max(size, 10);
}

/* ============================================================
   ESTIMATIVA DE FORÇA
   ============================================================ */

const FEEDBACK = {
    dictionary: 'Palavras comuns e nomes de jogos são os primeiros testados. Junte palavras que só você associaria.',
    context: 'O apelido e o e-mail são públicos: um ataque direcionado tenta eles primeiro.',
    leet: 'Trocar letras por símbolos (@ no lugar de a) não engana os programas de ataque.',
    sequence: 'Evite sequências como "abcd" ou "1234".',
    keyboard: 'Evite caminhos do teclado, como "qwerty" ou "asdf".',
    repeat: 'Evite repetir o mesmo caractere ou o mesmo trecho.',
    year: 'Anos e datas são fáceis de adivinhar.',
    short: 'Frases-senha longas são mais fortes e fáceis de lembrar: "pizza de quinta com o squad".',
};

/** Ataques por segundo em três cenários (ordem de grandeza). */
export const ATTACK_SCENARIOS = Object.freeze({
    online: { label: 'Online, com bloqueio de tentativas', perSecond: 10 / 3600 },
    offlineSlow: { label: 'Banco vazado, hash argon2id', perSecond: 1e4 },
    offlineFast: { label: 'Banco vazado, hash rápido (SHA-256)', perSecond: 1e10 },
});

/** Segundos → texto curto em português. */
export function formatDuration(seconds) {
    // ~13,8 bilhões de anos em segundos
    if (!Number.isFinite(seconds) || seconds > 4.35e17) return 'mais que a idade do universo';
    const units = [
        [60 * 60 * 24 * 365 * 1000, 'milênio', 'milênios'],
        [60 * 60 * 24 * 365 * 100, 'século', 'séculos'],
        [60 * 60 * 24 * 365, 'ano', 'anos'],
        [60 * 60 * 24 * 30, 'mês', 'meses'],
        [60 * 60 * 24, 'dia', 'dias'],
        [60 * 60, 'hora', 'horas'],
        [60, 'minuto', 'minutos'],
        [1, 'segundo', 'segundos'],
    ];
    if (seconds < 1) return 'menos de 1 segundo';
    for (const [size, one, many] of units) {
        if (seconds >= size) {
            const value = Math.floor(seconds / size);
            if (value >= 1000 && one === 'milênio') return 'milhões de anos';
            return `${value.toLocaleString('pt-BR')} ${value === 1 ? one : many}`;
        }
    }
    return 'menos de 1 segundo';
}

/**
 * Estima a força em bits (log2 do número de palpites).
 * @returns {{bits:number, score:number, label:string, patterns:object[], feedback:string[], crackTimes:object}}
 */
export function estimateStrength(password, context = {}) {
    const text = normalizePassword(password);
    const chars = Array.from(text);
    if (chars.length === 0) return strengthResult(0, [], []);

    const unit = repeatedUnit(text);
    if (unit && unit.length < text.length) {
        const inner = estimateStrength(unit, context);
        const bits = inner.bits + Math.log2(chars.length / Array.from(unit).length);
        return strengthResult(bits, [{ kind: 'repeat', start: 0, end: chars.length }, ...inner.patterns], ['repeat', ...inner.kinds]);
    }

    const lower = chars.map((c) => stripAccents(c.toLowerCase()));
    const perChar = Math.log2(charsetSize(chars));
    const tokens = contextTokens(context);

    const costOf = (match) => {
        const len = match.end - match.start;
        const span = chars.slice(match.start, match.end);
        const upper = span.some((c) => c !== c.toLowerCase()) ? 1 : 0;
        switch (match.kind) {
            case 'context': return 1 + upper + (match.leet ? 1 : 0);
            case 'dictionary': return 10 + upper + (match.leet ? 1 : 0);
            case 'sequence': return Math.log2(26) + Math.log2(len);
            case 'keyboard': return Math.log2(40) + Math.log2(len);
            case 'repeat': return perChar + Math.log2(len);
            case 'year': return Math.log2(150);
            default: return len * perChar;
        }
    };

    const candidates = [
        ...findWords(lower, tokens, 'context'),
        ...findWords(lower, DICTIONARY, 'dictionary'),
        ...findSequences(lower),
        ...findKeyboard(lower),
        ...findRepeats(chars),
        ...findYears(chars),
    ].map((match) => {
        const cost = costOf(match);
        return { ...match, cost, savings: (match.end - match.start) * perChar - cost };
    }).filter((match) => match.savings > 0);

    // Guloso por economia: o atacante sempre usa o atalho mais barato.
    const chosen = [];
    [...candidates].sort((a, b) => b.savings - a.savings).forEach((match) => {
        if (chosen.every((other) => match.end <= other.start || match.start >= other.end)) chosen.push(match);
    });
    chosen.sort((a, b) => a.start - b.start);

    const covered = chosen.reduce((sum, match) => sum + (match.end - match.start), 0);
    const bits = chosen.reduce((sum, match) => sum + match.cost, 0)
        + (chars.length - covered) * perChar
        + (chosen.length > 1 ? Math.log2(chosen.length) : 0);

    const kinds = chosen.map((match) => match.kind);
    if (chosen.some((match) => match.leet)) kinds.push('leet');
    return strengthResult(bits, chosen, kinds);
}

function strengthResult(bits, patterns, kinds) {
    const rounded = Math.max(0, Math.round(bits * 10) / 10);
    const score = SCORE_THRESHOLDS.filter((limit) => rounded >= limit).length;
    const guesses = 2 ** Math.max(0, rounded - 1); // em média, metade do espaço
    const crackTimes = Object.fromEntries(Object.entries(ATTACK_SCENARIOS).map(([id, scenario]) => [
        id, { ...scenario, seconds: guesses / scenario.perSecond, text: formatDuration(guesses / scenario.perSecond) },
    ]));

    const feedback = [...new Set(kinds.map((kind) => FEEDBACK[kind === 'dictionary' ? 'dictionary' : kind]).filter(Boolean))];
    if (score < 3) feedback.push(FEEDBACK.short);

    return {
        bits: rounded,
        score,
        label: STRENGTH_LABELS[score],
        patterns,
        kinds: [...new Set(kinds)],
        feedback: [...new Set(feedback)],
        crackTimes,
    };
}

/* ============================================================
   REGRAS QUE BLOQUEIAM
   ============================================================ */

/**
 * "minecraft2024!!!", "p@ssw0rd123456789", "valorantvalorant",
 * "dragon pokemon batman 2026": só palavras da lista de bloqueio com
 * números, símbolos ou espaços em volta.
 * @returns {string|null} a palavra comum encontrada
 */
export function commonPasswordMatch(password) {
    const text = normalizePassword(password);
    const lower = Array.from(stripAccents(text.toLowerCase()));
    const plain = lower.join('');

    if (BLOCKLIST.has(plain) || BLOCKLIST.has(plain.replace(/\s+/g, ''))) return plain;

    const blockWords = [...BLOCKLIST].filter((word) => word.length >= 3 && /[a-z]/.test(word))
        .sort((a, b) => b.length - a.length);
    const matches = pickNonOverlapping(findWords(lower, blockWords, 'dictionary'));
    if (!matches.length) return null;

    const rest = lower.filter((_, index) => !matches.some((m) => index >= m.start && index < m.end));
    const hasLetters = rest.some((char) => /\p{L}/u.test(char));
    return hasLetters ? null : matches[0].word;
}

/** Algum pedaço do apelido ou do e-mail aparece na senha? */
export function personalInfoMatch(password, context = {}) {
    const lower = Array.from(stripAccents(normalizePassword(password).toLowerCase()));
    const match = findWords(lower, contextTokens(context), 'context')[0];
    return match ? match.word : null;
}

/**
 * Avalia uma senha contra o padrão inteiro.
 *
 * @param {string} password
 * @param {{nickname?:string, email?:string}} context
 * @returns {{
 *   ok:boolean, empty:boolean, length:number,
 *   errors:{code:string, message:string}[],
 *   checks:{id:string, label:string, ok:boolean}[],
 *   strength:ReturnType<typeof estimateStrength>
 * }}
 */
export function evaluatePassword(password, context = {}) {
    const text = normalizePassword(password);
    const length = Array.from(text).length;
    const strength = estimateStrength(text, context);
    const errors = [];

    const longEnough = length >= PASSWORD_POLICY.minLength;
    if (!longEnough) {
        errors.push({
            code: 'too_short',
            message: `Use pelo menos ${PASSWORD_POLICY.minLength} caracteres (agora são ${length}). Uma frase funciona bem: "pizza de quinta com o squad".`,
        });
    }
    if (length > PASSWORD_POLICY.maxLength) {
        errors.push({ code: 'too_long', message: `Use no máximo ${PASSWORD_POLICY.maxLength} caracteres.` });
    }
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(text)) {
        errors.push({ code: 'control_chars', message: 'A senha tem caracteres invisíveis (como Tab ou quebra de linha). Remova e tente de novo.' });
    }

    const personal = length ? personalInfoMatch(text, context) : null;
    if (personal) {
        errors.push({ code: 'personal_info', message: 'Não use o seu apelido nem partes do seu e-mail na senha: são as primeiras tentativas de um ataque direcionado.' });
    }

    const common = length ? commonPasswordMatch(text) : null;
    if (common) {
        errors.push({ code: 'common', message: `Essa senha é uma variação de uma senha comum ("${common}" com números ou símbolos). Ataques testam essas primeiro.` });
    }

    const strongEnough = strength.score >= PASSWORD_POLICY.minScore;
    if (length && !strongEnough && !common && !personal) {
        errors.push({
            code: 'weak',
            message: `Senha previsível demais (força: ${strength.label.toLowerCase()}). ${strength.feedback[0] ?? ''}`.trim(),
        });
    }

    const checks = [
        { id: 'length', label: `${PASSWORD_POLICY.minLength} caracteres ou mais`, ok: longEnough && length <= PASSWORD_POLICY.maxLength },
        { id: 'common', label: 'Não é senha comum nem variação dela', ok: length > 0 && !common },
        { id: 'personal', label: 'Não usa seu apelido nem seu e-mail', ok: length > 0 && !personal },
        { id: 'strength', label: 'Força estimada "Forte" ou acima', ok: strongEnough },
    ];

    return { ok: errors.length === 0, empty: length === 0, length, errors, checks, strength };
}

/** Atalho para regras de formulário: a primeira mensagem de erro, ou ''. */
export const passwordError = (password, context) => evaluatePassword(password, context).errors[0]?.message ?? '';
