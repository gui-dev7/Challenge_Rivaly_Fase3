/**
 * pwned.js — a senha já apareceu em algum vazamento?
 *
 * Usa a API "Pwned Passwords" do Have I Been Pwned com k-anonimato:
 *
 *   1. calcula o SHA-1 da senha AQUI (no navegador ou no servidor);
 *   2. envia só os 5 primeiros caracteres do hash (ex.: "5BAA6");
 *   3. recebe ~800 sufixos que começam com esse prefixo e confere
 *      localmente se o resto do hash está na lista.
 *
 * A senha e o hash completo nunca saem do dispositivo. É o método que
 * a NIST SP 800-63B recomenda para "comparar com senhas comprometidas".
 *
 * Funciona no navegador e no Node 18+ (fetch e crypto.subtle globais).
 * O SHA-1 aqui serve só como chave de busca, nunca para guardar senha.
 */

export const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/';

const toHex = (buffer) => Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();

/** SHA-1 em hexadecimal maiúsculo (formato do HIBP). */
export async function sha1Hex(text) {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) throw new Error('Web Crypto indisponível: abra por https:// ou localhost.');
    const bytes = new TextEncoder().encode(String(text ?? '').normalize('NFKC'));
    return toHex(await subtle.digest('SHA-1', bytes));
}

/** Procura o sufixo na resposta "SUFIXO:CONTAGEM\r\n…". */
export function countInRangeResponse(body, suffix) {
    const target = String(suffix).toUpperCase();
    for (const line of String(body ?? '').split(/\r?\n/)) {
        const [lineSuffix, count] = line.trim().split(':');
        if (lineSuffix?.toUpperCase() === target) return Number.parseInt(count, 10) || 0;
    }
    return 0;
}

/**
 * @param {string} password
 * @param {{fetchImpl?:Function, timeoutMs?:number, padding?:boolean}} options
 *   padding: pede respostas com entradas falsas (contagem 0) para que nem
 *   o tamanho da resposta revele o prefixo. Só no servidor: no navegador
 *   o cabeçalho extra dispararia uma pré-checagem de CORS.
 * @returns {Promise<{status:'pwned'|'clean'|'unavailable', count:number, prefix:string, error?:string}>}
 */
export async function checkPwnedPassword(password, { fetchImpl = globalThis.fetch, timeoutMs = 4000, padding = false } = {}) {
    let prefix = '';
    try {
        const hash = await sha1Hex(password);
        prefix = hash.slice(0, 5);
        const suffix = hash.slice(5);

        const controller = typeof AbortController === 'function' ? new AbortController() : null;
        const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
        timer?.unref?.();

        let response;
        try {
            response = await fetchImpl(`${HIBP_RANGE_URL}${prefix}`, {
                headers: padding ? { 'Add-Padding': 'true' } : undefined,
                signal: controller?.signal,
            });
        } finally {
            if (timer) clearTimeout(timer);
        }

        if (!response?.ok) return { status: 'unavailable', count: 0, prefix, error: `HTTP ${response?.status ?? '?'}` };
        const count = countInRangeResponse(await response.text(), suffix);
        return { status: count > 0 ? 'pwned' : 'clean', count, prefix };
    } catch (error) {
        return { status: 'unavailable', count: 0, prefix, error: error?.name === 'AbortError' ? 'tempo esgotado' : String(error?.message ?? error) };
    }
}

/** Mensagem pronta para o formulário. */
export function pwnedMessage(result) {
    if (result?.status !== 'pwned') return '';
    const times = result.count.toLocaleString('pt-BR');
    return `Esta senha já apareceu ${times} ${result.count === 1 ? 'vez' : 'vezes'} em vazamentos conhecidos. Ataques usam essas listas primeiro: escolha outra.`;
}
