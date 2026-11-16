/**
 * server-api.js — conversa com a API de autenticação, quando ela existe.
 *
 * Três ambientes:
 *   - npm run demo     → API completa (server/), via proxy do Vite;
 *   - Vercel           → só /api/health e /api/password-check (api/);
 *   - npm run dev puro → nenhuma API: o site segue com a validação local.
 *
 * Toda chamada devolve { available, status, body }. "available: false"
 * quer dizer que não houve resposta JSON da API (servidor desligado, rota
 * inexistente neste ambiente ou rede fora): quem chama decide o que fazer.
 */

const TIMEOUT_MS = 5000;

async function call(path, { method = 'GET', body } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
        const response = await fetch(path, {
            method,
            headers: body ? { 'Content-Type': 'application/json', Accept: 'application/json' } : { Accept: 'application/json' },
            body: body ? JSON.stringify(body) : undefined,
            credentials: 'same-origin',
            signal: controller.signal,
        });
        const type = response.headers.get('content-type') ?? '';
        if (!type.includes('application/json')) return { available: false, status: response.status, body: null };
        const data = await response.json();
        // 404 em JSON = API no ar, mas sem esta rota neste ambiente.
        if (response.status === 404) return { available: false, status: 404, body: data };
        return { available: true, status: response.status, body: data, retryAfter: response.headers.get('retry-after') };
    } catch {
        return { available: false, status: 0, body: null };
    } finally {
        clearTimeout(timer);
    }
}

export const serverHealth = () => call('/api/health');
export const serverPasswordCheck = (payload) => call('/api/password-check', { method: 'POST', body: payload });
export const serverRegister = (payload) => call('/api/register', { method: 'POST', body: payload });
export const serverLogin = (payload) => call('/api/login', { method: 'POST', body: payload });
export const serverAccounts = () => call('/api/demo/accounts');
