/**
 * http-handler.mjs — transforma o auth-service em rotas HTTP.
 *
 *   GET  /api/health          estado do servidor e políticas em vigor
 *   POST /api/password-check  avalia uma senha (padrão + vazamentos)
 *   POST /api/register        cria conta (argon2id)
 *   POST /api/login           entra (bloqueio por e-mail e IP)
 *   GET  /api/demo/accounts   SÓ NA DEMO LOCAL: mostra os hashes guardados
 *
 * Funciona com o http do Node (server/index.mjs) e com Vercel Functions
 * (api/), que entregam req.body já lido.
 *
 * Defesas do transporte:
 *   - POST só com Content-Type: application/json. Um <form> de outro site
 *     não consegue mandar JSON sem pré-checagem de CORS, então isto
 *     fecha o caminho de CSRF clássico;
 *   - corpo limitado a 8 KB (sem hash de textos gigantes);
 *   - Cache-Control: no-store em tudo (resposta com dado de conta não
 *     fica em cache de proxy nem do navegador);
 *   - erro interno nunca devolve stack trace.
 */

import { PASSWORD_POLICY } from '../js/core/password-policy.js';
import { THROTTLE_POLICY } from '../js/core/throttle.js';
import { preferredAlgorithm, ARGON2ID, SCRYPT } from './password-hasher.mjs';

const MAX_BODY_BYTES = 8 * 1024;

const BASE_HEADERS = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Resource-Policy': 'same-origin',
};

function send(res, status, body, headers = {}) {
    res.statusCode = status;
    Object.entries({ ...BASE_HEADERS, ...headers }).forEach(([key, value]) => res.setHeader(key, value));
    res.end(JSON.stringify(body));
}

class HttpError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

async function readJson(req) {
    if (req.body !== undefined) {
        // Vercel já leu o corpo.
        if (typeof req.body === 'string') {
            try { return JSON.parse(req.body); } catch { throw new HttpError(400, 'JSON inválido.'); }
        }
        return req.body ?? {};
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) throw new HttpError(413, 'Corpo grande demais.');
        chunks.push(chunk);
    }
    if (!size) return {};
    try {
        return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
        throw new HttpError(400, 'JSON inválido.');
    }
}

const clientIp = (req) => req.socket?.remoteAddress ?? 'desconhecido';

/**
 * @param {ReturnType<import('./auth-service.mjs').createAuthService>} service
 * @param {{routes?: string[]}} options rotas habilitadas (padrão: todas)
 */
export function createRequestHandler(service, { routes = ['health', 'password-check', 'register', 'login', 'demo-accounts'] } = {}) {
    const enabled = new Set(routes);

    const table = {
        'GET /api/health': ['health', async () => ({
            status: 200,
            body: {
                ok: true,
                service: 'rivaly-auth-demo',
                hashing: preferredAlgorithm === 'argon2id'
                    ? { algorithm: 'argon2id', memoryKiB: ARGON2ID.memory, passes: ARGON2ID.passes, parallelism: ARGON2ID.parallelism }
                    : { algorithm: 'scrypt', N: 2 ** SCRYPT.ln, r: SCRYPT.r, p: SCRYPT.p },
                passwordPolicy: PASSWORD_POLICY,
                throttle: THROTTLE_POLICY,
                routes: [...enabled],
            },
        })],
        'POST /api/password-check': ['password-check', async (req) => service.checkPassword(await readJson(req))],
        'POST /api/register': ['register', async (req) => service.register(await readJson(req))],
        'POST /api/login': ['login', async (req) => service.login(await readJson(req), { ip: clientIp(req) })],
        'GET /api/demo/accounts': ['demo-accounts', async () => service.listAccounts()],
    };

    return async function handler(req, res) {
        try {
            const path = new URL(req.url ?? '/', 'http://localhost').pathname.replace(/\/+$/, '');
            const route = table[`${req.method} ${path}`];

            if (!route || !enabled.has(route[0])) {
                const exists = Object.entries(table).some(([key, [name]]) => key.endsWith(` ${path}`) && enabled.has(name));
                return exists
                    ? send(res, 405, { ok: false, error: 'Método não permitido.' })
                    : send(res, 404, { ok: false, error: 'Rota não encontrada.' });
            }

            if (req.method === 'POST') {
                const type = String(req.headers?.['content-type'] ?? '');
                if (!type.toLowerCase().startsWith('application/json')) {
                    return send(res, 415, { ok: false, error: 'Envie Content-Type: application/json.' });
                }
            }

            const result = await route[1](req);
            return send(res, result.status, result.body, result.headers);
        } catch (error) {
            if (error instanceof HttpError) return send(res, error.status, { ok: false, error: error.message });
            console.error('[rivaly-auth] erro interno:', error);
            return send(res, 500, { ok: false, error: 'Erro interno. Tente de novo.' });
        }
    };
}
