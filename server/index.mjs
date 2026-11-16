/**
 * index.mjs — servidor local da demo de autenticação.
 *
 *   npm run server   só a API, em http://127.0.0.1:8787
 *   npm run demo     API + site (Vite), com /api redirecionado para cá
 *
 * Escuta só em 127.0.0.1: a API de demonstração não fica exposta na rede.
 */

import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { createAuthService } from './auth-service.mjs';
import { createRequestHandler } from './http-handler.mjs';
import { preferredAlgorithm } from './password-hasher.mjs';

export const AUTH_PORT = Number(process.env.RIVALY_AUTH_PORT ?? 8787);

export function startAuthServer({ port = AUTH_PORT, host = '127.0.0.1', quiet = false } = {}) {
    const log = quiet ? () => {} : (message) => console.log(`[rivaly-auth] ${message}`);
    const service = createAuthService({ log });
    const server = http.createServer(createRequestHandler(service));

    return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
            const { port: actual } = server.address();
            log(`API de autenticação em http://${host}:${actual}/api  (hash: ${preferredAlgorithm})`);
            resolve({ server, service, port: actual });
        });
    });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    startAuthServer().catch((error) => {
        console.error(error.code === 'EADDRINUSE'
            ? `[rivaly-auth] A porta ${AUTH_PORT} já está em uso. Feche o outro servidor ou use RIVALY_AUTH_PORT=8788.`
            : error);
        process.exit(1);
    });
}
