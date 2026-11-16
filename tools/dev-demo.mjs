/**
 * dev-demo.mjs — sobe a demo completa com um comando só.
 *
 *   npm run demo
 *
 * 1. API de autenticação (server/index.mjs) em http://127.0.0.1:8787
 * 2. Site pelo Vite, que redireciona /api para a API (vite.config.js)
 *
 * Ctrl+C encerra os dois.
 */

import { startAuthServer } from '../server/index.mjs';

const { server: authServer } = await startAuthServer();

const { createServer } = await import('vite');
const vite = await createServer({ configFile: 'vite.config.js' });
await vite.listen();

console.log('');
vite.printUrls();
console.log('\n  Laboratório de senha: /seguranca.html   ·   Criar conta: /login.html?mode=create\n');

const shutdown = async () => {
    await vite.close();
    authServer.close();
    process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
