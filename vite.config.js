import { resolve } from 'node:path';
import { readFileSync, cpSync, existsSync, mkdirSync, copyFileSync, statSync } from 'node:fs';

/**
 * Vite is a DEV TOOL ONLY.
 *
 * The application itself stays HTML5 + CSS3 + vanilla ES Modules +
 * Bootstrap 5.3 (served locally from vendor/). Nothing here is imported
 * by the product; Vite gives LAN access, instant reload, correct MIME
 * types and a production build for Vercel.
 */

/* ------------------------------------------------------------
   Security headers: one source of truth.
   vercel.json is what production serves; `npm run preview` reads the
   same file so the Content-Security-Policy can be tested locally.
   ------------------------------------------------------------ */
function vercelHeaders() {
    try {
        const config = JSON.parse(readFileSync(resolve('vercel.json'), 'utf8'));
        const rule = (config.headers ?? []).find((entry) => entry.source === '/(.*)');
        return Object.fromEntries((rule?.headers ?? []).map(({ key, value }) => [key, value]));
    } catch {
        return {};
    }
}

/* ------------------------------------------------------------
   Classic scripts are not bundled by Vite (they are not modules):
   Bootstrap's bundle and the file:// warning are copied verbatim.
   ------------------------------------------------------------ */
function copyStaticScripts() {
    return {
        name: 'rivaly-copy-static-scripts',
        apply: 'build',
        closeBundle() {
            cpSync(resolve('vendor'), resolve('dist/vendor'), { recursive: true });
            mkdirSync(resolve('dist/js'), { recursive: true });
            copyFileSync(resolve('js/protocol-check.js'), resolve('dist/js/protocol-check.js'));
        },
    };
}

/* ------------------------------------------------------------
   404 page in dev and preview, like Vercel does in production.
   ------------------------------------------------------------ */
function notFoundPage() {
    const isPageRequest = (req) => req.method === 'GET' && (req.headers.accept ?? '').includes('text/html');

    // O Vite roda este middleware ANTES do que serve os .html; sem esta
    // checagem toda página viraria 404 no `npm run dev`.
    const pageExists = (root, url) => {
        try {
            const path = decodeURIComponent(new URL(url, 'http://localhost').pathname);
            const file = resolve(root, `.${path.endsWith('/') ? `${path}index.html` : path}`);
            return file.startsWith(resolve(root)) && existsSync(file) && statSync(file).isFile();
        } catch {
            return false;
        }
    };

    return {
        name: 'rivaly-404',
        configureServer(server) {
            return () => {
                server.middlewares.use(async (req, res, next) => {
                    if (!isPageRequest(req) || pageExists(server.config.root, req.url)) return next();
                    const html = await server.transformIndexHtml(req.url, readFileSync(resolve('404.html'), 'utf8'));
                    res.statusCode = 404;
                    res.setHeader('Content-Type', 'text/html; charset=utf-8');
                    res.end(html);
                });
            };
        },
        configurePreviewServer(server) {
            return () => {
                server.middlewares.use((req, res, next) => {
                    const file = resolve('dist/404.html');
                    if (!isPageRequest(req) || !existsSync(file) || pageExists(resolve('dist'), req.url)) return next();
                    res.statusCode = 404;
                    res.setHeader('Content-Type', 'text/html; charset=utf-8');
                    res.end(readFileSync(file, 'utf8'));
                });
            };
        },
    };
}

/* ------------------------------------------------------------
   /api -> servidor local da demo de autenticação (server/index.mjs).
   Mesma origem para o navegador: sem CORS e o cookie de sessão
   SameSite=Strict funciona. Sem o servidor rodando, o site percebe
   que a API está fora e segue só com a validação do navegador.
   ------------------------------------------------------------ */
const AUTH_API = `http://127.0.0.1:${process.env.RIVALY_AUTH_PORT ?? 8787}`;
const apiProxy = { '/api': { target: AUTH_API, changeOrigin: false } };

export default {
    // Multi-page: every .html is a real page, so a missing file must
    // 404 instead of silently falling back to index.html.
    appType: 'mpa',

    plugins: [copyStaticScripts(), notFoundPage()],

    server: {
        host: true,        // bind 0.0.0.0 -> reachable from the LAN
        port: 5173,
        strictPort: false,
        open: false,
        proxy: apiProxy,
    },

    preview: {
        host: true,
        port: 4173,
        headers: vercelHeaders(),
        proxy: apiProxy,
    },

    // Each screen is a real entry point. A page missing from this list is
    // a 404 in production, so every new page has to be added here.
    build: {
        rollupOptions: {
            input: {
                home: resolve('index.html'),
                login: resolve('login.html'),
                onboarding: resolve('onboarding.html'),
                dashboard: resolve('dashboard.html'),
                library: resolve('library.html'),
                discover: resolve('discover.html'),
                passport: resolve('passport.html'),
                achievements: resolve('achievements.html'),
                squads: resolve('squads.html'),
                settings: resolve('settings.html'),
                arena: resolve('arena.html'),
                clans: resolve('clans.html'),
                feed: resolve('feed.html'),
                sitemap: resolve('sitemap.html'),
                security: resolve('seguranca.html'),
                notFound: resolve('404.html'),
            },
        },
    },
};
