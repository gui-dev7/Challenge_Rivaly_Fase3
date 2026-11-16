/**
 * build-entrega.mjs — gera o PDF dos slides e o ZIP da entrega.
 *
 *   npm run entrega            PDF + ZIP (o ZIP exige o link do vídeo)
 *   npm run entrega -- --previa   também salva um PNG de cada slide
 *   npm run entrega -- --pasta <dir>   lê foto e link de <dir> e grava o PDF e o ZIP lá
 *
 * Passos:
 *   1. lê o link do YouTube em entrega/link-do-video.txt;
 *   2. abre entrega/slides.html no Chrome ou Edge sem janela (headless),
 *      com o link e o QR code no 1º e no 10º slide;
 *   3. imprime o PDF (10 páginas, 1920 × 1080);
 *   4. monta entrega/dist/Challenge_Rivaly_Fase3.zip com o PDF e o .txt
 *      lado a lado, na raiz do ZIP.
 *
 * Sem dependências: fala com o navegador pelo DevTools Protocol
 * (WebSocket nativo do Node 22+) e escreve o ZIP com node:zlib.
 */

import { spawn } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import zlib from 'node:zlib';

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = join(HERE, 'dist');
const NAME = 'Challenge_Rivaly_Fase3';
const PREVIEW = process.argv.includes('--previa');

/**
 * --pasta <dir>: a pasta de entrega (fora do projeto). A foto e o link são
 * lidos de lá primeiro, e o PDF e o ZIP também são gravados lá.
 */
const pastaIndex = process.argv.indexOf('--pasta');
const PASTA = pastaIndex > -1 && process.argv[pastaIndex + 1] ? resolve(process.argv[pastaIndex + 1]) : null;
const SOURCES = [PASTA, HERE].filter(Boolean);

const firstExisting = (names) => SOURCES.flatMap((dir) => names.map((name) => join(dir, name))).find((path) => existsSync(path)) ?? null;

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/* ============================================================
   1. LINK DO VÍDEO
   ============================================================ */

function readVideoLink() {
    // Vale o primeiro arquivo que tiver um link: a pasta de entrega, depois entrega/.
    const line = SOURCES.map((dir) => join(dir, 'link-do-video.txt'))
        .filter((file) => existsSync(file))
        .map((file) => readFileSync(file, 'utf8').replace(/^﻿/, '').split(/\r?\n/).map((text) => text.trim())
            .find((text) => text && !text.startsWith('#')))
        .find(Boolean);
    if (!line) return null;
    try {
        const url = new URL(line);
        const youtube = /(^|\.)youtube\.com$|^youtu\.be$/.test(url.hostname);
        return url.protocol === 'https:' && youtube ? url.href : null;
    } catch {
        return null;
    }
}

/* ============================================================
   2. NAVEGADOR (Chrome ou Edge, sem janela)
   ============================================================ */

function findBrowser() {
    const candidates = [
        process.env.CHROME_PATH,
        'C:/Program Files/Google/Chrome/Application/chrome.exe',
        'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
        'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
        'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
        '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge',
    ].filter(Boolean);
    return candidates.find((path) => existsSync(path)) ?? null;
}

async function openBrowser(executable) {
    const profile = mkdtempSync(join(tmpdir(), 'rivaly-entrega-'));
    const child = spawn(executable, [
        '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
        '--no-first-run', '--no-default-browser-check', '--hide-scrollbars', '--allow-file-access-from-files',
        'about:blank',
    ], { stdio: 'ignore' });

    let port = null;
    for (let i = 0; i < 100 && !port; i += 1) {
        await sleep(100);
        const file = join(profile, 'DevToolsActivePort');
        if (existsSync(file)) port = Number(readFileSync(file, 'utf8').split('\n')[0]);
    }
    if (!port) throw new Error('O navegador não abriu a porta de depuração.');

    let pageTarget;
    for (let i = 0; i < 50 && !pageTarget; i += 1) {
        try {
            const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
            pageTarget = targets.find((target) => target.type === 'page');
        } catch { /* ainda subindo */ }
        if (!pageTarget) await sleep(100);
    }

    const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
    await new Promise((done, fail) => { ws.addEventListener('open', done); ws.addEventListener('error', fail); });

    let id = 0;
    const pending = new Map();
    ws.addEventListener('message', (message) => {
        const data = JSON.parse(message.data);
        if (data.id && pending.has(data.id)) {
            const { done, fail } = pending.get(data.id);
            pending.delete(data.id);
            if (data.error) fail(new Error(data.error.message)); else done(data.result);
        }
    });
    const send = (method, params = {}) => new Promise((done, fail) => {
        id += 1;
        pending.set(id, { done, fail });
        ws.send(JSON.stringify({ id, method, params }));
    });

    const close = () => {
        ws.close();
        child.kill();
        setTimeout(() => { try { rmSync(profile, { recursive: true, force: true }); } catch { /* o Windows às vezes segura o perfil */ } }, 500);
    };
    return { send, close };
}

/* ============================================================
   3. ZIP (formato PKZIP, deflate)
   ============================================================ */

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
});
const crc32 = (buffer) => (zlib.crc32
    ? zlib.crc32(buffer)
    : (buffer.reduce((c, byte) => CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8), 0xffffffff) ^ 0xffffffff) >>> 0);

function dosDateTime(date = new Date()) {
    const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
    const day = ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
    return { time, day };
}

function buildZip(files) {
    const { time, day } = dosDateTime();
    const locals = [];
    const centrals = [];
    let offset = 0;

    for (const { name, data } of files) {
        const nameBytes = Buffer.from(name, 'utf8');
        const compressed = zlib.deflateRawSync(data, { level: 9 });
        const crc = crc32(data);

        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0);
        local.writeUInt16LE(20, 4);         // versão necessária
        local.writeUInt16LE(0x0800, 6);     // nomes em UTF-8
        local.writeUInt16LE(8, 8);          // deflate
        local.writeUInt16LE(time, 10);
        local.writeUInt16LE(day, 12);
        local.writeUInt32LE(crc, 14);
        local.writeUInt32LE(compressed.length, 18);
        local.writeUInt32LE(data.length, 22);
        local.writeUInt16LE(nameBytes.length, 26);
        local.writeUInt16LE(0, 28);
        locals.push(local, nameBytes, compressed);

        const central = Buffer.alloc(46);
        central.writeUInt32LE(0x02014b50, 0);
        central.writeUInt16LE(20, 4);
        central.writeUInt16LE(20, 6);
        central.writeUInt16LE(0x0800, 8);
        central.writeUInt16LE(8, 10);
        central.writeUInt16LE(time, 12);
        central.writeUInt16LE(day, 14);
        central.writeUInt32LE(crc, 16);
        central.writeUInt32LE(compressed.length, 20);
        central.writeUInt32LE(data.length, 24);
        central.writeUInt16LE(nameBytes.length, 28);
        central.writeUInt32LE(offset, 42);
        centrals.push(central, nameBytes);

        offset += local.length + nameBytes.length + compressed.length;
    }

    const centralSize = centrals.reduce((sum, part) => sum + part.length, 0);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(files.length, 8);
    end.writeUInt16LE(files.length, 10);
    end.writeUInt32LE(centralSize, 12);
    end.writeUInt32LE(offset, 16);
    return Buffer.concat([...locals, ...centrals, end]);
}

/* ============================================================
   EXECUÇÃO
   ============================================================ */

const escapeAttr = (text) => text.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

const video = readVideoLink();
const browserPath = findBrowser();
if (!browserPath) {
    console.error('Não achei Chrome nem Edge. Instale um deles ou defina CHROME_PATH.');
    process.exit(1);
}

mkdirSync(DIST, { recursive: true });
const renderFile = join(HERE, '_render.html');
const photo = firstExisting(['foto.jpg', 'foto.jpeg', 'foto.png', 'foto.JPG', 'foto.PNG']);
let source = readFileSync(join(HERE, 'slides.html'), 'utf8')
    .replace('data-video-url=""', `data-video-url="${escapeAttr(video ?? '')}"`);
if (photo) source = source.replace('src="foto.jpg"', `src="${escapeAttr(pathToFileURL(photo).href)}"`);
writeFileSync(renderFile, source);

const pdfPath = join(DIST, `${NAME}.pdf`);
const browser = await openBrowser(browserPath);
try {
    await browser.send('Page.enable');
    await browser.send('Emulation.setDeviceMetricsOverride', { width: 1920, height: 1080, deviceScaleFactor: 1, mobile: false });
    await browser.send('Page.navigate', { url: pathToFileURL(renderFile).href });

    let ready = false;
    for (let i = 0; i < 100 && !ready; i += 1) {
        await sleep(150);
        const { result } = await browser.send('Runtime.evaluate', {
            expression: 'window.__slidesReady === true && Array.from(document.images).every((img) => img.complete)',
            returnByValue: true,
        });
        ready = result?.value === true;
    }
    if (!ready) console.warn('Aviso: a página demorou para carregar; o PDF pode ter saído sem fontes ou imagens.');

    const { result: info } = await browser.send('Runtime.evaluate', {
        expression: 'JSON.stringify({ slides: document.querySelectorAll(".slide").length, qr: document.querySelectorAll("[data-qr] img").length, photo: Boolean(document.querySelector(".person__photo")) })',
        returnByValue: true,
    });
    const stats = JSON.parse(info.value);

    if (PREVIEW) {
        const previewDir = join(DIST, 'previa');
        mkdirSync(previewDir, { recursive: true });
        for (let n = 0; n < stats.slides; n += 1) {
            const shot = await browser.send('Page.captureScreenshot', {
                format: 'png', captureBeyondViewport: true, clip: { x: 0, y: n * (1080 + 24), width: 1920, height: 1080, scale: 0.5 },
            });
            writeFileSync(join(previewDir, `slide-${String(n + 1).padStart(2, '0')}.png`), Buffer.from(shot.data, 'base64'));
        }
        console.log(`Prévia: ${previewDir}`);
    }

    const pdf = await browser.send('Page.printToPDF', { printBackground: true, preferCSSPageSize: true, displayHeaderFooter: false });
    writeFileSync(pdfPath, Buffer.from(pdf.data, 'base64'));
    const pages = (Buffer.from(pdf.data, 'base64').toString('latin1').match(/\/Type\s*\/Page[^s]/g) ?? []).length;

    console.log(`PDF: ${pdfPath} (${pages} páginas)`);
    if (pages > 10) console.warn('ATENÇÃO: a atividade pede no máximo 10 slides.');
    if (!stats.photo) console.warn(`Falta a foto: salve como foto.jpg em ${PASTA ?? 'entrega/'} e rode de novo.`);
    else console.log(`Foto: ${photo}`);
    if (video && !stats.qr) console.warn('O QR code não foi gerado (sem internet?). O link aparece em texto.');
} finally {
    browser.close();
    rmSync(renderFile, { force: true });
}

if (PASTA) {
    copyFileSync(pdfPath, join(PASTA, `${NAME}.pdf`));
    console.log(`PDF copiado para: ${join(PASTA, `${NAME}.pdf`)}`);
}

if (!video) {
    console.warn('\nO ZIP NÃO foi gerado: falta o link do vídeo.');
    console.warn(`Publique o vídeo no YouTube como "Não listado", cole o link em ${join(PASTA ?? HERE, 'link-do-video.txt')} e gere de novo.`);
    process.exit(0);
}

const txtName = 'link-do-video.txt';
const zipBytes = buildZip([
    { name: `${NAME}.pdf`, data: readFileSync(pdfPath) },
    { name: txtName, data: Buffer.from(`${video}\n`, 'utf8') },
]);
writeFileSync(join(DIST, txtName), `${video}\n`);
writeFileSync(join(DIST, `${NAME}.zip`), zipBytes);
const zipPath = join(PASTA ?? DIST, `${NAME}.zip`);
writeFileSync(zipPath, zipBytes);
console.log(`ZIP: ${zipPath}\n  ├─ ${NAME}.pdf\n  └─ ${txtName}  →  ${video}`);
