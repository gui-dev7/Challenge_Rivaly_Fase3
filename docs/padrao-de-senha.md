# Padrão de senha da RIVALY

O que a RIVALY exige de uma senha, como guarda, como impede tentativa e erro e o que ainda é proposta. Faz parte do Enterprise Challenge (FIAP, com a Palo Alto Networks), V3.1.

> **Legenda.** ✅ funciona e tem teste · 🖥️ funciona no servidor da demo (`npm run demo`) · 📝 proposta, ainda não implementada.

## 1. As regras (o quê)

| # | Regra | Por quê | Status |
|---|---|---|---|
| 1 | **Mínimo de 15 caracteres, máximo de 128.** Contados como caracteres de verdade (um emoji conta 1) depois de normalizar em NFKC. | NIST SP 800-63B-4 exige 15 quando a senha é o único fator. O teto evita negação de serviço por hash de textos gigantes. | ✅ |
| 2 | **Espaços, acentos e emoji são aceitos.** Frases-senha como "pizza de quinta com o squad" valem. | Frases longas são fortes e fáceis de lembrar. | ✅ |
| 3 | **Sem regra de composição obrigatória** (nada de "1 maiúscula, 1 número, 1 símbolo"). | A NIST proíbe: a regra empurra para `Senha@2026`, que todo ataque testa. O medidor da RIVALY recusa `Senha@2026forte` mesmo atendendo à composição clássica. | ✅ |
| 4 | **Lista de bloqueio**: senhas mais vazadas, nomes de jogos, personagens, times e do próprio serviço, **inclusive variações** (`p@ssw0rd`, `minecraft2024!!!`, `valorantvalorant`). | São as primeiras de qualquer dicionário de ataque. | ✅ |
| 5 | **Sem dados pessoais**: nada do apelido nem do e-mail (`nova.silva@fiap.com.br` → `nova`, `silva`, `novasilva`, `fiap`). | Ataque direcionado tenta isso primeiro; apelido é público na comunidade. | ✅ |
| 6 | **Força estimada "Forte" ou acima** (cerca de 55 bits), por um estimador que reconhece dicionário, leet, sequências, teclado, repetições e anos. | Pega o que as regras fixas deixam passar (`aaaaaaaaaaaaaaa`, `qwertyuiopasdfg`). | ✅ |
| 7 | **Senha vazada é recusada** (Have I Been Pwned, Pwned Passwords) com **k-anonimato**: só 5 caracteres do SHA-1 saem do aparelho. | NIST manda comparar com senhas comprometidas. Credential stuffing usa exatamente essas listas. | ✅ no navegador · 🖥️ no servidor, com *padding* |
| 8 | **Hash lento com sal por conta.** Servidor: **argon2id** (19 MiB, t=2, p=1). Navegador: **PBKDF2-SHA256 com 600.000 iterações**. Formato com parâmetros embutidos, para subir o custo depois. | Se o banco vazar, cada palpite custa caro e contas com a mesma senha têm hashes diferentes. | ✅ navegador · 🖥️ servidor |
| 9 | **Bloqueio progressivo**: 5 erros seguidos liberam; no 5º, pausa de 30 s que dobra (1, 2, 4, 8 min) até 15 min. Por **e-mail** e por **IP** (20 erros). Pausa temporária, nunca permanente. | Freia força bruta e credential stuffing sem deixar que alguém tranque a conta de outra pessoa de propósito. | ✅ navegador · 🖥️ servidor (HTTP 429 + `Retry-After`) |
| 10 | **Mensagem genérica** ("E-mail ou senha incorretos.") e **o mesmo tempo de resposta** para e-mail inexistente; cadastro com a mesma resposta para e-mail novo ou repetido. | Impede descobrir quem tem conta (enumeração). | ✅ login · 🖥️ cadastro |
| 11 | **Sessão em cookie `HttpOnly; SameSite=Strict`** (e `Secure` em HTTPS), token aleatório de 32 bytes guardado **como hash**. | JavaScript de terceiros não lê o cookie; outro site não consegue usá-lo. | 🖥️ |
| 12 | **Sem troca periódica obrigatória** e sem "dica de senha". Troca só quando há sinal de vazamento. | NIST: troca forçada gera senhas previsíveis (`Senha1`, `Senha2`...). | ✅ (por desenho) |
| 13 | **Recuperação de conta segura**: link de uso único, aleatório (32 bytes), guardado como hash, válido por 15 min, resposta igual exista o e-mail ou não; ao trocar a senha, todas as sessões caem e o dono recebe aviso. | Recuperação mal feita é a porta dos fundos mais comum. | 📝 |
| 14 | **MFA opcional** com app autenticador (TOTP, RFC 6238) e 10 códigos de recuperação; obrigatório para líderes e oficiais de clã. Depois, **passkeys** (WebAuthn). | Com MFA, uma senha vazada sozinha não basta. Passkey não pode ser digitada num site falso. | 📝 |

## 2. Como funciona (o como)

```text
 NAVEGADOR (login.html / seguranca.html)                SERVIDOR (server/, api/)
 ─────────────────────────────────────────              ───────────────────────────────
 password-policy.js ── medidor ao vivo                  password-policy.js (o MESMO arquivo)
 pwned.js ── SHA-1 → "5BAA6" ──► api.pwnedpasswords.com ◄── pwned.js com Add-Padding
 password-hash.js ── PBKDF2 600k + sal                  password-hasher.mjs ── argon2id
 throttle.js ── pausa local (experiência)               throttle.js ── por e-mail e por IP (vale)
            │                                                       ▲
            └──── POST /api/password-check (JSON) ──────────────────┘
                  POST /api/register · POST /api/login · GET /api/health
```

- **Uma regra, dois lados.** `js/core/password-policy.js` é puro (sem DOM, sem rede) e é importado pelo formulário e pelo servidor. O cliente dá feedback; o servidor decide.
- **Defesa em profundidade no cadastro:** formulário → vazamento (HIBP) → servidor (`/api/password-check`, quando existe) → `register()` revalida antes de gravar.
- **Migração sem dor:** contas antigas (SHA-256 com sal fixo) entram uma última vez e o hash é trocado por PBKDF2 no mesmo login (`needsRehash`). O servidor faz o mesmo de scrypt para argon2id.
- **Transporte:** a API só aceita `Content-Type: application/json` (um `<form>` de outro site não consegue enviar, o que fecha o CSRF clássico), corpo de até 8 KB, `Cache-Control: no-store` e erro interno sem stack trace.

### Arquivos

| Arquivo | Papel |
|---|---|
| `js/core/password-policy.js` | Regras, lista de bloqueio, estimador de força |
| `js/core/pwned.js` | Consulta k-anônima ao Have I Been Pwned |
| `js/core/password-hash.js` | PBKDF2 no navegador e migração do hash antigo |
| `js/core/throttle.js` | Bloqueio progressivo (relógio injetável) |
| `js/core/account-rules.js` | Apelido e e-mail (compartilhado com o servidor) |
| `js/core/auth.js` | Cadastro e login locais usando tudo acima |
| `js/ui/password-meter.js` | Medidor de força e checklist |
| `js/pages/security.js`, `seguranca.html` | Laboratório de segurança |
| `server/password-hasher.mjs` | argon2id (fallback scrypt), formato PHC |
| `server/auth-service.mjs` | Cadastro, login, bloqueio por e-mail/IP, sessão |
| `server/http-handler.mjs`, `server/index.mjs` | Rotas HTTP e servidor local |
| `api/password-check.js`, `api/health.js` | As mesmas rotas como Vercel Functions |
| `tests/password-policy`, `throttle`, `pwned`, `password-hash`, `auth-local`, `auth-server` | 44 testes novos |

## 3. Como rodar a demonstração

```bash
npm ci
npm run demo     # API em 127.0.0.1:8787 + site em http://localhost:5173
npm test         # 83 testes
```

Abra `http://localhost:5173/seguranca.html`:

1. **Teste uma senha**: clique nos exemplos (`Senha@2026`, `minecraft2024!!!`, `password12345678`) e veja a checklist, o tempo de quebra e o prefixo enviado ao HIBP.
2. **Como a senha é guardada**: o hash antigo sai igual duas vezes; o novo, diferente.
3. **Bloqueio**: erre 5 vezes e tente a senha certa durante a pausa.
4. **Servidor**: crie a conta, erre o login 5 vezes (HTTP 429 com `Retry-After`) e veja o hash `$argon2id$...` guardado.

No cadastro de verdade (`login.html?mode=create`) o medidor aparece embaixo da senha, e o envio recusa senha vazada.

## 4. Limites honestos

- A conta do produto ainda vive no `localStorage`: quem tem o aparelho nas mãos pode ler e editar. O PBKDF2 protege a senha de quem abre o DevTools, mas o bloqueio do navegador é só experiência (apagar o armazenamento zera a contagem). **O controle que vale é o do servidor.**
- O servidor da demo guarda tudo em memória: reiniciar apaga as contas. A rota `/api/demo/accounts` existe só para mostrar o hash na apresentação e não é publicada na Vercel.
- O estimador de força é uma versão simplificada da ideia do zxcvbn. Em produção, o recomendado é o `zxcvbn-ts` completo, com dicionários maiores.
- Na Vercel publicamos apenas `/api/health` e `/api/password-check` (stateless). Cadastro e login no servidor dependem do banco de dados da Fase 1 do roteiro.

## 5. Base

- NIST SP 800-63B-4, *Digital Identity Guidelines: Authentication and Authenticator Management* (2025), seção de senhas.
- OWASP ASVS 5.0, capítulo V6 (Authentication).
- OWASP Password Storage Cheat Sheet e Authentication Cheat Sheet.
- Have I Been Pwned, Pwned Passwords API (consulta por intervalo, k-anonimato, *padding*).
- RFC 9106 (Argon2), RFC 8018 (PBKDF2), RFC 6238 (TOTP), W3C WebAuthn.
- LGPD, Lei 13.709/2018, art. 46 (segurança dos dados pessoais).
