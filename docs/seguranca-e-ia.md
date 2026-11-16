# Proposta de cibersegurança e IA da RIVALY

Enterprise Challenge, FIAP Sistemas de Informação, com a Palo Alto Networks. Guilherme Oliveira Santos, RM576218. Versão do produto: V3.1.

> **Legenda.** ✅ implementado e testado nesta entrega · 📝 proposta com plano de integração.
> O padrão de senha está detalhado em [`padrao-de-senha.md`](padrao-de-senha.md).

---

## 1. A dor

Conta de jogo vale dinheiro: skins, itens, ranks e contas "upadas" são revendidos. Por isso a conta gamer é alvo de:

- **Credential stuffing**: robôs testam pares de e-mail e senha vazados de outros sites, porque muita gente reaproveita a senha.
- **Phishing**: "skin grátis", "sorteio de V-Bucks", páginas falsas de login da Steam ou do Discord.
- **Boosting e smurf**: conta compartilhada ou comprada para subir de rank, que corrói a confiança no ranking.
- **Toxicidade**: assédio e ofensa em comunidades competitivas, que expulsa jogadores.

Na RIVALY, quem rouba a conta rouba a **identidade inteira**: o Passaporte, o clã, o rating da Arena e a reputação construída com aliados e rivais.

## 2. Diagnóstico do código (V3.0)

| Já existia ✅ | Encontrado no código | O que foi feito |
|---|---|---|
| CSP restritiva, `frame-ancestors 'none'`, `nosniff`, `Permissions-Policy`, COOP (`vercel.json`) | Senha mínima de **6** caracteres, sem lista de bloqueio | Padrão de 15+ com bloqueio, dados pessoais e HIBP ✅ |
| Proteção contra *open redirect* no `?redirect=` (`login.js`) | **SHA-256 com sal fixo**: mesma senha, mesmo hash | PBKDF2 600k com sal (navegador) e argon2id (servidor) ✅ |
| `escapeHtml` em 28 módulos, `noHtml`/`sanitizeText` no Feed, Clãs e Passaporte | Mensagem **"Não há conta com este e-mail"** (enumeração) | Mensagem genérica e tempo igual ✅ |
| Bootstrap servido localmente (sem CDN de terceiros) | **Tentativas ilimitadas** de login | Bloqueio progressivo por e-mail e IP ✅ |
| Exportação de dados sem credenciais (Configurações) | **2 vulnerabilidades altas** no Vite e no `source-map-js` (`npm audit`) | Dependências atualizadas, 0 vulnerabilidades ✅ |
| | Sem HSTS | `Strict-Transport-Security` de 2 anos ✅ |
| | Dados de jogo (rating, clã) editáveis no `localStorage` | Validação no servidor quando houver backend 📝 |

## 3. Plano de cibersegurança (em camadas, no espírito Zero Trust)

O princípio vem do modelo Zero Trust (NIST SP 800-207, também a base dos produtos da Palo Alto Networks): **nunca confiar no cliente, verificar cada pedido no servidor, dar o menor privilégio possível.**

### 3.1 Identidade e acesso
- ✅ Padrão de senha completo (15+, sem composição, bloqueio, contexto, HIBP).
- ✅ argon2id (servidor) e PBKDF2 (navegador), com migração de hashes antigos.
- ✅ Bloqueio progressivo por e-mail e IP, HTTP 429 com `Retry-After`.
- ✅ Mensagem genérica no login e resposta única no cadastro.
- ✅ Sessão em cookie `HttpOnly; SameSite=Strict; Secure`, token guardado como hash.
- 📝 MFA opcional (TOTP), obrigatório para líder e oficial de clã (papéis que já existem em `clans-store.js`).
- 📝 Recuperação por link único de 15 min; passkeys (WebAuthn).
- 📝 Login com Google/Microsoft (Fase 1 do roteiro) com OAuth 2.0 + PKCE e validação de `state`.

### 3.2 Aplicação web
- ✅ CSP, HSTS e demais cabeçalhos; `connect-src` liberado só para a API do HIBP.
- ✅ API aceita só JSON (fecha CSRF por formulário), corpo de até 8 KB, `no-store`, erro sem stack trace.
- ✅ A mesma validação no cliente e no servidor (`password-policy.js`, `account-rules.js`).
- 📝 Toda regra de jogo (rating, XP, papéis de clã) recalculada no servidor: o cliente só envia a intenção.
- 📝 Testes de segurança automatizados (OWASP ZAP no CI) a cada deploy.

### 3.3 Dados e privacidade (LGPD)
- ✅ Minimização: a conta só pede apelido, e-mail e senha.
- ✅ Exportação dos dados pelo próprio usuário, sem credenciais nem estado de segurança.
- 📝 Banco com criptografia em repouso; e-mail cifrado e indexado por hash.
- 📝 Política de retenção (logs de segurança por 90 dias) e canal do encarregado (DPO).

### 3.4 Cadeia de suprimentos
- ✅ `npm audit` zerado; `package-lock.json` versionado; Bootstrap e fontes locais.
- 📝 Dependabot e `npm audit --audit-level=high` bloqueando o CI.

### 3.5 Monitoramento e resposta
- ✅ O servidor da demo registra cadastro, falhas e sucessos de login sem senha e sem token.
- 📝 Alerta de pico de falhas por IP ou ASN (sinal de credential stuffing).
- 📝 Aviso ao usuário em login de aparelho novo, com "não fui eu" encerrando as sessões.
- 📝 Plano de resposta a incidente: conter, avisar a ANPD e os titulares quando houver risco relevante, e fazer o pós-mortem.

### 3.6 Modelo de ameaças (STRIDE)

| Ameaça | Exemplo na RIVALY | Controle |
|---|---|---|
| **S**poofing | Credential stuffing com senhas vazadas | Padrão de senha + HIBP + bloqueio ✅ · MFA 📝 |
| **T**ampering | Editar o `localStorage` para virar líder de clã ou subir o rating | Regras de jogo no servidor 📝 |
| **R**epudiation | "Não fui eu que postei isso" | Logs de segurança com data, IP e sessão 📝 |
| **I**nformation disclosure | Descobrir quem tem conta; banco vazado | Mensagem genérica ✅ · argon2id + sal ✅ |
| **D**enial of service | Senha de 1 MB para travar o hash; flood de login | Teto de 128 caracteres e 8 KB ✅ · rate limit ✅ |
| **E**levation of privilege | XSS num post do Feed; redirect para site falso | CSP + `escapeHtml` + `noHtml` ✅ · redirect seguro ✅ |

## 4. IA no produto

Cinco usos ligados ao que a RIVALY já tem, com regra de ouro: **a IA sugere, a pessoa decide**, e nenhuma IA toma ação irreversível sozinha.

| # | Uso | Onde entra no código | Dados que usa | Guarda-corpo |
|---|---|---|---|---|
| 1 | **Login de risco** (autenticação adaptativa): pontua cada login de 0 a 100 | Antes de `login()` no servidor (`auth-service.mjs`) | Aparelho novo, IP/ASN, país, horário habitual, ritmo de tentativas, "viagem impossível" | Risco baixo passa; médio pede MFA; alto bloqueia e avisa o dono. Explicação registrada em log |
| 2 | **Moderação de toxicidade** no Feed e nos comentários | `feed-store.js` (`createPost`, `addComment`), antes de publicar | Só o texto do post | Primeiro sugere reescrever; oculta só com revisão humana; sempre com recurso |
| 3 | **Antifraude da Arena**: detectar *smurf* e *boosting* | `arena-store.js`, a cada partida registrada | Curva de rating, adversários repetidos, horários, ganho fora do padrão (Isolation Forest + regras) | Marca para revisão e congela o rating em análise; nunca bane sozinho |
| 4 | **Anti-phishing de links** no Feed (e no chat futuro) | Ao publicar texto com URL | URL (domínio parecido com Steam/Discord, encurtador, "skin grátis") + listas de reputação | Avisa antes de abrir e bloqueia os maliciosos conhecidos. É a mesma ideia do filtro de URL dos firewalls de nova geração |
| 5 | **Explicação dos matches** do DNA Gamer e da compatibilidade de squad | `compatibility.js` já calcula os 7 fatores | Só os números do cálculo, sem e-mail nem nome | O modelo de linguagem só explica a conta que o código já fez; não muda o resultado |

Como integrar sem expor dados: as chamadas de IA ficam no servidor (nunca com chave no navegador), com minimização (só o campo necessário), registro do que foi decidido e por quê, e avaliação periódica de falsos positivos, sobretudo na moderação em português com gírias de jogo.

## 5. Em que me baseei

- **NIST SP 800-63B-4** (2025): regras de senha, lista de bloqueio, senhas comprometidas e limite de tentativas.
- **OWASP ASVS 5.0** (V6 Authentication) e **OWASP Top 10**: requisitos verificáveis e riscos mais comuns da web.
- **OWASP Password Storage** e **Authentication Cheat Sheets**: argon2id, PBKDF2, mensagens genéricas e bloqueio.
- **Have I Been Pwned**: Pwned Passwords com k-anonimato.
- **NIST SP 800-207** (Zero Trust) e o modelo Zero Trust da **Palo Alto Networks**.
- **LGPD** (Lei 13.709/2018): art. 6º (necessidade e segurança), art. 46 (medidas técnicas) e art. 48 (comunicação de incidente).
- **STRIDE** (Microsoft) para o modelo de ameaças.
