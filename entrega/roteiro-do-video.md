# Roteiro do vídeo pitch (até 5 minutos)

Cerca de 690 palavras, o que dá **4 min 35 s** num ritmo de fala tranquilo (150 palavras por minuto). Os tempos à esquerda são o ponto em que cada parte começa. Se passar de 5 minutos no ensaio, encurte o slide 4 (a aplicação) e a parte do servidor na demonstração.

**Antes de gravar**

- [ ] Rode `npm run demo` e abra `http://localhost:5173/seguranca.html` numa aba, com zoom de 125%.
- [ ] Na seção 4 da página, **crie a conta no servidor antes** (apelido Nova_7, senha `pizza de quinta com o squad`), para a demonstração só precisar dos erros de login.
- [ ] Abra o PDF dos slides em tela cheia numa segunda janela.
- [ ] Grave em 1080p (o Clipchamp, que já vem no Windows, ou o OBS servem). Áudio limpo vale mais que vídeo da câmera.

---

### 0:00 · Slide 1: capa e integrante

> Olá! Eu sou o Guilherme Oliveira Santos, RM 576218, de Sistemas de Informação na FIAP. Este é o meu Enterprise Challenge com a Palo Alto Networks: a proposta de cibersegurança e de inteligência artificial para a RIVALY, a minha aplicação web na área de games.

### 0:20 · Slide 2: tema e escopo

> O tema é proteger a identidade gamer. Nesta entrega, eu foquei na porta de entrada: a senha e o login. O padrão de senha está implementado no navegador e no servidor, com hash argon2id, bloqueio por tentativas e quarenta e quatro testes novos. MFA, recuperação de conta e os usos de IA ficam como proposta, com o plano de integração.

### 0:45 · Slide 3: a dor

> Por que isso importa? Conta de jogo vale dinheiro: skins, ranks e itens são revendidos. Por isso, contas gamer sofrem credential stuffing, que é testar senhas vazadas de outros sites, além de phishing de "skin grátis", boosting e toxicidade. Na RIVALY, quem rouba a conta rouba a identidade inteira. E a versão 3.0 aceitava senha de seis caracteres, sem limite de tentativas.

### 1:10 · Slide 4: a aplicação

> A RIVALY é uma plataforma de identidade gamer. Você monta o seu Passaporte, responde ao DNA Gamer e o sistema encontra aliados e rivais compatíveis. Ela tem Squads, Arena com rating no estilo Elo, Clãs e Feed. É feita em HTML, CSS, JavaScript e Bootstrap, e está publicada na Vercel.

### 1:30 · Slide 5: diagnóstico

> Eu comecei analisando o código. Já havia boas defesas: CSP, proteção contra redirecionamento aberto e escape de HTML contra XSS. Mas encontrei problemas: hash SHA-256 com sal fixo, então a mesma senha gerava o mesmo hash; uma mensagem que revelava quais e-mails tinham conta; e duas vulnerabilidades altas nas dependências. Tudo isso foi corrigido.

### 1:55 · Slide 6: plano de cibersegurança

> O plano segue o princípio Zero Trust, que também é a base da Palo Alto: nunca confiar no cliente e verificar tudo no servidor. São cinco camadas: identidade, aplicação, dados seguindo a LGPD, dependências e monitoramento. O que está em verde já funciona; o que está em laranja é o próximo passo, como calcular rating e XP no servidor.

### 2:20 · Slide 7: IA

> Para a IA, eu escolhi usos que resolvem problemas reais da RIVALY. Login de risco, que pede MFA quando o acesso parece estranho. Moderação de toxicidade no Feed. Antifraude da Arena, contra smurf e boosting. Anti-phishing nos links. E explicar em linguagem natural por que dois jogadores combinam. A regra vale para todos: a IA sugere e a pessoa decide, com o mínimo de dados.

### 2:50 · Slide 8: padrão de senha, as regras

> Agora, o padrão de senha. Eu me baseei na NIST 800-63B, versão 4, e no OWASP ASVS. A senha tem de 15 a 128 caracteres, e frases com espaço valem. Não existe regra de "uma maiúscula e um símbolo", porque ela gera senhas como "Senha@2026". Bloqueio senhas comuns e suas variações, dados pessoais e senhas que já vazaram. O hash é lento e com sal, e o login pausa depois de cinco erros seguidos.

### 3:20 · Slide 9: padrão de senha, como funciona

> E como funciona: o mesmo arquivo de regras roda no navegador, dando o feedback ao vivo, e no servidor, que é quem decide. Para checar vazamentos, só cinco caracteres do hash saem do aparelho. No servidor, a senha vira um hash argon2id. Compare com o hash antigo, que era igual para todo mundo que usava a mesma senha.

### 3:45 · Demonstração (troque para o navegador, em `seguranca.html`)

> Vamos ver funcionando. Esta é a página de segurança da RIVALY.

*Clique em **Senha@2026**.*

> "Senha@2026" é recusada: é curta e é uma variação de senha comum.

*Clique em **password12345678**.*

> Esta tem 16 caracteres, mas já apareceu mais de vinte e quatro mil vezes em vazamentos.

*Clique em **pizza de quinta com o squad** e depois em **Gerar os hashes**.*

> Já uma frase como esta é muito forte. Repare que os dois hashes antigos saem iguais, e os novos saem diferentes.

*Desça até a seção 4 e clique em **Entrar** cinco vezes com uma senha errada.*

> E no servidor, depois de cinco erros, a resposta é 429: uma pausa de trinta segundos, que vale até para a senha certa.

### 4:35 · Slide 10: fechamento

> Resumindo: tudo isso está funcionando, com 83 testes passando, zero vulnerabilidades no npm audit e a documentação no repositório. Os próximos passos são o backend com banco de dados, o MFA e a primeira IA, o login de risco. Os links estão na tela. Obrigado, e GG!

---

**Depois de gravar**

1. No YouTube, em **Visibilidade**, escolha **Não listado** e copie o link.
2. Cole o link em `entrega/link-do-video.txt`.
3. Rode `npm run entrega`. O link e o QR code entram no 1º e no 10º slide, e o ZIP sai em `entrega/dist/`.
