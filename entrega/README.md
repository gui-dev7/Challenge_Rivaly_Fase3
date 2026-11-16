# Entrega: Enterprise Challenge (Cibersegurança e IA)

Tudo o que a atividade pede, gerado a partir desta pasta.

| Item pedido | Onde está |
|---|---|
| Apresentação de até 10 slides, em PDF | `slides.html` → `dist/Challenge_Rivaly_Fase3.pdf` (10 páginas, 16:9) |
| Slide do integrante com nome, RM e foto | Slide 1 (a foto vem de `foto.jpg`) |
| Tema e escopo · inspiração ou dor · descrição da aplicação | Slides 2, 3 e 4 |
| Plano de cibersegurança e IA | Slides 5, 6 e 7 · detalhes em `../docs/seguranca-e-ia.md` |
| Padrão de senha (o quê e como) | Slides 8 e 9 · detalhes em `../docs/padrao-de-senha.md` |
| Demonstração funcional | `../seguranca.html` + `npm run demo` · slide 10 |
| Roteiro do vídeo de até 5 minutos | `roteiro-do-video.md` |
| Link do vídeo nos slides e num .txt | `link-do-video.txt` → slides 1 e 10 (texto + QR code) e `.txt` no ZIP |
| ZIP com o PDF e o .txt, na mesma pasta | `dist/Challenge_Rivaly_Fase3.zip` |

## Como finalizar

1. **Foto:** salve uma foto quadrada como `entrega/foto.jpg`. Ela fica fora do Git de propósito (o repositório é público).
2. **Vídeo:** grave seguindo `roteiro-do-video.md` e publique no YouTube como **Não listado**.
3. **Link:** cole o link na primeira linha sem `#` de `link-do-video.txt`.
4. **Gerar:** na raiz do projeto, rode

   ```bash
   npm run entrega
   ```

   O script abre os slides no Chrome ou no Edge sem janela, coloca o link e o QR code, imprime o PDF e monta o ZIP:

   ```text
   entrega/dist/Challenge_Rivaly_Fase3.zip
   ├── Challenge_Rivaly_Fase3.pdf
   └── link-do-video.txt
   ```

   Sem o link, ele gera só o PDF e avisa. `npm run entrega -- --previa` também salva um PNG de cada slide em `dist/previa/`.
5. **Conferir:** descompacte o ZIP numa pasta nova e abra os dois arquivos antes de enviar.

Para mudar um texto, edite `slides.html` (dá para abrir direto no navegador) e rode `npm run entrega` de novo.

### Pasta de entrega fora do projeto

`npm run entrega -- --pasta <dir>` lê `foto.jpg` e `link-do-video.txt` primeiro de `<dir>` e grava o PDF e o ZIP lá. É o que o `GERAR-ENTREGA.bat` da pasta `Entrega_Challenge_Rivaly_Fase3` (ao lado do projeto, fora do Git) faz com dois cliques.
