# Estudo: redesenho dos Definições (GoGo Gadget 0.9.26)

Documento de estudo para o Ricardo. **Nada disto está implementado**: o ecrã de Definições continua com o layout atual (só mudaram os comportamentos dos itens 3, 4 e 5 do lote 0.9.26). Fonte: `SettingsScreen.kt`, `InstallSettings.kt`, `ShieldSettingsStore` em `SecurityShield.kt`, `AppLanguage.kt`, `AppIcon.kt`.

---

## 1. Inventário atual

Todas as linhas usam o mesmo `SettingRow`: altura mínima 56 dp, nome à esquerda (bodyLarge), valor em texto à direita (bodyMedium, cor secundária), separador de 1 px entre linhas. Uma seta `>` aparece em **qualquer** linha com ação.

| # | Grupo | Linha | O que mostra | O que faz ao tocar | Problemas |
|---|-------|-------|--------------|--------------------|-----------|
| 1 | Aspeto | Tema | Sistema / Claro / Azul / Escuro | Abre sub-ecrã com 4 opções (rádio) | Um ecrã inteiro para 4 opções; o título do sub-ecrã é secundário e pequeno |
| 2 | Aspeto | Ícone da app | Azul / Claro / Escuro | Abre sub-ecrã com 3 opções (rádio) + nota | Idem; o utilizador não vê o ícone antes de escolher |
| 3 | Segurança | Escudo antivírus | Ativado / Desativado (ícone de escudo verde se ligado) | Alterna ligado/desligado | Mostra seta `>` mas não navega; sem descrição do que protege; desligar não avisa o que se perde |
| 4 | Segurança | Chave do VirusTotal | "Definida (••••)" / "Não definida (obrigatória)" | Abre sub-ecrã (campo + Guardar, ou valor mascarado + lixo desde 0.9.26) | Está ativa mesmo com o Escudo desligado; o valor "(••••)" não diz nada |
| 5 | Segurança | Análise profunda | Ativado / Desativado | Alterna | Sem descrição ("profunda" em quê?); depende do Escudo mas não fica cinzenta quando este está desligado; seta enganadora |
| 6 | Instalação | Atalho no ecrã principal | Ativado / Desativado | Alterna (instalação em modo utilizador) | Nome não explica o efeito (o launcher cria o ícone numa instalação nova); seta enganadora |
| 7 | Instalação | Eliminar o APK após a instalação | Desligado / Ligado / Automático (0.9.26) | Percorre os 3 estados a cada toque | Três estados num toque cíclico não são descobríveis; sem descrição da diferença entre Ligado e Automático |
| 8 | Instalação | Backup antes de atualizar | Ativado / Desativado (0.9.26; antes era texto fixo "Ativado" sem ação) | Alterna | Sem descrição (onde ficam as cópias, só 1 versão por app); sem atalho para o separador Backups |
| 9 | Idioma | Idioma | Sistema / nome do idioma | Abre as definições de idioma da app do Android (API 33+); abaixo disso a linha é só informação | Grupo com uma única linha; sem seta em Android < 13 e sem explicação |
| 10 | Acerca | Versão | Número da versão | Nada | Informação, mas com o mesmo aspeto das linhas que fazem coisas |
| 11 | Acerca | Código-fonte | "GitHub" | **Nada** (não tem ação) | Parece uma ligação mas não abre nada |
| 12 | Acerca | Licença | GPL-3.0 | Nada | Só informação |

Problemas transversais:

1. **Aspeto igual para ações diferentes**: alternar, navegar e só mostrar informação parecem a mesma coisa (todas têm texto à direita; as ações têm `>`, incluindo os interruptores).
2. **Valores sem coluna fixa**: o texto à direita tem larguras diferentes e empurra o nome; em francês/espanhol os nomes longos ("Copia de seguridad antes de actualizar") quebram em duas linhas com o valor desalinhado.
3. **Sem descrições**: nenhuma linha explica o efeito. As opções de segurança são justamente as que mais precisam.
4. **Sem relação entre opções**: Análise profunda e Chave do VirusTotal só fazem sentido com o Escudo ligado.
5. **Voltar nos sub-ecrãs**: o botão do sistema fecha o Tema e a Chave do VirusTotal (`MainActivity`), mas o sub-ecrã do Ícone guarda o estado dentro do `SettingsScreen` e o `BackHandler` não o conhece, por isso o botão do sistema sai das Definições em vez de fechar o seletor (a confirmar num dispositivo; não corrigido neste lote). Cada sub-ecrã repete ainda o cabeçalho "Voltar" em texto.
6. **Grupo "Idioma" isolado** e grupo "Aspeto" com duas linhas: a ordem dos grupos não reflete a importância (a segurança é a razão de ser da app e está em segundo lugar).

---

## 2. Agrupamento e ordem propostos

Ordem por importância e frequência de uso:

1. **Segurança** (o que a app promete)
   - Escudo antivírus
   - Chave do VirusTotal (só ativa com o Escudo ligado)
   - Análise profunda (só ativa com o Escudo ligado)
2. **Instalação**
   - Backup antes de atualizar
   - Eliminar o APK após a instalação
   - Atalho no ecrã principal
3. **Aspeto e idioma** (junta os grupos "Aspeto" e "Idioma")
   - Tema
   - Ícone da app
   - Idioma
4. **Dispositivos** (proposta nova, ver secção 4)
   - Esquecer todos os dispositivos
5. **Acerca**
   - Versão
   - Código-fonte (passa a abrir a ligação)
   - Licença

### O que remover, juntar ou acrescentar

| Ação | Item | Motivo |
|------|------|--------|
| Juntar | Grupo Idioma dentro de "Aspeto e idioma" | Um grupo com uma linha não se justifica |
| Remover o aspeto de ligação | Código-fonte | Ou passa a abrir o GitHub, ou deixa de mostrar "GitHub" como valor; proposta: abrir a ligação |
| Substituir | Tema e Ícone em sub-ecrãs | Controlo de segmentos na própria linha (3–4 opções cabem), poupa um ecrã e um toque |
| Substituir | Eliminar APK em toque cíclico | Controlo de 3 segmentos (Desligado, Ligado, Automático) na própria linha |
| Acrescentar | Descrição de uma linha em cada item | Ver secção 3 |
| Acrescentar | Estado dependente (cinzento) | Chave e Análise profunda cinzentas com o Escudo desligado |
| Acrescentar | Esquecer todos os dispositivos | `ConnectionModel.resetConnections()` já existe; hoje só corre quando o último dispositivo é esquecido. É uma proposta, precisa de confirmação (diálogo igual ao de "Esquecer") |
| Acrescentar (opcional) | "Abrir Backups" na linha de Backup antes de atualizar | Liga a definição ao separador onde as cópias aparecem |
| Não acrescentar | Mais opções de aparência | Fora do âmbito |

---

## 3. Anatomia de uma linha

Uma grelha, para todas as linhas:

```
|<-24->| título                                   |<-16->| controlo |<-24->|
|      | descrição (1 linha, 2 no máximo)         |      |          |      |
```

- **Margens**: 24 dp laterais (as mesmas de `Margin`), 16 dp entre o texto e o controlo.
- **Altura**: mínimo 64 dp com descrição (56 dp sem), toda a linha é a área de toque (≥ 48 dp).
- **Título**: bodyLarge, cor de texto, 1–2 linhas.
- **Descrição**: bodySmall, cor secundária, máximo 2 linhas. Uma frase que diz o efeito, não o nome repetido.
- **Coluna do controlo** com largura fixa (96 dp) alinhada à direita, para os controlos ficarem na mesma vertical em todas as linhas. Há só três tipos:
  1. **Interruptor** (ligar/desligar): retângulo plano 44 × 24 dp, raio 0, com a posição do botão e o texto "Ativado/Desativado" para leitores de ecrã (`Role.Switch`). Sem seta.
  2. **Segmentos** (2–4 opções): faixa de botões planos com 1 px de linha, o selecionado preenchido com `accent`. Ocupa a largura toda sob a descrição, em vez da coluna do controlo.
  3. **Navegação** (abre outro ecrã ou o sistema): valor curto em texto secundário + seta `>`. **Só** estas linhas têm seta.
- **Informação** (Versão, Licença): valor à direita, sem seta e sem área de toque.
- **Estado desativado**: título e descrição em cor secundária, controlo sem interação, `Modifier.semantics { disabled() }`.
- Contraste: título e descrição seguem os pares já testados em `ContrastTest` (texto e secundário ≥ 4,5:1 sobre fundo e superfície, nos três temas).

Descrições propostas (para o `strings.xml`, 4 idiomas):

| Linha | Descrição (PT) |
|-------|----------------|
| Escudo antivírus | Verifica cada ficheiro antes de o instalar. |
| Chave do VirusTotal | Necessária para consultar ficheiros desconhecidos. |
| Análise profunda | Examina o interior do pacote em busca de código suspeito. |
| Backup antes de atualizar | Guarda a versão instalada para a poder repor. Só a última versão de cada app. |
| Eliminar o APK após a instalação | Desligado: nunca. Ligado: mostra o botão. Automático: apaga após uma instalação bem-sucedida. |
| Atalho no ecrã principal | O launcher cria o ícone ao instalar uma app nova. |
| Tema | Sistema, Claro, Azul ou Escuro. |
| Ícone da app | O ícone no launcher. |
| Idioma | Abre as definições de idioma do Android. |

---

## 4. Esboço (ASCII)

```
+------------------------------------------------------+
|  Definições                                          |
+------------------------------------------------------+
|  SEGURANÇA                                           |
+------------------------------------------------------+
|  Escudo antivírus                         [ ====|]   |
|  Verifica cada ficheiro antes de o instalar.         |
+------------------------------------------------------+
|  Chave do VirusTotal                      ••••a3f9 > |
|  Necessária para consultar ficheiros desconhecidos.  |
+------------------------------------------------------+
|  Análise profunda                         [ ====|]   |
|  Examina o interior do pacote.                       |
+------------------------------------------------------+
|  INSTALAÇÃO                                          |
+------------------------------------------------------+
|  Backup antes de atualizar                [ ====|]   |
|  Guarda a versão instalada para a poder repor.       |
+------------------------------------------------------+
|  Eliminar o APK após a instalação                    |
|  Automático apaga após uma instalação bem-sucedida.  |
|  [ Desligado ][ Ligado ][#Automático# ]              |
+------------------------------------------------------+
|  Atalho no ecrã principal                 [|==== ]   |
|  O launcher cria o ícone ao instalar uma app nova.   |
+------------------------------------------------------+
|  ASPETO E IDIOMA                                     |
+------------------------------------------------------+
|  Tema                                                |
|  [ Sistema ][ Claro ][ Azul ][#Escuro# ]             |
+------------------------------------------------------+
|  Ícone da app                                        |
|  [ Azul ][ Claro ][#Escuro# ]                        |
+------------------------------------------------------+
|  Idioma                                  Português > |
+------------------------------------------------------+
|  DISPOSITIVOS                                        |
+------------------------------------------------------+
|  Esquecer todos os dispositivos                    > |
+------------------------------------------------------+
|  ACERCA                                              |
+------------------------------------------------------+
|  Versão                                      0.9.26  |
|  Código-fonte                             GitHub  >  |
|  Licença                                    GPL-3.0  |
+------------------------------------------------------+
```

Legenda: `[ ====|]` interruptor ligado, `[|==== ]` desligado; `#texto#` segmento selecionado; `>` só em linhas que navegam.

---

## 5. Esforço e riscos

- **Código**: um `SettingRow` novo com três variantes (interruptor, segmentos, navegação) substitui o atual; os sub-ecrãs de Tema e Ícone deixam de existir (menos estado `themeOpen`/`iconOpen` em `MainActivity`). A chave do VirusTotal mantém o sub-ecrã.
- **Strings**: 9 descrições novas x 4 idiomas, mais "Esquecer todos os dispositivos" e o diálogo. `TranslationsTest` já apanha chaves em falta.
- **Testes**: funções puras para o estado desativado (Chave/Análise profunda dependem do Escudo) e para o texto de acessibilidade dos interruptores.
- **Riscos**: o controlo de segmentos com 4 opções em francês ("Système / Clair / Bleu / Sombre") cabe em 312 dp, mas em ecrãs de 320 dp ou fonte grande precisa de quebrar para duas linhas ou voltar ao sub-ecrã; confirmar num dispositivo real. "Esquecer todos os dispositivos" apaga também as chaves ADB (`Everything` em `AdbIdentityTest`), por isso exige confirmação clara.
- **Decisões para o Ricardo**: (1) juntar Idioma em "Aspeto e idioma"? (2) segmentos em vez de sub-ecrãs para Tema/Ícone? (3) o Escudo desligado deve cinzentar a Chave e a Análise profunda? (4) incluir "Esquecer todos os dispositivos"? (5) o Código-fonte abre o GitHub?
