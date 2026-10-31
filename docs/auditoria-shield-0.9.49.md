# Auditoria ao Escudo antivírus do GoGo Gadget — versão 0.9.49

Auditoria **só de leitura**. Não alterei código, recursos, testes nem ficheiros de build. Não corri o Gradle, não fiz commit/push e não usei o adb. A única coisa que executei foram leituras de ficheiros e três scripts curtos em `python3 -I` (só `zipfile`/`struct`/`hashlib`, sem escrever nada no repositório) sobre o APK do Octave. Os scripts ficaram fora do repositório, em `/tmp/audit_scripts/`.

Abreviaturas de caminhos (para as citações `ficheiro:linha`):

- `K/` = `app/src/main/kotlin/app/gogogadget/`
- `T/` = `app/src/test/kotlin/app/gogogadget/`
- `R/` = `app/src/main/res/`

Regra de honestidade: tudo o que está citado com `ficheiro:linha` foi lido por mim no código desta árvore de trabalho (versionName 0.9.49, `app/build.gradle:16`). O que não pude confirmar está marcado **"não verificado"**.

---

## 1. Resumo em 10 linhas

1. **Crítica.** Quando há um aviso amarelo "no aparelho" (código dinâmico, chave de teste, permissão de auto-atualização, biblioteca nativa), o Escudo **ignora por completo o resultado do VirusTotal**, mesmo que 40 motores digam "malware" (`K/SecurityShield.kt:324`). Um amarelo pode ser aceite pelo utilizador, por isso um ficheiro que devia ser vermelho instala-se com um toque. O teste `T/SecurityShieldTest.kt:330` fixa este comportamento como se fosse correto.
2. **Alta.** O mesmo atalho explica o "Sem análise do VirusTotal disponível" do Octave: o veredicto é construído com contadores a 0 (`K/SecurityShield.kt:324`) e o cartão traduz "0 motores" como "sem análise" (`K/HomeScreen.kt:956,966`). A consulta ao VirusTotal foi feita; o resultado foi deitado fora.
3. **Alta.** Caso Octave: o ficheiro que o GoGo analisou **não é** o `base.apk` que foi extraído do telemóvel. Provado: esse APK não tem `classes2.dex` e nenhuma das 42 058 strings do seu DEX ativa a regra (secção 2).
4. **Alta.** A regra do "DexClassLoader" dispara por uma simples menção ao tipo em qualquer sítio do DEX, incluindo bibliotecas. O texto ainda afirma "carrega da Internet", o que a regra nunca verifica (`K/StaticAnalyzer.kt:132-144`, `R/values-pt-rPT/strings.xml:197`).
5. **Alta.** Sem rede, com quota esgotada ou com chave rejeitada, o resultado é **vermelho sem saída** (`K/SecurityShield.kt:337-340`). Sem chave nenhuma é amarelo. A informação é a mesma (não há prova online), a consequência é oposta, e viola a regra "sem paternalismo".
6. **Alta.** Uma única deteção em 70 motores (`malicious+suspicious > 0`) é vermelho sem opção (`K/SecurityShield.kt:327-331`). Mods "sem anúncios" têm quase sempre 1 a 3 deteções de heurística. Isto contradiz "mods são desejados".
7. **Alta.** O cartão amarelo só explica o **primeiro** motivo, com título fixo "mod / código dinâmico" e detalhe técnico **em inglês** (`K/ConnectionModel.kt:1551-1564`, `K/HomeScreen.kt:886`). O utilizador consente sem ver os outros motivos.
8. **Média/Alta.** Falhas silenciosas dão "limpo": o `catch (_: Throwable) {}` do deep scan (`K/StaticAnalyzer.kt:371`), o ZIP aninhado maior que 64 MiB (`:254-268`) e a consulta ao aparelho que falha (`K/ConnectionModel.kt:1204-1206`).
9. **Média.** MetaDefender só entra quando o VirusTotal não dá veredicto. Quando responde, a interface diz "VirusTotal" e o relatório abre sempre o VirusTotal. Em pacotes (APKM/XAPK) o relatório abre o hash do contentor, que nunca foi consultado.
10. **Média.** Há vários falsos positivos prováveis em apps limpas (`CN=Unknown`, `OU=Android`, `"index\n"` num ficheiro de texto, APK com `.apk` embebido) e falsos negativos fáceis (payload fora de `assets/`/`res/raw`, blob cifrado, loader ofuscado). Quase nenhuma destas regras tem teste de falso positivo (secção 7).

---

## 2. Caso Octave — causa exata, com prova

### 2.1 O que sei provar

Ficheiro: `/root/.hermes/cache/scratch/octave/base.apk`. SHA-256 confirmado: `cfb6e5a6027a59ae21734139f7214d460f21ea8c849fd0826c479e0ed902b28e`.

| Facto medido | Resultado |
|---|---|
| Ficheiros DEX na raiz | **só `classes.dex`** (10 710 624 bytes). Não existe `classes2.dex` em lado nenhum. |
| Strings no DEX (reimplementei `parseDexStrings`, `K/StaticAnalyzer.kt:66-112`) | 42 058 `string_ids`, todas lidas (não chega ao limite de 100 000). |
| `DexClassLoader`, `InMemoryDexClassLoader`, `PathClassLoader`, `dalvik/system`, `BaseDexClassLoader`, `DelegateLastClassLoader` nas strings | **0 ocorrências** de todos. Só existe `Ljava/lang/ClassLoader;`. |
| Os mesmos nomes nos bytes do DEX **já descomprimido** | 0 ocorrências. |
| Prefixos de adware (`K/StaticAnalyzer.kt:28-43`) | 0. Strings de caminhos dinâmicos (`/data/data/`, `/sdcard/`, `/code_cache/`…): 0. |
| Assets/`res/raw` (regras de `checkAssetPayload`, `:179-242`) | 0 achados. `assets/sing/vocals-v1.tflite` (19,7 MB) e `assets/dexopt/baseline.prof` passam. |
| Bibliotecas nativas (`K/CodeInspection.kt:100-129`) | Todas ELF válidas para a pasta (arm64 = 183, arm = 40, x86 = 3, x86_64 = 62). Sem marcadores `frida`/`lspatch`/`XposedBridge`. Só `JNI_OnLoad` (normal). |
| Assinatura | Blocos v2 e v3. Certificado único, SHA-256 `6f804efc…1e3b33`, `CN=Octave` (autoassinado, válido de 10-08-2026 a 02-08-2056). Não bate em nenhum token de debug (`K/SecurityShield.kt:88-102`). |
| Permissões no manifesto | Inclui `android.permission.REQUEST_INSTALL_PACKAGES`. Não inclui `SYSTEM_ALERT_WINDOW`, SMS, acessibilidade nem administrador de dispositivo. |

**Nota sobre a "pesquisa de bytes = 0" feita no APK:** não prova nada. Neste APK o `classes.dex` está comprimido (método deflate, `compress_type 8`), por isso uma pesquisa de texto no ficheiro `.apk` bruto nunca encontraria o nome, mesmo que existisse. Por isso descomprimi o DEX e li a tabela de strings, tal como o Escudo faz. O resultado confirma 0.

### 2.2 Conclusão

**O `base.apk` instalado, tal como está, nunca poderia gerar o cartão "DexClassLoader found in classes2.dex".** O Escudo só produz aquele texto quando existe, dentro do ZIP analisado, uma entrada com nome `classes2.dex` cujas strings contêm a referência ao tipo (`K/StaticAnalyzer.kt:346-350` dá ao detalhe o nome real da entrada, e `:133-136` escreve a frase). Se o nome saiu "classes2.dex" sem pasta, a entrada está na raiz de um APK que o Escudo abriu. Este APK não a tem.

### 2.3 Segunda prova: a ordem dos motivos

Este APK pede `REQUEST_INSTALL_PACKAGES`. Para o pacote `com.octave.app` (sem "store", "market", "installer"… no nome, `K/StaticAnalyzer.kt:439-445`) a regra `checkAbusivePermissions` devolve `SelfUpdaterPermission` (`:308-314`).

No pacote analisado, essa permissão é verificada **antes** do bytecode (`:391-394`). Por isso o primeiro motivo teria sido "auto-atualização". O cartão mostra `verdict.reasons.first()` (`K/ConnectionModel.kt:1551`) e o detalhe vem do primeiro achado do deep scan (`:1290-1291`). O dono viu **Dropper** + frase do DexClassLoader. Isto só acontece se o ficheiro analisado **não pedia** `REQUEST_INSTALL_PACKAGES`. O `base.apk` extraído pede. Logo, o manifesto do ficheiro analisado era diferente do instalado.

Esta segunda prova assume que a app corria exatamente este código. Se for outra build, confirma-se pelo registo (2.5).

### 2.4 Hipóteses que descartei, e a que sobra

| Hipótese | Veredicto | Porquê |
|---|---|---|
| Erro de leitura da tabela de strings (falso positivo do parser) | **Descartada** | Reimplementei o parser: 0 correspondências nas 42 058 strings e nos bytes descomprimidos. |
| Cache antiga | **Descartada para o dropper** | O deep scan não tem cache. A única cache (`ReputationCache`, `K/Reputation.kt:34-104`) guarda só contagens de motores por SHA-256 (`:35`), nunca motivos. |
| Pacote APKM/XAPK com outros APKs dentro | **Improvável** | O instalado é um APK universal (4 ABIs, 39 MB) e o motivo-ordem (2.3) também não bate. Num pacote o Escudo analisa **todos** os APKs, incluindo os que o filtro de splits não instala (`K/StaticAnalyzer.kt:396-408` vs `K/PackageBundle.kt:606-664`). Um split desses podia ter `classes2.dex`, mas então o base também teria `REQUEST_INSTALL_PACKAGES` e o 1.º motivo seria outro. |
| **Ficheiro diferente do instalado** | **A que sobra** | Outra build com o mesmo `versionName` "Public Version 1.2", ou outro ficheiro escolhido no seletor, ou um ficheiro analisado e **recusado**, com outro instalado depois. O instalado tem `installerPackageName=null` (registo do hermes, `/root/.hermes/logs/agent.log:19460`), compatível com instalação via ADB, mas isso não diz de que ficheiro veio. |

### 2.5 Como fechar o caso (sem aparelho)

O terminal do GoGo da sessão em causa regista `> source:`, `> sha256: <hash>` e `> deep scan: found DropperDetected (...)` (`K/ConnectionModel.kt:1646,1238,1287`). Se o `> sha256:` ≠ `cfb6e5a6…`, está provado que era outro ficheiro. Se for igual, o código desta árvore está em contradição consigo próprio, e é um bug novo que eu teria de ver (não vejo como).

Fica um defeito real independente do desfecho: **o cartão e o relatório não dizem qual ficheiro nem qual APK interior foram analisados**. O hash curto está no estado (`K/HomeScreen.kt:1101-1103`), mas não no cartão amarelo. Por isso foi impossível ao dono reconhecer que o aviso era sobre outro ficheiro (falha F9/F10).

### 2.6 "Sem análise do VirusTotal disponível" com chaves configuradas

Causa certa (não é falta de consulta, é texto e lógica):

1. A consulta é feita. As chaves são lidas (`K/ConnectionModel.kt:1300-1301`) e `lookupReputation` corre (`:1337-1350`), sempre que a variável `online` for verdadeira (`:1333`).
2. Depois `evaluateShieldVerdict` começa por: `if (offline.reasons.isNotEmpty()) return ShieldVerdict.Warning(sha256, offline.reasons, 0, 0, offline)` (`K/SecurityShield.kt:324`). O resultado online nunca é lido. O `Warning` sai com `vtMalicious = 0` e `vtTotal = 0`.
3. O cartão chama `cautionVtNote(verdict)`. Com `vtTotal == 0` cai no `else` e escreve `caution_vt_result_none` = "Sem análise do VirusTotal disponível" (`K/HomeScreen.kt:956,966`, `R/values-pt-rPT/strings.xml:201`).
4. Consequência extra: um ficheiro desconhecido do VirusTotal (o caso típico de uma app pequena como esta, certificado criado em ago-2026) **nunca recebe a oferta de enviar para análise**, porque a oferta (`ShieldVerdict.NeedsUpload`) só nasce depois da linha 324 (`:343-347`).
5. Possível causa adicional (**não verificado**): se a chave estivesse corrompida no Keystore, `loadKey` apaga-a em silêncio (`K/SecurityShield.kt:1331-1333`) e o registo diria "no API key set" (`K/ConnectionModel.kt:1315-1317`). O registo da sessão mostra qual dos dois casos foi.

---

## 3. Lista numerada de falhas

Legenda: **Gravidade** · o que acontece ao utilizador · causa · correção · teste que a provaria.

### Críticas e altas

**F1 — CRÍTICA. Um aviso amarelo esconde o vermelho do VirusTotal.**
- Utilizador: um APK com `CN=Android Debug` (amarelo) e 40 deteções no VirusTotal aparece como "chave de teste", amarelo. "Instalar mesmo assim" instala-o.
- Causa: `K/SecurityShield.kt:324` devolve logo os motivos offline. O teste `T/SecurityShieldTest.kt:325-331` ("Also beats a malware hit") garante isso como se fosse desejado. A consulta online é feita na mesma (`K/ConnectionModel.kt:1334-1353`) e deitada fora.
- Correção: separar *achados* (código, assinatura, permissões) da *prova online*. O veredicto final é o pior dos dois: qualquer `MalwareDetected` é vermelho, qualquer vermelho offline é vermelho, e os amarelos somam-se. A oferta de envio ao VirusTotal deve existir mesmo com amarelos offline.
- Teste: `offlineYellowPlusVtFlaggedIsRed` (offline `[DebugOrTestCertificate]` + `Found(40,0,70)` → `Warning[MalwareDetected]`, tier Red). Inverter a asserção da linha 330 (só vale quando o offline é vermelho).

**F2 — ALTA. "Sem análise do VirusTotal" quando houve análise.**
- Utilizador: vê "sem análise" com chaves e Proteção Máxima ativas. Desconfia do Escudo.
- Causa: F1 + `K/HomeScreen.kt:956-966`. O texto confunde "não consultado" com "total = 0". Também `cautionVtNote` mostra, para `Clean` de atualização confiável sem consulta (`vtSummary == null`), o mesmo "Sem análise" (`:963-966`).
- Correção: o veredicto transporta *evidência por fonte* (VirusTotal: Found/Unknown/Unavailable/NãoConsultado, MetaDefender: idem). O texto diz exatamente o que aconteceu.
- Teste: UI/unitário de `cautionVtNote` (extrair a função para texto puro) para os 6 estados.

**F3 — ALTA. A regra DexClassLoader é demasiado larga e o texto mente.**
- Utilizador: apps limpas com a biblioteca certa aparecem como "mod / código dinâmico, pode carregar código da Internet".
- Causa: `K/StaticAnalyzer.kt:132-144`. Basta uma string que *contenha* `dalvik.system.DexClassLoader`, seja igual a `DexClassLoader` ou contenha `Ldalvik/system/DexClassLoader;`. Num DEX real, a tabela de strings contém o descritor do tipo sempre que **qualquer classe** o referencia (construir, converter, declarar, `instanceof`), incluindo bibliotecas (ver secção 4.1). Nada confirma que há `new DexClassLoader`, que há `INTERNET`, nem que o ficheiro carregado vem de fora. A frase `caution_dropper_risk` (`R/values-pt-rPT/strings.xml:197`) afirma "carregar da Internet".
- Correção: ver secção 4.1 (sinais melhores, texto honesto, rebaixar a "informativo" quando só bibliotecas conhecidas).
- Teste: fixtures sintéticos com o descritor numa classe `androidx.multidex.*` (não deve gerar cartão) e numa classe da própria app com `INTERNET` + payload em `assets/` (deve gerar amarelo).

**F4 — ALTA. Sem rede ou quota = vermelho sem saída; sem chave = amarelo.**
- Utilizador: o telemóvel está ligado só ao Wi-Fi do aparelho de destino (sem Internet), ou o VirusTotal devolve 429 (limite diário de 500, `R/values-pt-rPT/strings.xml:286`), ou a chave foi rejeitada. Resultado: "VirusTotal inacessível", **bloqueado**, sem botão. A mesma app sem chave seria amarela e instalável.
- Causa: `K/SecurityShield.kt:335-340` (`!hasKey` → amarelo; `unreachable` → `VirusTotalUnreachable` = vermelho, `:185-193`). Teste que o fixa: `T/SecurityShieldTest.kt:360-371`. Texto também engana: 429 e chave inválida dizem "não foi possível contactar" (`R/values-pt-rPT/strings.xml:119`).
- Correção: `Unavailable`, `RateLimited` e `InvalidKey` passam a amarelo com texto próprio ("não foi possível verificar online agora / quota esgotada / chave rejeitada"). Vermelho fica para provas negativas.
- Teste: reescrever `ruleEUnreachableRateLimitedOrRejectedKeyBlocks` para exigir tier Yellow e uma razão por causa.

**F5 — ALTA/MÉDIA. VirusTotal falhou + MetaDefender "não conhece" vira "desconhecido".**
- Utilizador: com o VirusTotal em 429 e o MetaDefender em 404, o Escudo trata o ficheiro como "desconhecido" (amarelo, com pergunta de envio ao VirusTotal), em vez de "não foi possível verificar". O texto "Nenhum motor online conhece este ficheiro" é falso (o VirusTotal nem respondeu). Se recusar o envio, fica `NotKnownToVirusTotal` amarelo.
- Causa: `combineLookups` dá prioridade a `UnknownHash` sobre as falhas (`K/Reputation.kt:191-196`; teste `T/Shield0928Test.kt:341` fixa-o). Com chave VT inválida e MD 404 pede-se envio com uma chave que sabemos estar rejeitada (`K/ConnectionModel.kt:1358-1359`).
- Correção: só é "desconhecido" quando **todas as fontes consultadas** responderam "desconhecido". Se alguma falhou, é "verificação incompleta".
- Teste: `[RateLimited, UnknownHash]` → resultado "incompleto".

**F6 — ALTA (política). 1 deteção em 70 motores = vermelho definitivo.**
- Utilizador: um mod sem anúncios com 1/68 ("Riskware", "AdWare", de um motor obscuro) é bloqueado sem escolha. O mesmo acontece a algumas apps limpas com falso positivo de um único motor.
- Causa: `K/SecurityShield.kt:327-331` (`malicious > 0 || suspicious > 0`); MetaDefender: `maxOf(detected, 1)` (`K/Reputation.kt:133`). `suspicious` pesa o mesmo que `malicious`. Teste que fixa 1 deteção: `T/SecurityShieldTest.kt:336,338`.
- Correção (proposta, decisão do dono): vermelho se `malicious ≥ 5` ou ≥ 10 % dos motores, ou qualquer deteção com nome de família grave (Trojan, Spy, Banker, Dropper, SMS) vinda de motores de topo; 1–4 deteções fracas (Riskware/Adware/PUA) → amarelo a mostrar quantas e quais. Exige ler `last_analysis_results` (hoje só se lê `last_analysis_stats`, `K/SecurityShield.kt:1193`).
- Teste: tabela de limites (0, 1, 4, 5, 8 deteções sobre 70).

**F8 — ALTA. Consentimento informado incompleto no cartão amarelo.**
- Utilizador: com `[SelfUpdater, Dropper, DebugOrTest]` só vê um motivo e uma frase. O "Instalar mesmo assim" cobre todos os outros sem os mostrar. O título é sempre "Atenção: mod / código dinâmico", mesmo para "sem chave" ou "não conhecido".
- Causa: `K/ConnectionModel.kt:1551` (`reasons.first()`), `R/values-pt-rPT/strings.xml:194` (título fixo), `K/HomeScreen.kt:884-897` (um só texto), `:951` (`else` devolve o texto de dropper para qualquer razão nova).
- Correção: listar **todos** os motivos amarelos, cada um com o seu texto e o seu "o que isto significa"; título neutro ("Atenção antes de instalar"); sem `else` que reutilize texto de dropper.
- Teste: motivos `[SelfUpdater, DebugOrTest]` → o cartão mostra os dois.

**F9 — ALTA. Texto técnico em inglês no ecrã traduzido.**
- Utilizador (pt-PT) lê: "Dynamic class loader (DexClassLoader) found in classes2.dex", "REQUEST_INSTALL_PACKAGES requested by non-store application (com.octave.app)", "Signed with test/mod certificate (…)", "File hash is not known to the online antivirus engines", "libx.so contains the marker "frida-agent"".
- Causa: strings literais em `K/ConnectionModel.kt:1554-1563` e `K/StaticAnalyzer.kt:135,139,150,164,194,199,210,218,235,292,311`, `K/CodeInspection.kt:107,113,117,123,126`; o cartão mostra `prompt.detail` tal e qual (`K/HomeScreen.kt:886`). Os testes de traduções (`T/TranslationsTest.kt`) só vigiam `strings.xml`, não estes literais.
- Correção: `StaticAnalysisIssue` passa a levar um código + parâmetros (não texto); a interface formata em 5 idiomas. O inglês fica só no registo do terminal.
- Teste: nenhuma string de `prompt.detail` existe fora de `strings.xml` (teste de varrimento dos literais) e um teste por motivo × idioma.

**F14 — ALTA. "Chave de teste/mod" dispara em apps de programadores independentes.**
- Utilizador: apps normais, autoassinadas, aparecem como "assinadas com certificado público de teste ou de mod (APK não fidedigno / modificado)".
- Causa: `K/SecurityShield.kt:88-102` inclui `CN=Unknown`, `CN=Test`, `OU=Android`, `O=Android`, `CN=Android`. `CN=Unknown, OU=Unknown, O=Unknown…` é o que o `keytool` preenche quando se carrega Enter em tudo, e é frequente em apps pequenas e legítimas. `OU=Android` aparece em equipas "Android" de empresas. O teste junta Subject **e Issuer**, em dois formatos (`:644-653`). A pesquisa é por substring com limite só à direita (`:616-626`), por isso `O=Android Studio Labs` também bate. Não há nenhum teste de falso positivo (secção 7).
- Correção: manter só o que identifica *chaves públicas conhecidas*: o SHA-256 das chaves AOSP e do certificado de debug, mais o DN completo exato do certificado de debug (`CN=Android Debug, O=Android, C=US`). O resto (nomes de ferramentas de mod: MT Manager, Lucky Patcher, APKTool) fica como amarelo com texto "assinado por ferramenta de modificação". `CN=Unknown`/`CN=Test` fora.
- Teste: certificado sintético `CN=Unknown,OU=Unknown,O=Unknown` → não amarelo. Certificado debug real → amarelo.

**F18 — ALTA (falso negativo). Cobertura de payload escondido é estreita.**
- Utilizador: um dropper com o payload cifrado em `assets/data.bin`, em `res/drawable/x.png`, em `lib/…/libx.so` (ELF válido com payload dentro), na raiz do APK (`a.dat`) ou em `kotlin/…` passa.
- Causa: só `assets/` e `res/raw/` são examinados (`K/StaticAnalyzer.kt:418-421`, `:360-368`). Dentro destes só se vê: extensão `.dex/.apk/.jar`, o primeiro KiB com `dex\n`, ou ZIP com `classes*.dex`/`.so` (`:179-242`). Sem teste de entropia. ZIP aninhado maior que 64 MiB é cortado (`:254-268`), o `ZipFile` falha no fim truncado, o `catch` devolve `null` (`:268-269`) e o ficheiro sai limpo. Basta acrescentar enchimento.
- Correção: ver 4.1 (pontuação de payload; entropia alta + nome genérico em qualquer pasta; aninhado grande → amarelo "não foi possível inspecionar", nunca limpo).
- Teste: fixtures `assets/data.bin` com 4 KiB de bytes aleatórios; ZIP aninhado de 65 MiB (gerado em memória/sparse) → "não inspecionável".

**F19 — ALTA (fail-open). O deep scan engole qualquer erro e diz "limpo".**
- Utilizador: se o ZIP tiver uma entrada corrompida a meio, ou faltar memória num DEX grande, o scan pára e o registo mostra `deep scan: clean (0 dropper/adware signatures, N DEX files inspected)`.
- Causa: `catch (_: Throwable) {}` sem registo (`K/StaticAnalyzer.kt:371`). A mensagem (`K/ConnectionModel.kt:1293`) usa `dexCount`, que conta DEX *encontrados*, não *analisados com sucesso*. `parseDexStrings` devolve `emptySet()` para qualquer cabeçalho estranho (`K/StaticAnalyzer.kt:67-82`) e conta como inspecionado. O teste `corruptOrTruncatedDexDoesNotCrash` (`T/StaticAnalyzerTest.kt:370`) valida só "não rebenta", não "avisa".
- Correção: o resultado ganha `incomplete: List<motivo>`. Qualquer DEX ilegível, truncado, ou erro no ZIP → `ScanIncomplete` (amarelo) e o registo diz "análise incompleta".
- Teste: APK com `classes.dex` truncado → `ScanIncomplete`, não "clean".

**F26 — ALTA (decisão do dono; não verificado em aparelho). O GoGo desliga o Play Protect no aparelho de destino, para sempre.**
- Utilizador: depois de qualquer instalação (com o Escudo ligado **ou desligado**) as definições globais `verifier_verify_adb_installs=0` e `package_verifier_user_consent=-1` ficam gravadas e nunca são repostas.
- Causa: `K/PackageBundle.kt:675-676,743-745`; `K/ConnectionModel.kt:1714-1715`. Não existe nenhum comando de restauro (procurado: nenhuma ocorrência de `put global … 1`). O segundo comando é global, não só para ADB. **Não verifiquei** o efeito exato em cada versão do Android. Mas o comentário no código ("Keep Google Play Protect out of ADB installs") mostra a intenção.
- Correção: repor o valor anterior no fim (ler antes, gravar depois), ou só tocar na definição específica de ADB, e dizê-lo nas "Informações".
- Teste: fake `AdbClient` que regista os comandos: um `get` antes e um `put` com o valor original depois.

### Médias

**F7 — MÉDIA. A idade da análise nunca conta.** `K/SecurityShield.kt:1201-1210` ("shown, never used to decide"). Um ficheiro analisado há 4 anos com 0/58 é Verde. Malware novo que na altura ninguém detetava mantém-se limpo até o VirusTotal reanalisar. Correção: se `last_analysis_date` tiver mais de N dias (proposta: 30), pedir reanálise (`POST /files/{id}/analyse`) ou rebaixar a amarelo "análise antiga". Teste: `Found` com data de há 2 anos.

**F10 — MÉDIA. Em pacotes, o relatório e o hash mostrado são os do contentor.** `K/ConnectionModel.kt:1219` calcula `sha256Hex(sourceFile)`. Para APKM/XAPK/APKS esse é o ZIP completo; o VirusTotal foi perguntado pelos hashes de cada APK (`:1318-1356`). O botão "Abrir relatório" abre `…/gui/file/<hash do contentor>` (`K/HomeScreen.kt:1121,1158`), que o VirusTotal normalmente não conhece. Correção: o veredicto guarda a lista (nome, tamanho, SHA-256, fonte, resultado) por APK; o botão abre um APK (ou escolhe). Teste: veredicto de bundle → `reportLinks` com um link por APK consultado.

**F11 — MÉDIA. MetaDefender é invisível.** Ver secção 5.

**F12 — MÉDIA. A cor mostrada não é a decisão real.**
- Amarelo recusado pelo utilizador volta como caixa vermelha "instalação bloqueada" (`K/HomeScreen.kt:1029-1043`: `statusColor = if (isAuth) accent else error`, sem olhar para o *tier*).
- Num pacote (APKM/XAPK/APKS), depois de "instalar mesmo assim", `userAuthorized` **nunca é posto a verdadeiro** (só no ramo do APK único, `K/ConnectionModel.kt:1690`, não no do pacote, `:1775`). Na instalação bem-sucedida continua a aparecer "bloqueada" a vermelho.
- Correção: cor derivada do tier + decisão (`Amarelo-recusado`, `Amarelo-autorizado`, `Vermelho`). Teste: unitário da função que decide cor/texto.

**F15 — MÉDIA/ALTA. `AbusivePermissions` é vermelho sem saída e dispara em apps legítimas.**
- `REQUEST_INSTALL_PACKAGES` + `SYSTEM_ALERT_WINDOW`, ou + qualquer SMS num pacote cujo nome não tem "sms/mms/messaging" (`K/StaticAnalyzer.kt:289-306`). Exemplos **prováveis** (**não verificado**, depende da versão): clientes de mensagens com atualização própria e SMS (Telegram, Truecaller…), lançadores/gestores de ficheiros de TV com sobreposição e instalação. Para um dono que usa TVs e box com apps "side-loaded", é exatamente o público.
- A deteção da permissão é por substring em todo o manifesto binário (`K/SecurityShield.kt:877-883,891-902`), por isso `com.x.permission.READ_SMS` ou um `android:permission="…SEND_SMS"` de proteção de um serviço próprio contam como "pedida". O Octave mostra a contagem inflacionada: a lista decodificada inclui `BIND_JOB_SERVICE` e `BIND_QUICK_SETTINGS_TILE`, que são guardas de serviços, não pedidos (2.1).
- Correção: ler os elementos `<uses-permission>` do AXML (não a tabela de strings). Rebaixar a amarelo a combinação com SMS; manter vermelho só `INSTALL + OVERLAY + ACESSIBILIDADE` ou `SMS + OVERLAY`. Teste: manifesto com `android:permission="…SEND_SMS"` num serviço → não conta.

**F16 — MÉDIA. Lista de adware.**
- Lista de 14 prefixos de redes dos anos 2012-2016 (`K/StaticAnalyzer.kt:28-43`), mais StartApp (rede de anúncios convencional ainda usada) e `com.secneo` (isto é um *packer*, não adware). Vermelho sem saída.
- A correspondência é `startsWith(prefix)` **sem limite de ponto** (`:423-430`). `com.waps` apanha `com.wapsomething`; `com.youmi` apanha `com.youmixyz`.
- Aplica-se a *qualquer string* do DEX (`:130-153`), não só a tipos: um bloqueador de anúncios ou uma app tipo Exodus Privacy, que *lista* nomes de pacotes de trackers como texto, dá "adware agressivo".
- Falso negativo: adware moderno usa nomes ofuscados; a lista não ajuda.
- Correção: só tipos (`L…;`), com fronteira de ponto; StartApp e semelhantes passam a "rastreadores" (informativo, `K/CodeInspection.kt:13-48`). Vermelho só para famílias com comportamento provado. Teste: `com.wapsomething` não casa; string solta num ficheiro de lista não casa.

**F17 — MÉDIA (falso positivo). `"index\n"` conta como DEX.** A assinatura embebida é `64 65 78 0A` = `dex\n` em qualquer posição dos primeiros 1024 bytes (`K/StaticAnalyzer.kt:21,216-221`). Qualquer ficheiro de texto em `assets/` ou `res/raw/` com uma linha que acabe em `…dex` (`index`, `Yandex`, `codex`, `Rolodex`) dispara "Embedded DEX payload" (amarelo). Prova por raciocínio (a sequência é `i-n-d-e-x-\n`). Correção: exigir o cabeçalho completo (`dex\n0\d\d\0`) e só no início, ou a estrutura mínima do cabeçalho. Teste: asset `home\nindex\n…`.

**F20 — BAIXA/MÉDIA (falso negativo). Limites do parser DEX.** Só as primeiras 100 000 strings (`K/StaticAnalyzer.kt:14,81`) e 32 MiB por DEX (`:13,348`). A tabela está ordenada por conteúdo, por isso o que fica de fora são as últimas (nomes em minúsculas). Um DEX grande com muito código pode perder strings. Além disso, um `dataOff` fora do ficheiro cortado é ignorado em silêncio (`:88`). Correção: ler tudo (com limite de memória razoável) e marcar *incompleto* se cortar (ver F19).

**F21 — MÉDIA (falso positivo). `PathClassLoader` + caminho no mesmo DEX.** `K/StaticAnalyzer.kt:142-144,156-166`: basta um DEX de 10 MB conter, em lugares diferentes, o tipo `PathClassLoader` e *qualquer* string com `/storage/`, `/sdcard/`, `/code_cache/`, `app_dex`. Uma app de ficheiros ou o MultiDex já cumprem isto. Teste: DEX com `PathClassLoader` + `/storage/emulated/0/Download` não deve dar dropper.

**F22 — MÉDIA. Código nativo.**
- `InvalidNativeLibrary` é vermelho sem saída (`K/CodeInspection.kt:104-119`): ficheiros `.so` vazios ou de enchimento (usados para forçar instalação 64-bit; **não verificado**) dão "não é um ficheiro ELF" (`size < 20`). Mod que reaproveita bibliotecas arm64 na pasta `armeabi-v7a` fica bloqueada. Rebaixar a amarelo, pelo menos quando só uma pasta de ABI tem o erro.
- Marcadores `frida-agent`, `frida-gadget`, `lspatch`, `XposedBridge` (`:85`) aparecem em bibliotecas de **proteção anti-adulteração** (bancos, jogos), que *procuram* essas palavras. Amarelo com texto "comum em mods e apps protegidas" é aceitável (`R/values-pt-rPT/strings.xml`, `caution_suspicious_native_risk`), mas o título do cartão continua a dizer "mod / código dinâmico" (F8).
- Limite de 16 MiB por biblioteca (`K/StaticAnalyzer.kt:19,353`): marcadores depois dos 16 MiB passam (Unity `libil2cpp` costuma ser maior).

**F23 — MÉDIA. APK com `.apk` lá dentro é rejeitado como "não é uma app".** `K/PackageBundle.kt:203-205,226-228`: se existir `AndroidManifest.xml` na raiz **e** qualquer entrada `*.apk` (por exemplo `assets/stub.apk`), devolve `Invalid(reason_parse)` ("Não foi possível ler este ficheiro como uma app"). Atinge instaladores e ferramentas que levam um APK de apoio (exemplo provável: Magisk, **não verificado**). `looksInstallable` faz igual (`K/IncomingFile.kt:36-40`). Correção: um manifesto na raiz = APK único, e as entradas `.apk` internas são tratadas como dados (analisadas, mas não instaladas). Teste: APK com `assets/x.apk`.

**F24 — MÉDIA/ALTA. Deteção de versão mais antiga e troca de assinatura dependem de um texto que ninguém viu.**
- O instalador usa `-r -d` sempre (`K/AdbLogic.kt:267`, `K/PackageBundle.kt:679`): o `pm` **aceita** versões antigas. A única defesa contra "downgrade para uma versão vulnerável" é `VersionDowngrade`, que precisa de `versionCode` instalado vindo de `dumpsys package`.
- A assinatura instalada vem de uma regex `sha-256|cert-sha256 [:=] <64 hex>` (`K/SecurityShield.kt:109`). O único exemplo no repositório é um texto inventado `cert-sha256=…` (`T/SecurityShieldTest.kt:491-503`). Não encontrei no disco nenhuma saída real de `dumpsys package` (procurei `PackageSignatures`). Pelo que conheço, `dumpsys package` imprime `signatures=PackageSignatures{… signatures:[2b4c4b0b] …}` (hash curto, não SHA-256), mas **não verificado**. Se for assim, em aparelhos remotos (TV, box, o uso principal) `sigSha256` é sempre `null`, logo `SignatureMismatch` e "atualização confiável" nunca ativam; só no telemóvel local há o recurso ao `PackageManager` (`:1088-1105`).
- Se a consulta ao aparelho falhar (`runCatching … getOrDefault("")`, `:1080`; `catch … null`, `K/ConnectionModel.kt:1204-1206`) a defesa de downgrade desliga-se em silêncio (fail-open).
- Correção: obter versão e certificado de forma robusta (`cmd package dump`/`pm list packages --show-versioncode` e `dumpsys package` com a verificação do formato real), e quando a consulta falhar mostrar "não foi possível comparar com a versão instalada" (amarelo) em vez de continuar como se nada. Teste: saída real de `dumpsys` de uma versão de Android (fornecida pelo dono).

**F25 — MÉDIA (decisão do dono). "Atualização confiável" é Verde sem consulta online.** `K/SecurityShield.kt:333`: mesma assinatura + versão ≥ + zero achados → `Clean` mesmo **sem chave** e mesmo com tudo inacessível. Isto contradiz a regra escrita "sem chave nunca é Verde (máx. Amarelo)", embora esteja explicado ao utilizador (`how_t4_body`). Duas consequências: (a) um mod instalado, quando se atualiza com a mesma chave do modder, passa sempre; (b) uma app instalada que peça `REQUEST_INSTALL_PACKAGES` (como o Octave) tem sempre achados offline, logo **nunca** é "atualização confiável" e volta ao amarelo em cada atualização. Decidir: manter com texto claro, ou exigir pelo menos "não sinalizado" quando houver prova online.

**F27 — MÉDIA. Chaves de API.**
- A chave só é testada na primeira consulta; uma chave errada fica "Ativa ••••" e a Home mostra "Proteção Máxima" a verde (`K/MainActivity.kt:198-200`), mas todas as consultas dão `InvalidKey` → vermelho sem saída (F4).
- Se a decifração falhar uma vez (`K/SecurityShield.kt:1331-1333`) a chave é **apagada** sem avisar. Uma falha transitória do Keystore (arranque, ecrã bloqueado) custa a chave. Depois a app diz "sem chave" na próxima instalação.
- Guardar uma chave volta a ligar o Escudo sem perguntar (`K/InfoScreens.kt:280,290`).
- Correção: validar a chave ao guardar (chamada de teste), e só apagar em erro definitivo (`KeyPermanentlyInvalidatedException`), nunca em erro genérico.

**F28 — MÉDIA. "Proteção Máxima" ignora o deep scan.** `K/MainActivity.kt:198-200` = Escudo ligado **e** alguma chave. A "Análise profunda" (`K/SettingsScreen.kt:172-183`) pode estar desligada, o que apaga as regras de dropper, adware, permissões abusivas e bibliotecas nativas (`K/ConnectionModel.kt:1271-1298`). Fica Verde com "Máxima" sem estas regras, incluindo as que são vermelhas. Correção: "Máxima" só com deep scan ligado; senão "Parcial", com o motivo.

**F32 — MÉDIA. `SelfUpdaterPermission` amarelo para quase todas as apps com atualizador próprio.** `K/StaticAnalyzer.kt:308-314`. Octave, navegadores, mensageiros, gestores de ficheiros… O dono vê um cartão de aviso por causa de uma permissão corrente. Correção: informação (linha no resultado), amarelo só em combinação com outro achado grave. A exceção "loja" é por *nome* do pacote (`:439-445`): `com.evil.store` passa, `com.minhaapp.installer` passa.

**F35 — BAIXA/MÉDIA. Janela de manipulação do ficheiro.** O `filesUnchangedSinceScan` recalcula o hash antes de enviar (`K/SecurityShield.kt:1402-1405`, `K/ConnectionModel.kt:1699-1704`), mas depois reabre o ficheiro (`:1716`). Os ficheiros ficam em `externalCacheDir` (`:1633`), legível/escrevível por outras apps em Android ≤ 10 (**não verificado** no aparelho do dono). Nova tentativa por "test-only" no pacote **não volta a verificar** (`:1819-1831`). Janela pequena, mas é o ponto onde o Escudo diz "o ficheiro verificado é o que instala". Correção: copiar para `filesDir`/`cacheDir` (interno) e instalar daí; reverificar em cada tentativa.

### Baixas

**F13** — O bloqueio vermelho mostra o texto do **primeiro** motivo, não do mais grave: com `[SelfUpdater, AdwareDetected]` o título é "Esta app pode instalar outras apps" (`K/ConnectionModel.kt:1505`). Ordenar por gravidade.

**F29** — A animação de 4 s no botão de proteção não faz nada (o valor só muda no fim, `K/HomeScreen.kt:424-438`). O texto "A sincronizar heurísticas…", "A descarregar assinaturas dos motores na cloud…" (`R/values-pt-rPT/strings.xml:255-264`) descreve ações que não existem. As etapas (`protection_activating_step1…3`) nem são usadas em código (só `protection_activating`/`protection_deactivating`, `K/HomeScreen.kt:405-406`). Contraria "nenhum interruptor sem efeito real". Remover os textos e a espera.

**F30** — `TooLargeToVerify` existe com texto e cor vermelha, mas nada o produz (um ficheiro grande vira `NotKnownToVirusTotal`, `K/SecurityShield.kt:345`). O comentário da função `severity()` (`:175-184`) também está desatualizado (lista `AdwareDetected` etc. certo, mas não menciona `SelfUpdaterPermission`/`SuspiciousNativeCode`). Remover ou usar.

**F31** — "Reverter" instala os APK guardados sem passar pelo Escudo nem verificar hash (`K/ConnectionModel.kt:429-458`; `K/BackupManager.kt` não guarda SHA-256). Quem alterar a pasta `filesDir/backups` pode trocar o APK. Baixo risco (pasta privada), mas é um caminho de instalação sem Escudo. Guardar o hash no momento do backup e reverificá-lo.

**F33** — Em `queryArchiveAppInfo` usa-se `signingCertificateHistory.firstOrNull()` como "o assinante" (`K/SecurityShield.kt:1125-1127`, e `:1099-1100`). Para apps com rotação de chave, o histórico começa no certificado mais antigo; a ordem exata é **não verificada**. Afeta o amarelo "chave de teste" quando a chave antiga era de teste e a atual não.

**F34** — A contagem "Permissões pedidas: N" inclui guardas `android:permission` (ver F15).

**F36** — Limite de 4 pedidos/minuto só na janela curta (`K/VirusTotal.kt:42-57`); não há controlo de 500/dia. Um pacote com 20 APK com código leva ≥ 5 min só em esperas, sem aviso. Sugestão: consultar só o APK base primeiro.

**F37** — Splits "só de recursos" não vão ao VirusTotal (`K/ApkHardening.kt:143-144`) e os `.obb` não são analisados (`K/ConnectionModel.kt:1305`). Um split sem DEX mas com payload em `assets/` é visto pela análise local (se estiver ligada), nunca online. Aceitável, mas deve constar no texto.

**F38** — `issueDetail` do vermelho `MalformedArchive` é sobrescrito pelo primeiro achado do deep scan (`K/ConnectionModel.kt:1290-1291`).

**F39** — A cache não guarda a **fonte** do veredicto (VT ou MD) nem a data da análise (`K/Reputation.kt:35,52`). Depois de um acerto na cache, o registo diz "analysis date unknown" e o texto diz VirusTotal mesmo que tenha vindo do MetaDefender. Mudar ou apagar a chave não limpa a cache (só é consultada quando há chave, `K/ConnectionModel.kt:1333`, mas um veredicto antigo vale 48 h depois de trocar de chave). Envenenamento: a pasta `filesDir` é privada; sem prova de adulteração externa (**não verificado** em aparelho com root).

**F40** — `MinVtEngines = 20` aplica-se também ao MetaDefender (`K/SecurityShield.kt:41,341`). Quantos `total_avs` devolve o MetaDefender para um APK é **não verificado**: se for menos de 20, todos os veredictos "limpo" do MetaDefender dariam `TooFewEngines` vermelho.

---

## 4. Regra a regra

### 4.1 Regra do DexClassLoader / InMemoryDexClassLoader / PathClassLoader

**O que o código faz** (`K/StaticAnalyzer.kt:125-169`): percorre todas as strings do DEX. `DexClassLoader` ou `InMemoryDexClassLoader`: se a string contém o nome qualificado, ou é igual ao nome curto, ou contém o descritor `L…;`, é `DropperDetected`. `PathClassLoader`: só conta se no mesmo DEX houver também uma string com um "caminho dinâmico" (`:432-437`).

**Por que isto dá falsos positivos**
- Num DEX, cada tipo referenciado por *qualquer* classe entra na tabela de strings. A string não diz *quem* o usa nem *como*.
- Bibliotecas de terceiros que referenciam estes tipos, **por mecanismo** (não testei APKs reais destas, tudo **não verificado**): carregamento dinâmico de módulos (Play Core/SplitCompat, Play Services Dynamite), MultiDex, Huawei HMS, motores de hot-patch (Tinker, Sophix), WebView/Chromium embebido, Flutter com componentes diferidos, React Native/SoLoader. Quase todas as grandes plataformas têm alguma forma de carregar código ou bibliotecas em execução. Ver a tabela de exemplos abaixo.
- `PathClassLoader` + um caminho `/storage/…` no mesmo DEX (F21) é uma coincidência trivial, não prova.
- Os testes sintéticos usam `"dalvik.system.DexClassLoader"` como string simples (`T/StaticAnalyzerTest.kt:118`), que **não é** como um DEX real guarda o tipo (`Ldalvik/system/DexClassLoader;`). Nenhum teste usa o descritor, nem a presença da string em código de biblioteca.

**Falsos negativos**
- Strings ofuscadas ou montadas (`"dalvik.system." + "DexClassLoader"`; descodificadas em tempo de execução).
- Outras vias que nunca nomeiam estes tipos: `BaseDexClassLoader`, `DelegateLastClassLoader`, `DexFile.loadDex`, `dlopen` de `.so` descarregado, `defineClass`, JavaScript remoto num `WebView`.
- Droppers reais escondem o payload cifrado numa pasta qualquer (F18), descarregam-no depois, escrevem-no em `files/` e carregam-no (a partir do Android 14, para `targetSdk ≥ 34`, o DEX tem de ser só de leitura; os droppers adaptam-se a isso). Nada disto é visto.

**Melhor modelo (proposta)**: pontuação em vez de gatilho único.

| Sinal | Peso | Como medir |
|---|---|---|
| Payload candidato fora da pasta de código: ficheiro com entropia alta (> 7,5 bits/byte) e nome genérico (`*.bin`, `*.dat`, sem extensão) em `assets/`, `res/raw/`, raiz | forte | entropia dos primeiros 4 KiB; qualquer pasta |
| Cabeçalho DEX/ZIP/ELF válido onde não devia (assets, `res/*`, raiz) | forte | `dex\n0\d\d\0` completo no início |
| O **construtor** do loader é chamado por uma classe **da própria app** (não de um pacote de biblioteca conhecido) | médio | tabela `method_ids` do DEX: entrada `Ldalvik/system/DexClassLoader;-><init>`; opcional: analisar `invoke-direct` |
| `INTERNET` + o loader + escrita em ficheiro no mesmo componente | médio | manifesto + classe |
| `REQUEST_INSTALL_PACKAGES` + loader + `INTERNET` | médio | manifesto |
| Só o *tipo* referenciado, em pacotes de biblioteca conhecidos (`androidx.multidex`, `com.google.android.play.core`, `com.google.android.gms`, `org.chromium`, `com.huawei.hms`, `com.tencent.tinker`) | **fraco → informativo** | prefixos |

Decisão: ≥ 1 sinal forte → amarelo "código escondido"; 1 médio + loader próprio → amarelo; só fraco → linha informativa no resultado (sem cartão). Texto: "Esta app contém código que pode carregar mais código depois de instalada" (nunca "da Internet" sem `INTERNET`).

**Exemplos pedidos** (com o que sei e o que não):

| Biblioteca / caso | Dispara hoje? | Estado da prova |
|---|---|---|
| Octave (Compose + TensorFlow Lite + Room, DEX único) | **Não** | **Verificado** (porte do parser sobre o APK real, secção 2) |
| TensorFlow Lite (`libtensorflowlite_jni.so`, `.tflite` de 19,7 MB) | Não (ELF válido, sem marcadores; `.tflite` sem `dex\n` nos primeiros KiB) | **Verificado** neste APK |
| Google Play Services / Firebase / Crashlytics | Provavelmente só o tipo, em código de módulos dinâmicos | **Não verificado** (sem APK real) |
| Facebook SDK, ads SDKs, Unity, Flutter, React Native, WebView/Chromium | Depende da versão; todos usam carregamento dinâmico ou classes de biblioteca | **Não verificado**; testar com APKs reais antes de calibrar |

### 4.2 Assinatura

**Como é lida hoje**
- v1: ficheiros `META-INF/*.RSA|DSA|EC` (`K/SecurityShield.kt:600-607`).
- v2/v3/v3.1: o bloco `APK Sig Block 42` antes do diretório central (`:700-753`), com os certificados lidos de todos os signatários (`:776-809`). v4 (`.idsig`) é ignorado. O signatário v2/v3 ganha sobre v1 (`:592-595`).
- **O Escudo não verifica a validade da assinatura**, só extrai o certificado (diz-o no registo, `K/ConnectionModel.kt:1257`, e no comentário `:436`). Quem verifica é o `pm`. Na instalação a assinatura inválida falha. Mas o ecrã pode mostrar "assinado por X", "atualização confiável" ou "chave de teste" com base num certificado copiado de outro APK.
- Em Android local o `PackageManager` valida (`getPackageArchiveInfo`, `:1119-1148`), mas se falhar volta-se ao certificado extraído sem validação (`K/SecurityShield.kt:391,397`).
- Pacotes: cada split é lido; qualquer certificado de qualquer split com chave de teste marca o pacote (`:405-425`). **Não se exige que todos os splits tenham o mesmo assinante** (o `pm` rejeita-o, mas o Escudo diz "assinado" mesmo assim).

**Como a assinatura podia subir a confiança**
1. Continuidade de assinante com a app instalada (já existe, F24/F25).
2. Lista curada de impressões digitais de editores conhecidos (Google, Meta, Telegram, F-Droid…), para aceitar "é o original" sem consulta online. Exige manutenção e fonte citável (não a inventei).
3. Uma app com o mesmo nome de pacote e o mesmo certificado vista em muitos envios/anos no VirusTotal (não verificado se a API expõe isto de forma estável) dá "popularidade", que é um sinal.
4. "Original ≠ mod" não se decide só pelo certificado: um APK modificado e reassinado pelo modder tem um certificado *diferente* do original. Sem referência (instalada ou curada) o Escudo só sabe "assinado por alguém", como no Octave (`CN=Octave`).

### 4.3 Reputação online (VirusTotal / MetaDefender / cache)

Fluxo (`K/Reputation.kt:204-227`, `K/ConnectionModel.kt:1318-1356`):

1. Sem chaves → `online = false` → `res = Unavailable`.
2. Cache (48 h por SHA-256) → devolve e termina.
3. VirusTotal (`GET /api/v3/files/{sha256}`, `x-apikey`) com o `RequestPacer` de 4/min (`K/ConnectionModel.kt:1339`).
4. Se o VirusTotal **não** deu `Found` (sem chave, 404, 429, 401/403, erro de rede), consulta o MetaDefender (`GET /v4/hash/{sha256}`, cabeçalho `apikey`).
5. `combineLookups` (`K/Reputation.kt:187-197`): deteção ganha; senão o `Found` com mais motores; senão `UnknownHash`; `InvalidKey`; `RateLimited`; `Unavailable`.
6. `Found` guarda-se na cache (só contagens).

| Situação | Cor hoje | Observação |
|---|---|---|
| Sem chave, não é atualização confiável | Amarelo `VirusTotalKeyMissing` | OK com a regra |
| VT `Found` limpo ≥ 20 motores, sem achados | Verde | OK |
| VT `Found` com ≥ 1 deteção | Vermelho | F6 |
| VT 404 e MD 404 | Amarelo com pergunta de envio ao VirusTotal (só se houver chave VT) | OK, mas sem achados offline (F1) |
| VT 429 ou erro de rede, MD 404 | Amarelo "desconhecido" | F5 (devia ser "incompleto") |
| VT 429 ou erro de rede, sem MD | **Vermelho** | F4 |
| Timeout 10 s (`K/SecurityShield.kt:1216`) | `Unavailable` → **Vermelho** | F4 |
| Chave inválida | **Vermelho** "não foi possível contactar" | F4/F27 |
| Cache acertou | Usa o que está lá, 48 h | F7/F39 |

Pontos extra:
- Os pedidos HTTP não seguem redirecionamentos e a chave só vai para `virustotal.com`/`api.metadefender.com` (`K/VirusTotal.kt:170-176,201-209`; `K/Reputation.kt:143-148`). Bom.
- Respostas > 256 KiB são rejeitadas como `Unavailable` (`K/SecurityShield.kt:1040-1044`). Uma resposta legítima do VirusTotal com `last_analysis_results` completo pode passar de 256 KiB (**não verificado**); hoje só se lê `last_analysis_stats`, mas para F6 será preciso ler os resultados por motor.
- O VirusTotal só devolve 200 se *já viu* o ficheiro. Se o ficheiro foi carregado agora e a análise ainda corre, o fluxo de envio espera até 10 minutos (`K/VirusTotal.kt:31`) e termina em `VirusTotalUnreachable` vermelho se demorar (`K/ConnectionModel.kt:1465-1468`).

---

## 5. MetaDefender: quando atua hoje, o que devia fazer, relatório

**Quando atua hoje** — exatamente quando as quatro condições se juntam (`K/Reputation.kt:204-224`): há chave MetaDefender; não houve acerto na cache; o VirusTotal não devolveu `Found` (sem chave VT, 404, 429, 401/403, erro, resposta inválida); e o ficheiro é o APK base ou um split com código (`K/ApkHardening.kt:143`). **Nunca** corre quando o VirusTotal responde com veredicto, mesmo que seja com poucos motores.

**Parser** (`K/Reputation.kt:114-140`): lê `scan_results.scan_all_result_i`, `total_avs`, `total_detected_avs` e `file_info.sha256`. Códigos tratados como "limpo" `{0, 7}` e "marcado" `{1, 2, 4, 6, 8}` (`:25-26`). Pela documentação da OPSWAT de que me lembro (0 = sem ameaça, 1 = infetado, 2 = suspeito, 3 = falhou, 4 = limpo/eliminado, 5 = desconhecido, 6 = em quarentena, 7 = ignorado-limpo, 8 = ignorado-sujo, 9 = limite de arquivos excedido, 10 = não analisado), a leitura parece coerente. **Não verificado** contra a documentação atual: a lista nova tem códigos acima de 10 e o cenário "arquivo ao limite de profundidade" merece teste.

**Mostra-se o resultado do MetaDefender?** Em lado nenhum com o nome da fonte.
- No registo do terminal: "MetaDefender answered: Found" (`K/Reputation.kt:223`) e a linha de contagens sem fonte (`K/ConnectionModel.kt:1393-1402`).
- Na interface: o `Found` do MetaDefender é guardado como se fosse do VirusTotal. O Verde diz "nenhum motor o assinala (VirusTotal 0/38)" (`R/values-pt-rPT/strings.xml:106`, `K/HomeScreen.kt:994`, `:964`). Isso é falso quando o veredicto veio do MetaDefender.
- O botão "Abrir relatório do VirusTotal" abre sempre o VirusTotal (`K/HomeScreen.kt:1158`). Para um ficheiro que só o MetaDefender conhece, abre uma página "não encontrado".

**O que devia fazer**
1. Guardar *por fonte* e por APK: nome, SHA-256, tamanho, e para cada fonte (VT, MD) o estado (`Found(m,s,total,data)`, `Desconhecido`, `Indisponível`, `Quota`, `ChaveRejeitada`, `NãoConsultado`).
2. Consultar o MetaDefender também quando o VT responde mas com pouca fiabilidade (total < 20, análise antiga) ou com 1–4 deteções fracas (segunda opinião). Evita o problema "VT limpo mas desatualizado" (F7).
3. Regra de combinação: qualquer deteção grave → vermelho; ambas as fontes limpas e recentes → verde; só uma fonte limpa → verde se ≥ 20 motores e análise recente, senão amarelo; fontes divergentes → amarelo com as duas contagens.
4. Texto: "VirusTotal 0/70 · MetaDefender 0/38", ou "só o MetaDefender respondeu (0/38)".
5. Cache com `fonte` e `data da análise` (F39).

**Relatório / links**
- VirusTotal: `https://www.virustotal.com/gui/file/<sha256>` (`K/HomeScreen.kt:1158`) — formato correto, de que tenho conhecimento.
- MetaDefender (API): `GET https://api.metadefender.com/v4/hash/<sha256>` com cabeçalho `apikey` — é o que o código usa (`K/Reputation.kt:21,155,166`). A resposta de sucesso traz também `data_id`.
- MetaDefender (página web de resultados): **não consegui verificar** (a pesquisa web não foi autorizada nesta sessão). Pela memória: `https://metadefender.com/results/hash/<sha256>` e, com o `data_id` da resposta da API, `https://metadefender.com/results/file/<data_id>/regular/overview`. O domínio mudou várias vezes (`metadefender.opswat.com`). **Incerto — confirmar à mão antes de usar.** Sugestão: guardar o `data_id` e abrir `…/results/file/<data_id>/regular/overview`; se não existir, ocultar o botão em vez de abrir uma página errada.
- Limites do plano gratuito do MetaDefender: `api_md_limit` diz só "limite diário definido pela OPSWAT" (`R/values-pt-rPT/strings.xml:287`); valores reais **não verificados**.

---

## 6. Revisão regra a regra

### 6.1 Todos os `ShieldWarningReason` (`K/SecurityShield.kt:148-169`)

| Motivo | O que deteta / gatilho exato | Cor | Risco de falso positivo | Risco de falso negativo | Correção |
|---|---|---|---|---|---|
| `MalwareDetected` | `malicious>0` ou `suspicious>0` numa fonte (`:327-331`) | Vermelho | 1 motor sobre 70 em apps limpas e mods (F6) | Análise antiga (F7); malware novo ainda "limpo" | Limiar + nomes; reanálise |
| `UnsignedPackage` | sem v1 nem v2/v3, ou sem certificado legível (`:437,467`); qualquer exceção (`:430-434`) | Vermelho | Exceção ao ler um split v2-only legítimo → "sem assinatura" | Não valida a assinatura (só `pm`) | Validar ou dizer "não verificada aqui" na UI |
| `DebugOrTestCertificate` | hash da chave AOSP/SHA-1 de debug, ou DN com os tokens da lista (`:88-102,628-631,656`) | Amarelo | `CN=Unknown`, `OU=Android`, `O=Android`, `CN=Test` (F14) | Mod reassinado com chave própria | Só chaves/DN conhecidos |
| `SignatureMismatch` | assinante ≠ instalado e ≠ linhagem (`:452-456`) | Vermelho | Só se a leitura do instalado estiver errada (F24) | Aparelhos remotos sem SHA-256 (F24) | Leitura robusta |
| `VersionDowngrade` | `versionCode` < instalado (`:457-459`) | Vermelho | Reverter manualmente uma atualização má; o "Reverter" interno passa sem Escudo (F31) | Falha na consulta → desliga (F24) | Amarelo; consulta robusta |
| `VirusTotalKeyMissing` | nenhuma chave (VT ou MD), não é atualização confiável (`:335`) | Amarelo | — | — | OK |
| `NotKnownToVirusTotal` | hash desconhecido e (sem chave VT, ficheiro > 650 MB, ou envio recusado) (`:343-346`, `K/ConnectionModel.kt:1433`) | Amarelo | F5 (VT falhou) | — | Estado "incompleto" |
| `VirusTotalUnreachable` | VT e MD falharam, 429, 401/403, upload falhou (`:337-340`) | **Vermelho** | Offline, quota, chave rejeitada (F4) | — | Amarelo |
| `TooFewEngines` | `Found.total < 20` (`:341`) | Vermelho | MD pode devolver < 20 (F40); análise ainda a decorrer | — | Amarelo; ver F40 |
| `TooLargeToVerify` | **nunca produzido** | Vermelho | — | — | Remover (F30) |
| `PackageMismatch` | nome do pacote ilegível ou diferente entre base, splits e metadados (`K/PackageBundle.kt:123-128`) | Vermelho | Um XAPK com metadados de outra versão | — | OK, texto claro |
| `DropperDetected` | ver 4.1 e 6.2 | Amarelo | F3, F17, F21 | F18, F20 | Pontuação |
| `AdwareDetected` | prefixo de lista (F16) | **Vermelho** | rede de anúncios corrente; listas de trackers como texto | adware moderno | Amarelo/informativo |
| `AbusivePermissions` | INSTALL+OVERLAY, ou INSTALL+SMS fora de apps SMS (`K/StaticAnalyzer.kt:289-306`) | Vermelho | F15 | combinações sem `INSTALL` (SMS+OVERLAY+acessibilidade) | Ler elementos; combinações |
| `SelfUpdaterPermission` | só `REQUEST_INSTALL_PACKAGES`, nome sem "loja" (`:308-314`) | Amarelo | quase toda a app com atualizador (F32) | nomes com "store" | Informativo |
| `CompromisedKey` | SHA-256 de platform/shared/media AOSP (`K/SecurityShield.kt:79-86`) | Vermelho | Praticamente nenhum | Chaves OEM vazadas não incluídas (assumido no comentário `:75-77`) | Acrescentar com fonte citável |
| `LegacySignatureOnly` | só v1 + `minSdk ≥ 24` ou `targetSdk ≥ 30` (`K/ApkHardening.kt:32-33`) | Vermelho | Apps antigas de minSdk baixo e `targetSdk` baixo (corretamente não bloqueadas) | SDK desconhecido → não julga | OK |
| `MalformedArchive` | BadPack/Janus/tabelas incoerentes (`K/ApkHardening.kt:55-128`) | Vermelho | Pouco provável; ZIP64 é "não julgado" (`:82`) | ZIP64 passa | OK; ZIP64 → amarelo |
| `InvalidNativeLibrary` | `.so` que não é ELF/classe/máquina errada para a pasta (`K/CodeInspection.kt:104-119`) | Vermelho | `.so` de enchimento, ABI trocada (F22) | `.so` válido com payload dentro | Amarelo |
| `SuspiciousNativeCode` | marcador (`frida`, `lspatch`, `XposedBridge`) ou nome de packer (`:85,88,122-127`) | Amarelo | bibliotecas anti-tamper (F22) | outros packers | OK, texto |

### 6.2 Regras de deteção que não são um motivo isolado

| Regra | Gatilho | FP | FN |
|---|---|---|---|
| Asset com extensão `.dex/.apk/.jar` (`K/StaticAnalyzer.kt:192-203`) | extensão em `assets/` ou `res/raw/` | apps que levam um `.jar`/`.apk` de apoio (mas os `.apk` já falham antes, F23) | extensão trocada |
| Asset começa com `dex\n` (`:206-213`) | 4 bytes | raro | cabeçalho alterado/cifrado |
| `dex\n` nos primeiros 1024 bytes (`:216-221`) | substring | **`index\n`** (F17) | idem |
| `.lottie` ignorado (`:187-189`) | extensão | — | `.lottie` com `.so` dentro passa. **Corrigido**: há teste `lottieAnimationAssetDoesNotTriggerDropperDetected` (`T/StaticAnalyzerTest.kt:195`) |
| ZIP em assets com `classes*.dex` ou `.so` (`:225-239,245-273`) | ZIP aninhado ≤ 64 MiB | pacotes de recursos com `.so` | ZIP > 64 MiB, falha → limpo (F18) |
| `isDexEntry` (`:413-416`) | qualquer pasta + `classes\d*.dex` | — | — |
| Trackers (informativo) | prefixos (`K/CodeInspection.kt:13-48`) | nunca bloqueia | nunca bloqueia |

---

## 7. Lacunas de testes

Contagens por pesquisa nos ficheiros de teste (**feita por `grep`**): os testes cobrem o caminho feliz de quase tudo e quase nenhum caso adverso.

| Regra / função | Teste existente | Lacuna |
|---|---|---|
| `evaluateShieldVerdict` | `T/SecurityShieldTest.kt:325-413` (regras A–H) | O teste A **fixa o defeito** F1. Nenhum teste de offline amarelo + VT vermelho como vermelho. |
| `DropperDetected` (loaders) | `T/StaticAnalyzerTest.kt:117-148` | Só strings com ponto (`dalvik.system.X`). Nenhum descritor `L…;`; nenhum teste de FP com biblioteca; nenhum teste de ofuscação. |
| Payload em assets | `:152-262` | Nenhum de entropia/blob; nenhum `index\n`; nenhum ZIP aninhado > 64 MiB; nenhum APK truncado a meio. |
| `.lottie` | `:195-222` | Corrigido e testado. |
| Adware | `:265-296` | Só casos positivos. Nada sobre fronteira de ponto nem strings soltas. |
| Permissões abusivas | `:301-343` | Só nomes curtos (`REQUEST_INSTALL_PACKAGES`). Nenhum teste com manifesto binário real, nem com `android:permission=` de serviço. |
| `isAppStoreOrPackageManager` / `isSuspiciousDynamicPath` / `matchAdwareSdk` | indireto | Sem testes diretos. |
| `isDebugOrTestCertificateDn` | indireto (`T/SecurityShieldTest.kt:218-235`, só `CN=Android Debug`) | **Nenhum** teste de `CN=Unknown`, `CN=Test`, `OU=Android`, `O=Android`; nenhum de FP. |
| AXML (`extractManifestVersionCode`) | **nenhum direto** | sem teste do analisador binário. |
| `inspectApkSigningBlock` v3/v3.1, linhagem | `T/Shield0928Test.kt:233` (rotação); `T/ShieldHardeningTest.kt:152-238` | Sem v3.1 nem v4; sem assinaturas inválidas; sem splits de assinantes diferentes. |
| `queryArchiveAppInfo`, `queryInstalledAppInfo` | `parseDumpsys…` com texto inventado (`T/SecurityShieldTest.kt:491`) | Sem saída real de `dumpsys`. Sem teste de falha. |
| MetaDefender | `T/Shield0928Test.kt:310-395` | Sem teste da apresentação (fonte), sem a combinação `[Unavailable, Unknown]` → "incompleto", sem `total_avs < 20`. |
| Cache | `:346-365` | Sem teste de fonte/data; sem teste de mudar chave. |
| `verifyPackageWithShield` / `resolveCautionPrompt` / `cautionVtNote` | **nenhum** (funções privadas ou `@Composable`) | É aqui que está F2, F8, F9, F12. |
| Fail-open do deep scan | `T/StaticAnalyzerTest.kt:370` (só "não rebenta") | Nenhum "avisa que está incompleto". |
| Bundles | `T/PackageBundleTest.kt` (714 linhas) | Sem teste de `userAuthorized` em bundle; sem APK com `.apk` interior. |
| Traduções | `T/TranslationsTest.kt` | Não vê strings literais em inglês no código (F9). |

---

## 8. Plano de correção (uma única versão, proposta 0.9.50)

Ordem pensada para que cada passo seja testável e para que o seguinte não seja desfeito pelo anterior.

**Passo 1 — Motor de veredictos (F1, F2, F4, F5, F6, F7, F10, F11, F39, F40).**
- Novo `ShieldVerdict` com `evidence: List<ApkEvidence>` (nome, tamanho, SHA-256, `vt: SourceResult`, `md: SourceResult`) e `findings: List<Finding>` (código + parâmetros, sem texto). O texto vive na interface.
- `evaluateShieldVerdict`: calcula `online` e `findings` em separado; o tier final é o máximo. Offline amarelo + online vermelho = vermelho. Falhas online (`Unavailable`, `RateLimited`, `InvalidKey`) = amarelo próprio. A oferta de envio existe também com amarelos offline.
- `combineLookups`: "desconhecido" só se todas as fontes consultadas o disseram.
- Limiar de deteções (a decidir pelo dono, F6) e idade da análise (F7).
- Cache com fonte e data.

**Passo 2 — Regra do dropper e do deep scan (F3, F17, F18, F19, F20, F21).**
- Pontuação (4.1). `method_ids` para saber se o *construtor* é chamado; prefixos de biblioteca conhecidos → informativo.
- `dex\n0\d\d\0` completo no início; entropia em qualquer pasta.
- `ScanIncomplete` para qualquer erro, truncagem ou ZIP aninhado grande (nunca "limpo").
- Remover o limite silencioso de 100 000 strings ou marcar incompleto.

**Passo 3 — Regras de certificado, permissões e adware (F14, F15, F16, F22, F32).**
- Só tokens/hashes realmente públicos; `CN=Unknown` fora.
- Permissões lidas de `<uses-permission>`; SMS sozinho = amarelo.
- Adware por tipos com fronteira de ponto; redes correntes → informativo; `SelfUpdater` → informativo.
- `InvalidNativeLibrary` e `.so` vazios → amarelo.

**Passo 4 — Interface e textos (F8, F9, F12, F13, F28, F29, F30).**
- Cartão amarelo com todos os motivos, título neutro, texto 100 % traduzido em pt-PT, pt, es, fr, en e linha "Ficheiro: nome · SHA-256 curto · APK analisado".
- Cor derivada de (tier, decisão). `userAuthorized` também em pacotes.
- Fonte de cada veredicto e botões de relatório certos (VT por APK; MD só com URL confirmado).
- "Proteção Máxima" só com deep scan ligado. Remover animação/textos fantasma e o motivo morto.

**Passo 5 — Instalação e robustez (F23, F24, F26, F27, F31, F33, F35).**
- Manifesto na raiz = APK único. Consulta de versão/assinatura robusta com estado "não comparado".
- Repor as definições do Play Protect (ou não as tocar).
- Validar a chave ao guardar e nunca apagá-la por erro transitório.
- Copiar para armazenamento interno e reverificar em cada tentativa; hash nos backups.

**Passo 6 — Testes novos (os seguintes obrigam as correções acima).**

Fixtures sintéticos (construídos por código, como `buildTestDex`/`createTestApk` em `T/StaticAnalyzerTest.kt:15-95`):
- `dex-lib-multidex`: DEX com `Landroidx/multidex/MultiDex;` e `Ldalvik/system/BaseDexClassLoader;` → sem cartão.
- `dex-own-loader`: classe da app que referencia `Ldalvik/system/DexClassLoader;-><init>` + `INTERNET` + `assets/payload.bin` (4 KiB aleatórios) → amarelo "código escondido".
- `dex-type-only-gms`: só tipo em `Lcom/google/android/gms/…` → informativo.
- `asset-index-text`: `assets/words.txt` com `home\nindex\n` → sem achado.
- `nested-zip-65mb`: ZIP aninhado de 65 MiB → `ScanIncomplete`.
- `truncated-dex`: `classes.dex` cortado a meio → `ScanIncomplete`.
- `apk-with-embedded-apk`: raiz com manifesto + `assets/stub.apk` → instalável (F23).
- `cert-unknown`: certificado `CN=Unknown,OU=Unknown,O=Unknown` → sem aviso; `cert-android-debug` → amarelo.
- `manifest-service-guard`: manifesto binário com `android:permission="…SEND_SMS"` num serviço → não conta como pedida.
- `native-empty-so`: `lib/arm64-v8a/libdummy.so` vazio → amarelo.
- `bundle-two-splits-different-signer`: pacote com 2 assinantes → amarelo/vermelho com texto.
- `vt-offline-yellow-plus-flagged`: veredicto F1.
- `vt-429-md-404`: veredicto "incompleto".
- Testes de interface sem Compose: funções puras `shieldCardModel(verdict, userDecision)` (motivos, cor, texto) com os 5 idiomas.
- Teste de varrimento: nenhum literal de interface em inglês fora de `strings.xml` (procura dos literais usados em `prompt.detail`).

Verificação final (fora desta auditoria): correr os 412 testes existentes e os novos; instalar o Octave real e outro APK com `REQUEST_INSTALL_PACKAGES`; comparar registo do terminal com o cartão.

---

## 9. O que não consigo verificar sem aparelho ou sem chaves reais

- **Qual ficheiro o GoGo analisou no Octave** — só o registo do terminal da sessão (linhas `> source:`, `> sha256:`, `> deep scan:`, `> reputation:`) o diz.
- **O que o VirusTotal e o MetaDefender devolvem hoje** para o hash `cfb6e5a6…` e para APKs reais: sem chaves não consultei nada. Não sei quantos `total_avs` o MetaDefender dá a um APK, nem os limites do plano gratuito.
- **O URL real da página de resultados do MetaDefender** (a pesquisa web não foi autorizada) e a lista atual de valores de `scan_all_result_i`.
- **Saída real de `dumpsys package`** em Android 11–15 e se inclui SHA-256 do certificado (F24). Sem isso, não sei se a "atualização confiável" funciona em aparelhos remotos.
- **O efeito exato** em cada versão do Android de `verifier_verify_adb_installs` e `package_verifier_user_consent` (F26).
- **Ordem de `signingCertificateHistory`** com rotação de chave (F33).
- **Se `externalCacheDir` é acessível a outras apps** no aparelho do dono (depende da versão do Android) — F35.
- **O comportamento com APKs reais** de Google Play Services, Firebase, Crashlytics, Facebook SDK, Unity, Flutter, React Native e WebView: só raciocinei pelo mecanismo. Falta correr o porte do parser (ou a app) sobre APKs reais e contar quantos disparam, antes de calibrar a nova pontuação.
- **Apps legítimas concretas** que disparam `AbusivePermissions` (Telegram, Truecaller, apps de TV): dependem da versão.
- **Se o ecrã mostra o cartão como descrevi** em pt-PT, a pt, es e fr: li as strings e o código, não vi o ecrã.
- **O estado de `Keystore`** em aparelhos reais (apagamento silencioso da chave): só raciocínio pelo código (`K/SecurityShield.kt:1324-1335`).

---

## Anexo técnico — referências rápidas para quem corrige

| # | Ficheiro:linha | Resumo |
|---|---|---|
| F1 | `K/SecurityShield.kt:324`; `T/SecurityShieldTest.kt:325-331` | offline antes de online |
| F2 | `K/HomeScreen.kt:955-967`; `K/SecurityShield.kt:324` | `vtTotal==0` → "sem análise" |
| F3 | `K/StaticAnalyzer.kt:132-144`; `R/values-pt-rPT/strings.xml:197` | substring de tipo |
| F4 | `K/SecurityShield.kt:335-340,185-193`; `T/SecurityShieldTest.kt:360-371` | falha online = vermelho |
| F5 | `K/Reputation.kt:187-197`; `T/Shield0928Test.kt:341` | prioridade de `UnknownHash` |
| F6 | `K/SecurityShield.kt:327-331`; `K/Reputation.kt:133` | qualquer deteção = vermelho |
| F7/F39 | `K/SecurityShield.kt:1201-1210`; `K/Reputation.kt:35,47-62,212-215` | idade ignorada; cache sem fonte |
| F8 | `K/ConnectionModel.kt:1551-1566`; `K/HomeScreen.kt:884-897,951` | só o 1.º motivo |
| F9 | `K/ConnectionModel.kt:1554-1563`; `K/StaticAnalyzer.kt:135,139,150,164,194,199,210,218,235,292,311`; `K/CodeInspection.kt:107,113,117,123,126` | inglês no cartão |
| F10 | `K/ConnectionModel.kt:1219`; `K/HomeScreen.kt:1121,1158` | hash do contentor |
| F12 | `K/HomeScreen.kt:1029-1043`; `K/ConnectionModel.kt:1690,1775` | cor ≠ decisão |
| F14 | `K/SecurityShield.kt:88-102,616-631,644-656` | tokens de DN |
| F15 | `K/StaticAnalyzer.kt:281-306`; `K/SecurityShield.kt:815-902` | permissões |
| F16 | `K/StaticAnalyzer.kt:28-43,423-430` | adware |
| F17 | `K/StaticAnalyzer.kt:21,216-221` | `index\n` |
| F18 | `K/StaticAnalyzer.kt:245-273,360-368,418-421` | cobertura de payload |
| F19/F20 | `K/StaticAnalyzer.kt:13-14,67-112,371`; `K/ConnectionModel.kt:1293` | fail-open |
| F21 | `K/StaticAnalyzer.kt:142-144,156-166,432-437` | PathClassLoader |
| F22 | `K/CodeInspection.kt:85,88,100-129` | nativo |
| F23 | `K/PackageBundle.kt:203-205,226-228`; `K/IncomingFile.kt:36-40` | APK com `.apk` |
| F24 | `K/SecurityShield.kt:109,1062-1067,1080,1088-1105`; `K/AdbLogic.kt:267`; `K/PackageBundle.kt:679`; `K/ConnectionModel.kt:1197-1209` | dumpsys / downgrade |
| F25 | `K/SecurityShield.kt:289-297,333` | atualização confiável |
| F26 | `K/PackageBundle.kt:675-676,743-745`; `K/ConnectionModel.kt:1714-1715` | Play Protect |
| F27 | `K/SecurityShield.kt:1324-1335`; `K/InfoScreens.kt:280,290`; `K/MainActivity.kt:198-200` | chaves |
| F28 | `K/MainActivity.kt:198-200`; `K/ConnectionModel.kt:1271-1298`; `K/SettingsScreen.kt:172-183` | "Máxima" |
| F29 | `K/HomeScreen.kt:405-406,424-438`; `R/values-pt-rPT/strings.xml:255-264` | animação sem efeito |
| F30 | `K/SecurityShield.kt:158,175-193` | motivo morto |
| F31 | `K/ConnectionModel.kt:429-458` | reverter sem Escudo |
| F35 | `K/SecurityShield.kt:1402-1405`; `K/ConnectionModel.kt:1633,1699-1704,1819-1831` | TOCTOU |
