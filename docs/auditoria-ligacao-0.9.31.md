# Auditoria completa do ciclo de ligação — GoGo Gadget 0.9.31

Data: 2026-10-28 · Âmbito: só leitura de código (nenhum ficheiro-fonte alterado, sem Gradle, sem comandos git que mudem estado).
Ficheiros lidos: `ConnectionModel.kt`, `AdbClient.kt`, `AdbKeys.kt`, `AdbTls.kt`, `AdbLogic.kt`, `Discovery.kt`, `LocalPairing.kt`, `PairingService.kt`, `PairingNotifier.kt`, `DeviceMenu.kt`, `DevicesScreen.kt`, `MainActivity.kt`, `Graph.kt`, `ConnectionState.kt`, partes de `HomeScreen.kt`, `docs/ADB-LIBRARY.md`, testes.
Para confirmar o comportamento do libadb-android 3.1.1 (não há fontes, só `.class`), desmontei o bytecode com `javap` em `/root/.hermes/cache/scratch/libadb`. Onde uma conclusão vem do bytecode, está indicado «(bytecode)».

> **Limitação do `git diff`:** o HEAD (`071090d`) é a versão 0.9.6 e **todo** o trabalho de 0.9.7–0.9.31 está por commitar, por isso o diff é um só e não separa 0.9.28–0.9.31. Confirmei por outra via que `probeDevices`, `reachable`, `SESSION_PING_MS` e `DeviceMenu.kt` **não existem no HEAD** (`git show HEAD:…` não os contém; `DeviceMenu.kt` nem existe no HEAD). São, portanto, código novo, coerente com «começou a dar erros desde a 0.9.28–0.9.31».

---

## 1. Resumo

**Causa raiz do que o dono reporta:** o `probeDevices()` (`ConnectionModel.kt:356-394`) foi feito para saber se os dispositivos guardados estão acessíveis, mas **também decide se a sessão ADB ligada está viva**, e fá-lo com o sinal errado. Testa TCP à porta **5555** (ou a portas mDNS que, nessa altura, quase nunca existem) em vez da porta real da sessão. Em Wireless Debugging a porta é aleatória, logo o teste falha com um dispositivo perfeitamente saudável, e o código **marca `ConnectionLost` e faz `adb.disconnect()`** (linhas 388-391). Isto dispara em cada `onResume` (`MainActivity.kt:63`), em cada abertura do dropdown e de 4 em 4 s com o dropdown aberto (`DeviceMenu.kt:358-363`).

**Efeito em cascata (segundo erro grave):** depois de falsamente «perdido», o dispositivo fica **cinzento e não seleccionável** (`isDeviceSelectable`, `DeviceMenu.kt:62`, `288-291`) porque o mesmo sonda TCP nunca o vê «disponível» (mesma porta errada) e, no ecrã Dispositivos, nem aparece na lista «na rede» por já estar guardado (`DevicesScreen.kt:76-77`). O utilizador fica sem forma de tocar no dispositivo.

**Das 8 suspeitas do responsável:** 1 verdadeira (com matiz), 2 parcialmente verdadeira, 3 verdadeira (janela estreita mas destrutiva), 4 **verdadeira e é a principal**, 5 falsa como descrita (mas há um problema mais grave ao lado), 6 verdadeira, 7 verdadeira (e o `detail` nem sequer é mostrado na UI), 8 vários achados adicionais (secção 4).

**Achado novo importante (bytecode do libadb):** `AbsAdbConnectionManager.isConnected()`, `connect()`, `disconnect()` e `openStream()` fazem todos `synchronized(mLock)`, e `AdbConnection.open()` espera pelo OKAY do dispositivo com `Object.wait()` **sem timeout**. Numa ligação meio-aberta (TV desligada sem FIN/RST) um `shell` fica preso dentro de `openStream` **a segurar `mLock`**, e `disconnect()` (que o código chama sob `adbLock`) fica bloqueado atrás dele — potencialmente ~15 min (retransmissões TCP do kernel). Resultado: `adbLock` retido, todas as ligações seguintes expiram com «Inacessível/Allow timeout». É exactamente o cenário «desliguei a TV → a app passa a dar erros em tudo».

**Solução recomendada (secção 5):** (a) remover do sonda toda a lógica de sessão e nunca sondar por TCP o dispositivo ligado; (b) vigilância de sessão própria: estado do libadb sem bloqueio + keepalive único, sob `adbLock` com `tryLock`, com verificação de geração/sessão e histerese de 2 falhas; (c) sonda TCP **só** para dispositivos não ligados, com mDNS ligado durante a sonda e histerese.

---

## 2. Verificação das suspeitas do responsável

| # | Suspeita | Veredicto | Evidência |
|---|----------|-----------|-----------|
| 1 | `adb.shell("echo gogo")` corre fora de `adbLock` | **VERDADEIRA** (o dano real não é o descrito) | `ConnectionModel.kt:385` |
| 2 | `probeJob?.cancel()` não pára o shell bloqueante; os pings acumulam-se | **PARCIAL** | `:357`, `:385-386`, `AdbClient.kt:187-190` |
| 3 | Sem verificação de geração | **VERDADEIRA** | `:381-391` |
| 4 | `tcpUp` usa porta guardada/mDNS, não a ligada | **VERDADEIRA — causa principal** | `:362-374`, `:382`, `Discovery.kt:72-76`, `AdbLogic.kt:519-520` |
| 5 | `onResume` corre contra `installFrom` | **FALSA como descrita**; há problema equivalente | `MainActivity.kt:63`, `:384`, `:388` |
| 6 | Timeout de 2,5 s curto demais | **VERDADEIRA** | `:127`, `:386` |
| 7 | `Error` com `detail = null` | **VERDADEIRA** (e agravada) | `:390`, `HomeScreen.kt:1098-1106` |

### 1) Shell fora de `adbLock` — VERDADEIRA, mas o dano é outro
- `:385` `async(Dispatchers.IO) { runCatching { adb.shell("echo gogo") }.getOrNull() }` não passa por `blocking()`/`adbLock`. O contrato de `Graph.adbLock` (`Graph.kt:15-19`) é «ADB calls run one at a time, whoever makes them».
- **Matiz:** não encontrei corrupção de protocolo. O libadb multiplexa streams por `localId`, e `openStream` é `synchronized(mLock)` (bytecode), por isso o contador `mLastLocalId++` (não atómico em `AdbConnection.open`) fica protegido ao passar pelo manager. O que realmente corre mal:
  1. **O ping disputa `mLock`** com `connect()`, `disconnect()`, `isConnected` e com o `openStream` do `install` (que abre com `adb.shell(DisableAdbVerifyCommand)` logo no início, `:1406`). Um ping pendurado atrasa tudo isto.
  2. **Falsos negativos auto-infligidos:** `connect()` do `LibAdbClient` começa por `disconnect()` (`AdbClient.kt:149`) e `begin()` chama `abortAdb` → `adb.disconnect()`. Um ping em curso nessa altura falha *porque* o utilizador mudou de dispositivo, e é interpretado como «dispositivo desligado».
  3. Hoje há **outro caminho sem lock**: `performAutoBackup` → `backupManager.createBackup(adb, …)` em `withContext(Dispatchers.IO)` (`ConnectionModel.kt:1295-1297`) faz `adb.shell`/`adb.pull` fora de `adbLock` (`BackupManager.kt:62`, `:143`). Está dentro do fluxo de instalação (sequencial), mas corre em paralelo com sonda/keepalive.

### 2) `cancel()` não pára o bloqueante — PARCIAL
- A parte TCP é limitada: `Socket.connect(…, 1200 ms)` (`:397`), cada dispositivo tenta as portas em série (`ports.any`) → no máximo `nPortas × 1,2 s`, sem acumulação séria.
- O ping é o problema: `withTimeoutOrNull(2500) { ping.await() }` (`:386`) só abandona o `await`; a thread do `Dispatchers.IO` continua até `ShellTimeoutMs = 30 s` (`AdbClient.kt:91`, `guarded` em `:189`). **Pior:** o `guarded` só arranca depois de `openStream` devolver (`AdbClient.kt:188`); o `openStream` em si não tem watchdog e, numa ligação meio-aberta, bloqueia indefinidamente (bytecode: `AdbConnection.open` → `stream.wait()` sem timeout).
- Com o dropdown aberto são lançados pings de 4 em 4 s (`DeviceMenu.kt:360`), mas a primeira falha põe o estado em `Error` e os pings param — por isso a «acumulação» é limitada a poucos, mas cada um pode reter uma thread e `mLock` durante muito tempo.
- Há ainda uma janela: `cancel()` pelo `probeDevices` seguinte pode ocorrer entre `:390` (estado → `Error`) e `:391` (`withContext(IO){ adbLock… disconnect }`); o `withContext` lança `CancellationException` e **o `disconnect` nunca corre** → UI diz «perdida», libadb mantém `active` vivo (estado incoerente; só o próximo `connect()` limpa).

### 3) Sem verificação de geração — VERDADEIRA
- `:381` capta `dev`, `:384` reavalia `connection.state`, mas depois do ping (até 2,5 s) `:388` usa o `dev` **antigo** com `connection` possivelmente já novo. Cenário: o utilizador troca de dispositivo → `begin()` faz `generation++` e `abortAdb` fecha a sessão antiga → o ping antigo falha → `connection.state == Connected` (a nova ligação loopback/rápida já terminou) → `connection = Error(dev antigo)` e `adb.disconnect()` (`:391`) **fecha a sessão nova**. Janela estreita, mas o efeito é destruir silenciosamente uma sessão boa.
- O `disconnect` de `:391` é um `LibAdbClient.disconnect()` global: fecha *todos* os managers e o `pairing` em curso (`AdbClient.kt:255-260`), sem verificar a que sessão pertence.
- Contraste: `blocking()` já tem a verificação (`if (mine == generation)`, `:775`). O sonda não a usa.

### 4) Porta errada → falso «em baixo» — VERDADEIRA e é o bug principal
- `saveRecent(Target(name, host, 0, …))` guarda **sempre porta 0** (`:653`) e `forgetPorts` zera ao carregar (`:156`, `AdbLogic.kt:520`). Logo `t.port == 0` e `probePorts(0, announced)` = `[5555] + announced` (`DeviceMenu.kt:68-69`).
- `announced` vem de `discovery.found.value` (`:361`), mas o mDNS **só corre enquanto há razão de scan** (`scan("picker"|"pair"|op…)`, `:405-411`) e `NsdDiscovery.release()` esvazia `state` ao libertar o último utilizador (`Discovery.kt:72-76`). No ecrã Home com a sessão ligada não há scan → `announced = []` → só se testa a porta **5555**.
- Em Wireless Debugging (Android 11+, TVs incluídas) a porta de ligação é aleatória; 5555 está fechada → `tcpReachable` devolve `false` → `tcpUp = false` (`:382`) → condição `:388` verdadeira → `ConnectionLost` + `disconnect()` **numa sessão saudável**.
- A porta real da sessão (`connection.device.port`, `:650`) existe e nunca é usada no sonda.
- Pior: mesmo quando o `install?.working == true` (que só protege o ping, `:384`), o veredicto TCP continua a matar a sessão a meio de uma instalação (`:388` não consulta `install`).

### 5) `onResume` vs `installFrom` — FALSA como descrita; existe problema equivalente
- Ao regressar do seletor, o AndroidX entrega o `ActivityResult` **antes** de `onResume` (callback em `onActivityResult`/ao passar a STARTED). Logo `installFrom` (`:792-797`) já pôs `install = InstallStatus(working = true, …)` quando `probeDevices` arranca em `MainActivity.kt:63`. O ping é portanto normalmente saltado. A corrida «`install?.working` ainda não é true» **não** se verifica no caminho normal (nota: confirmado por leitura do contrato AndroidX; não testado em dispositivo).
- **O que é verdade:** (i) se o utilizador *cancela* o seletor, o `onResume` corre o veredicto TCP (suspeita 4) e mata a sessão sem instalação em curso; (ii) o guard cobre só o ping, não o `tcpUp` (ver 4); (iii) `installFrom` não verifica a saúde da sessão antes de começar a análise do Shield (minutos) — uma sessão já morta só é descoberta no fim (`:806`).

### 6) 2,5 s é curto demais — VERDADEIRA
- `SESSION_PING_MS = 2_500L` (`:127`) cobre: abrir stream ADB, `fork` do shell na TV, eco, marcador — numa TV de gama baixa com Wi-Fi em *power-save* (DTIM), ocupada em *dexopt*, ou durante a instalação, passa de 2,5 s com frequência. **Uma única falha** declara perda (sem histerese). Nem sequer se distingue «lento» de «morto».

### 7) `detail = null` — VERDADEIRA (e agravada)
- `:390` `Connection(ConnectionState.Error, dev, AdbError.ConnectionLost, null)`: sem causa. E **não escreve nenhuma linha no log do terminal** (compare-se com `run()` que faz `log.add(failureLine(…))`, `:659`).
- Agravante: `Connection.detail` **não é mostrado em lado nenhum da UI** — `ConnectionPanel` só mostra `it.message` (`HomeScreen.kt:1098-1106`) e `grep` por `.detail` em `HomeScreen.kt` só encontra `prompt.detail`. O comentário em `ConnectionState.kt:12` («shown under the error») ficou desactualizado desde o commit `071090d` (que removeu a linha de diagnóstico). Ou seja: qualquer erro de ligação é indiagnosticável no ecrã; só o log do terminal ajuda, e o sonda não escreve nele.

---

## 3. Achados (por gravidade)

### F1 — Crítico — Sonda mata sessões saudáveis (porta errada, sem mDNS)
- **Evidência:** `ConnectionModel.kt:356-394` (esp. `:361`, `:373`, `:382`, `:388-391`); `DeviceMenu.kt:68-69`; `Discovery.kt:72-76`; `ConnectionModel.kt:653`, `AdbLogic.kt:519-520`.
- **Sintoma:** ligado a uma TV por Wireless Debugging, ao voltar à app (ou ao abrir o dropdown) aparece «Ligação perdida. Escolha o dispositivo outra vez.» sem a TV ter sido desligada. Cada `onResume`/rotação repete.
- **Correcção exacta (hotfix):** apagar as linhas 380-392 (bloco de sessão) e `SESSION_PING_MS`; excluir da lista `targets` o host do dispositivo ligado (`connection.device?.host`), que é CONNECTED por definição. O estado da sessão passa a ser decidido só pela vigilância de sessão (secção 5.2).

### F2 — Crítico — Dispositivos de Wireless Debugging ficam cinzentos e não seleccionáveis
- **Evidência:** mesma causa de F1 para os dispositivos *não ligados*: `probePorts` só tem 5555 sem mDNS (`:361`); `DevicesScreen.kt:75` chama `onOpen()` no `LaunchedEffect(Unit)` no mesmo instante em que `scanForPicker` arranca o mDNS (`MainActivity.kt:142-145`) → `found` ainda vazio → sonda só 5555; o ecrã Dispositivos **não tem refresh periódico** (só o `DeviceDropdown` tem, `DeviceMenu.kt:358-363`); e o menu não depende de `found` (`MainActivity.kt:155`: `remember(model.recent, model.reachable, connection)`), pelo que quando o mDNS responde nada volta a sondar. `isDeviceSelectable(UNAVAILABLE) == false` (`DeviceMenu.kt:62`) e a linha guardada fica inerte (`:291`); a secção «dispositivos na rede» exclui os já guardados (`DevicesScreen.kt:76-77`).
- **Sintoma:** «a minha TV aparece Indisponível e não consigo tocar nela», nem no dropdown nem no ecrã Dispositivos; só a entrada manual funciona. Piora após um falso `ConnectionLost` (F1), que ainda remove o host de `reachable` (`:389`).
- **Correcção exacta:** (a) sondar com mDNS activo: `scan("probe", true)` durante o ciclo, esperar até ~1,5 s por serviços `Connect` dos hosts por resolver, correr TCP, `scan("probe", false)`; (b) reagir a mudanças de `found` (debounce 500 ms → nova sonda); (c) candidatos de porta = `[lastGoodPort (prefs, só como pista), portas mDNS, 5555]`; (d) refresh periódico (5 s no ecrã Dispositivos e com dropdown aberto; 20 s no Home); (e) manter uma linha inerte *apenas* se a sonda disser inacessível, nunca por falta de dados.

### F3 — Alto — `shell` do ping pode ficar preso a segurar `mLock` do libadb e travar `disconnect()` sob `adbLock`
- **Evidência (bytecode):** `AbsAdbConnectionManager.openStream/connect/disconnect/isConnected` têm `monitorenter` em `mLock`; `AdbConnection.open(String)` faz `stream.wait()` sem timeout; `AdbConnection.isConnected()`/`isConnectionEstablished()`/`close()` **não** têm monitor. No código: `AdbClient.kt:188` (`openStream` fora do `guarded`), `ConnectionModel.kt:391` (`adbLock.withLock { adb.disconnect() }`), `AdbClient.kt:255-260` (`disconnect()` → `manager.disconnect()`).
- **Sintoma:** desligar a TV (sem FIN/RST) → ping bloqueado no `openStream` → `disconnect()` bloqueado em `mLock` **a segurar `adbLock`** até o TCP desistir (~15 min por defeito) → toda a ligação/instalação seguinte espera por `adbLock` e expira (25 s/45 s) com «Inacessível» ou «Tempo excedido ao autorizar», mesmo com a TV já de volta.
- **Correcção exacta:** guardar, em `LibAdbClient.connect`, uma referência `@Volatile` ao `AdbConnection` (`next.adbConnection`, obtida logo após `connect` com sucesso, sem contenção). Criar `AdbClient.kill()` que faz `conn.close()` (sem `mLock`) — desbloqueia o `open()` pendente (o reader thread termina, `cleanupStreams` fecha o stream e acorda o `wait`). Usar `kill()` em `abortAdb`/watchdog **antes** de `disconnect()`. O `ping()` (5.2) passa a ter watchdog que cobre também o `openStream`.

### F4 — Alto — Sem histerese e timeout curto (falsos «perdida»)
- **Evidência:** `ConnectionModel.kt:127`, `:386`, `:388`.
- **Sintoma:** TV ocupada/Wi-Fi em poupança de energia → um ping lento marca perda → sessão destruída.
- **Correcção exacta:** 2 falhas consecutivas (espaçadas ≥5 s) antes de declarar perda; timeout do ping 8 s (1.ª) e 10 s (2.ª); uma falha *definitiva* (reader thread morto, `isAlive == false`) conta como perda imediata (não é lentidão).

### F5 — Alto — Sem geração/identidade de sessão no resultado do sonda
- **Evidência:** `ConnectionModel.kt:381-391` (ver suspeita 3).
- **Sintoma:** troca de dispositivo durante um sonda pode fechar a sessão nova.
- **Correcção exacta:** capturar `val g = generation` e `val sid = adb.sessionId` antes de qualquer espera; só aplicar `markLost` se `g == generation && sid == adb.sessionId && connection.device == dev && connection.state == Connected`, e **repetir a verificação dentro de `adbLock`** antes do `disconnect` (como faz `blocking.abandon`, `:775`).

### F6 — Alto — `currentSubnet()` escolhe a primeira sub-rede privada por ordem alfabética, de qualquer interface
- **Evidência:** `DeviceMenu.kt:105-109` (`own.sorted().firstOrNull{…}`), `Discovery.kt:30-35` (`ownAddresses()` percorre **todas** as interfaces: `wlan0`, `rmnet_data*`, `tun0`, hotspot…).
- **Sintoma:** com dados móveis (IPv4 privado CGNAT `10.x`) ou VPN (`10.8.x`) activos, `"10.…" < "192.168.…"` → `currentSubnet` devolve a sub-rede do 4G/VPN; todos os dispositivos da LAN `192.168.1.x` passam a «outras redes» (`OTHER_NETWORK`, cinzentos) e **nem são sondados** (`ConnectionModel.kt:363`). *Precisa de confirmação em dispositivo (depende do operador), mas o código não discrimina interfaces.*
- **Correcção exacta:** `currentSubnets(own): Set<String>` (todas as sub-redes privadas /24 das interfaces activas, ou melhor, só a rede Wi-Fi/Ethernet via `ConnectivityManager`/`LinkProperties`); um dispositivo está «nesta rede» se a sua sub-rede ∈ conjunto. Actualizar `deviceMenuEntries` e `probeDevices`.

### F7 — Alto — Ligar/cancelar não é interrompível (`mLock` + `Socket(host, port)` sem timeout)
- **Evidência (bytecode):** `AbsAdbConnectionManager.connect(String,int)` segura `mLock` durante todo o `Builder.build()` + `AdbConnection.connect()`; o construtor de `AdbConnection` chama `new Socket(String,int)` (sem timeout de ligação, ~2 min num anfitrião que não responde). No código: `AdbClient.kt:148-158`, `ConnectionModel.kt:564` (`abortAdb` → `adb.disconnect()` → `manager.disconnect()` fica à espera de `mLock`), `:769` (`abortJob?.join()` em cada `blocking`).
- **Sintoma:** tocar num dispositivo desligado → «A ligar…» 25–45 s → erro; tocar «Cancelar» e noutro dispositivo bom → este também fica à espera do aborto anterior e expira com «Inacessível/Allow timeout».
- **Correcção exacta:** (a) pré-sonda TCP (3 s) à porta escolhida antes de `adb.connect` para dispositivos de rede → falha rápida com `Unreachable`; (b) `kill()` lock-free (F3) usado em `abortAdb`; (c) `connect` com limpeza em caso de excepção (F12).

### F8 — Médio — `adb.isConnected` na thread principal (risco de ANR)
- **Evidência:** `ConnectionModel.kt:806` (`adb.isConnected` dentro de `viewModelScope.launch` → Main). `LibAdbClient.isConnected` → `AbsAdbConnectionManager.isConnected()` é `synchronized(mLock)` (bytecode).
- **Sintoma:** falha de instalação numa sessão meio-aberta enquanto outra thread tem um `openStream` pendente (segura `mLock`) → a thread principal bloqueia em `isConnected` e a UI congela (ANR). Raro, mas fatal quando ocorre.
- **Correcção exacta:** usar o `isAlive` lock-free (5.2) ou `withContext(Dispatchers.IO)`.

### F9 — Médio — Reconexão silenciosa no arranque e porta de reserva 5555
- **Evidência:** `ConnectionModel.kt:220` (`recent.firstOrNull()?.let { connect(it, silent = true) }`), `:634` + `:673-675` (`findNetworkPort`: espera `NETWORK_PORT_WAIT_MS = 2 s` pelo mDNS recém-iniciado e depois `networkConnectPort` cai em **5555**), `AdbLogic.kt:360-361`, `:125` (`connectPortWaitMs` só se aplica a dispositivos locais).
- **Sintoma:** TV por Wireless Debugging: ao abrir a app, a reconexão silenciosa tenta 5555 → recusado → `Unreachable` → `GoIdle` (silencioso) → fica «Sem ligação» sem explicação. Também depois de emparelhar um dispositivo de rede (`submitCode` → `run(paired=true)`) a espera continua a ser só 2 s. Se `recent.first()` for um dispositivo de **outra** rede, a app tenta ligar-lhe no arranque (até 25 s a segurar `adbLock`, estado «A ligar…», sem seleccionar).
- **Correcção exacta:** (a) para rede, aplicar `connectPortWaitMs(paired)` também (5 s/15 s) e *tentar candidatos por TCP* `[porta mDNS, lastGoodPort, 5555]`; (b) só reconectar no arranque se `recent.first()` estiver na rede actual (`subnet ∈ currentSubnets`) e, idealmente, depois de uma sonda TCP bem-sucedida; (c) guardar `lastGoodPort` em prefs (como pista, não como verdade).

### F10 — Médio — `reachable = emptySet()` ao abrir (pisca tudo cinzento)
- **Evidência:** `ConnectionModel.kt:358` (`if (!keep) reachable = emptySet()`), chamado em `MainActivity.kt:186`, `:223`.
- **Sintoma:** cada vez que se abre o dropdown/ecrã Dispositivos, todos os dispositivos ficam cinzentos até ao fim da sonda (1,2 s+), mesmo os que estavam disponíveis.
- **Correcção exacta:** nunca limpar; manter o último resultado com carimbo de tempo e histerese (5.3). «Começar cinzento» só na primeira abertura da app.

### F11 — Médio — `installFrom`/revert sem verificação prévia da sessão
- **Evidência:** `ConnectionModel.kt:793` e `:264` só verificam `connection.state == Connected`.
- **Sintoma:** com a TV já desligada, o utilizador escolhe um APK, a app corre o Shield (hash, análise, VirusTotal — minutos) e só no fim descobre «Ligação perdida».
- **Correcção exacta:** pré-verificação `adb.isAlive` (lock-free, instantânea) em `installFrom`/`revertBackups`/`confirmCaution`; se falsa → `markLost(...)` + mensagem imediata.

### F12 — Baixo — Ligação falhada deixa socket aberto até à próxima ligação
- **Evidência:** `AdbClient.kt:150-157`: `next.connect()` lança excepção (AdbPairingRequired, IOException) → `next.disconnect()` só é chamado no ramo `false`. O socket + reader thread ficam abertos até ao `disconnect()` do próximo `connect()`.
- **Correcção:** `try { … } catch (t: Throwable) { runCatching { next.disconnect() }; throw t }`.

### F13 — Baixo — `deviceModel()` só apanha `IOException`
- **Evidência:** `ConnectionModel.kt:690-696`. `openStream` converte `InterruptedException`/`AdbPairingRequiredException` em `IllegalStateException` (bytecode), que sai de `run()` como `AdbError.Failed` logo após uma ligação bem-sucedida.
- **Correcção:** `catch (e: Exception)` excepto `CancellationException`.

### F14 — Baixo — Sessões locais (loopback) sem qualquer vigilância
- **Evidência:** guard `!dev.local` em `:384`, sem alternativa.
- **Sintoma:** desligar Wireless Debugging no telemóvel mantém «Ligado» no ecrã até a primeira operação falhar.
- **Correcção:** a vigilância lock-free (`isAlive`, 5.2) serve também o local (custo zero, sem rede).

### F15 — Baixo — `menu` não depende de `found`/sub-rede
- **Evidência:** `MainActivity.kt:155-161` (`remember(model.recent, model.reachable, connection)`; `currentSubnet(own)` calculado uma vez). Mudança de Wi-Fi sem mudar `reachable` não recalcula. Também há um desalinhamento de indentação em `:157`.
- **Correcção:** incluir `model.subnets` (state) na chave; actualizar quando a rede muda.

### F16 — Baixo — mDNS: falhas de arranque ignoradas e entradas obsoletas
- **Evidência:** `Discovery.kt:119-120` (`onStartDiscoveryFailed`/`onStopDiscoveryFailed` vazios); `findNetworkPort` usa `mdnsConnectPort` com `found.value` possivelmente obsoleto (a própria nota em `ConnectionModel.kt:352-354` admite que o mDNS sobrevive a um dispositivo desligado).
- **Correcção:** registar falha no log; nunca confiar numa porta mDNS sem confirmar por TCP (pré-sonda de F7).

### F17 — Baixo — Serviço de emparelhamento: `onTimeout`/`onDestroy` cancelam o scope a meio
- **Evidência:** `PairingService.kt:84`, `:86-90` (`scope.cancel()`), `:158-162`. Um emparelhamento em curso pode terminar sem notificação de resultado (`finish` nunca corre). Fora do âmbito dos erros recentes; registado por completude.

### Verificado e correcto (sem acção)
- Escrita de `mutableStateOf` (`connection`, `install`, `reachable`, `recent`, `backups`, `pairPort…`): todas ocorrem na Main (corrotinas de `viewModelScope`, `postLog`/`updateInstallProgress` fazem `launch`, `refreshBackups` usa `withContext(Main)`). O `TerminalLog` é thread-safe (`StateFlow.update`).
- Reset do contexto TLS (`AdbTls.kt`) sempre sob `adbLock` (`connect`, `pair`, `deleteIdentity`) e a regra ProGuard cobre o campo `sslContext`. O contexto só é usado no *handshake* do `connect`, por isso o reset não afecta sessões vivas.
- Chave por dispositivo (`identityFor`/`withDeviceId`/`provisionalIds`) é coerente entre `connect`, `submitCode` e `saveRecent`.
- Contagem de referências do mDNS (`scan`/`acquire`/`release`) é idempotente; `begin()` e `finally` de `run()` não duplicam libertações.
- `tcpReachable` fecha o socket (`use`); `keepSavedHosts` evita «disponível» de dispositivo esquecido.
- O estado do libadb **tem** sinal de vida utilizável: o *reader thread* (`AdbConnection`) apanha qualquer excepção/EOF/RST e, no `finally`, limpa `mConnectionEstablished` e fecha os streams (bytecode). Logo `AdbConnection.isConnected() && isConnectionEstablished()` reflecte morte *activa* da ligação; só a morte **silenciosa** (sem FIN/RST) exige um keepalive.

---

## 4. Estados `Error` vs `NotConnected` — transições actuais
- `run()`: falha → `fail()` → `Error` (com `detail`) **ou** `GoIdle` → `NotConnected` se silencioso (`nextAfterConnectFailure`, `AdbLogic.kt:408-413`). A razão da falha silenciosa só fica no log (`:659`).
- `installFrom` com `IOException`: `Error(ConnectionLost, diagnostic(e))` (`:806-807`) sem `adb.disconnect()` — a sessão libadb fica «ligada» por baixo.
- Sonda: `Error(ConnectionLost, null)` + `disconnect` (F1, F7).
- O estado `Error` não tem saída automática: só o utilizador a limpa, e nessa altura (F1/F2) o dispositivo está cinzento/inerte.

---

## 5. Desenho da solução correcta

Objectivo: «dispositivos de rede guardados começam cinzentos ao abrir; passam a Disponível só quando realmente acessíveis; um dispositivo ligado que se desliga é detectado e fica cinzento/não seleccionável; nunca perturbar uma sessão saudável nem uma instalação».

### 5.1 Princípio: duas máquinas de estado separadas
1. **Sessão ligada** (um só dispositivo): `Healthy → Suspect → Lost`. Sem TCP, sem mDNS. Fonte: estado do libadb + keepalive.
2. **Dispositivos não ligados**: `Unknown(cinzento) → Available → Unavailable`. Fonte: TCP (com mDNS activo durante a sonda). Nunca toca na sessão.

O dispositivo ligado nunca entra na sonda TCP.

### 5.2 Vigilância da sessão (`SessionWatch`)
**`AdbClient` (novos membros):**
```kotlin
val sessionId: Long          // incrementa em cada connect() bem-sucedido; 0 sem sessão
val isAlive: Boolean         // lock-free: conn.isConnected() && conn.isConnectionEstablished() (sem mLock)
fun ping(timeoutMs: Long): Boolean   // abre "shell:echo", watchdog que cobre também o openStream
fun kill()                   // conn.close() lock-free: desbloqueia open()/read() pendentes
```
`LibAdbClient`: após `next.connect(...)` com sucesso, `conn = next.adbConnection` (`@Volatile`) e `sessionId++`. `isAlive` e `kill()` usam `conn` e **não** tocam em `mLock`. `disconnect()` limpa `conn`.

**`ConnectionModel`:**
- `private var watchJob: Job?` iniciado em `run()` logo após `connection = Connected` e cancelado em `begin()`.
- Laço: a cada 2 s verifica `adb.isAlive` (custo zero). `false` ⇒ `markLost(reason = "libadb: reader terminou")` **imediato** (morte activa, sem histerese).
- Keepalive: de 25 em 25 s **só se** `app em primeiro plano` (resumed) e `device não local` e `install?.working != true` e `adbLock.tryLock()` conseguir (ocupado = a sessão está a trabalhar = viva). Sob o lock: `ping(8 s)`. Falha ⇒ `Suspect`; 2.º ping 5 s depois (10 s). Segunda falha ⇒ `markLost("ping 2×")`. Sucesso ⇒ `Healthy`.
- Antes de cada espera: capturar `g = generation`, `sid = adb.sessionId`, `dev`. Depois de cada espera e **de novo dentro de `adbLock`**: `if (g != generation || sid != adb.sessionId || connection.device != dev) return`.
- `markLost(g, dev, reason)` (na Main): grava `log.add("> session: lost - $reason")`, `connection = Connection(Error, dev, ConnectionLost, detail = reason)`, e, sob `adbLock`, `adb.kill(); adb.disconnect()` apenas se a geração/sessão ainda coincidirem. Nunca `disconnect` global às cegas.
- `onResume`: verificação imediata de `isAlive` (sem ping) + ping único (sem histerese de tempo, mas com as 2 falhas) quando a app esteve >30 s em segundo plano.
- Preflight de operações (`installFrom`, `revertBackups`, backup, `confirmCaution`): `if (!adb.isAlive) { markLost(…); return }`.
- Mostrar o `detail` no cartão `Error` (linha pequena, `HomeScreen.kt:1098`), ou pelo menos escrever sempre uma linha no terminal.

**Lógica pura e testável (`LivenessTracker`)**, sem Android:
```kotlin
class LivenessTracker(private val failuresToLose: Int = 2) {
    enum class Verdict { Healthy, Suspect, Lost }
    fun onFlagsDead(): Verdict = Verdict.Lost
    fun onPing(ok: Boolean): Verdict   // ok ⇒ reset; falha ⇒ Suspect até failuresToLose
    fun reset()
}
```

### 5.3 Disponibilidade dos não ligados (`AvailabilityProbe`)
- **Quando:** `onResume` (1 vez, imediato), ecrã Dispositivos / dropdown aberto (cada 5 s), Home inactivo (cada 20–30 s), nada em segundo plano (`onPause` cancela). Re-sonda com *debounce* quando `found` muda.
- **Alvos:** guardados na sub-rede actual (`currentSubnets`), excluindo o dispositivo ligado e o telemóvel.
- **mDNS durante a sonda:** `scan("probe", true)` no início do ciclo; esperar até ~1,5 s por serviços `Connect` dos hosts sem porta conhecida; `scan("probe", false)` no fim. (Em alternativa manter `scan("watch")` enquanto a app está visível e houver dispositivos de rede guardados.)
- **Portas candidatas por host:** `[lastGoodPort, …portas mDNS do host, 5555]`, sem repetições; `lastGoodPort` guardado em prefs separado de `recent` (só pista).
- **Teste:** `Socket.connect(host, porta, 1200 ms)` em paralelo (máx. 4 simultâneos), `async` por host, sem tocar em ADB.
- **Histerese:** `Unknown/Unavailable → Available` à primeira resposta; `Available → Unavailable` só após **2 sondas falhadas** seguidas. Sem `reachable = emptySet()`.
- **Semântica:** só `Available` se uma porta aceitar TCP (mDNS sozinho não basta, como já está documentado em `ConnectionModel.kt:350-355`).
- **Seleccionável:** inalterado (`CONNECTED`/`AVAILABLE`). Depois de `Lost`, o dispositivo passa a «não ligado» e entra na sonda; volta a ser seleccionável quando a sonda o vir.
- **Opcional (recomendado):** reconexão silenciosa única quando um dispositivo que acabou de `Lost` voltar a `Available` (a chave já está autorizada com «Sempre permitir»).

### 5.4 O que NÃO fazer
- Não sondar por TCP o dispositivo ligado nem fazer pings em intervalos curtos (4 s) na sessão viva.
- Não chamar `adb.isConnected`/`disconnect()` na Main nem sem perceber que bloqueiam em `mLock`.
- Não aplicar `disconnect()` global depois de uma espera sem verificar geração/sessão.

---

## 6. Plano de implementação (do menor/seguro para o maior)

**Passo 1 — Hotfix 0.9.32 (≈25 linhas, remove o dano)**
1. `ConnectionModel.probeDevices`: apagar o bloco de sessão (`:380-392`) e a constante `SESSION_PING_MS` (`:127`); excluir `connection.device?.host` de `targets`.
2. Não limpar `reachable` quando `keep=false` (remover `:358`, manter só na 1.ª execução).
3. Sempre `log.add` ao entrar em `Error`/`NotConnected` por qualquer razão.
*Resultado:* acabam os falsos `ConnectionLost` e a sessão deixa de ser destruída ao voltar à app. Perde-se temporariamente a detecção de TV desligada (volta no Passo 3).

**Passo 2 — Disponibilidade correcta (F2, F6, F10)**
4. `currentSubnets(own)` (conjunto) em `DeviceMenu.kt`; actualizar `deviceMenuEntries` e `probeDevices`.
5. `probePorts` aceita `lastGoodPort`; guardar `lastGoodPort` em prefs após uma ligação bem-sucedida.
6. mDNS durante a sonda (`scan("probe")`), re-sonda por mudança de `found` com debounce, refresh no ecrã Dispositivos, cadência por contexto.
7. Histerese de 2 falhas para `Available → Unavailable`.

**Passo 3 — Vigilância de sessão (F3, F4, F5, F7, F8, F11, F14)**
8. `AdbClient`: `sessionId`, `isAlive`, `ping(timeoutMs)`, `kill()`; implementar em `LibAdbClient` com handle lock-free ao `AdbConnection`.
9. `LivenessTracker` (puro) + `SessionWatch` em `ConnectionModel` com geração/sessão e `tryLock`.
10. Preflight `isAlive` em `installFrom`/`revertBackups`; `isAlive` em vez de `isConnected` em `:806`.
11. `abortAdb`/`blocking.abandon` chamam `kill()` antes de `disconnect()`.
12. Mostrar `detail` no cartão de erro.

**Passo 4 — Robustez de ligação (F7, F9, F12, F13, F16)**
13. Pré-sonda TCP (3 s) antes de `adb.connect` em dispositivos de rede; candidatos de porta; `connectPortWaitMs(paired)` também para rede.
14. Reconexão do arranque só se `recent.first()` na rede actual.
15. `LibAdbClient.connect` com limpeza em excepção; `deviceModel()` com `catch (Exception)`.
16. `performAutoBackup` por `blocking()`/`adbLock`.

**Passo 5 — Opcional**
17. `ConnectivityManager` callback (exige `ACCESS_NETWORK_STATE`, actualizar `docs/ADB-LIBRARY.md`) para accionar verificação imediata quando o Wi-Fi cai/volta.

---

## 7. Testes a adicionar
O projecto só tem `junit` e `org.json` em teste e **não há teste algum que instancie `ConnectionModel`** (precisa de `Application`). Por isso a lógica nova deve ser extraída para funções/classes puras, e o resto coberto por testes com `FakeAdbClient`/`FakeDiscovery` (as interfaces `AdbClient` e `DeviceDiscovery` já o permitem; usar `runBlocking`, `kotlinx-coroutines-core` já está no classpath de teste).

1. `LivenessTrackerTest`: uma falha ⇒ `Suspect`; duas ⇒ `Lost`; sucesso intermédio reinicia; `onFlagsDead` ⇒ `Lost` imediato; `reset` limpa.
2. `ProbePortsTest` (estender `Shield0928Test`): inclui `lastGoodPort`; sem repetições; nunca 5555 duplicado; ignora portas inválidas.
3. `CurrentSubnetsTest` (estender `DeviceMenuTest`): `{ "10.20.0.5" (rmnet), "192.168.1.10" }` ⇒ ambas as sub-redes; dispositivo `192.168.1.x` conta como «nesta rede»; sem interfaces ⇒ vazio. Regressão de F6.
4. `AvailabilityHysteresisTest`: `Unavailable→Available` à 1.ª; `Available→Unavailable` só à 2.ª falha; recuperação reinicia contador; começa `Unknown` (cinzento).
5. `ProbeTargetsTest`: o host do dispositivo ligado e o do telemóvel nunca são alvo de TCP; dispositivos de outra sub-rede não são sondados.
6. `MarkLostGuardTest` (função pura `shouldApplyLoss(g, gNow, sid, sidNow, dev, devNow, state)`): troca de dispositivo, nova sessão, estado ≠ `Connected` ⇒ não aplica (regressão F5).
7. `SessionWatchTest` com `FakeAdbClient` (`isAlive` programável, `ping` programável, contador de chamadas) e `Mutex` real: (a) com `adbLock` ocupado não há ping; (b) com `install.working` não há ping; (c) ping falha 1× ⇒ continua `Connected`; (d) 2× ⇒ `Error(ConnectionLost, detail ≠ null)` e uma linha no log; (e) `isAlive=false` ⇒ perda imediata; (f) mudança de geração durante o ping ⇒ nenhum `disconnect`.
8. `ConnectPortCandidatesTest`: ordem `[mdns, lastGood, 5555]`; espera longa após emparelhar em rede (`connectPortWaitMs` para rede).
9. `DeviceMenuTest` adicional: após `Lost` o dispositivo aparece `UNAVAILABLE` (inerte) *apenas* enquanto não está em `reachable`; ao entrar em `reachable` volta a `AVAILABLE` (selecionável).
10. Teste de contrato do `AdbClient` falso: `kill()` desbloqueia um `shell` pendente (garante que o `abortAdb` não depende de `mLock`).

### Validação manual em dispositivo (obrigatória antes de lançar)
- TV com Wireless Debugging (porta aleatória): ligar, sair da app, voltar (×10), rodar o ecrã, abrir/fechar o dropdown 1 min ⇒ **nenhuma** perda espúria.
- Idem durante uma instalação grande ⇒ sem perda nem interferência.
- Desligar a TV da ficha (sem FIN) ⇒ «Ligação perdida» em ≤ ~40 s e dispositivo cinzento; ligar a TV ⇒ volta a Disponível sem reiniciar a app.
- Standby da TV (RST imediato) ⇒ perda em ≤ 3 s.
- Telemóvel com dados móveis + VPN ligados ⇒ dispositivos da LAN continuam «nesta rede».
- Tocar em dispositivo desligado e logo noutro bom ⇒ o segundo liga sem esperar o primeiro expirar.
- Desligar Wireless Debugging no próprio telemóvel ⇒ sessão local passa a «perdida».
