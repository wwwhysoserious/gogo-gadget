<p align="center">
  <img src="assets/banner.png" alt="GoGo Gadget Banner" width="100%">
</p>

<p align="center">
  <a href="README.md"><img src="https://img.shields.io/badge/Language-English-blue?style=for-the-badge&logo=google-translate&logoColor=white" alt="English"></a>
  <a href="README.pt.md"><img src="https://img.shields.io/badge/Idioma-Portugu%C3%AAs-00E676?style=for-the-badge&logo=google-translate&logoColor=white" alt="Português"></a>
  <a href="README.es.md"><img src="https://img.shields.io/badge/Idioma-Espa%C3%B1ol-orange?style=for-the-badge&logo=google-translate&logoColor=white" alt="Español"></a>
</p>

<p align="center">
  <a href="https://github.com/wwwhysoserious/gogo-gadget/releases/latest"><img src="https://img.shields.io/github/v/release/wwwhysoserious/gogo-gadget?color=00E676&label=Vers%C3%A3o&logo=android&logoColor=white&style=for-the-badge" alt="Última Versão"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/Licen%C3%A7a-GPL--3.0-blue.svg?style=for-the-badge" alt="Licença: GPL-3.0"></a>
  <img src="https://img.shields.io/badge/Android-11%2B%20(API%2030%2B)-3DDC84.svg?style=for-the-badge&logo=android&logoColor=white" alt="Android 11+">
  <img src="https://img.shields.io/badge/Seguran%C3%A7a-Zero--Trust-black.svg?style=for-the-badge&logo=shield" alt="Zero-Trust">
  <img src="https://img.shields.io/badge/Shizuku-Opcional-orange.svg?style=for-the-badge" alt="Shizuku Opcional">
  <img src="https://img.shields.io/badge/Root-N%C3%A3o%20Necess%C3%A1rio-success.svg?style=for-the-badge" alt="Sem Root">
</p>

---

## Visão Geral

O **GoGo Gadget** é o instalador e gestor de pacotes APK definitivo para Android, desenhado de raiz com **Segurança Zero-Trust** e **Autonomia Total no próprio telemóvel**.

Ao contrário das ferramentas antigas, liga-se diretamente através da **Depuração sem fios (Wireless Debugging)** nativa do Android — ou seja: **Sem Computador**, **Sem Root** e **Sem Processos Escondidos em Segundo Plano** a gastar bateria.

### Pontos Fortes em Destaque:
* **Zero Permissões Perigosas**: Privacidade a 100%. **Nunca pede acesso às tuas fotos, documentos, ficheiros pessoais, contactos nem acessibilidade** (a permissão invasiva `MANAGE_EXTERNAL_STORAGE` nunca é necessária).
* **Suporte Completo a Split APKs**: Instala `.apk` simples, pacotes divididos (`.apks`, `.apkm`, `.xapk`) e arquivos `.zip` sem falhas nem erros chatos de leitura.
* **Antivírus Pré-Instalação**: Analisa o código DEX (`classes.dex`) antes de instalar para **apanhar trojans, droppers e permissões abusivas** antes que o ficheiro toque no sistema.
* **Reversão Automática em 1 Toque**: Atualizaste uma app e a nova versão vem cheia de bugs ou publicidade? O GoGo Gadget **guarda uma cópia da versão antiga que funcionava**, permitindo voltar atrás num só toque sem perder nada.
* **Envio para Outros Dispositivos na Rede**: Instala diretamente no teu smartphone ou **envia qualquer aplicação por Wi-Fi para outro telemóvel ou tablet Android** da tua casa.
* **Zero Dependências da Google**: **100% Código Aberto e Gratuito (GPL-3.0)**, sem serviços da Google Play, sem telemetria e sem ferramentas de rastreio.
* **Só Funciona Quando Precisas**: Não tem processos fantasma a correr em segundo plano depois de o fechares.

---

## Porquê o GoGo Gadget? (A Diferença)

| Funcionalidade | Instalador Normal | Instaladores via Shizuku | **GoGo Gadget** |
| :--- | :---: | :---: | :---: |
| **Precisa de Computador / PC** | Sim (na 1ª configuração) | Quase sempre | **Nunca** (100% no telemóvel) |
| **Precisa de Root** | Não | Opcional / Modo Root | **Não** (Zero Root) |
| **Processos Ativos em 2º Plano** | Não | Sim (Sempre a correr) | **Não** (Desliga ao fechar) |
| **Inspeção de Segurança DEX** | Nenhuma | Nenhuma | **Análise Completa de Código** |
| **Voltar Atrás se a App Falhar** | Nenhuma | Nenhuma | **Reversão em 1 Toque** |
| **Abre .xapk, .apkm, .apks** | Dá Erro | Requer passos manuais | **Instalação Direta** |
| **Envio para Androids na Rede** | Não | Não | **Deteção Wi-Fi Integrada** |
| **Zero Código ou Tracking Google** | Não | Opcional | **100% Livre e Aberto** |

---

## Os Problemas Reais que o GoGo Gadget Resolve

* **O Problema dos Ficheiros Divididos (`.xapk`, `.apkm`, `.apks`)**
  * *A Dor*: Descarregas uma app fora da loja oficial e o telemóvel recusa-se a abrir o ficheiro, dando um erro de pacote inválido.
  * *A Solução*: O GoGo Gadget lê o conteúdo em memória e faz a instalação correta através do ADB local numa fração de segundo.

* **A Dependência de Cabos ou Serviços Frágeis (como Shizuku)**
  * *A Dor*: Precisar de ligar o telemóvel ao PC por cabo USB ou manter um serviço em segundo plano que desliga sozinho sempre que o telemóvel reinicia.
  * *A Solução*: Liga-se diretamente à depuração sem fios do Android localmente, sem depender de computadores.

* **O Perigo de Instalar Apps Cegas (Cavalos de Troia)**
  * *A Dor*: O sistema normal só vê se o ficheiro está corrompido, mas não avisa se a app traz código que descarrega vírus depois de instalada.
  * *A Solução*: O motor de segurança inspeciona o código antes da instalação e avisa logo se encontrar coisas suspeitas.

* **Atualizações Estragadas e Falhas nas Apps**
  * *A Dor*: Uma aplicação atualiza, deixa de funcionar bem e o Android não deixa voltar à versão antiga sem apagar todos os teus dados.
  * *A Solução*: O GoGo Gadget guarda a versão anterior em segurança para poderes reverter com um toque.

* **O Pesadelo das Permissões Invasivas**
  * *A Dor*: Outros instaladores exigem acesso a todas as tuas fotografias, documentos e ficheiros pessoais para funcionar.
  * *A Solução*: **Zero Permissões Perigosas.** O GoGo Gadget nunca toca nas tuas fotografias nem nos teus documentos pessoais.

* **Passar Apps para Outro Dispositivo Android**
  * *A Dor*: Ter de mandar ficheiros por pens USB, WhatsApp ou nuvens lentas para instalar noutro dispositivo.
  * *A Solução*: Envia diretamente pela rede Wi-Fi de casa para qualquer outro dispositivo Android detetado.

---

## Demonstração (Vídeo Promo)

<p align="center">
  <img src="assets/promo/phone-promo.gif" width="85%" alt="Demonstração do GoGo Gadget a correr num telemóvel" />
  <br>
  <a href="https://github.com/wwwhysoserious/gogo-gadget/releases/download/v1.0.0/GoGo-Gadget-Phone-Promo.mp4">
    <b>⬇️ Descarregar Vídeo em Alta Definição (Full HD 1080p MP4)</b>
  </a>
</p>

---

## Capturas de Ecrã

<p align="center">
  <img src="assets/screenshots/01-home-verified.png" width="30%" alt="Ecrã Inicial GoGo Gadget" />
  &nbsp;&nbsp;
  <img src="assets/screenshots/02-security-engine.png" width="30%" alt="Motor de Segurança e APIs" />
  &nbsp;&nbsp;
  <img src="assets/screenshots/03-clean-architecture.png" width="30%" alt="Verificação de Segurança Pré-Instalação" />
</p>

---

## Como Funciona

<p align="center">
  <img src="assets/diagrams/how-it-works-linear.png" width="75%" alt="Arquitetura Linear GoGo Gadget" />
</p>

1. **Escolher o Ficheiro**: Abre ficheiros `.apk`, pacotes divididos (`.apks`, `.apkm`, `.xapk`) ou ficheiros `.zip`.
2. **Inspeção de Segurança**: Análise rápida aos cabeçalhos DEX e verificação de reputação para garantir que a aplicação é segura.
3. **Ligação Sem Fios Segura**: Estabelece a ligação com o sistema por depuração sem fios diretamente no telemóvel.
4. **Instalação e Cópia de Segurança**: Instala a aplicação e guarda uma cópia da versão anterior para poderes voltar atrás se precisares.

---

## Descarregar e Instalar

Descarrega a versão oficial assinada na página de [Releases do GitHub](https://github.com/wwwhysoserious/gogo-gadget/releases/latest):

* **[Descarregar GoGo Gadget v1.0.0 APK](https://github.com/wwwhysoserious/gogo-gadget/releases/download/v1.0.0/GoGo-Gadget-v1.0.0.apk)**

---

## Licença

Distribuído sob a licença **GPL-3.0-or-later**. Consulta o ficheiro [LICENSE](LICENSE) para mais informações.
