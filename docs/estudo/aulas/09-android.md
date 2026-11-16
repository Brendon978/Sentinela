# Aula 9 — Android por dentro

O suficiente para entender o que o Sentinela consegue fazer no celular, o que não consegue, e por quê.

---

## 1. Arquitetura

```
 apps (Kotlin/Java, e código nativo C/C++ pelo NDK)
 ────────────────────────────────────────────
 framework Android (serviços do sistema: ConnectivityManager, PackageManager…)
 ────────────────────────────────────────────
 bibliotecas nativas e ART (a máquina virtual dos apps)
 ────────────────────────────────────────────
 kernel Linux (processos, memória, rede, drivers)
```

O Android é um Linux por baixo. A pilha TCP/IP é a do kernel Linux, e é por isso que o motor em C
do Sentinela é o mesmo no celular e no PC.

## 2. Isolamento: um usuário por app

Cada app instalado ganha um **UID** (número de usuário Linux) próprio e roda isolado na sua
"caixa de areia" (*sandbox*): não lê os arquivos nem a memória dos outros. O **SELinux** reforça
isso com regras do sistema.

Consequência para o Sentinela: toda conexão de rede pertence a um UID, e o Android deixa o app de
VPN perguntar "de que UID é esta conexão?" (`getConnectionOwnerUid`). É assim que se sabe que foi o
Instagram e não o WhatsApp.

## 3. Permissões

- **Normais** (internet, vibrar): concedidas na instalação.
- **Perigosas** (câmera, microfone, localização, contatos): o usuário aprova na hora.
- **Especiais** (acessibilidade, sobrepor outros apps, administrador do dispositivo, VPN): o
  usuário liga numa tela própria das configurações.

### Por que acessibilidade é tão perigosa

O serviço de acessibilidade foi feito para leitores de tela: ele **lê tudo o que aparece na tela e
pode tocar em qualquer botão**. É exatamente o que o malware bancário brasileiro usa (as famílias
de trojans bancários que roubam a senha e fazem o Pix sozinhos). Por isso os bancos desconfiam de
qualquer app com acessibilidade ligada, e por isso o Nubank bloqueou o seu launcher. O Sentinela
**nunca** usa acessibilidade.

## 4. adb

O **Android Debug Bridge** liga o PC ao celular (por cabo ou Wi-Fi) quando a depuração está ativa:

```sh
adb devices -l                      # aparelhos conectados
adb install -r app.apk              # instala ou atualiza
adb logcat                          # log do sistema ao vivo
adb shell dumpsys connectivity      # estado da rede
adb shell pm list packages          # apps instalados
adb pull /sdcard/Download/x.pcap .  # copia arquivo para o PC
```

Em forense de celular, o adb é uma das formas de coleta **lógica** (sem root): pega o que o
sistema deixa.

## 5. VpnService

É a API que deixa um app comum (sem root) virar a VPN do aparelho:

1. O app chama `VpnService.prepare()`; o Android mostra o aviso "permitir conexão VPN?" e o
   **usuário** confirma (só da primeira vez).
2. O app monta a interface com o `VpnService.Builder`: endereço próprio (ex.: `10.111.0.1`), rotas
   (`0.0.0.0/0` = tudo), servidor DNS, quais apps entram ou ficam de fora.
3. `establish()` devolve o descritor do **tun** (aula 5).
4. A partir daí, todo o tráfego dos apps passa pelo app de VPN. Aparece o ícone de chave na barra.

Limites:
- **Uma VPN por vez** (por isso o Tailscale cai quando o Sentinela grava).
- O tráfego de quem usa o seu **hotspot** não passa pela VPN.
- O conteúdo HTTPS continua cifrado: os apps não confiam em certificados instalados pelo usuário
  desde o Android 7.

## 6. O que dá e o que não dá sem root

| sem root dá | sem root não dá |
|---|---|
| ver o tráfego dos apps do próprio celular (VpnService) | ver o tráfego de outros aparelhos do Wi-Fi |
| saber qual app abriu cada conexão | modo monitor na placa Wi-Fi interna |
| descobrir aparelhos da rede (mDNS, varredura) | ler a memória ou os arquivos de outros apps |
| ler o histórico de uso de apps (com permissão) | capturar na interface real (`wlan0`) |

**Root** = conseguir rodar como o usuário 0 (root do Linux). Exige desbloquear o bootloader (o
que apaga o aparelho) e quebra a segurança que os bancos exigem.

---

## Exercícios

1. Com o celular no adb, rode `adb shell dumpsys package com.whatsapp | grep -i permission` e
   veja as permissões que ele tem.
2. Por que o app de VPN precisa se excluir da própria VPN?
3. Explique a um amigo, em três frases, por que um "app de limpar celular" que pede acessibilidade
   é suspeito.
4. Um app manda dados pela rede só quando a tela está desligada. Como o Sentinela pode perceber isso?

### Respostas

2. Senão os sockets que o próprio Sentinela abre para a Internet voltariam para o tun, e ele
   receberia o próprio tráfego de novo, num loop infinito.
3. Acessibilidade lê tudo da tela e toca em qualquer botão. Limpar arquivos não precisa disso.
   Pedir esse poder sem motivo é o comportamento clássico de trojan bancário.
4. Observando quando a tela liga e desliga (o sistema avisa) e marcando as conexões abertas com a
   tela desligada. É a regra `MADRUGADA_OU_TELA_DESLIGADA` do plano.

## Para pesquisar mais

- developer.android.com: VpnService, "Permissions on Android", "Application sandbox".
- Nikolay Elenkov, *Android Security Internals*.
- Relatórios públicos de empresas de segurança sobre trojans bancários brasileiros no Android.
