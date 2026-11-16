# Aula 3 — Linux e terminal

Ferramentas de rede e de forense vivem no terminal. Você já usa Linux no dia a dia; esta aula
organiza o que importa para o projeto.

---

## 1. Navegar e manipular arquivos

| comando | faz | exemplo |
|---|---|---|
| `pwd` | mostra onde você está | |
| `ls -la` | lista tudo, com detalhes e ocultos | |
| `cd` | muda de pasta | `cd ~/brendon\ projects/sentinela` |
| `cat`, `less` | mostra arquivo (o `less` rola; `q` sai) | `less README.md` |
| `head -n 20`, `tail -f` | começo do arquivo; acompanha o fim ao vivo | `tail -f /var/log/pacman.log` |
| `cp`, `mv`, `rm`, `mkdir` | copia, move, apaga, cria pasta | |
| `grep -rn "texto" pasta/` | procura texto | `grep -rn sn_checksum native/` |
| `find . -name "*.pcap"` | procura arquivo | |
| `xxd arquivo \| head` | mostra o arquivo em hex | ótimo para ver um `.pcap` |
| `sha256sum arquivo` | hash do arquivo | é o que prova a integridade da evidência |

Caminho **absoluto** começa em `/` (`/home/brendon/...`); **relativo** parte de onde você está
(`native/src`). `~` é a sua pasta pessoal, `.` é a pasta atual e `..` é a de cima. Espaço no nome
precisa de `\ ` ou aspas.

---

## 2. Permissões e usuários

```
-rwxr-xr-x  1 brendon brendon  1234 nov 13  testes-c.sh
 │  │  │
 │  │  └─ outros: ler e executar
 │  └──── grupo: ler e executar
 └─────── dono: ler, escrever e executar
```

- `chmod +x arquivo` torna executável.
- `sudo comando` roda como **root** (administrador). Capturar tráfego de rede exige root ou uma
  permissão especial (*capability*), porque ver o tráfego de outros programas é poderoso.
- Grupos: o Wireshark criou o grupo `wireshark`; quem está nele pode capturar sem `sudo`
  (`sudo usermod -aG wireshark $USER` e entrar de novo na sessão).

---

## 3. Processos e sinais

- `ps aux | grep nome` lista processos; `top` ou `htop` mostra ao vivo.
- `Ctrl+C` manda o sinal **SIGINT** (pede para parar). `kill PID` manda **SIGTERM**;
  `kill -9 PID` manda **SIGKILL** (mata sem chance de limpar).
- `comando &` roda em segundo plano.

Em forense isso importa: um programa morto com `-9` não tem chance de fechar arquivos, e um
`.pcap` pode ficar cortado no meio.

---

## 4. Redirecionamento e pipes

Todo programa nasce com três **descritores de arquivo** (file descriptors, "fd"):

| fd | nome | padrão |
|---|---|---|
| 0 | stdin (entrada) | teclado |
| 1 | stdout (saída) | tela |
| 2 | stderr (erros) | tela |

```sh
comando > saida.txt          # stdout para arquivo (sobrescreve)
comando >> saida.txt         # acrescenta
comando 2> erros.txt         # só os erros
comando > tudo.txt 2>&1      # saída e erros no mesmo arquivo
comando1 | comando2          # a saída de um vira a entrada do outro
```

Quando um comando "não mostra erro nenhum" mas também não funciona, mande o `2>` para um arquivo
e leia: muitas vezes a explicação está no **stderr**.

Exemplo de pipe útil: quais IPs mais aparecem numa captura?

```sh
tshark -r captura.pcap -T fields -e ip.dst | sort | uniq -c | sort -rn | head
```

---

## 5. "Tudo é arquivo"

No Linux, quase tudo é acessado como arquivo, por um descritor: arquivos de verdade, o terminal,
pipes, **sockets de rede** e **a interface TUN** que o Sentinela usa. Um programa lê e escreve
num socket com as mesmas ideias de ler e escrever num arquivo. Essa ideia volta na aula 5.

`ls -l /proc/<PID>/fd` mostra os descritores abertos de um processo. É uma técnica de forense ao
vivo: dá para ver que arquivos e conexões um programa suspeito tem abertos.

---

## 6. Pacotes (pacman)

```sh
sudo pacman -S nome        # instala
sudo pacman -Syu           # atualiza o sistema inteiro
pacman -Ss palavra         # procura
pacman -Qi nome            # detalhes de um instalado
```

No Arch/CachyOS, **não** faça `pacman -Sy nome` (atualizar a lista e instalar um só): isso gera
"atualização parcial" e pode quebrar bibliotecas. Ou instala com a lista que já tem, ou atualiza tudo.

---

## 7. Comandos de rede

| comando | mostra | |
|---|---|---|
| `ip addr` | suas interfaces e endereços | `enp30s0` é o cabo, `wl...` é Wi-Fi, `lo` é o 127.0.0.1 |
| `ip route` | rotas; a `default via` é o roteador | no seu PC: `192.168.77.1` |
| `ip neigh` | tabela ARP (IP ↔ MAC dos vizinhos) | |
| `ss -tunap` | conexões e portas abertas, com o programa dono | forense ao vivo |
| `ping 1.1.1.1` | o destino responde? quanto demora? | |
| `traceroute 1.1.1.1` | por quais roteadores o pacote passa | |
| `dig exemplo.com` | consulta DNS detalhada | `dig AAAA`, `dig @8.8.8.8` |
| `curl -v https://...` | faz um pedido HTTP mostrando tudo | inclusive o TLS |
| `nmcli` | controla o Wi-Fi pelo terminal | |

---

## Exercícios

1. Descubra o IP do seu PC, o do roteador e o MAC do roteador.
2. Rode `ss -tunap` e ache uma conexão do navegador. Para que IP e porta ela vai?
3. Use `dig` para descobrir o IPv4 e o IPv6 de `wikipedia.org`.
4. Gere o hash de um arquivo, altere um único caractere dele e gere de novo. O que muda?
5. Rode `tools/testes-c.sh > saida.txt` e veja se as falhas foram para o arquivo. Se não, por quê,
   e como corrigir?

### Respostas

1. `ip addr` (procure `inet` na interface ativa), `ip route` (a linha `default via`) e
   `ip neigh` (o MAC do IP do roteador).
2. Depende do momento; procure linhas com `users:(("firefox"...` (ou o seu navegador) e porta `:443`.
3. `dig A wikipedia.org +short` e `dig AAAA wikipedia.org +short`.
4. O hash muda **inteiro**, não só um pedaço: é o "efeito avalanche". Por isso o hash prova que a
   evidência não foi alterada.
5. As linhas `FALHOU` saem pelo stderr e continuam na tela. Use `tools/testes-c.sh > saida.txt 2>&1`.

## Para pesquisar mais

- *The Linux Command Line*, William Shotts — gratuito em linuxcommand.org.
- **OverTheWire Bandit** (overthewire.org/wargames/bandit) — jogo que ensina terminal fase a fase.
- `man ip`, `man ss`, `man bash` — o manual está sempre no próprio sistema.
