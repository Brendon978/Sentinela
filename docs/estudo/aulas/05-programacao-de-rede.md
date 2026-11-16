# Aula 5 — Programação de rede

Na aula 4 você viu os pacotes. Aqui você vê como um programa conversa pela rede, e como o
Sentinela se coloca no meio do caminho.

---

## 1. Socket

Um **socket** é a "tomada" que o sistema operacional dá para um programa falar pela rede. Para o
programa, ele é só um descritor de arquivo (lembra da aula 3): você escreve e lê bytes, e o kernel
cuida de IP, TCP, retransmissão etc.

```c
int fd = socket(AF_INET, SOCK_STREAM, 0);   /* IPv4 + TCP   (AF_INET6 = IPv6) */
int fd = socket(AF_INET, SOCK_DGRAM, 0);    /* IPv4 + UDP */
```

## 2. Cliente TCP mínimo

```c
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in destino = {0};
    destino.sin_family = AF_INET;
    destino.sin_port = htons(80);                 /* htons: porta para big-endian (aula 1!) */
    inet_pton(AF_INET, "93.184.215.14", &destino.sin_addr);

    if (connect(fd, (struct sockaddr *)&destino, sizeof destino) < 0) {  /* faz o handshake */
        perror("connect");
        return 1;
    }

    const char *pedido = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    send(fd, pedido, strlen(pedido), 0);

    char buf[4096];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof buf, 0)) > 0)   /* 0 = o outro lado fechou (FIN) */
        fwrite(buf, 1, (size_t)n, stdout);

    close(fd);                                       /* manda o FIN */
    return 0;
}
```

Repare: o programa nunca vê o SYN, o ACK ou a retransmissão. O kernel faz tudo isso.

## 3. Servidor TCP mínimo

```c
int srv = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in end = { .sin_family = AF_INET, .sin_port = htons(8080) };
end.sin_addr.s_addr = htonl(INADDR_LOOPBACK);          /* 127.0.0.1 */
bind(srv, (struct sockaddr *)&end, sizeof end);        /* "fico com a porta 8080" */
listen(srv, 16);                                       /* aceito conexões */
int cli = accept(srv, NULL, NULL);                     /* espera alguém conectar */
/* ... recv/send com cli ... */
```

## 4. UDP

Sem conexão: cada `sendto` vira um datagrama, e cada `recvfrom` recebe um e diz de quem veio.

```c
sendto(fd, dados, n, 0, (struct sockaddr *)&destino, sizeof destino);
recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&origem, &tam);
```

## 5. Esperar várias coisas ao mesmo tempo: não bloqueante + `poll`

`recv` normalmente **bloqueia**: o programa para até chegar algo. Um proxy como o Sentinela cuida
de centenas de conexões; não dá para ficar parado em uma.

A solução:

1. Deixar os sockets **não bloqueantes** (`fcntl(fd, F_SETFL, O_NONBLOCK)`): se não tem nada,
   `recv` volta na hora com o erro `EAGAIN`.
2. Usar `poll` para **dormir até qualquer um** dos descritores ter novidade:

```c
struct pollfd fds[2] = {
    { .fd = fd_tun, .events = POLLIN },   /* chegou pacote de um app? */
    { .fd = fd_sock, .events = POLLIN },  /* chegou resposta do servidor? */
};
int prontos = poll(fds, 2, 1000);          /* espera até 1000 ms */
if (fds[0].revents & POLLIN) { /* ler do tun */ }
if (fds[1].revents & POLLIN) { /* ler do socket */ }
```

Isso é o **laço de eventos**, o coração do motor (`motor.c`). Ele gasta bateria só quando chega algo.

## 6. TUN: o cabo de rede de mentira

Uma interface **TUN** é uma placa de rede virtual. Em vez de mandar os pacotes para um cabo, o
kernel os entrega para **um programa**, que lê pacotes IP inteiros pelo descritor dela. E o que o
programa escreve nela, o kernel trata como pacote chegando da rede.

```
 app (Instagram)                                   Internet
      │ socket normal                                  ▲
      ▼                                                │
 kernel ── rota padrão aponta para o tun ──► fd_tun ──►│ Sentinela (motor.c)
                                             lê o pacote IP cru,
                                             abre um socket de verdade e repassa
```

É assim que qualquer app de VPN funciona. O Android dá isso para os apps pelo **`VpnService`**:
o app pede, o usuário autoriza, e o app recebe o `fd` do tun.

## 7. O truque do Sentinela: um NAT dentro do celular

O Sentinela recebe do tun pacotes **crus** (cabeçalho IP + TCP/UDP), mas para falar com a Internet
ele usa **sockets normais**. Então ele precisa traduzir:

- **UDP:** chegou um datagrama do app para `1.1.1.1:53` → o motor manda o payload com `sendto`
  pelo próprio socket → a resposta volta → o motor **monta** um pacote IP+UDP de volta (com
  checksum certinho, o seu `checksum.c`!) e escreve no tun.
- **TCP:** é mais difícil. O app acha que está falando TCP com o servidor, mas quem responde o
  handshake é o motor. Ele faz o papel do servidor para o app (SYN+ACK, seq/ack, janela, FIN) e o
  papel de cliente para o servidor real (pelo socket, onde o kernel cuida do TCP).

E para não criar um loop (o socket do próprio Sentinela voltar para o tun), o app se exclui da VPN
(`addDisallowedApplication`).

---

## Exercícios

1. Compile e rode o cliente TCP acima. Rode `tshark -i any -f "tcp port 80"` ao mesmo tempo
   (com sudo) e ache o handshake.
2. Por que `htons(80)` e não só `80`?
3. Escreva um servidor UDP de eco: tudo que receber, devolve para quem mandou.
4. No laço com `poll`, o que acontece se você esquecer o `O_NONBLOCK` e chamar `recv` num socket
   que o `poll` não marcou como pronto?
5. Por que o TCP do Sentinela é mais difícil que o UDP?

### Respostas

1. Três pacotes: `[SYN]`, `[SYN, ACK]` e `[ACK]`, depois o `GET`.
2. A rede usa big-endian; o processador, little-endian. `htons` (*host to network short*) troca
   os bytes quando precisa. Sem ele, a porta 80 (`0x0050`) iria como `0x5000` = 20480.
3. Um laço com `recvfrom(fd, buf, ..., &origem, &tam)` seguido de `sendto(fd, buf, n, 0, &origem, tam)`.
4. O `recv` bloqueia e o laço inteiro trava: nenhuma outra conexão é atendida até chegar algo naquela.
5. UDP é sem estado: cada datagrama é independente. No TCP, o motor precisa manter o estado de
   cada conexão (seq, ack, janela, quem fechou) e seguir as regras dos dois lados ao mesmo tempo.

## Para pesquisar mais

- **Beej's Guide to Network Programming** (beej.us/guide/bgnet) — gratuito, a melhor introdução.
- `man 7 socket`, `man 7 tcp`, `man 2 poll`.
- Documentação do kernel: `Documentation/networking/tuntap.rst`.
- Android: developer.android.com/reference/android/net/VpnService.
