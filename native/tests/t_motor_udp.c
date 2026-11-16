/* Testes da Tarefa 6: o motor com relé UDP e DNS, pela bancada (tun falso + relógio
 * falso + servidores locais). O teste faz o papel dos apps do celular. */
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "banca.h"
#include "sn_fluxos.h"
#include "sn_pcap.h"
#include "teste.h"

static const uint8_t APP_V4[16] = {10, 111, 0, 1};
static const uint8_t APP_V6[16] = {0xfd, 0, 0, 0x5e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t LO_V4[16] = {127, 0, 0, 1};
static const uint8_t LO_V6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t DNS_VIRTUAL[16] = {10, 111, 0, 53};

static sn_tupla tupla_app(int v, uint16_t porta_app, const uint8_t *destino, uint16_t porta_dest) {
    sn_tupla t = {.versao = (uint8_t)v, .protocolo = SN_PROTO_UDP, .porta_origem = porta_app,
                  .porta_destino = porta_dest};
    memcpy(t.ip_origem, v == 4 ? APP_V4 : APP_V6, 16);
    memcpy(t.ip_destino, destino, 16);
    return t;
}

static int manda_udp(sn_banca *b, const sn_tupla *t, const char *texto) {
    uint8_t pkt[2048];
    size_t n = sn_montar_udp(pkt, sizeof pkt, t, (const uint8_t *)texto, strlen(texto));
    return n ? banca_enviar(b, pkt, n) : -1;
}

/* Recebe um pacote do motor e confere: IP/UDP válidos, checksum certo, vindo de
 * `t->destino` para `t->origem` (o sentido inverso da ida). Copia o payload. */
static int recebe_resposta(sn_banca *b, const sn_tupla *t, uint8_t *dados, size_t cap, size_t *n_dados) {
    uint8_t pkt[2048];
    ssize_t n = banca_receber(b, pkt, sizeof pkt, BANCA_TETO_MS);
    if (n <= 0) { fprintf(stderr, "  nenhum pacote do motor\n"); return 0; }
    sn_ip ip;
    if (sn_ip_ler(pkt, (size_t)n, &ip) != SN_OK || ip.protocolo != SN_PROTO_UDP) return 0;
    if (!sn_transporte_checksum_ok(pkt, &ip)) { fprintf(stderr, "  checksum errado\n"); return 0; }
    if (memcmp(ip.origem, t->ip_destino, 16) || memcmp(ip.destino, t->ip_origem, 16)) {
        fprintf(stderr, "  endereços trocados na resposta\n");
        return 0;
    }
    sn_udp u;
    if (sn_udp_ler(pkt + ip.tam_cabecalho, ip.tam_total - ip.tam_cabecalho, &u) != SN_OK) return 0;
    if (u.porta_origem != t->porta_destino || u.porta_destino != t->porta_origem) return 0;
    *n_dados = u.tamanho - 8u;
    if (*n_dados > cap) return 0;
    memcpy(dados, pkt + ip.tam_cabecalho + 8, *n_dados);
    return 1;
}

static sn_config config_base(void) {
    sn_config c = {0};
    c.dns_virtual[0].versao = 4;
    memcpy(c.dns_virtual[0].ip, DNS_VIRTUAL, 16);
    c.n_dns_virtual = 1;
    return c;
}

TESTE(motor_udp_eco_v4) {
    sn_servidor_teste eco;
    CONFERE(servidor_udp_iniciar(&eco, 4, 0) == 0);
    sn_config c = config_base();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_tupla t = tupla_app(4, 40000, LO_V4, eco.porta);
    CONFERE(manda_udp(&b, &t, "ping") == 0);
    uint8_t d[64];
    size_t n = 0;
    int ok = recebe_resposta(&b, &t, d, sizeof d, &n);
    size_t de = 0;
    uint16_t tam;
    const uint8_t *ev = banca_evento(&b, SN_EV_FLUXO_NOVO, &de, &tam, BANCA_TETO_MS);
    banca_fim(&b);
    servidor_udp_parar(&eco);
    CONFERE(ok);
    CONFERE_IGUAL_INT(n, 4);
    CONFERE_IGUAL_MEM(d, "ping", 4);
    CONFERE(ev != NULL);
    CONFERE_IGUAL_INT(tam, 4 + 1 + 1 + 16 + 2 + 16 + 2 + 8);
    CONFERE_IGUAL_INT(le32_ev(ev), 1);    /* id */
    CONFERE_IGUAL_INT(ev[4], 4);          /* versão */
    CONFERE_IGUAL_INT(ev[5], SN_PROTO_UDP);
    CONFERE_IGUAL_MEM(ev + 6, APP_V4, 16);
    CONFERE_IGUAL_INT(le16_ev(ev + 22), 40000);
    CONFERE_IGUAL_MEM(ev + 24, LO_V4, 16);
    CONFERE_IGUAL_INT(le16_ev(ev + 40), eco.porta);
    CONFERE_IGUAL_INT(le64_ev(ev + 42), 1700000000ull * 1000000ull);
}

TESTE(motor_udp_eco_v6) {
    sn_servidor_teste eco;
    if (servidor_udp_iniciar(&eco, 6, 0) != 0)
        PULA("sem IPv6 nesta máquina (::1 indisponível); caminho v6 do tun coberto por motor_dns_virtual_v6");
    sn_config c = config_base();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_tupla t = tupla_app(6, 40001, LO_V6, eco.porta);
    CONFERE(manda_udp(&b, &t, "ola v6") == 0);
    uint8_t d[64];
    size_t n = 0;
    int ok = recebe_resposta(&b, &t, d, sizeof d, &n);
    banca_fim(&b);
    servidor_udp_parar(&eco);
    CONFERE(ok);
    CONFERE_IGUAL_INT(n, 6);
    CONFERE_IGUAL_MEM(d, "ola v6", 6);
}

TESTE(motor_dns_virtual_vai_ao_real_e_gera_evento) {
    sn_servidor_teste dns;
    CONFERE(servidor_udp_iniciar(&dns, 4, 1) == 0);
    sn_config c = config_base();
    c.dns_real[0].endereco.versao = 4;
    memcpy(c.dns_real[0].endereco.ip, LO_V4, 16);
    c.dns_real[0].porta = dns.porta;
    c.n_dns_real = 1;
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    /* consulta qualquer (o DNS falso responde sempre www.exemplo.com) */
    uint8_t consulta[64];
    size_t nf = sn_fixture("dns_consulta", consulta, sizeof consulta);
    sn_tupla t = tupla_app(4, 40002, DNS_VIRTUAL, 53);
    uint8_t pkt[256];
    size_t n = sn_montar_udp(pkt, sizeof pkt, &t, consulta + 28, nf - 28);
    CONFERE(banca_enviar(&b, pkt, n) == 0);
    uint8_t d[512];
    size_t nd = 0;
    int ok = recebe_resposta(&b, &t, d, sizeof d, &nd); /* vem "do" 10.111.0.53:53 */
    size_t de = 0;
    uint16_t tam;
    const uint8_t *ev = banca_evento(&b, SN_EV_DNS, &de, &tam, BANCA_TETO_MS);
    banca_fim(&b);
    servidor_udp_parar(&dns);
    CONFERE(ok);
    CONFERE(nd > 12);
    CONFERE_IGUAL_INT(d[0], consulta[28]); /* mesmo id da consulta */
    CONFERE(ev != NULL);
    CONFERE_IGUAL_INT(le16_ev(ev), 2);    /* 2 endereços */
    CONFERE_IGUAL_INT(ev[2], 4);
    CONFERE_IGUAL_INT(ev[3], 4);
    const uint8_t a1[4] = {93, 184, 215, 14};
    CONFERE_IGUAL_MEM(ev + 4, a1, 4);
    size_t pos_nome = 2 + 2 + 2 * 16;
    CONFERE_IGUAL_INT(le16_ev(ev + pos_nome), 15);
    CONFERE_IGUAL_MEM(ev + pos_nome + 2, "www.exemplo.com", 15);
}

TESTE(motor_dns_virtual_v6_vai_ao_real_v4) {
    /* App em IPv6 pergunta ao DNS virtual fd00:5e:1::53; o motor repassa a um DNS real IPv4.
     * Cobre o lado IPv6 do tun mesmo numa máquina sem IPv6 na rede. */
    static const uint8_t DNS_VIRTUAL_V6[16] = {0xfd, 0, 0, 0x5e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53};
    sn_servidor_teste dns;
    CONFERE(servidor_udp_iniciar(&dns, 4, 1) == 0);
    sn_config c = config_base();
    c.dns_virtual[1].versao = 6;
    memcpy(c.dns_virtual[1].ip, DNS_VIRTUAL_V6, 16);
    c.n_dns_virtual = 2;
    c.dns_real[0].endereco.versao = 4;
    memcpy(c.dns_real[0].endereco.ip, LO_V4, 16);
    c.dns_real[0].porta = dns.porta;
    c.n_dns_real = 1;
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    uint8_t consulta[64];
    size_t nf = sn_fixture("dns_consulta", consulta, sizeof consulta);
    sn_tupla t = tupla_app(6, 40008, DNS_VIRTUAL_V6, 53);
    uint8_t pkt[256];
    size_t n = sn_montar_udp(pkt, sizeof pkt, &t, consulta + 28, nf - 28);
    CONFERE(banca_enviar(&b, pkt, n) == 0);
    uint8_t d[512];
    size_t nd = 0;
    int ok = recebe_resposta(&b, &t, d, sizeof d, &nd); /* IPv6, vindo de fd00:5e:1::53 */
    banca_fim(&b);
    servidor_udp_parar(&dns);
    CONFERE(ok);
    CONFERE(nd > 12);
}

TESTE(motor_troca_de_dns_no_meio_da_sessao) {
    /* A rede mudou (Wi-Fi -> dados): o Kotlin manda os DNS novos e a próxima consulta vai
     * para eles. Os dois "DNS" respondem igual; o que muda é quem recebe. */
    sn_servidor_teste dns1, dns2;
    CONFERE(servidor_udp_iniciar(&dns1, 4, 1) == 0);
    CONFERE(servidor_udp_iniciar(&dns2, 4, 1) == 0);
    sn_config c = config_base();
    c.dns_real[0].endereco.versao = 4;
    memcpy(c.dns_real[0].endereco.ip, LO_V4, 16);
    c.dns_real[0].porta = dns1.porta;
    c.n_dns_real = 1;
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    uint8_t consulta[64];
    size_t nf = sn_fixture("dns_consulta", consulta, sizeof consulta);
    uint8_t pkt[256], d[512];
    size_t n, nd;
    sn_tupla t1 = tupla_app(4, 40010, DNS_VIRTUAL, 53);
    n = sn_montar_udp(pkt, sizeof pkt, &t1, consulta + 28, nf - 28);
    banca_enviar(&b, pkt, n);
    int ok1 = recebe_resposta(&b, &t1, d, sizeof d, &nd);

    sn_servidor novo = {.porta = dns2.porta};
    novo.endereco.versao = 4;
    memcpy(novo.endereco.ip, LO_V4, 16);
    sn_motor_trocar_dns(b.m, &novo, 1);
    servidor_udp_parar(&dns1); /* o DNS antigo some, como o roteador fora de alcance */

    sn_tupla t2 = tupla_app(4, 40011, DNS_VIRTUAL, 53);
    n = sn_montar_udp(pkt, sizeof pkt, &t2, consulta + 28, nf - 28);
    banca_enviar(&b, pkt, n);
    int ok2 = recebe_resposta(&b, &t2, d, sizeof d, &nd);
    banca_fim(&b);
    servidor_udp_parar(&dns2);
    CONFERE(ok1);
    CONFERE(ok2);
}

TESTE(motor_udp_expira_com_bytes_e_fim) {
    sn_servidor_teste eco;
    CONFERE(servidor_udp_iniciar(&eco, 4, 0) == 0);
    sn_config c = config_base();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_tupla t = tupla_app(4, 40003, LO_V4, eco.porta);
    manda_udp(&b, &t, "abc");
    uint8_t d[64];
    size_t n;
    int ok = recebe_resposta(&b, &t, d, sizeof d, &n);
    banca_avancar(&b, SN_UDP_OCIOSO_US + 1000000);
    size_t de = 0;
    uint16_t tam;
    const uint8_t *fim = banca_evento(&b, SN_EV_FLUXO_FIM, &de, &tam, BANCA_TETO_MS);
    uint8_t motivo = fim ? fim[12] : 0xff;
    size_t de_b = 0;
    const uint8_t *bytes = banca_evento(&b, SN_EV_FLUXO_BYTES, &de_b, &tam, 0);
    uint64_t env = bytes ? le64_ev(bytes + 4) : 0, rec = bytes ? le64_ev(bytes + 12) : 0;
    uint32_t pacotes = bytes ? le32_ev(bytes + 20) : 0;
    banca_fim(&b);
    servidor_udp_parar(&eco);
    CONFERE(ok);
    CONFERE(fim != NULL);
    CONFERE_IGUAL_INT(motivo, SN_FIM_TEMPO);
    CONFERE(bytes != NULL);
    CONFERE(de_b < de); /* bytes antes do fim */
    CONFERE_IGUAL_INT(env, 3);
    CONFERE_IGUAL_INT(rec, 3);
    CONFERE_IGUAL_INT(pacotes, 2);
}

TESTE(motor_encerrar_fecha_fluxos_abertos) {
    sn_servidor_teste eco;
    CONFERE(servidor_udp_iniciar(&eco, 4, 0) == 0);
    sn_config c = config_base();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_tupla t = tupla_app(4, 40004, LO_V4, eco.porta);
    manda_udp(&b, &t, "x");
    uint8_t d[64];
    size_t n;
    int ok = recebe_resposta(&b, &t, d, sizeof d, &n);
    banca_parar(&b);
    size_t de = 0;
    uint16_t tam;
    const uint8_t *fim = banca_evento(&b, SN_EV_FLUXO_FIM, &de, &tam, 0);
    uint8_t motivo = fim ? fim[12] : 0xff;
    int ret = b.ret;
    banca_fim(&b);
    servidor_udp_parar(&eco);
    CONFERE(ok);
    CONFERE_IGUAL_INT(ret, 0);
    CONFERE(fim != NULL);
    CONFERE_IGUAL_INT(motivo, SN_FIM_SESSAO); /* cortado pelo fim da gravação, não fechado pelo app */
}

static uint64_t mono_real_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

TESTE(motor_para_sem_trafego_em_menos_de_1s) {
    sn_config c = config_base();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    uint64_t t0 = mono_real_ms();
    banca_parar(&b); /* volta só se o motor acordou com o pedido de parada */
    uint64_t gasto = mono_real_ms() - t0;
    int ret = b.ret;
    banca_fim(&b);
    CONFERE_IGUAL_INT(ret, 0);
    CONFERE(gasto < 1000);
}

TESTE(motor_hora_voltando_nao_expira_fluxos) {
    sn_servidor_teste eco;
    CONFERE(servidor_udp_iniciar(&eco, 4, 0) == 0);
    sn_config c = config_base();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_tupla t = tupla_app(4, 40009, LO_V4, eco.porta);
    manda_udp(&b, &t, "a");
    uint8_t d[64];
    size_t n;
    int ok = recebe_resposta(&b, &t, d, sizeof d, &n);
    banca_ajustar_hora(&b, -3600ll * 1000000); /* Android acertou a hora: voltou 1 h */
    banca_avancar(&b, 2000000);                /* e passaram 2 s de verdade */
    /* prova de vida: o mesmo fluxo continua respondendo, sem FIM no meio */
    manda_udp(&b, &t, "b");
    int ok2 = recebe_resposta(&b, &t, d, sizeof d, &n);
    banca_avancar(&b, 2000000);
    manda_udp(&b, &t, "c");
    int ok3 = recebe_resposta(&b, &t, d, sizeof d, &n);
    int fins = banca_conta(&b, SN_EV_FLUXO_FIM);
    int novos = banca_conta(&b, SN_EV_FLUXO_NOVO);
    banca_fim(&b);
    servidor_udp_parar(&eco);
    CONFERE(ok && ok2 && ok3);
    CONFERE_IGUAL_INT(fins, 0);
    CONFERE_IGUAL_INT(novos, 1);
}

TESTE(motor_tun_fechado_do_outro_lado_encerra) {
    sn_config c = config_base();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    close(b.app_fd); /* o "Android" fechou o tun */
    b.app_fd = -1;
    uint64_t t0 = mono_real_ms();
    pthread_join(b.thread, NULL);
    uint64_t gasto = mono_real_ms() - t0;
    b.rodando = 0;
    int ret = b.ret;
    banca_fim(&b);
    CONFERE_IGUAL_INT(ret, -1);
    CONFERE(gasto < BANCA_TETO_MS);
}

static int conta_pcap(void *ctx, uint64_t q, const uint8_t *p, size_t n) {
    (void)q; (void)p; (void)n;
    (*(int *)ctx)++;
    return 0;
}

TESTE(motor_grava_ida_e_volta_no_pcap) {
    sn_servidor_teste eco;
    CONFERE(servidor_udp_iniciar(&eco, 4, 0) == 0);
    char caminho[256];
    snprintf(caminho, sizeof caminho, "/tmp/sn-motor-XXXXXX");
    int fd = mkstemp(caminho);
    close(fd);
    sn_config c = config_base();
    c.caminho_pcap = caminho;
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_tupla t = tupla_app(4, 40005, LO_V4, eco.porta);
    manda_udp(&b, &t, "gravar");
    uint8_t d[64];
    size_t n;
    int ok = recebe_resposta(&b, &t, d, sizeof d, &n);
    banca_fim(&b); /* fecha o pcap */
    servidor_udp_parar(&eco);
    int pacotes = 0;
    long r = sn_pcap_ler(caminho, conta_pcap, &pacotes);
    unlink(caminho);
    CONFERE(ok);
    CONFERE_IGUAL_INT(r, 2);
}

TESTE(motor_forcar_tcp_descarta_quic) {
    sn_servidor_teste eco;
    CONFERE(servidor_udp_iniciar(&eco, 4, 0) == 0);
    sn_config c = config_base();
    c.forcar_tcp = 1;
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_tupla quic = tupla_app(4, 40006, LO_V4, 443);
    manda_udp(&b, &quic, "quic");
    sn_tupla t = tupla_app(4, 40007, LO_V4, eco.porta); /* o motor trata em ordem: */
    manda_udp(&b, &t, "depois");                          /* quando este volta, o QUIC já passou */
    uint8_t d[64];
    size_t n;
    int ok = recebe_resposta(&b, &t, d, sizeof d, &n);
    int novos = banca_conta(&b, SN_EV_FLUXO_NOVO);
    banca_fim(&b);
    servidor_udp_parar(&eco);
    CONFERE(ok);
    CONFERE_IGUAL_INT(novos, 1); /* só o fluxo do eco */
}

/* v1.2 (epoll): muitos fluxos abertos ao mesmo tempo; cada um recebe o seu eco. */
TESTE(motor_muitos_fluxos_udp) {
    enum { N = 300 };
    sn_servidor_teste eco;
    CONFERE(servidor_udp_iniciar(&eco, 4, 0) == 0);
    sn_config c = config_base();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    static uint8_t visto[N];
    memset(visto, 0, sizeof visto);
    int recebidos = 0;
    for (int i = 0; i < N; i++) {
        sn_tupla t = tupla_app(4, (uint16_t)(41000 + i), LO_V4, eco.porta);
        manda_udp(&b, &t, "m");
    }
    for (int i = 0; i < N; i++) {
        uint8_t pkt[2048];
        ssize_t n = banca_receber(&b, pkt, sizeof pkt, BANCA_TETO_MS);
        if (n <= 0)
            break;
        sn_ip ip;
        sn_udp u;
        if (sn_ip_ler(pkt, (size_t)n, &ip) != SN_OK ||
            sn_udp_ler(pkt + ip.tam_cabecalho, ip.tam_total - ip.tam_cabecalho, &u) != SN_OK)
            continue;
        int k = (int)u.porta_destino - 41000;
        if (k >= 0 && k < N && !visto[k]) {
            visto[k] = 1;
            recebidos++;
        }
    }
    banca_fim(&b);
    servidor_udp_parar(&eco);
    CONFERE_IGUAL_INT(recebidos, N);
}

/* v1.2 (epoll): expira, fecha o socket e abre outro fluxo, três vezes; cada novo fluxo tem que
 * ser acordado pelo laço (o número do descritor costuma voltar, mas o teste não depende disso). */
TESTE(motor_fd_reusado) {
    sn_servidor_teste eco;
    CONFERE(servidor_udp_iniciar(&eco, 4, 0) == 0);
    sn_config c = config_base();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    int ok = 1;
    for (int i = 0; i < 3 && ok; i++) {
        sn_tupla t = tupla_app(4, (uint16_t)(42000 + i), LO_V4, eco.porta);
        manda_udp(&b, &t, "r");
        uint8_t d[64];
        size_t n = 0;
        ok = recebe_resposta(&b, &t, d, sizeof d, &n) && n == 1;
        banca_avancar(&b, SN_UDP_OCIOSO_US + 1000000); /* expira e fecha o socket */
        size_t de = 0;
        uint16_t tam;
        for (int k = 0; k <= i && ok; k++)
            ok = banca_evento(&b, SN_EV_FLUXO_FIM, &de, &tam, BANCA_TETO_MS) != NULL;
    }
    banca_fim(&b);
    servidor_udp_parar(&eco);
    CONFERE(ok);
}
