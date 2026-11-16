/* Testes da Tarefa 7: relé TCP. O teste é o app (mini cliente TCP montando segmentos à mão)
 * e conversa com servidores TCP locais de verdade através do motor. */
#include <stdlib.h>

#include "banca_tcp.h"
#include "sn_fluxos.h"
#include "teste.h"

static sn_config config_tcp(void) {
    sn_config c = {0};
    return c;
}

TESTE(tcp_handshake_responde_synack_com_mss) {
    sn_servidor_tcp s = {0};
    CONFERE(servidor_tcp_iniciar(&s, SRV_ECO) == 0);
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41000, s.porta);
    int r = cli_conectar(&b, &cli);
    uint16_t mss = cli.mss_motor;
    size_t de = 0;
    uint16_t tam;
    const uint8_t *ev = banca_evento(&b, SN_EV_FLUXO_NOVO, &de, &tam, BANCA_TETO_MS);
    uint8_t proto = ev ? ev[5] : 0;
    cli_fin(&b, &cli);
    cli_receber(&b, &cli, 0);
    banca_fim(&b);
    servidor_tcp_esperar(&s);
    cli_liberar(&cli);
    CONFERE_IGUAL_INT(r, 0);
    CONFERE(mss >= 536 && mss <= 1460);
    CONFERE_IGUAL_INT(proto, SN_PROTO_TCP);
}

TESTE(tcp_porta_fechada_recebe_rst) {
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41001, porta_fechada());
    int r = cli_conectar(&b, &cli);
    int rst = cli.rst_recebido;
    banca_parar(&b);
    size_t de = 0;
    uint16_t tam;
    const uint8_t *fim = banca_evento(&b, SN_EV_FLUXO_FIM, &de, &tam, 0);
    uint8_t motivo = fim ? fim[12] : 0xff;
    banca_fim(&b);
    cli_liberar(&cli);
    CONFERE_IGUAL_INT(r, -1);
    CONFERE(rst);
    CONFERE_IGUAL_INT(motivo, SN_FIM_ERRO);
}

TESTE(tcp_eco_e_fechamento_dos_dois_lados) {
    sn_servidor_tcp s = {0};
    CONFERE(servidor_tcp_iniciar(&s, SRV_ECO) == 0);
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41002, s.porta);
    int ok = cli_conectar(&b, &cli) == 0 && cli_enviar(&b, &cli, "hello", 5) == 0 &&
             cli_receber(&b, &cli, 5) == 0;
    int eco = ok && cli.n_rx == 5 && memcmp(cli.rx, "hello", 5) == 0;
    cli_fin(&b, &cli);           /* app fecha -> servidor vê EOF -> fecha -> FIN para o app */
    cli_receber(&b, &cli, 0);
    int fin = cli.fin_recebido;
    /* espera o motor ver o ACK do FIN dele; fecha e o encerrar emite FIM com o motivo */
    while (cli_processa(&b, &cli, 200)) {}
    banca_parar(&b);
    size_t de = 0;
    uint16_t tam;
    const uint8_t *fim = banca_evento(&b, SN_EV_FLUXO_FIM, &de, &tam, 0);
    uint8_t motivo = fim ? fim[12] : 0xff;
    size_t de_b = 0;
    const uint8_t *bytes = banca_evento(&b, SN_EV_FLUXO_BYTES, &de_b, &tam, 0);
    uint64_t env = bytes ? le64_ev(bytes + 4) : 0, rec = bytes ? le64_ev(bytes + 12) : 0;
    banca_fim(&b);
    servidor_tcp_esperar(&s);
    cli_liberar(&cli);
    CONFERE(ok);
    CONFERE(eco);
    CONFERE(fin);
    CONFERE_IGUAL_INT(motivo, SN_FIM_FECHADO);
    CONFERE_IGUAL_INT(env, 5);
    CONFERE_IGUAL_INT(rec, 5);
}

TESTE(tcp_um_mega_do_app_para_o_servidor) {
    sn_servidor_tcp s = {0};
    CONFERE(servidor_tcp_iniciar(&s, SRV_SUMIDOURO) == 0);
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41003, s.porta);
    size_t n = 1 << 20;
    uint8_t *d = malloc(n);
    for (size_t i = 0; i < n; i++) d[i] = dado(i);
    uint64_t esperado = fnv64(FNV64_INICIO, d, n);
    int ok = cli_conectar(&b, &cli) == 0 && cli_enviar(&b, &cli, d, n) == 0;
    free(d);
    cli_fin(&b, &cli);
    cli_receber(&b, &cli, 0); /* o sumidouro responde (bytes, hash) e fecha */
    uint64_t recebidos = 0, hash = 0;
    if (cli.n_rx == 16) {
        memcpy(&recebidos, cli.rx, 8);
        memcpy(&hash, cli.rx + 8, 8);
    }
    banca_fim(&b);
    servidor_tcp_esperar(&s);
    cli_liberar(&cli);
    CONFERE(ok);
    CONFERE_IGUAL_INT(recebidos, n);
    CONFERE(hash == esperado);
}

TESTE(tcp_um_mega_do_servidor_para_o_app) {
    sn_servidor_tcp s = {.n_fonte = 1 << 20};
    CONFERE(servidor_tcp_iniciar(&s, SRV_FONTE) == 0);
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41004, s.porta);
    int ok = cli_conectar(&b, &cli) == 0 && cli_receber(&b, &cli, 0) == 0;
    int certo = cli.n_rx == (1u << 20);
    for (size_t i = 0; certo && i < cli.n_rx; i++)
        if (cli.rx[i] != dado(i)) certo = 0;
    int fin = cli.fin_recebido;
    cli_fin(&b, &cli);
    banca_fim(&b);
    servidor_tcp_esperar(&s);
    cli_liberar(&cli);
    CONFERE(ok);
    CONFERE(certo);
    CONFERE(fin);
}

TESTE(tcp_janela_zero_pausa_e_reabre) {
    sn_servidor_tcp s = {.n_fonte = 200000};
    CONFERE(servidor_tcp_iniciar(&s, SRV_FONTE) == 0);
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41005, s.porta);
    cli.janela = 4000; /* janela pequena: o motor só pode mandar 4000 bytes sem confirmação */
    int ok = cli_conectar(&b, &cli) == 0;
    /* não confirma nada: lê pacotes "na mão" sem responder */
    uint8_t pkt[4096];
    size_t recebido = 0;
    ssize_t n;
    while ((n = banca_receber(&b, pkt, sizeof pkt, 300)) > 0) {
        sn_ip ip;
        sn_tcp t;
        if (sn_ip_ler(pkt, (size_t)n, &ip) == SN_OK &&
            sn_tcp_ler(pkt + ip.tam_cabecalho, ip.tam_total - ip.tam_cabecalho, &t) == SN_OK)
            recebido += ip.tam_total - ip.tam_cabecalho - t.tam_cabecalho;
    }
    int respeitou = recebido > 0 && recebido <= 4000;
    /* reabre: anuncia janela grande e pede retransmissão a partir do que tem (ack = início) */
    cli.janela = 65535;
    cli_segmento(&b, &cli, cli.seq, SN_TCP_ACK, NULL, 0);
    cli_receber(&b, &cli, 0);
    int completo = cli.n_rx == 200000;
    cli_fin(&b, &cli);
    banca_fim(&b);
    servidor_tcp_esperar(&s);
    cli_liberar(&cli);
    CONFERE(ok);
    CONFERE(respeitou);
    CONFERE(completo);
}

TESTE(tcp_retransmissao_do_app_nao_duplica) {
    sn_servidor_tcp s = {0};
    CONFERE(servidor_tcp_iniciar(&s, SRV_SUMIDOURO) == 0);
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41006, s.porta);
    int ok = cli_conectar(&b, &cli) == 0;
    cli_segmento(&b, &cli, cli.seq, SN_TCP_ACK | SN_TCP_PSH, "abcdef", 6);
    cli_segmento(&b, &cli, cli.seq, SN_TCP_ACK | SN_TCP_PSH, "abcdef", 6); /* repetido */
    cli_segmento(&b, &cli, cli.seq + 3, SN_TCP_ACK | SN_TCP_PSH, "defghi", 6); /* sobrepõe */
    cli.seq += 9;
    cli_fin(&b, &cli);
    cli_receber(&b, &cli, 0);
    uint64_t recebidos = 0, hash = 0;
    if (cli.n_rx == 16) {
        memcpy(&recebidos, cli.rx, 8);
        memcpy(&hash, cli.rx + 8, 8);
    }
    banca_fim(&b);
    servidor_tcp_esperar(&s);
    cli_liberar(&cli);
    CONFERE(ok);
    CONFERE_IGUAL_INT(recebidos, 9);
    CONFERE(hash == fnv64(FNV64_INICIO, (const uint8_t *)"abcdefghi", 9));
}

TESTE(tcp_rst_do_app_derruba_o_servidor) {
    sn_servidor_tcp s = {0};
    CONFERE(servidor_tcp_iniciar(&s, SRV_ECO) == 0);
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41007, s.porta);
    int ok = cli_conectar(&b, &cli) == 0 && cli_enviar(&b, &cli, "x", 1) == 0;
    cli_segmento(&b, &cli, cli.seq, SN_TCP_RST, NULL, 0);
    servidor_tcp_esperar(&s); /* o servidor sai: tem de ser por RST, não por FIN */
    int reset = s.erro_reset;
    banca_parar(&b);
    size_t de = 0;
    uint16_t tam;
    const uint8_t *fim = banca_evento(&b, SN_EV_FLUXO_FIM, &de, &tam, 0);
    uint8_t motivo = fim ? fim[12] : 0xff;
    banca_fim(&b);
    cli_liberar(&cli);
    CONFERE(ok);
    CONFERE(reset); /* RST do app chega ao servidor como RST (upload abortado não parece completo) */
    CONFERE_IGUAL_INT(motivo, SN_FIM_RESET);
}

TESTE(tcp_uma_perda_nao_vira_tempestade) {
    sn_servidor_tcp s = {.n_fonte = 400000};
    CONFERE(servidor_tcp_iniciar(&s, SRV_FONTE) == 0);
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41010, s.porta);
    cli.descartar = 3; /* o 3º segmento de dados se perde */
    int ok = cli_conectar(&b, &cli) == 0 && cli_receber(&b, &cli, 400000) == 0;
    int certo = cli.n_rx == 400000;
    for (size_t i = 0; certo && i < cli.n_rx; i++)
        if (cli.rx[i] != dado(i)) certo = 0;
    uint64_t vistos = cli.bytes_vistos;
    cli_fin(&b, &cli);
    banca_fim(&b);
    servidor_tcp_esperar(&s);
    cli_liberar(&cli);
    CONFERE(ok);
    CONFERE(certo);
    /* reenvio proporcional à perda: no máximo 50% a mais que o necessário */
    CONFERE(vistos < 600000);
}

TESTE(tcp_keepalive_do_app_recebe_ack) {
    sn_servidor_tcp s = {0};
    CONFERE(servidor_tcp_iniciar(&s, SRV_ECO) == 0);
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41011, s.porta);
    int ok = cli_conectar(&b, &cli) == 0;
    int antes = cli.acks_recebidos;
    cli_segmento(&b, &cli, cli.seq - 1, SN_TCP_ACK, NULL, 0); /* sonda de keepalive do Linux */
    cli_processa(&b, &cli, BANCA_TETO_MS);
    int respondeu = cli.acks_recebidos > antes;
    cli_fin(&b, &cli);
    cli_receber(&b, &cli, 0);
    banca_fim(&b);
    servidor_tcp_esperar(&s);
    cli_liberar(&cli);
    CONFERE(ok);
    CONFERE(respondeu);
}

TESTE(tcp_motor_sonda_janela_fechada_do_app) {
    sn_servidor_tcp s = {.n_fonte = 100000};
    CONFERE(servidor_tcp_iniciar(&s, SRV_FONTE) == 0);
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41012, s.porta);
    int ok = cli_conectar(&b, &cli) == 0;
    cli.janela = 0;
    cli_segmento(&b, &cli, cli.seq, SN_TCP_ACK, NULL, 0); /* fecha a janela */
    while (cli_processa(&b, &cli, 300)) {}
    cli.janela = 65535; /* reabre, mas o aviso "se perde": não manda nada */
    banca_avancar(&b, 3000000);
    int recebeu = cli_receber(&b, &cli, 100000) == 0 && cli.n_rx == 100000;
    cli_fin(&b, &cli);
    banca_fim(&b);
    servidor_tcp_esperar(&s);
    cli_liberar(&cli);
    CONFERE(ok);
    CONFERE(recebeu); /* a sonda do motor recebe a janela nova e o envio volta */
}

TESTE(tcp_segmento_sem_fluxo_recebe_rst) {
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41008, 9);
    cli_segmento(&b, &cli, 5000, SN_TCP_ACK, "?", 1);
    cli_processa(&b, &cli, BANCA_TETO_MS);
    int rst = cli.rst_recebido;
    int novos = banca_conta(&b, SN_EV_FLUXO_NOVO);
    banca_fim(&b);
    cli_liberar(&cli);
    CONFERE(rst);
    CONFERE_IGUAL_INT(novos, 0);
}

TESTE(tcp_sni_em_dois_segmentos) {
    sn_servidor_tcp s = {0};
    CONFERE(servidor_tcp_iniciar(&s, SRV_SUMIDOURO) == 0);
    sn_config c = config_tcp();
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41009, s.porta);
    uint8_t p[2048];
    size_t n = sn_fixture("tls_client_hello_sni", p, sizeof p);
    const uint8_t *ch = p + 40; /* IPv4 20 + TCP 20 */
    size_t n_ch = n - 40;
    int ok = cli_conectar(&b, &cli) == 0 && cli_enviar(&b, &cli, ch, n_ch) == 0; /* parte em 1400 + resto */
    size_t de = 0;
    uint16_t tam;
    const uint8_t *ev = banca_evento(&b, SN_EV_SNI, &de, &tam, BANCA_TETO_MS);
    char nome[64] = {0};
    if (ev && tam >= 6 && le16_ev(ev + 4) < sizeof nome)
        memcpy(nome, ev + 6, le16_ev(ev + 4));
    cli_fin(&b, &cli);
    cli_receber(&b, &cli, 0);
    banca_fim(&b);
    servidor_tcp_esperar(&s);
    cli_liberar(&cli);
    CONFERE(ok);
    CONFERE(ev != NULL);
    CONFERE(strcmp(nome, "www.exemplo.com.br") == 0);
}

TESTE(tcp_dns_virtual_vai_ao_dns_real) {
    /* Resposta UDP truncada faz o resolvedor repetir por TCP no DNS virtual: o motor tem de
     * levar essa conexão ao DNS real, como faz no UDP. */
    sn_servidor_tcp s = {0};
    CONFERE(servidor_tcp_iniciar(&s, SRV_ECO) == 0);
    sn_config c = config_tcp();
    c.dns_virtual[0].versao = 4;
    c.dns_virtual[0].ip[0] = 10; c.dns_virtual[0].ip[1] = 111; c.dns_virtual[0].ip[3] = 53;
    c.n_dns_virtual = 1;
    c.dns_real[0].endereco.versao = 4;
    c.dns_real[0].endereco.ip[0] = 127; c.dns_real[0].endereco.ip[3] = 1;
    c.dns_real[0].porta = s.porta; /* o "DNS real" é o eco local */
    c.n_dns_real = 1;
    sn_banca b;
    CONFERE(banca_iniciar(&b, &c) == 0);
    sn_cliente cli;
    cli_iniciar(&cli, 41020, 53);
    const uint8_t virt[16] = {10, 111, 0, 53};
    memcpy(cli.t.ip_destino, virt, 16);
    int ok = cli_conectar(&b, &cli) == 0 && cli_enviar(&b, &cli, "dns", 3) == 0 && cli_receber(&b, &cli, 3) == 0;
    int eco = cli.n_rx == 3 && memcmp(cli.rx, "dns", 3) == 0;
    cli_fin(&b, &cli);
    cli_receber(&b, &cli, 0);
    banca_fim(&b);
    servidor_tcp_esperar(&s);
    cli_liberar(&cli);
    CONFERE(ok);
    CONFERE(eco);
}
