/* Dissecador: mostra um pacote camada por camada, como o painel de detalhes do Wireshark.
 * Contrato em include/sn_dissecar.h. Reaproveita os parsers das Tarefas 1, 2 e 4 — ele só
 * formata o que eles já sabem ler. Aulas 04 e 06. */
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "bytes.h"
#include "sn_dissecar.h"
#include "sn_nomes.h"
#include "sn_transporte.h"

enum { MAX_DADOS = 256 };

typedef struct {
    char *s;
    size_t cap, n;
} saida;

/* Acrescenta texto formatado, cortando se não couber; mantém sempre o '\0'. */
static void escreve(saida *o, const char *fmt, ...) {
    if (o->n + 1 >= o->cap)
        return;
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(o->s + o->n, o->cap - o->n, fmt, ap);
    va_end(ap);
    if (r < 0)
        return;
    size_t k = (size_t)r;
    o->n = o->n + k < o->cap - 1 ? o->n + k : o->cap - 1;
}

static void texto_ip(uint8_t versao, const uint8_t *ip, char *dst, size_t cap) {
    inet_ntop(versao == 4 ? AF_INET : AF_INET6, ip, dst, (socklen_t)cap);
}

static const char *nome_proto(uint8_t p) {
    return p == SN_PROTO_TCP ? "TCP" : p == SN_PROTO_UDP ? "UDP" : p == 1 ? "ICMP" : p == 58 ? "ICMPv6" : "?";
}

/* "SYN, ACK" a partir das flags. */
static void texto_flags(uint8_t f, char *dst, size_t cap) {
    static const struct { uint8_t bit; const char *nome; } tab[] = {
        {SN_TCP_FIN, "FIN"}, {SN_TCP_SYN, "SYN"}, {SN_TCP_RST, "RST"}, {SN_TCP_PSH, "PSH"}, {SN_TCP_ACK, "ACK"},
    };
    dst[0] = '\0';
    size_t n = 0;
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++) {
        if (!(f & tab[i].bit))
            continue;
        int r = snprintf(dst + n, cap - n, "%s%s", n ? ", " : "", tab[i].nome);
        if (r < 0 || (size_t)r >= cap - n)
            break;
        n += (size_t)r;
    }
}

static void dados_hex(saida *o, const uint8_t *d, size_t n) {
    if (n == 0)
        return;
    escreve(o, "\nDados (%zu bytes)\n", n);
    size_t mostra = n < MAX_DADOS ? n : MAX_DADOS;
    for (size_t i = 0; i < mostra; i += 16) {
        escreve(o, "  %04zx  ", i);
        for (size_t k = 0; k < 16; k++)
            if (i + k < mostra)
                escreve(o, "%02x ", d[i + k]);
            else
                escreve(o, "   ");
        escreve(o, " ");
        for (size_t k = 0; k < 16 && i + k < mostra; k++)
            escreve(o, "%c", d[i + k] >= 0x20 && d[i + k] < 0x7f ? d[i + k] : '.');
        escreve(o, "\n");
    }
    if (mostra < n)
        escreve(o, "  … (+%zu bytes)\n", n - mostra);
}

static void camada_dns(saida *o, const uint8_t *d, size_t n) {
    sn_dns_resposta r;
    int ret = sn_dns_ler_resposta(d, n, &r);
    if (ret == SN_ERR_FORMATO && n >= 12 && !(d[2] & 0x80)) {
        escreve(o, "\nDNS\n  Tipo: consulta\n  Id: 0x%04x\n", (unsigned)be16(d));
        return;
    }
    if (ret != SN_OK)
        return;
    escreve(o, "\nDNS\n  Tipo: resposta\n  Id: 0x%04x\n  Nome: %s\n", r.id, r.nome);
    for (int i = 0; i < r.n_enderecos; i++) {
        char ip[INET6_ADDRSTRLEN];
        texto_ip(r.enderecos[i].versao, r.enderecos[i].ip, ip, sizeof ip);
        escreve(o, "  Endereço: %s\n", ip);
    }
}

size_t sn_dissecar(const uint8_t *p, size_t n, char *s, size_t cap) {
    saida o = {s, cap, 0};
    if (cap == 0)
        return 0;
    s[0] = '\0';

    sn_ip ip;
    int r = sn_ip_ler(p, n, &ip);
    if (r != SN_OK) {
        escreve(&o, "Resumo: pacote %s (%zu bytes)\n", r == SN_ERR_FRAGMENTO ? "fragmentado" : "inválido ou cortado", n);
        dados_hex(&o, p, n);
        return o.n;
    }
    char ori[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    texto_ip(ip.versao, ip.origem, ori, sizeof ori);
    texto_ip(ip.versao, ip.destino, dst, sizeof dst);
    const uint8_t *l4 = p + ip.tam_cabecalho;
    size_t n4 = ip.tam_total - ip.tam_cabecalho;

    /* Lê o transporte antes, para montar o resumo. */
    sn_udp u;
    sn_tcp t;
    int udp_ok = ip.protocolo == SN_PROTO_UDP && sn_udp_ler(l4, n4, &u) == SN_OK;
    int tcp_ok = ip.protocolo == SN_PROTO_TCP && sn_tcp_ler(l4, n4, &t) == SN_OK;
    char flags[48] = "";
    if (tcp_ok)
        texto_flags(t.flags, flags, sizeof flags);
    const char *fmt_ip = ip.versao == 6 ? "[%s]:%u" : "%s:%u";
    char a[64], b[64];
    if (udp_ok || tcp_ok) {
        snprintf(a, sizeof a, fmt_ip, ori, udp_ok ? u.porta_origem : t.porta_origem);
        snprintf(b, sizeof b, fmt_ip, dst, udp_ok ? u.porta_destino : t.porta_destino);
    } else {
        snprintf(a, sizeof a, "%s", ori);
        snprintf(b, sizeof b, "%s", dst);
    }
    size_t dados = udp_ok ? (size_t)u.tamanho - 8 : tcp_ok ? n4 - t.tam_cabecalho : 0;
    escreve(&o, "Resumo: %s %s → %s", nome_proto(ip.protocolo), a, b);
    if (tcp_ok)
        escreve(&o, " [%s]", flags);
    escreve(&o, " %zu bytes de dados\n", dados);

    /* IP */
    if (ip.versao == 4) {
        uint16_t campo = be16(p + 10);
        int ok = sn_checksum(p, ip.tam_cabecalho, 0) == 0;
        escreve(&o, "\nIPv4\n  Versão: 4\n  Tamanho do cabeçalho: %u\n  Tamanho total: %u\n", ip.tam_cabecalho, ip.tam_total);
        escreve(&o, "  Identificação: 0x%04x\n  Não fragmentar: %s\n", (unsigned)be16(p + 4), (p[6] & 0x40) ? "sim" : "não");
        escreve(&o, "  TTL: %u\n  Protocolo: %u (%s)\n", ip.ttl, ip.protocolo, nome_proto(ip.protocolo));
        escreve(&o, "  Checksum: 0x%04x [%s]\n", campo, ok ? "correto" : "errado");
    } else {
        escreve(&o, "\nIPv6\n  Versão: 6\n  Tamanho do payload: %u\n", ip.tam_total - 40u);
        escreve(&o, "  Hop limit: %u\n  Próximo cabeçalho: %u (%s)\n", ip.ttl, ip.protocolo, nome_proto(ip.protocolo));
        if (ip.tam_cabecalho > 40)
            escreve(&o, "  Extensões: %u bytes\n", ip.tam_cabecalho - 40u);
    }
    escreve(&o, "  Origem: %s\n  Destino: %s\n", ori, dst);

    /* Transporte */
    const uint8_t *app = NULL;
    if (udp_ok) {
        uint16_t campo = be16(l4 + 6);
        escreve(&o, "\nUDP\n  Porta de origem: %u\n  Porta de destino: %u\n  Tamanho: %u\n",
                u.porta_origem, u.porta_destino, u.tamanho);
        escreve(&o, "  Checksum: 0x%04x [%s]\n", campo, sn_transporte_checksum_ok(p, &ip) ? "correto" : "errado");
        app = l4 + 8;
        if (u.porta_origem == 53 || u.porta_destino == 53)
            camada_dns(&o, app, dados);
    } else if (tcp_ok) {
        uint16_t campo = be16(l4 + 16);
        escreve(&o, "\nTCP\n  Porta de origem: %u\n  Porta de destino: %u\n", t.porta_origem, t.porta_destino);
        escreve(&o, "  Sequência: %u\n  Confirmação: %u\n", t.seq, t.ack);
        escreve(&o, "  Flags: 0x%03x (%s)\n  Janela: %u\n  Tamanho do cabeçalho: %u\n", t.flags, flags, t.janela, t.tam_cabecalho);
        if (t.mss)
            escreve(&o, "  MSS: %u\n", t.mss);
        escreve(&o, "  Checksum: 0x%04x [%s]\n", campo, sn_transporte_checksum_ok(p, &ip) ? "correto" : "errado");
        app = l4 + t.tam_cabecalho;
        char sni[SN_NOME_MAX + 1];
        if (dados && sn_tls_sni(app, dados, sni, sizeof sni) == SN_OK)
            escreve(&o, "\nTLS ClientHello\n  SNI: %s\n", sni);
    } else {
        app = l4;
        dados = n4;
    }
    dados_hex(&o, app, dados);
    return o.n;
}
