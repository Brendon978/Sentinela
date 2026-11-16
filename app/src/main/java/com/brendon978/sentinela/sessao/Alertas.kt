package com.brendon978.sentinela.sessao

import com.brendon978.sentinela.ia.Atributos
import java.time.Instant
import java.time.ZoneId

/** As regras fixas da v1 (o lado "regras" da comparação regras × IA do artigo). */
enum class Regra(val titulo: String) {
    MADRUGADA_OU_TELA_DESLIGADA("Atividade de madrugada ou com a tela desligada"),
    DOMINIO_NOVO("Domínio nunca visto para este app"),
    RASTREADOR("Rastreador conhecido"),
    PORTA_INCOMUM("Porta incomum"),
    DNS_ESCONDIDO("DNS fora do caminho normal (DoT, DoH ou DNS direto)"),
    COMPORTAMENTO_ANOMALO("Comportamento fora do padrão do app (IA)"),
}

data class Alerta(
    val regra: Regra,
    val pacote: String?,
    val rotulo: String,
    val fluxoId: Long,
    val detalhe: String,
    val quandoUs: Long,
)

/**
 * Avalia as regras sobre as conexões de uma sessão. Puro: fuso, histórico de domínios e os
 * endereços do DNS virtual vêm no contexto (os testes controlam). No máximo um alerta por app
 * e regra; ele aponta o primeiro fluxo (pela hora de início) que disparou.
 */
object Alertas {
    data class Contexto(
        val fuso: ZoneId,
        /** (pacote, domínio) já vistos em sessões anteriores. */
        val dominiosVistos: Set<Pair<String, String>>,
        /** DNS virtual do tun e DNS reais da rede: falar com eles é o caminho normal. */
        val dnsVirtuais: Set<String>,
        /** (pacote, regra) que o usuário mandou ignorar. */
        val excecoes: Set<Pair<String?, Regra>> = emptySet(),
        /** Modelo do normal de cada app (treinado com sessões anteriores); null = sem IA. */
        val linhaDeBase: com.brendon978.sentinela.ia.LinhaDeBase? = null,
    ) {
        /** Apps que já têm histórico (só eles disparam "domínio novo"). Calculado uma vez. */
        val appsComHistorico: Set<String> by lazy { dominiosVistos.mapTo(HashSet()) { it.first } }
    }

    private val PORTAS_NORMAIS = setOf(53, 80, 123, 443, 853, 5228) + (3478..3481)
    private val PROVEDORES_DOH = setOf(
        "dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net", "doh.opendns.com",
        "dns.nextdns.io", "doh.cleanbrowsing.org", "dns.adguard-dns.com",
    )
    private val IPS_DOH = setOf(
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844",
    )

    fun avaliar(linhas: List<LinhaFluxo>, c: Contexto): List<Alerta> {
        val vistos = HashSet<Pair<String?, Regra>>()
        val saida = mutableListOf<Alerta>()
        val anomalias = c.linhaDeBase?.avaliar(linhas).orEmpty().associateBy { it.fluxoId }
        for (l in linhas.sortedBy { it.inicioUs }) {
            val ia = anomalias[l.fluxoId]?.let { Regra.COMPORTAMENTO_ANOMALO to explicar(it, l) }
            for ((regra, detalhe) in disparos(l, c) + listOfNotNull(ia)) {
                if ((l.pacoteApp to regra) in c.excecoes) continue
                if (vistos.add(l.pacoteApp to regra))
                    saida += Alerta(regra, l.pacoteApp, l.rotulo, l.fluxoId, detalhe, l.inicioUs)
            }
        }
        return saida
    }

    /** Em palavras: o que fugiu do padrão e com que nota. */
    private fun explicar(a: com.brendon978.sentinela.ia.Achado, l: LinhaFluxo): String {
        val o_que = when (a.indice) {
            Atributos.BYTES_ENVIADOS -> "volume enviado fora do padrão (${com.brendon978.sentinela.ui.Lista.bytes(l.bytesEnviados)})"
            Atributos.BYTES_RECEBIDOS -> "volume recebido fora do padrão (${com.brendon978.sentinela.ui.Lista.bytes(l.bytesRecebidos)})"
            Atributos.PACOTES -> "número de pacotes fora do padrão (${l.pacotes})"
            Atributos.DURACAO -> "duração fora do padrão"
            Atributos.HORA_SEN, Atributos.HORA_COS -> "horário em que o app não costuma conectar"
            Atributos.FREQUENCIA_PORTA -> "porta que o app não costuma usar (${l.portaDestino})"
            Atributos.FREQUENCIA_TELA -> if (l.telaDesligada) "conexão com a tela desligada, fora do costume do app" else "conexão com a tela ligada, fora do costume do app"
            else -> "combinação fora do padrão"
        }
        return "${l.dominio ?: l.ipDestino}: $o_que; nota ${"%.3f".format(java.util.Locale.ROOT, a.nota)} (limiar ${"%.3f".format(java.util.Locale.ROOT, a.limiar)})"
    }

    private fun disparos(l: LinhaFluxo, c: Contexto): List<Pair<Regra, String>> {
        val r = mutableListOf<Pair<Regra, String>>()
        val alvo = l.dominio ?: l.ipDestino
        val ehDnsVirtual = l.ipDestino in c.dnsVirtuais

        if (l.pacoteApp != null) {
            val hora = Instant.ofEpochMilli(l.inicioUs / 1000).atZone(c.fuso).hour
            if (hora < 5 || l.telaDesligada) {
                val quando = if (l.telaDesligada) "com a tela desligada" else "às ${"%02d".format(hora)}h"
                r += Regra.MADRUGADA_OU_TELA_DESLIGADA to "Conexão com $alvo $quando"
            }
            if (l.dominio != null && l.pacoteApp in c.appsComHistorico && (l.pacoteApp to l.dominio) !in c.dominiosVistos)
                r += Regra.DOMINIO_NOVO to "Primeira vez falando com ${l.dominio}"
        }
        Rastreadores.de(l.dominio)?.let { r += Regra.RASTREADOR to "${l.dominio}: ${it.empresa} · ${it.categoria}" }
        if (l.portaDestino !in PORTAS_NORMAIS)
            r += Regra.PORTA_INCOMUM to "${l.nomeProtocolo} ${l.ipDestino}:${l.portaDestino}"
        if (!ehDnsVirtual) {
            val dot = l.portaDestino == 853
            val doh = l.portaDestino == 443 && (l.dominio in PROVEDORES_DOH || l.ipDestino in IPS_DOH)
            val direto = l.portaDestino == 53
            if (dot || doh || direto) {
                val como = if (dot) "DNS sobre TLS" else if (doh) "DNS sobre HTTPS" else "DNS direto, sem passar pelo DNS da rede"
                r += Regra.DNS_ESCONDIDO to "$como para $alvo"
            }
        }
        return r
    }
}
