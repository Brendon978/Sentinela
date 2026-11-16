package com.brendon978.sentinela.rede

import java.util.Locale

/**
 * Mapa da rede Wi-Fi (fase 2): o que se aprende sem root sobre os aparelhos vizinhos.
 * Aula 04 (seções 2 e 10) e aula 06 (nmap). Só em rede própria ou autorizada.
 */

/** Resposta a um M-SEARCH do SSDP (UPnP Device Architecture 1.1, §1.3.3). */
data class RespostaSsdp(val ip: String, val servidor: String?, val local: String?, val tipo: String?)

object Ssdp {
    /** Pergunta "quem está aí?" para todos os aparelhos UPnP (multicast 239.255.255.250:1900). */
    const val PERGUNTA = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"

    /** Lê uma resposta (cabeçalhos tipo HTTP, sem diferenciar maiúsculas). null se não for resposta. */
    fun ler(texto: String, de: String): RespostaSsdp? {
        val linhas = texto.split("\r\n", "\n")
        if (!linhas.first().uppercase(Locale.ROOT).startsWith("HTTP/1.1 200")) return null
        val cab = linhas.drop(1).mapNotNull { l ->
            val i = l.indexOf(':')
            if (i <= 0) null else l.substring(0, i).trim().uppercase(Locale.ROOT) to l.substring(i + 1).trim()
        }.toMap()
        return RespostaSsdp(de, cab["SERVER"]?.ifEmpty { null }, cab["LOCATION"]?.ifEmpty { null }, cab["ST"]?.ifEmpty { null })
    }
}

object SubRede {
    /**
     * IPs da sub-rede IPv4 (sem o endereço da rede, o de broadcast e o próprio `ip`). Rede maior
     * que /24 fica na /24 em volta do celular: varredura leve, nunca milhares de endereços.
     */
    fun hosts(ip: String, prefixo: Int): List<String> {
        val p = ip.split('.').map { it.toInt() }
        val n = (p[0] shl 24) or (p[1] shl 16) or (p[2] shl 8) or p[3]
        val bitsHost = 32 - prefixo.coerceIn(24, 30)
        val rede = n and (-1 shl bitsHost)
        val total = (1L shl bitsHost) - 2 // tira rede e broadcast
        return (1..total).asSequence()
            .map { rede + it.toInt() }
            .filter { it != n }
            .map { "${it ushr 24 and 255}.${it ushr 16 and 255}.${it ushr 8 and 255}.${it and 255}" }
            .toList()
    }
}

enum class TipoAparelho(val nome: String) {
    ROTEADOR("Roteador"),
    TV_OU_STREAMING("TV ou streaming"),
    IMPRESSORA("Impressora"),
    CAMERA("Câmera"),
    APPLE("iPhone/iPad/Mac"),
    COMPUTADOR_OU_NAS("Computador ou NAS"),
    DESCONHECIDO("Aparelho"),
}

/** O que se sabe de um aparelho (de uma ou mais fontes). */
data class Aparelho(
    val ip: String,
    val nomes: Set<String> = emptySet(),
    val servicos: Set<String> = emptySet(), // tipos mDNS, ex.: _googlecast._tcp
    val portas: Set<Int> = emptySet(),      // portas TCP que aceitaram conexão
    val servidor: String? = null,           // cabeçalho SERVER do SSDP
    val gateway: Boolean = false,
)

/** Palpite do tipo pelo que o aparelho anuncia e pelas portas abertas. */
object Classificador {
    fun tipo(a: Aparelho): TipoAparelho {
        val s = a.servicos.joinToString(" ").lowercase(Locale.ROOT)
        return when {
            a.gateway -> TipoAparelho.ROTEADOR
            "_googlecast" in s || "_airplay" in s || "_spotify" in s || 8009 in a.portas -> TipoAparelho.TV_OU_STREAMING
            "_ipp" in s || "_printer" in s || "_pdl" in s || 9100 in a.portas || 631 in a.portas -> TipoAparelho.IMPRESSORA
            "_rtsp" in s || 554 in a.portas -> TipoAparelho.CAMERA
            62078 in a.portas || "_apple" in s || "_companion" in s -> TipoAparelho.APPLE
            "_smb" in s || 445 in a.portas || 22 in a.portas || 3389 in a.portas -> TipoAparelho.COMPUTADOR_OU_NAS
            else -> TipoAparelho.DESCONHECIDO
        }
    }
}

object Mapa {
    /** Junta os achados do mesmo IP (de mDNS, SSDP e portas) e ordena pelo IP. */
    fun juntar(achados: List<Aparelho>): List<Aparelho> =
        achados.groupBy { it.ip }.map { (ip, xs) ->
            Aparelho(
                ip, xs.flatMap { it.nomes }.toSet(), xs.flatMap { it.servicos }.toSet(),
                xs.flatMap { it.portas }.toSet(), xs.firstNotNullOfOrNull { it.servidor }, xs.any { it.gateway },
            )
        }.sortedBy { a -> a.ip.split('.').fold(0L) { acc, p -> acc * 256 + (p.toLongOrNull() ?: 0) } }
}
