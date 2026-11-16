package com.brendon978.sentinela.sessao

import com.brendon978.sentinela.dados.SessaoSalva
import com.brendon978.sentinela.motor.MotivoFim
import com.brendon978.sentinela.ui.Lista
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Fluxos em CSV (RFC 4180), para análise no PC (pandas) e para o artigo.
 *
 * Anonimizado: IP de destino e domínio viram pseudônimos `ip-…`/`dom-…` (HMAC-SHA256 com um sal
 * aleatório por exportação). O mesmo valor dá o mesmo pseudônimo dentro do arquivo (a análise
 * continua possível), mas não dá para reverter nem cruzar dois arquivos. A origem fica só quando é
 * o endereço do tun (igual em todo celular); o IP do Wi-Fi do celular, que às vezes aparece como
 * origem (QUIC do Chrome), também vira pseudônimo. O app fica (é informação pública).
 */
object Exportacao {

    private val COLUNAS = listOf(
        "fluxo_id", "inicio_utc", "duracao_s", "protocolo", "ip_origem", "porta_origem", "ip_destino",
        "porta_destino", "pacote_app", "app", "dominio", "origem_dominio", "bytes_enviados",
        "bytes_recebidos", "pacotes", "tela_desligada", "motivo_fim", "nota_ia", "limiar_ia",
    )

    fun csv(linhas: List<LinhaFluxo>, anonimizar: Boolean, sal: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(if (sal.isEmpty()) ByteArray(1) else sal, "HmacSHA256")) }
        fun pseudo(prefixo: String, v: String) =
            prefixo + mac.doFinal(v.toByteArray()).take(6).joinToString("") { "%02x".format(it) }
        val sb = StringBuilder(COLUNAS.joinToString(",")).append("\r\n")
        for (l in linhas.sortedBy { it.inicioUs }) {
            val ipDestino = if (anonimizar) pseudo("ip-", l.ipDestino) else l.ipDestino
            val ipOrigem = if (anonimizar && l.ipOrigem !in com.brendon978.sentinela.vpn.Tun.ENDERECOS) pseudo("ip-", l.ipOrigem) else l.ipOrigem
            val dominio = l.dominio?.let { if (anonimizar) pseudo("dom-", it) else it }.orEmpty()
            val duracao = l.fimUs?.let { String.format(Locale.ROOT, "%.3f", (it - l.inicioUs) / 1e6) }.orEmpty()
            val campos = listOf(
                l.fluxoId.toString(), Instant.ofEpochMilli(l.inicioUs / 1000).toString(), duracao, l.nomeProtocolo,
                ipOrigem, l.portaOrigem.toString(), ipDestino, l.portaDestino.toString(), l.pacoteApp.orEmpty(),
                l.rotulo, dominio, l.origemDominio, l.bytesEnviados.toString(), l.bytesRecebidos.toString(),
                l.pacotes.toString(), if (l.telaDesligada) "1" else "0", l.motivoFim?.let { MotivoFim.de(it).name }.orEmpty(),
                l.notaIa?.let { String.format(Locale.ROOT, "%.4f", it) }.orEmpty(),
                l.limiarIa?.let { String.format(Locale.ROOT, "%.4f", it) }.orEmpty(),
            )
            sb.append(campos.joinToString(",") { campo(it) }).append("\r\n")
        }
        return sb.toString()
    }

    /** Campo CSV: entre aspas (com aspas dobradas) quando tem vírgula, aspas ou quebra de linha. */
    private fun campo(v: String) =
        if (v.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) "\"" + v.replace("\"", "\"\"") + "\"" else v
}

/** Uma seção do relatório: título e linhas de texto. */
data class Secao(val titulo: String, val linhas: List<String>)

/**
 * Conteúdo do relatório da sessão (o PDF só desenha isto). Segue a estrutura de um laudo
 * (aula 08): identificação, integridade, cadeia de custódia, achados. Horários em hora local,
 * sempre com o fuso escrito.
 */
object Relatorio {
    fun conteudo(
        s: SessaoSalva, linhas: List<LinhaFluxo>, alertas: List<Alerta>,
        aparelho: String, versaoApp: String, fuso: ZoneId, geradoEmMs: Long,
    ): List<Secao> {
        val fmt = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss").withZone(fuso)
        fun hora(ms: Long) = "${fmt.format(Instant.ofEpochMilli(ms))} ($fuso)"
        val arquivo = s.caminhoPcap.substringAfterLast('/')
        val porApp = PorApp.resumir(linhas)
        return listOf(
            Secao("Identificação", listOf(
                "Ferramenta: Sentinela $versaoApp (captura por VPN local, sem root)",
                "Aparelho: $aparelho",
                "Início da captura: ${hora(s.inicioMs)}",
                "Fim da captura: ${hora(s.fimMs)}",
                "Situação: " + when (s.estado) {
                    com.brendon978.sentinela.dados.EstadoSessaoSalva.GRAVANDO -> "gravando"
                    com.brendon978.sentinela.dados.EstadoSessaoSalva.CONCLUIDA -> "concluída"
                    com.brendon978.sentinela.dados.EstadoSessaoSalva.INTERROMPIDA -> "interrompida (o app parou no meio)"
                },
                "Total: ${s.pacotes} pacotes, ${Lista.bytes(s.bytes)}, ${linhas.size} conexões",
                "IA (linha de base por app): " + (s.iaApps?.let { "modelos para $it apps; ${linhas.count { it.notaIa != null }} conexões julgadas" }
                    ?: "não rodou nesta sessão (sem histórico suficiente ou não terminou de treinar)"),
            )),
            Secao("Integridade", listOf(
                "Arquivo: $arquivo (pcap, Raw IP)",
                "SHA-256: ${s.sha256}",
                "Conferir no PC: sha256sum -c ${Evidencia.arquivoSha256(s.caminhoPcap).name}",
            )),
            Secao("Cadeia de custódia", listOf(
                "Coleta: ${hora(s.inicioMs)} a ${hora(s.fimMs)}, no próprio aparelho, pelo Sentinela $versaoApp",
                if (s.estado == com.brendon978.sentinela.dados.EstadoSessaoSalva.INTERROMPIDA)
                    "Sessão interrompida (o app parou no meio): hash calculado sobre o que chegou ao arquivo, " +
                        "quando o app foi reaberto, e guardado no banco e em arquivo .sha256"
                else "Hash calculado ao encerrar a captura e guardado no banco do app e em arquivo .sha256",
                "Relatório gerado em: ${hora(geradoEmMs)}",
                "Acessos posteriores: registrar abaixo (quem, quando, para quê)",
            )),
            Secao("Resumo por app", porApp.map { r ->
                "${r.rotulo}: ${r.conexoes} conexões, ↑ ${Lista.bytes(r.bytesEnviados)} ↓ ${Lista.bytes(r.bytesRecebidos)}" +
                    if (r.rastreadores.isNotEmpty()) " — rastreadores: ${r.rastreadores.joinToString(", ")}" else ""
            }),
            Secao("Alertas", if (alertas.isEmpty()) listOf("Nenhum.") else alertas.map {
                "${fmt.format(Instant.ofEpochMilli(it.quandoUs / 1000))} — ${it.rotulo}: ${it.regra.titulo}. ${it.detalhe}"
            }),
            Secao("Domínios", linhas.mapNotNull { it.dominio }.groupingBy { it }.eachCount()
                .entries.sortedByDescending { it.value }.map { "${it.key} (${it.value})" }),
        )
    }
}
