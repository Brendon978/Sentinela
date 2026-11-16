package com.brendon978.sentinela.sessao

import com.brendon978.sentinela.motor.Protocolo
import com.brendon978.sentinela.vpn.App
import java.io.File
import java.security.DigestInputStream
import java.security.MessageDigest

/**
 * Integridade da captura (aula 08): o SHA-256 do .pcap é calculado ao fechar a sessão e
 * guardado no banco e num arquivo .sha256 ao lado, no formato do `sha256sum`, para conferir
 * no PC com `sha256sum -c`.
 */
object Evidencia {
    /** Hash e número de pacotes de um pcap. */
    data class Resumo(val sha256: String, val pacotes: Long)

    /** O .sha256 que fica ao lado do .pcap. */
    fun arquivoSha256(caminhoPcap: String) = File(caminhoPcap.removeSuffix(".pcap") + ".sha256")

    /**
     * Uma passada só pelo arquivo: tudo o que é lido passa pelo SHA-256, e no caminho os
     * cabeçalhos de 16 bytes de cada registro são contados (o resumo da sessão tem de bater com
     * o capinfos). Para de contar no primeiro registro cortado, como o leitor do motor, mas o
     * hash cobre o arquivo inteiro.
     */
    fun resumir(arquivo: File): Resumo {
        val md = MessageDigest.getInstance("SHA-256")
        var pacotes = 0L
        DigestInputStream(arquivo.inputStream().buffered(64 * 1024), md).use { e ->
            val cab = ByteArray(16)
            val lixo = ByteArray(64 * 1024)
            fun pular(n: Long): Boolean {
                var falta = n
                while (falta > 0) {
                    val k = e.read(lixo, 0, minOf(falta, lixo.size.toLong()).toInt())
                    if (k < 0) return false
                    falta -= k
                }
                return true
            }
            if (pular(24)) {
                while (e.readNBytes(cab, 0, 16) == 16) {
                    val gravado = (cab[8].toLong() and 0xff) or ((cab[9].toLong() and 0xff) shl 8) or
                        ((cab[10].toLong() and 0xff) shl 16) or ((cab[11].toLong() and 0xff) shl 24)
                    if (!pular(gravado)) break
                    pacotes++
                }
            }
            while (e.read(lixo) >= 0) { /* o resto do arquivo também entra no hash */ }
        }
        return Resumo(md.digest().joinToString("") { "%02x".format(it) }, pacotes)
    }

    fun sha256(arquivo: File): String = resumir(arquivo).sha256

    fun contarPacotes(arquivo: File): Long = resumir(arquivo).pacotes

    /** "<hash>  <nome>\n" (dois espaços = modo binário/texto padrão do sha256sum). */
    fun linhaSha256(hash: String, nome: String) = "$hash  $nome\n"
}

/** Uma conexão como linha da tabela `fluxo` (tipos simples, sem classes do Android). */
data class LinhaFluxo(
    val sessaoId: Long,
    val fluxoId: Long,
    val protocolo: Int,
    val versaoIp: Int,
    val ipOrigem: String,
    val portaOrigem: Int,
    val ipDestino: String,
    val portaDestino: Int,
    val uid: Int,
    val pacoteApp: String?,
    val rotuloApp: String?,
    val dominio: String?,
    val origemDominio: String,
    val bytesEnviados: Long,
    val bytesRecebidos: Long,
    val pacotes: Long,
    val inicioUs: Long,
    val fimUs: Long?,
    val motivoFim: Int?,
    /** A tela estava desligada quando o fluxo começou (regra de alerta). */
    val telaDesligada: Boolean = false,
) {
    /** Nome do app, ou o rótulo de quem não tem app. */
    val rotulo: String get() = rotuloApp ?: App.SEM_APP

    /** "TCP", "UDP" ou "?". */
    val nomeProtocolo: String get() = Protocolo.de(protocolo).rotulo

    companion object {
        fun de(sessaoId: Long, c: Conexao) = LinhaFluxo(
            sessaoId, c.id, c.protocolo.numero, c.origem.versao, c.origem.texto, c.portaOrigem,
            c.destino.texto, c.portaDestino, c.app?.uid ?: -1, c.app?.pacote, c.app?.rotulo,
            c.dominio, c.origemDominio.name, c.bytesEnviados, c.bytesRecebidos, c.pacotes,
            c.inicioUs, c.fimUs, c.motivo?.codigo, c.telaDesligada,
        )
    }
}
