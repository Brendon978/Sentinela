package com.brendon978.sentinela.motor

/** Endereço IP vindo do motor (4 ou 16 bytes úteis). */
class Ip(val versao: Int, bytes: ByteArray) {
    val bytes: ByteArray = bytes.copyOf(if (versao == 4) 4 else 16)

    /** Forma de texto padrão (IPv6 comprimido pela RFC 5952, como o Wireshark mostra). Calculada uma vez. */
    val texto: String by lazy { if (versao == 4) this.bytes.joinToString(".") { (it.toInt() and 0xff).toString() } else v6() }

    private fun v6(): String {
        val grupos = IntArray(8) { ((bytes[2 * it].toInt() and 0xff) shl 8) or (bytes[2 * it + 1].toInt() and 0xff) }
        // a maior sequência de grupos zerados (2 ou mais) vira "::"; empate fica com a primeira
        var melhor = -1
        var tamMelhor = 1
        var i = 0
        while (i < 8) {
            if (grupos[i] == 0) {
                var j = i
                while (j < 8 && grupos[j] == 0) j++
                if (j - i > tamMelhor) { melhor = i; tamMelhor = j - i }
                i = j
            } else i++
        }
        fun hex(a: Int, b: Int) = (a until b).joinToString(":") { Integer.toHexString(grupos[it]) }
        return if (melhor < 0) hex(0, 8) else hex(0, melhor) + "::" + hex(melhor + tamMelhor, 8)
    }

    override fun equals(other: Any?) = other is Ip && other.versao == versao && other.bytes.contentEquals(bytes)
    override fun hashCode() = bytes.contentHashCode()
    override fun toString() = texto
}

enum class Protocolo(val numero: Int) {
    TCP(6), UDP(17), OUTRO(-1);

    /** Nome curto para a tela ("?" quando não é TCP nem UDP). */
    val rotulo: String get() = if (this == OUTRO) "?" else name

    companion object {
        fun de(n: Int) = entries.firstOrNull { it.numero == n } ?: OUTRO
    }
}

enum class MotivoFim(val codigo: Int) {
    FECHADO(0), RESET(1), TEMPO(2), ERRO(3), DESCONHECIDO(-1);

    companion object {
        fun de(n: Int) = entries.firstOrNull { it.codigo == n } ?: DESCONHECIDO
    }
}

/** Eventos do motor (contrato C2 de include/sentinela.h). */
sealed interface Evento {
    data class FluxoNovo(
        val id: Long, val protocolo: Protocolo,
        val origem: Ip, val portaOrigem: Int,
        val destino: Ip, val portaDestino: Int,
        val inicioUs: Long,
    ) : Evento

    data class FluxoBytes(val id: Long, val bytesEnviados: Long, val bytesRecebidos: Long, val pacotes: Long) : Evento
    data class FluxoFim(val id: Long, val fimUs: Long, val motivo: MotivoFim) : Evento
    data class Dns(val enderecos: List<Ip>, val nome: String) : Evento
    data class Sni(val id: Long, val nome: String) : Evento
    data class Perda(val descartados: Long) : Evento
}

data class LoteEventos(val eventos: List<Evento>, val erro: String?)

/**
 * Decodifica um lote de eventos: registros `u8 tipo | u16 tamanho | corpo`, little-endian.
 * Tipo desconhecido é pulado pelo tamanho (para o motor evoluir sem quebrar o app). Registro
 * cortado ou corpo menor que o esperado encerra a leitura com `erro`, mantendo o que veio antes.
 */
object Eventos {
    private class Leitor(val b: ByteArray, var i: Int, val fim: Int) {
        fun resta() = fim - i
        fun u8(): Int = b[i++].toInt() and 0xff
        fun u16(): Int = u8() or (u8() shl 8)
        fun u32(): Long = (u16().toLong()) or (u16().toLong() shl 16)
        fun u64(): Long = u32() or (u32() shl 32)
        fun bytes(n: Int): ByteArray = b.copyOfRange(i, i + n).also { i += n }
        fun texto(n: Int): String = String(bytes(n), Charsets.UTF_8)
    }

    private class Curto : Exception()

    fun decodificar(dados: ByteArray): LoteEventos {
        val eventos = mutableListOf<Evento>()
        var i = 0
        while (i < dados.size) {
            if (dados.size - i < 3) return LoteEventos(eventos, "registro cortado no cabeçalho (posição $i)")
            val tipo = dados[i].toInt() and 0xff
            val tam = (dados[i + 1].toInt() and 0xff) or ((dados[i + 2].toInt() and 0xff) shl 8)
            val inicio = i + 3
            if (inicio + tam > dados.size) return LoteEventos(eventos, "registro tipo $tipo cortado (posição $i)")
            try {
                corpo(tipo, Leitor(dados, inicio, inicio + tam))?.let(eventos::add)
            } catch (_: Curto) {
                return LoteEventos(eventos, "corpo do tipo $tipo menor que o esperado (posição $i)")
            }
            i = inicio + tam
        }
        return LoteEventos(eventos, null)
    }

    private fun exige(l: Leitor, n: Int) {
        if (l.resta() < n) throw Curto()
    }

    private fun corpo(tipo: Int, l: Leitor): Evento? = when (tipo) {
        1 -> {
            exige(l, 4 + 1 + 1 + 16 + 2 + 16 + 2 + 8)
            val id = l.u32()
            val versao = l.u8()
            val proto = Protocolo.de(l.u8())
            val origem = Ip(versao, l.bytes(16))
            val portaOrigem = l.u16()
            val destino = Ip(versao, l.bytes(16))
            val portaDestino = l.u16()
            Evento.FluxoNovo(id, proto, origem, portaOrigem, destino, portaDestino, l.u64())
        }
        2 -> {
            exige(l, 4 + 8 + 8 + 4)
            Evento.FluxoBytes(l.u32(), l.u64(), l.u64(), l.u32())
        }
        3 -> {
            exige(l, 4 + 8 + 1)
            Evento.FluxoFim(l.u32(), l.u64(), MotivoFim.de(l.u8()))
        }
        4 -> {
            exige(l, 2)
            val n = l.u16()
            exige(l, n * 17 + 2)
            val versoes = List(n) { l.u8() }
            val ips = versoes.map { Ip(it, l.bytes(16)) }
            val tamNome = l.u16()
            exige(l, tamNome)
            Evento.Dns(ips, l.texto(tamNome))
        }
        5 -> {
            exige(l, 4 + 2)
            val id = l.u32()
            val tamNome = l.u16()
            exige(l, tamNome)
            Evento.Sni(id, l.texto(tamNome))
        }
        6 -> {
            exige(l, 4)
            Evento.Perda(l.u32())
        }
        else -> null
    }
}
