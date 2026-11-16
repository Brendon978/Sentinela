package com.brendon978.sentinela.motor

/**
 * Ponte para o motor em C (libsentinela.so, contrato C1/C3 do plano).
 *
 * Ciclo: [criar] → numa thread própria [rodar] (bloqueia) → de outra thread, [eventos] a cada
 * 250 ms e [parar] para encerrar → depois que [rodar] voltou: [encerrar], um último [eventos]
 * para pegar os fins de fluxo, e [destruir].
 */
object Motor {
    init {
        System.loadLibrary("sentinela")
    }

    /**
     * @param dnsVirtuais endereços de DNS que o tun anuncia aos apps (ex.: "10.111.0.53").
     * @param dnsReais servidores DNS da rede ativa, para onde as consultas vão (porta 53).
     * @return handle, ou 0 se não deu para criar (ex.: o pcap não abriu).
     */
    external fun criar(caminhoPcap: String?, dnsVirtuais: Array<String>, dnsReais: Array<String>, forcarTcp: Boolean): Long

    /** O motor passa a ser dono do fd (venha de ParcelFileDescriptor.detachFd()). 0 = parou normalmente. */
    external fun rodar(handle: Long, fdTun: Int): Int
    external fun parar(handle: Long)

    /** A rede mudou: os próximos fluxos de DNS vão para estes servidores (porta 53). */
    external fun trocarDns(handle: Long, dnsReais: Array<String>)
    external fun eventos(handle: Long): ByteArray
    external fun encerrar(handle: Long)
    external fun destruir(handle: Long)

    /** Árvore do pacote em texto (linha 1 = resumo). */
    external fun dissecar(pacote: ByteArray): String

    /**
     * Pacotes de um fluxo, nos dois sentidos, com carimbo em [desdeUs, ateUs] (0 = sem limite):
     * cada um = 8 bytes de carimbo (us, LE) + o pacote. O intervalo separa duas conversas com a
     * mesma tupla.
     */
    external fun lerPacotes(
        caminhoPcap: String, protocolo: Int, ipOrigem: String, portaOrigem: Int,
        ipDestino: String, portaDestino: Int, desdeUs: Long, ateUs: Long, max: Int,
    ): Array<ByteArray>
}

/** Um pacote lido do pcap. `doApp` = saiu do celular (origem é o app). */
class Pacote(val quandoUs: Long, val bytes: ByteArray, val doApp: Boolean) {
    companion object {
        /** Separa o carimbo do prefixo; a origem do pacote diz o sentido. */
        fun de(bruto: ByteArray, ipApp: Ip): Pacote {
            var q = 0L
            for (i in 0 until 8) q = q or ((bruto[i].toLong() and 0xff) shl (8 * i))
            val p = bruto.copyOfRange(8, bruto.size)
            val versao = (p.firstOrNull()?.toInt() ?: 0) shr 4 and 0xf
            val origem = when (versao) {
                4 -> if (p.size >= 16) p.copyOfRange(12, 16) else ByteArray(0)
                6 -> if (p.size >= 24) p.copyOfRange(8, 24) else ByteArray(0)
                else -> ByteArray(0)
            }
            return Pacote(q, p, origem.contentEquals(ipApp.bytes))
        }
    }
}
