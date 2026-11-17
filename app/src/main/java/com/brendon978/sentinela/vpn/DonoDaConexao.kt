package com.brendon978.sentinela.vpn

import com.brendon978.sentinela.motor.Evento
import com.brendon978.sentinela.motor.Ip
import java.net.InetAddress
import java.net.InetSocketAddress

/** O app que abriu uma conexão. uid -1 = o Android não soube dizer. */
data class App(val uid: Int, val pacote: String?, val rotulo: String) {
    companion object {
        /** Rótulo de quem não tem app dono conhecido. */
        const val SEM_APP = "Sistema/desconhecido"
    }
}

/** Fronteira com o ConnectivityManager.getConnectionOwnerUid (só funciona para o app de VPN). */
fun interface FonteDono {
    fun uid(protocolo: Int, local: InetSocketAddress, remoto: InetSocketAddress): Int
}

/** Fronteira com o PackageManager. */
interface FontePacotes {
    fun pacotes(uid: Int): List<String>
    fun rotulo(pacote: String): String?
}

/**
 * Descobre de que app é cada fluxo. Precisa ser chamada logo no FluxoNovo: o Android só
 * responde enquanto a conexão existe. Vários pacotes podem dividir um uid (sharedUserId):
 * fica o primeiro.
 */
private val DNS_DO_SISTEMA = App(-1, null, "DNS do sistema")

/** AID_DNS: o resolvedor do Android usa esse uid para o DNS privado (DoT). */
private const val UID_RESOLVEDOR = 1051

class DonoDaConexao(
    private val fonteDono: FonteDono,
    private val fontePacotes: FontePacotes,
    /** Endereços do DNS virtual do tun. */
    private val dnsVirtuais: Set<Ip> = emptySet(),
) {
    private val porUid = HashMap<Int, App>()

    fun dono(e: Evento.FluxoNovo): App {
        val local = InetSocketAddress(InetAddress.getByAddress(e.origem.bytes), e.portaOrigem)
        val remoto = InetSocketAddress(InetAddress.getByAddress(e.destino.bytes), e.portaDestino)
        val uid = runCatching { fonteDono.uid(e.protocolo.numero, local, remoto) }.getOrDefault(-1)
        // Consulta do resolvedor do próprio Android ao DNS virtual: não tem app dono.
        if (uid < 0) return if (e.destino in dnsVirtuais) DNS_DO_SISTEMA else App(-1, null, App.SEM_APP)
        return porUid.getOrPut(uid) {
            val pacote = fontePacotes.pacotes(uid).firstOrNull()
            if (pacote == null) App(uid, null, if (uid == UID_RESOLVEDOR) DNS_DO_SISTEMA.rotulo else "Sistema (uid $uid)")
            else App(uid, pacote, fontePacotes.rotulo(pacote) ?: pacote)
        }
    }
}
