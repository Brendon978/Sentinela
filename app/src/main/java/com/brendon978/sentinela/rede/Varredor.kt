package com.brendon978.sentinela.rede

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.RouteInfo
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Collections
import kotlin.coroutines.resume

/**
 * Varre a rede Wi-Fi em que o celular está: anúncios mDNS, respostas SSDP e algumas portas TCP
 * de cada endereço da /24. Tudo pela rede Wi-Fi de verdade (mesmo com a VPN do Sentinela ligada,
 * o app fica fora dela). Outra VPN que não deixa apps se vincularem ao Wi-Fi (o Tailscale, por
 * exemplo) faz o mapa usar a rota normal, desde que ela não leve a rede local; se levar, o mapa não
 * varre (sondaria a rede do outro lado da VPN). Só em rede própria ou autorizada.
 */
class Varredor(private val ctx: Context) {
    companion object {
        private const val TAG = "Sentinela"
        /** Portas que dizem muito sobre o aparelho (aula 04, seção 7). */
        val PORTAS = listOf(22, 80, 443, 445, 554, 631, 3389, 8009, 8080, 9100, 62078)
        private val SERVICOS_MDNS = listOf(
            "_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_ipp._tcp", "_printer._tcp",
            "_pdl-datastream._tcp", "_smb._tcp", "_http._tcp", "_spotify-connect._tcp", "_hap._tcp",
            "_companion-link._tcp", "_rtsp._tcp", "_workstation._tcp", "_androidtvremote2._tcp",
        )
    }

    class SemWifi : Exception("Conecte o celular a uma rede Wi-Fi para mapear.")
    class VpnLevaARede : Exception(
        "Outra VPN ligada está levando a rede local por ela (por exemplo, um exit node do Tailscale sem " +
            "\"acesso à rede local\"). Desligue-a ou libere o acesso à rede local para mapear.",
    )

    /** Observação sobre a última varredura (null = nada a dizer). */
    var aviso: String? = null
        private set

    private val cm = ctx.getSystemService(ConnectivityManager::class.java)

    private fun redeWifi(): Network? = cm.allNetworks.firstOrNull {
        val c = cm.getNetworkCapabilities(it)
        c != null && c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    }

    suspend fun mapear(progresso: (String) -> Unit): List<Aparelho> = withContext(Dispatchers.IO) {
        val rede = redeWifi() ?: throw SemWifi()
        val lp = cm.getLinkProperties(rede) ?: throw SemWifi()
        val meu = lp.linkAddresses.firstOrNull { it.address is Inet4Address } ?: throw SemWifi()
        val gateway = lp.routes.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway?.hostAddress
        val hosts = SubRede.hosts(meu.address.hostAddress!!, meu.prefixLength)
        // Rede por onde os sockets saem: o Wi-Fi vinculado; null = rota normal (outra VPN não deixou vincular)
        val via = if (podeVincular(rede)) rede else {
            if (RotasVpn.levaPelaVpn(meu.address.hostAddress!!, rotasDeVpn())) throw VpnLevaARede()
            aviso = "Outra VPN está ligada (por exemplo, o Tailscale): o mapa foi pela rota normal até a rede local."
            null
        }
        progresso("Procurando em ${hosts.size} endereços…")
        val achados = coroutineScope {
            val m = async { mdns() }
            val s = async { ssdp(via) }
            val p = async { portas(via, hosts, progresso) }
            m.await() + s.await() + p.await()
        }
        Mapa.juntar(achados + listOfNotNull(gateway?.let { Aparelho(it, gateway = true) }))
    }

    /** Uma VPN sem "bypass" faz o Android recusar o vínculo ao Wi-Fi (EPERM). */
    private fun podeVincular(rede: Network): Boolean =
        runCatching { DatagramSocket().use { rede.bindSocket(it) } }
            .onFailure { Log.i(TAG, "sem vínculo ao Wi-Fi (outra VPN?): $it") }
            .isSuccess

    private fun rotasDeVpn(): List<RotasVpn.Rota> = cm.allNetworks
        .filter { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
        .flatMap { cm.getLinkProperties(it)?.routes.orEmpty() }
        .filter { it.destination.address is Inet4Address }
        .map { RotasVpn.Rota(it.destination.address.hostAddress!!, it.destination.prefixLength, it.type == RouteInfo.RTN_THROW) }

    // ------------------------------------------------------------------ portas

    private suspend fun portas(rede: Network?, hosts: List<String>, progresso: (String) -> Unit): List<Aparelho> = coroutineScope {
        val limite = Semaphore(64)
        val feitos = java.util.concurrent.atomic.AtomicInteger()
        hosts.map { ip ->
            async {
                val abertas = PORTAS.filter { porta ->
                    limite.withPermit { tentaConectar(rede, ip, porta) }
                }
                if (feitos.incrementAndGet() % 32 == 0) progresso("Portas: ${feitos.get()} de ${hosts.size}")
                if (abertas.isEmpty()) null else Aparelho(ip, portas = abertas.toSet())
            }
        }.mapNotNull { it.await() }
    }

    private fun tentaConectar(rede: Network?, ip: String, porta: Int): Boolean = runCatching {
        (rede?.socketFactory?.createSocket() ?: Socket()).use { s -> s.connect(InetSocketAddress(ip, porta), 400); true }
    }.getOrDefault(false)

    // ------------------------------------------------------------------ SSDP

    private suspend fun ssdp(rede: Network?): List<Aparelho> {
        val wifi = ctx.applicationContext.getSystemService(WifiManager::class.java)
        val trava = wifi.createMulticastLock("sentinela-ssdp").apply { setReferenceCounted(false); acquire() }
        return try {
            DatagramSocket().use { sock ->
                rede?.bindSocket(sock)
                sock.soTimeout = 300
                val destino = InetSocketAddress(InetAddress.getByName("239.255.255.250"), 1900)
                val pergunta = Ssdp.PERGUNTA.toByteArray()
                repeat(2) { sock.send(DatagramPacket(pergunta, pergunta.size, destino)) }
                val achados = mutableListOf<Aparelho>()
                val buf = ByteArray(2048)
                val fim = System.currentTimeMillis() + 3000
                while (System.currentTimeMillis() < fim) {
                    val pacote = DatagramPacket(buf, buf.size)
                    try {
                        sock.receive(pacote)
                    } catch (_: SocketTimeoutException) {
                        continue
                    }
                    val ip = pacote.address.hostAddress ?: continue
                    Ssdp.ler(String(pacote.data, 0, pacote.length), ip)?.let {
                        achados += Aparelho(ip, servidor = it.servidor)
                    }
                }
                achados
            }
        } catch (e: Exception) {
            Log.w(TAG, "SSDP falhou", e)
            emptyList()
        } finally {
            trava.release()
        }
    }

    // ------------------------------------------------------------------ mDNS

    private suspend fun mdns(): List<Aparelho> {
        val nsd = ctx.getSystemService(NsdManager::class.java)
        val encontrados = Collections.synchronizedList(mutableListOf<NsdServiceInfo>())
        val ouvintes = SERVICOS_MDNS.map { tipo ->
            object : NsdManager.DiscoveryListener {
                override fun onServiceFound(s: NsdServiceInfo) { encontrados += s }
                override fun onStartDiscoveryFailed(t: String, e: Int) { Log.w(TAG, "mDNS $t falhou ($e)") }
                override fun onStopDiscoveryFailed(t: String, e: Int) {}
                override fun onDiscoveryStarted(t: String) {}
                override fun onDiscoveryStopped(t: String) {}
                override fun onServiceLost(s: NsdServiceInfo) {}
            }.also { runCatching { nsd.discoverServices(tipo, NsdManager.PROTOCOL_DNS_SD, it) } }
        }
        delay(4000)
        ouvintes.forEach { runCatching { nsd.stopServiceDiscovery(it) } }
        // resolver um por vez (o NsdManager não gosta de resoluções em paralelo)
        val mutex = Mutex()
        return encontrados.toList().mapNotNull { s ->
            mutex.withLock { withTimeoutOrNull(1500) { resolver(nsd, s) } }
        }
    }

    @Suppress("DEPRECATION") // resolveService ainda funciona e cobre todas as versões do minSdk
    private suspend fun resolver(nsd: NsdManager, s: NsdServiceInfo): Aparelho? = suspendCancellableCoroutine { cont ->
        nsd.resolveService(s, object : NsdManager.ResolveListener {
            override fun onResolveFailed(info: NsdServiceInfo, erro: Int) { if (cont.isActive) cont.resume(null) }
            override fun onServiceResolved(info: NsdServiceInfo) {
                val ip = info.hostAddresses.firstOrNull { it is Inet4Address }?.hostAddress
                if (cont.isActive) cont.resume(ip?.let {
                    Aparelho(it, nomes = setOf(info.serviceName), servicos = setOf(info.serviceType.trim('.')))
                })
            }
        })
    }
}
