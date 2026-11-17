package com.brendon978.sentinela.vpn

import com.brendon978.sentinela.motor.Evento
import com.brendon978.sentinela.motor.Ip
import com.brendon978.sentinela.motor.Protocolo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.net.InetSocketAddress

class DonoDaConexaoTest {
    private fun ip4(vararg b: Int) = Ip(4, ByteArray(4) { b[it].toByte() })

    private fun fluxo(porta: Int, proto: Protocolo = Protocolo.TCP) = Evento.FluxoNovo(
        1, proto, ip4(10, 111, 0, 1), porta, ip4(93, 184, 215, 14), 443, 0,
    )

    private class Fontes(val uids: Map<Int, Int>, val pacotes: Map<Int, List<String>>) : FonteDono, FontePacotes {
        val consultas = mutableListOf<Triple<Int, InetSocketAddress, InetSocketAddress>>()
        val rotulosPedidos = mutableListOf<String>()
        override fun uid(protocolo: Int, local: InetSocketAddress, remoto: InetSocketAddress): Int {
            consultas += Triple(protocolo, local, remoto)
            return uids[local.port] ?: -1
        }
        override fun pacotes(uid: Int) = pacotes[uid].orEmpty()
        override fun rotulo(pacote: String): String? {
            rotulosPedidos += pacote
            return if (pacote == "com.android.chrome") "Chrome" else null
        }
    }

    @Test fun `acha o app pelo uid e consulta com os enderecos do fluxo`() {
        val f = Fontes(mapOf(40000 to 10123), mapOf(10123 to listOf("com.android.chrome")))
        val app = DonoDaConexao(f, f).dono(fluxo(40000))
        assertEquals(App(10123, "com.android.chrome", "Chrome"), app)
        val (proto, local, remoto) = f.consultas.single()
        assertEquals(6, proto)
        assertEquals("10.111.0.1", local.address.hostAddress)
        assertEquals(40000, local.port)
        assertEquals("93.184.215.14", remoto.address.hostAddress)
        assertEquals(443, remoto.port)
    }

    @Test fun `uid desconhecido vira sistema ou desconhecido`() {
        val f = Fontes(emptyMap(), emptyMap())
        val app = DonoDaConexao(f, f).dono(fluxo(40001, Protocolo.UDP))
        assertEquals(-1, app.uid)
        assertNull(app.pacote)
        assertEquals("Sistema/desconhecido", app.rotulo)
    }

    @Test fun `uid sem pacote e uid com pacote sem rotulo`() {
        val f = Fontes(mapOf(1 to 1000, 2 to 10200), mapOf(10200 to listOf("com.exemplo.semrotulo")))
        val d = DonoDaConexao(f, f)
        assertEquals(App(1000, null, "Sistema (uid 1000)"), d.dono(fluxo(1)))
        assertEquals(App(10200, "com.exemplo.semrotulo", "com.exemplo.semrotulo"), d.dono(fluxo(2)))
    }

    @Test fun `consulta sem dono ao dns virtual e do sistema`() {
        val f = Fontes(emptyMap(), emptyMap())
        val dnsVirtual = Ip(4, byteArrayOf(10, 111, 0, 53))
        val e = Evento.FluxoNovo(1, Protocolo.UDP, ip4(10, 111, 0, 1), 5000, dnsVirtual, 53, 0)
        assertEquals(App(-1, null, "DNS do sistema"), DonoDaConexao(f, f, setOf(dnsVirtual)).dono(e))
        assertEquals(App.SEM_APP, DonoDaConexao(f, f).dono(e).rotulo)
    }

    @Test fun `rotulo e cacheado por uid`() {
        val f = Fontes(mapOf(1 to 10123, 2 to 10123), mapOf(10123 to listOf("com.android.chrome")))
        val d = DonoDaConexao(f, f)
        d.dono(fluxo(1))
        d.dono(fluxo(2))
        assertEquals(1, f.rotulosPedidos.size)
    }

    @Test fun `uid 1051 e o resolvedor de dns do android (DoT)`() {
        val f = Fontes(mapOf(5 to 1051), emptyMap())
        assertEquals("DNS do sistema", DonoDaConexao(f, f).dono(fluxo(5)).rotulo)
    }
}
