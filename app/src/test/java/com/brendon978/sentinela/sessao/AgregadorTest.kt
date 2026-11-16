package com.brendon978.sentinela.sessao

import com.brendon978.sentinela.motor.Evento
import com.brendon978.sentinela.motor.Ip
import com.brendon978.sentinela.motor.MotivoFim
import com.brendon978.sentinela.motor.Protocolo
import com.brendon978.sentinela.vpn.App
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AgregadorTest {
    private fun ip4(vararg b: Int) = Ip(4, ByteArray(4) { b[it].toByte() })
    private val chrome = App(10123, "com.android.chrome", "Chrome")
    private val app = ip4(10, 111, 0, 1)
    private val servidor = ip4(93, 184, 215, 14)

    private fun novo(id: Long, destino: Ip = servidor, porta: Int = 443) =
        Evento.FluxoNovo(id, Protocolo.TCP, app, 40000 + id.toInt(), destino, porta, 1_000L * id)

    private fun agregador() = Agregador { chrome }

    @Test fun `fluxo novo ganha dono e dominio pelo dns visto antes`() {
        val a = agregador()
        a.aplicar(Evento.Dns(listOf(servidor), "www.exemplo.com"))
        a.aplicar(novo(1))
        val c = a.conexoes.getValue(1)
        assertEquals(chrome, c.app)
        assertEquals("www.exemplo.com", c.dominio)
        assertEquals(OrigemDominio.DNS, c.origemDominio)
    }

    @Test fun `sni vence o dns`() {
        val a = agregador()
        a.aplicar(Evento.Dns(listOf(servidor), "cdn.exemplo.net"))
        a.aplicar(novo(1))
        a.aplicar(Evento.Sni(1, "www.exemplo.com.br"))
        val c = a.conexoes.getValue(1)
        assertEquals("www.exemplo.com.br", c.dominio)
        assertEquals(OrigemDominio.SNI, c.origemDominio)
    }

    @Test fun `sni com ech nao apaga o nome real que veio do dns`() {
        val a = agregador()
        a.aplicar(Evento.Dns(listOf(servidor), "site-de-verdade.com"))
        a.aplicar(novo(1))
        a.aplicar(Evento.Sni(1, "cloudflare-ech.com", ech = true))
        assertEquals("site-de-verdade.com", a.conexoes.getValue(1).dominio)
        // sem nome pelo DNS, o do ECH é o que há (marcado)
        a.aplicar(novo(2, ip4(9, 9, 9, 9)))
        a.aplicar(Evento.Sni(2, "cloudflare-ech.com", ech = true))
        assertEquals(OrigemDominio.SNI_ECH, a.conexoes.getValue(2).origemDominio)
    }

    @Test fun `dns que chega depois preenche quem estava sem dominio mas nao troca sni`() {
        val a = agregador()
        a.aplicar(novo(1))
        a.aplicar(novo(2, ip4(1, 2, 3, 4)))
        a.aplicar(Evento.Sni(2, "sni.exemplo"))
        assertNull(a.conexoes.getValue(1).dominio)
        a.aplicar(Evento.Dns(listOf(servidor, ip4(1, 2, 3, 4)), "tarde.exemplo"))
        assertEquals("tarde.exemplo", a.conexoes.getValue(1).dominio)
        assertEquals("sni.exemplo", a.conexoes.getValue(2).dominio)
    }

    @Test fun `bytes e fim atualizam e a ordem de atividade sobe`() {
        val a = agregador()
        a.aplicar(novo(1))
        a.aplicar(novo(2))
        val ordemAntes = a.conexoes.getValue(1).ordem
        a.aplicar(Evento.FluxoBytes(1, 100, 2000, 7))
        val c = a.conexoes.getValue(1)
        assertEquals(100L, c.bytesEnviados)
        assertEquals(2000L, c.bytesRecebidos)
        assertEquals(7L, c.pacotes)
        assert(c.ordem > ordemAntes && c.ordem > a.conexoes.getValue(2).ordem)
        a.aplicar(Evento.FluxoFim(1, 9_000, MotivoFim.FECHADO))
        assertEquals(9_000L, a.conexoes.getValue(1).fimUs)
        assertEquals(MotivoFim.FECHADO, a.conexoes.getValue(1).motivo)
    }

    @Test fun `evento de fluxo desconhecido e perdas sao contados sem quebrar`() {
        val a = agregador()
        a.aplicar(Evento.FluxoBytes(99, 1, 1, 1))
        a.aplicar(Evento.Sni(99, "x"))
        a.aplicar(Evento.Perda(5))
        assertEquals(0, a.conexoes.size)
        assertEquals(5L, a.eventosPerdidos)
    }
}
