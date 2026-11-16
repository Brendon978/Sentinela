package com.brendon978.sentinela.motor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/** Bytes montados à mão a partir da tabela C2 do plano (little-endian). */
class EventosTest {
    private class Lote {
        val out = ByteArrayOutputStream()
        fun registro(tipo: Int, corpo: ByteArray) = apply {
            out.write(tipo)
            out.write(corpo.size and 0xff)
            out.write(corpo.size shr 8)
            out.write(corpo)
        }
        fun bytes(): ByteArray = out.toByteArray()
    }

    private class Corpo {
        val out = ByteArrayOutputStream()
        fun u8(v: Int) = apply { out.write(v) }
        fun u16(v: Int) = apply { out.write(v and 0xff); out.write(v shr 8 and 0xff) }
        fun u32(v: Long) = apply { for (i in 0 until 4) out.write((v shr (8 * i)).toInt() and 0xff) }
        fun u64(v: Long) = apply { for (i in 0 until 8) out.write((v shr (8 * i)).toInt() and 0xff) }
        fun ip(vararg b: Int) = apply { val ip = ByteArray(16); b.forEachIndexed { i, x -> ip[i] = x.toByte() }; out.write(ip) }
        fun texto(s: String) = apply { out.write(s.toByteArray()) }
        fun bytes(): ByteArray = out.toByteArray()
    }

    @Test
    fun `fluxo novo IPv4`() {
        val corpo = Corpo().u32(7).u8(4).u8(6).ip(10, 111, 0, 1).u16(40000).ip(93, 184, 215, 14).u16(443)
            .u64(1_700_000_000_000_000L).bytes()
        val lote = Eventos.decodificar(Lote().registro(1, corpo).bytes())
        assertNull(lote.erro)
        val e = lote.eventos.single() as Evento.FluxoNovo
        assertEquals(7L, e.id)
        assertEquals(Protocolo.TCP, e.protocolo)
        assertEquals("10.111.0.1", e.origem.texto)
        assertEquals(40000, e.portaOrigem)
        assertEquals("93.184.215.14", e.destino.texto)
        assertEquals(443, e.portaDestino)
        assertEquals(1_700_000_000_000_000L, e.inicioUs)
    }

    @Test
    fun `fluxo novo IPv6 com UDP`() {
        val corpo = Corpo().u32(1).u8(6).u8(17)
            .ip(0xfd, 0, 0, 0x5e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1).u16(5353)
            .ip(0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11).u16(53).u64(5).bytes()
        val e = Eventos.decodificar(Lote().registro(1, corpo).bytes()).eventos.single() as Evento.FluxoNovo
        assertEquals(Protocolo.UDP, e.protocolo)
        assertEquals("fd00:5e:1::1", e.origem.texto)
        assertEquals("2606:4700:4700::1111", e.destino.texto)
    }

    @Test
    fun `bytes e fim com valores grandes sem sinal`() {
        val bytes = Corpo().u32(0xFFFF_FFFFL).u64(5_000_000_000L).u64(3).u32(0x8000_0000L).bytes()
        val fim = Corpo().u32(2).u64(1_700_000_001_000_000L).u8(1).bytes()
        val lote = Eventos.decodificar(Lote().registro(2, bytes).registro(3, fim).bytes())
        val b = lote.eventos[0] as Evento.FluxoBytes
        assertEquals(4294967295L, b.id)
        assertEquals(5_000_000_000L, b.bytesEnviados)
        assertEquals(3L, b.bytesRecebidos)
        assertEquals(2147483648L, b.pacotes)
        val f = lote.eventos[1] as Evento.FluxoFim
        assertEquals(MotivoFim.RESET, f.motivo)
        assertEquals(1_700_000_001_000_000L, f.fimUs)
    }

    @Test
    fun `dns com dois enderecos e sni`() {
        val dns = Corpo().u16(2).u8(4).u8(6).ip(93, 184, 215, 14)
            .ip(0x26, 0x06, 0x28, 0, 0x02, 0x1f, 0xcb, 0x07, 0x68, 0x20, 0x80, 0xda, 0xaf, 0x6b, 0x8b, 0x2c)
            .u16(15).texto("www.exemplo.com").bytes()
        val sni = Corpo().u32(9).u16(18).texto("www.exemplo.com.br").bytes()
        val lote = Eventos.decodificar(Lote().registro(4, dns).registro(5, sni).bytes())
        val d = lote.eventos[0] as Evento.Dns
        assertEquals("www.exemplo.com", d.nome)
        assertEquals(listOf("93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"), d.enderecos.map { it.texto })
        val s = lote.eventos[1] as Evento.Sni
        assertEquals(9L, s.id)
        assertEquals("www.exemplo.com.br", s.nome)
    }

    @Test
    fun `perda e tipo desconhecido pulado`() {
        val lote = Eventos.decodificar(
            Lote().registro(99, byteArrayOf(1, 2, 3)).registro(6, Corpo().u32(12).bytes()).bytes()
        )
        assertNull(lote.erro)
        assertEquals(12L, (lote.eventos.single() as Evento.Perda).descartados)
    }

    @Test
    fun `lote cortado no meio vira erro e mantem o que veio antes`() {
        val inteiro = Lote().registro(6, Corpo().u32(1).bytes()).registro(5, Corpo().u32(1).u16(3).texto("abc").bytes()).bytes()
        val cortado = inteiro.copyOf(inteiro.size - 2)
        val lote = Eventos.decodificar(cortado)
        assertEquals(1, lote.eventos.size)
        assertNotNull(lote.erro)
    }

    @Test
    fun `corpo menor que o esperado vira erro sem excecao`() {
        val lote = Eventos.decodificar(Lote().registro(1, byteArrayOf(1, 2)).bytes())
        assertTrue(lote.eventos.isEmpty())
        assertNotNull(lote.erro)
    }
}
