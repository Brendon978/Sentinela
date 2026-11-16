package com.brendon978.sentinela.ui

import com.brendon978.sentinela.motor.Ip
import com.brendon978.sentinela.motor.Protocolo
import com.brendon978.sentinela.sessao.Conexao
import com.brendon978.sentinela.sessao.LinhaFluxo
import com.brendon978.sentinela.vpn.App
import org.junit.Assert.assertEquals
import org.junit.Test

class ListaTest {
    private fun ip(a: Int) = Ip(4, byteArrayOf(93, -72, -41, a.toByte()))
    private fun conexao(id: Long, ordem: Long, app: App?, dominio: String?, porta: Int = 443) = Conexao(
        id, Protocolo.TCP, Ip(4, byteArrayOf(10, 111, 0, 1)), 40000, ip(id.toInt()), porta, 0, app,
        dominio = dominio, ordem = ordem,
    )

    private val chrome = App(1, "com.android.chrome", "Chrome")
    private val zap = App(2, "com.whatsapp", "WhatsApp")

    @Test fun `ao vivo ordena pela atividade mais recente`() {
        val l = Lista.aoVivo(listOf(conexao(1, 5, chrome, "a"), conexao(2, 9, zap, "b"), conexao(3, 7, chrome, "c")))
        assertEquals(listOf(2L, 3L, 1L), l.map { it.fluxoId })
    }

    @Test fun `filtro por texto acha app dominio ip e porta sem diferenciar maiusculas`() {
        val linhas = Lista.aoVivo(
            listOf(conexao(1, 1, chrome, "www.exemplo.com"), conexao(2, 2, zap, "mmg.whatsapp.net"), conexao(3, 3, null, null, 853))
        )
        assertEquals(listOf(2L), Lista.filtrar(linhas, "WHATS", null).map { it.fluxoId })
        assertEquals(listOf(1L), Lista.filtrar(linhas, "exemplo", null).map { it.fluxoId })
        assertEquals(listOf(1L), Lista.filtrar(linhas, "93.184.215.1", null).map { it.fluxoId })
        assertEquals(listOf(3L), Lista.filtrar(linhas, "853", null).map { it.fluxoId })
        assertEquals(3, Lista.filtrar(linhas, "  ", null).size)
    }

    @Test fun `filtro por app combina com texto`() {
        val linhas = Lista.aoVivo(listOf(conexao(1, 1, chrome, "x.com"), conexao(2, 2, zap, "x.com")))
        assertEquals(listOf(1L), Lista.filtrar(linhas, "x.com", "com.android.chrome").map { it.fluxoId })
    }

    @Test fun `bytes legiveis`() {
        assertEquals("0 B", Lista.bytes(0))
        assertEquals("999 B", Lista.bytes(999))
        assertEquals("1,5 KB", Lista.bytes(1536))
        assertEquals("2,0 MB", Lista.bytes(2L * 1024 * 1024))
    }
}
