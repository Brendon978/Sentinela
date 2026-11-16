package com.brendon978.sentinela.vpn

import com.brendon978.sentinela.sessao.Alerta
import com.brendon978.sentinela.sessao.Alertas
import com.brendon978.sentinela.sessao.LinhaFluxo
import com.brendon978.sentinela.sessao.SessaoAtual
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import com.brendon978.sentinela.motor.Corpo
import com.brendon978.sentinela.motor.Lote
import java.time.ZoneOffset
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@OptIn(ExperimentalCoroutinesApi::class)
class CapturaTest {
    private val fuso = ZoneOffset.UTC

    private fun fluxoNovo(id: Long, porta: Int) = Lote().registro(
        1, Corpo().u32(id).u8(4).u8(17).ip(10, 111, 0, 1).u16(40000).ip(1, 1, 1, 1).u16(porta).u64(1_700_000_000_000_000L).bytes(),
    ).bytes()

    private fun fluxoBytes(id: Long, env: Long, rec: Long) =
        Lote().registro(2, Corpo().u32(id).u64(env).u64(rec).u32(2).bytes()).bytes()

    private class Fonte : FonteEventos {
        val fila = ConcurrentLinkedQueue<ByteArray>()
        override fun lote(): ByteArray = fila.poll() ?: ByteArray(0)
    }

    private open class Gravador : GravadorSessao {
        val gravacoes = CopyOnWriteArrayList<Int>() // quantas linhas em cada gravação
        val bytes = CopyOnWriteArrayList<Long>()
        override fun gravarParcial(id: Long, fluxos: List<LinhaFluxo>, alertas: List<Alerta>?, agoraMs: Long, bytes: Long, eventosPerdidos: Long) {
            gravacoes += fluxos.size
            this.bytes += bytes
        }
        override fun historico(): List<LinhaFluxo> = emptyList()
    }

    private fun iniciarSessao() = SessaoAtual.iniciar(
        7, 0, "/x.pcap", false, Alertas.Contexto(fuso, emptySet(), setOf("10.111.0.53")), { true }, { null },
    )

    @After fun limpar() { SessaoAtual.terminar() }

    /** Para no relógio virtual: o cancelamento dos jobs também roda no agendador do teste. */
    private fun TestScope.parar(c: Captura) {
        val j = launch { c.pararTrabalho() }
        runCurrent()
        assertTrue("a parada terminou", j.isCompleted)
    }

    @Test fun `eventos da fonte chegam a sessao e a cada 5 s a lista vai para o banco`() {
        val t = TestScope(StandardTestDispatcher())
        val d = StandardTestDispatcher(t.testScheduler)
        iniciarSessao()
        val fonte = Fonte().apply { fila += fluxoNovo(1, 443) + fluxoBytes(1, 3, 4) }
        val g = Gravador()
        val c = Captura(t, 7, fonte, g, d, fuso, { t.testScheduler.currentTime })
        c.iniciar()
        t.advanceTimeBy(300); t.runCurrent()
        assertEquals(1, SessaoAtual.estado.value.linhas.size)
        t.advanceTimeBy(5_000); t.runCurrent()
        assertEquals(listOf(1), g.gravacoes.toList())
        t.advanceTimeBy(5_000); t.runCurrent()
        assertEquals("nada mudou: não regrava", listOf(1), g.gravacoes.toList())
        fonte.fila += fluxoNovo(2, 80)
        t.advanceTimeBy(5_000); t.runCurrent()
        assertEquals("só o fluxo novo vai para o banco", listOf(1, 1), g.gravacoes.toList())
        assertEquals("bytes da sessão inteira, não só dos mudados", listOf(7L, 7L), g.bytes.toList())
        t.parar(c)
    }

    @Test fun `parar espera a gravacao em curso e depois dela nao grava mais`() = runBlocking {
        iniciarSessao()
        val dentro = CountDownLatch(1)
        val solta = CountDownLatch(1)
        val g = object : Gravador() {
            override fun gravarParcial(id: Long, fluxos: List<LinhaFluxo>, alertas: List<Alerta>?, agoraMs: Long, bytes: Long, eventosPerdidos: Long) {
                dentro.countDown()
                solta.await(30, TimeUnit.SECONDS)
                super.gravarParcial(id, fluxos, alertas, agoraMs, bytes, eventosPerdidos)
            }
        }
        val fonte = Fonte().apply { fila += fluxoNovo(1, 443) }
        // gravação a cada 50 ms (tempo real): a primeira começa logo
        val c = Captura(kotlinx.coroutines.CoroutineScope(Dispatchers.Default), 7, fonte, g, Dispatchers.IO, fuso, { 0 }, gravacaoMs = 50)
        c.iniciar()
        assertTrue("a gravação começou", dentro.await(30, TimeUnit.SECONDS))
        val parada = async(Dispatchers.Default) { c.pararTrabalho() }
        Thread.sleep(200) // estavel: só dá tempo de a parada (errada) passar; o teto real é o await abaixo
        assertFalse("parar não pode passar com a gravação no meio", parada.isCompleted)
        solta.countDown()
        withTimeout(30_000) { parada.await() }
        val feitas = g.gravacoes.size
        fonte.fila += fluxoNovo(2, 80)
        Thread.sleep(300) // estavel: janela em que uma gravação fantasma apareceria
        assertEquals(feitas, g.gravacoes.size)
        assertNotNull(c.terminar())
    }

    @Test fun `treino cancelado na parada nao entra na sessao`() = runBlocking {
        iniciarSessao()
        val lendo = CountDownLatch(1)
        val solta = CountDownLatch(1)
        val g = object : Gravador() {
            override fun historico(): List<LinhaFluxo> {
                lendo.countDown()
                solta.await(30, TimeUnit.SECONDS)
                return emptyList()
            }
        }
        val c = Captura(kotlinx.coroutines.CoroutineScope(Dispatchers.Default), 7, Fonte(), g, Dispatchers.IO, fuso, { 0 })
        c.iniciar()
        assertTrue("o treino começou a ler o histórico", lendo.await(30, TimeUnit.SECONDS))
        // sem despachar: o cancelamento acontece aqui mesmo, antes de soltar a leitura
        val parada = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { c.pararTrabalho() }
        solta.countDown()
        withTimeout(30_000) { parada.await() }
        assertNull("a IA não entrou na sessão parada", c.terminar()!!.iaApps)
    }

    @Test fun `terminar drena o que sobrou na fonte`() {
        val t = TestScope(StandardTestDispatcher())
        iniciarSessao()
        val fonte = Fonte()
        val c = Captura(t, 7, fonte, Gravador(), StandardTestDispatcher(t.testScheduler), fuso, { 0 })
        c.iniciar()
        t.parar(c)
        fonte.fila += fluxoNovo(9, 443) // o motor emite os fins depois de parar
        assertEquals(1, c.terminar()!!.linhas.size)
    }
}
