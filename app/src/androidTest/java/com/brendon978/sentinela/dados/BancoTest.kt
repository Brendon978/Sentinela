package com.brendon978.sentinela.dados

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.brendon978.sentinela.sessao.LinhaFluxo
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Roda no aparelho, num banco próprio do teste (não toca no banco do app). */
@RunWith(AndroidJUnit4::class)
class BancoTest {
    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var banco: Banco

    @Before fun abre() {
        ctx.deleteDatabase("sentinela-teste.db")
        banco = Banco(ctx, "sentinela-teste.db")
    }

    @After fun fecha() {
        banco.close()
        ctx.deleteDatabase("sentinela-teste.db")
    }

    private fun linha(id: Long, pacote: String?, dominio: String?) = LinhaFluxo(
        0, id, 6, 4, "10.111.0.1", 40000 + id.toInt(), "93.184.215.14", 443, 10123, pacote, "Chrome",
        dominio, "SNI", 10, 20, 3, 1_700_000_000_000_000, null, null,
    )

    @Test fun salvaELeSessaoComFluxos() {
        val s = SessaoSalva(0, 1000, 2000, "/x/sessao-1000.pcap", "abc", 3, 30, 0)
        val id = banco.salvarSessao(s, listOf(linha(1, "com.android.chrome", "www.exemplo.com"), linha(2, null, null)), 5000)
        val salvas = banco.sessoes()
        assertEquals(1, salvas.size)
        assertEquals(id, salvas[0].id)
        assertEquals("abc", salvas[0].sha256)
        val fluxos = banco.fluxos(id)
        assertEquals(listOf(1L, 2L), fluxos.map { it.fluxoId }.sorted())
        val f = fluxos.first { it.fluxoId == 1L }
        assertEquals(6, f.protocolo)
        assertEquals(id, f.sessaoId)
        assertEquals("www.exemplo.com", f.dominio)
        assertEquals(setOf("com.android.chrome" to "www.exemplo.com"), banco.dominiosVistos())
    }

    @Test fun alertasVoltamComOsCampos() {
        val a = com.brendon978.sentinela.sessao.Alerta(
            com.brendon978.sentinela.sessao.Regra.RASTREADOR, "com.jogo", "Jogo", 1, "x.doubleclick.net", 1_700_000_000_000_000,
        )
        val id = banco.salvarSessao(SessaoSalva(0, 1, 2, "/x", "h", 0, 0, 0), listOf(linha(1, "com.jogo", "x.doubleclick.net")), 1, listOf(a))
        assertEquals(listOf(a), banco.alertas(id))
    }

    /** O celular do Brendon tinha um banco da versão 1: ele tem de abrir e continuar funcionando. */
    @Test fun migraDaVersao1() {
        banco.close()
        ctx.deleteDatabase("sentinela-teste.db")
        val v1 = android.database.sqlite.SQLiteDatabase.openOrCreateDatabase(ctx.getDatabasePath("sentinela-teste.db"), null)
        v1.execSQL("CREATE TABLE sessao (id INTEGER PRIMARY KEY AUTOINCREMENT, inicio_ms INTEGER NOT NULL, fim_ms INTEGER NOT NULL, caminho_pcap TEXT NOT NULL, sha256 TEXT NOT NULL, pacotes INTEGER NOT NULL, bytes INTEGER NOT NULL, eventos_perdidos INTEGER NOT NULL)")
        v1.execSQL("CREATE TABLE fluxo (sessao_id INTEGER NOT NULL REFERENCES sessao(id) ON DELETE CASCADE, fluxo_id INTEGER NOT NULL, proto INTEGER NOT NULL, versao_ip INTEGER NOT NULL, ip_origem TEXT NOT NULL, porta_origem INTEGER NOT NULL, ip_destino TEXT NOT NULL, porta_destino INTEGER NOT NULL, uid INTEGER NOT NULL, pacote_app TEXT, rotulo_app TEXT, dominio TEXT, origem_dominio TEXT NOT NULL, bytes_env INTEGER NOT NULL, bytes_rec INTEGER NOT NULL, pacotes INTEGER NOT NULL, inicio_us INTEGER NOT NULL, fim_us INTEGER, motivo_fim INTEGER, PRIMARY KEY (sessao_id, fluxo_id))")
        v1.execSQL("CREATE TABLE dominio_visto (pacote_app TEXT NOT NULL, dominio TEXT NOT NULL, primeira_vez_ms INTEGER NOT NULL, PRIMARY KEY (pacote_app, dominio))")
        v1.execSQL("CREATE TABLE alerta (id INTEGER PRIMARY KEY AUTOINCREMENT, sessao_id INTEGER NOT NULL REFERENCES sessao(id) ON DELETE CASCADE, fluxo_id INTEGER, regra TEXT NOT NULL, pacote_app TEXT, detalhe TEXT NOT NULL, quando_ms INTEGER NOT NULL)")
        v1.execSQL("INSERT INTO sessao VALUES (1, 1, 2, '/x', 'h', 0, 0, 0)")
        v1.execSQL("INSERT INTO fluxo VALUES (1, 7, 6, 4, '10.111.0.1', 1, '1.1.1.1', 443, 1, 'com.a', 'A', 'a.com', 'SNI', 1, 1, 1, 0, NULL, NULL)")
        v1.version = 1
        v1.close()
        banco = Banco(ctx, "sentinela-teste.db")
        assertEquals(listOf(7L), banco.fluxos(1).map { it.fluxoId })
        assertEquals(false, banco.fluxos(1)[0].telaDesligada)
        banco.salvarSessao(SessaoSalva(0, 3, 4, "/y", "h", 0, 0, 0), listOf(linha(1, "com.a", "b.com")), 1,
            listOf(com.brendon978.sentinela.sessao.Alerta(com.brendon978.sentinela.sessao.Regra.DOMINIO_NOVO, "com.a", "A", 1, "b.com", 0)))
        assertEquals(2, banco.sessoes().size)
    }

    @Test fun gravacaoContinuaSemDuplicarEFechaNoFim() {
        val id = banco.abrirSessao(1000, "/x/sessao-1000.pcap")
        assertEquals(listOf(EstadoSessaoSalva.GRAVANDO), banco.sessoes().map { it.estado })
        banco.gravarParcial(id, listOf(linha(1, "com.a", "a.com")), emptyList(), 2000, bytes = 30, eventosPerdidos = 0)
        // o mesmo fluxo com bytes novos + um fluxo novo: atualiza, não duplica
        banco.gravarParcial(id, listOf(linha(1, "com.a", "a.com").copy(bytesRecebidos = 99), linha(2, "com.b", "b.com")), emptyList(), 3000, bytes = 149, eventosPerdidos = 0)
        val f = banco.fluxos(id)
        assertEquals(listOf(1L, 2L), f.map { it.fluxoId }.sorted())
        assertEquals(99L, f.first { it.fluxoId == 1L }.bytesRecebidos)
        assertEquals(emptySet<Pair<String, String>>(), banco.dominiosVistos()) // só aprende ao concluir
        banco.concluirSessao(id, "hash", 7, 300, 4000, 0, f, emptyList())
        val s = banco.sessoes().single()
        assertEquals(EstadoSessaoSalva.CONCLUIDA, s.estado)
        assertEquals("hash", s.sha256)
        assertEquals(7L, s.pacotes)
        assertEquals(2, banco.dominiosVistos().size)
    }

    @Test fun sessaoQueFicouGravandoViraInterrompida() {
        val pcap = java.io.File(ctx.cacheDir, "interrompida.pcap")
        // cabeçalho global + 1 registro inteiro de 4 bytes + 1 registro cortado
        val global = byteArrayOf(0xd4.toByte(), 0xc3.toByte(), 0xb2.toByte(), 0xa1.toByte(), 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 0, 101, 0, 0, 0)
        val reg = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4)
        pcap.writeBytes(global + reg + reg.copyOf(10))
        val viva = banco.abrirSessao(1, pcap.absolutePath)
        val gravandoAgora = banco.abrirSessao(2, "/outra.pcap")
        com.brendon978.sentinela.sessao.SessaoFinal.usando(gravandoAgora) // o serviço marca a sessão que abriu
        try {
            com.brendon978.sentinela.sessao.SessaoFinal.recuperar(banco)
        } finally {
            com.brendon978.sentinela.sessao.SessaoFinal.liberou(gravandoAgora)
        }
        val porId = banco.sessoes().associateBy { it.id }
        assertEquals(EstadoSessaoSalva.INTERROMPIDA, porId.getValue(viva).estado)
        assertEquals(1L, porId.getValue(viva).pacotes)
        assertEquals(64, porId.getValue(viva).sha256.length)
        assertEquals(EstadoSessaoSalva.GRAVANDO, porId.getValue(gravandoAgora).estado)
        pcap.delete()
    }

    @Test fun recuperarNaoMexeNaSessaoEmUsoNemNaConcluida() {
        val emUso = banco.abrirSessao(1, "/em-uso.pcap")         // gravando ou fechando neste processo
        val concluida = banco.abrirSessao(2, "/concluida.pcap")
        banco.concluirSessao(concluida, "h", 1, 1, 3, 0, emptyList(), emptyList())
        com.brendon978.sentinela.sessao.SessaoFinal.usando(emUso)
        try {
            com.brendon978.sentinela.sessao.SessaoFinal.recuperar(banco)
        } finally {
            com.brendon978.sentinela.sessao.SessaoFinal.liberou(emUso)
        }
        // e o "interrompida" não sobrescreve uma sessão que já foi concluída
        banco.marcarInterrompida(concluida, "outro", 99)
        val porId = banco.sessoes().associateBy { it.id }
        assertEquals(EstadoSessaoSalva.GRAVANDO, porId.getValue(emUso).estado)
        assertEquals(EstadoSessaoSalva.CONCLUIDA, porId.getValue(concluida).estado)
        assertEquals("h", porId.getValue(concluida).sha256)
    }

    @Test fun parcialGuardaEventosPerdidos() {
        val id = banco.abrirSessao(1, "/x.pcap")
        banco.gravarParcial(id, emptyList(), emptyList(), 2, bytes = 0, eventosPerdidos = 12)
        assertEquals(12L, banco.sessoes().single().eventosPerdidos)
    }

    @Test fun parcialSoComOQueMudouMantemORestoEOsAlertas() {
        val id = banco.abrirSessao(1, "/x.pcap")
        val alerta = com.brendon978.sentinela.sessao.Alerta(
            com.brendon978.sentinela.sessao.Regra.RASTREADOR, "com.a", "Chrome", 1, "x", 5_000,
        )
        banco.gravarParcial(id, listOf(linha(1, "com.a", "a.com"), linha(2, "com.b", "b.com")), listOf(alerta), 2, bytes = 60, eventosPerdidos = 0)
        // 5 s depois só o fluxo 2 mudou; alertas iguais vão como null
        banco.gravarParcial(id, listOf(linha(2, "com.b", "b.com").copy(bytesRecebidos = 500)), null, 3, bytes = 540, eventosPerdidos = 0)
        val f = banco.fluxos(id).associateBy { it.fluxoId }
        assertEquals(setOf(1L, 2L), f.keys)
        assertEquals(500L, f.getValue(2).bytesRecebidos)
        assertEquals(listOf(alerta), banco.alertas(id))
        assertEquals(540L, banco.sessoes().single().bytes)
    }

    @Test fun apagarSessaoLevaOsFluxosJunto() {
        val id = banco.salvarSessao(SessaoSalva(0, 1, 2, "/x", "h", 0, 0, 0), listOf(linha(1, null, null)), 1)
        banco.apagarSessao(id)
        assertEquals(0, banco.sessoes().size)
        assertEquals(0, banco.fluxos(id).size)
    }
}
