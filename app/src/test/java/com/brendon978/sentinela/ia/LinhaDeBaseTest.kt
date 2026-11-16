package com.brendon978.sentinela.ia

import com.brendon978.sentinela.sessao.LinhaFluxo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.ZoneId
import java.time.ZonedDateTime
import kotlin.math.exp
import kotlin.random.Random

/**
 * Testes da IA com dados sintéticos parecidos com tráfego real (bytes e duração log-normais,
 * várias horas do dia, tela desligada em parte dos fluxos). As taxas medidas aqui são as que o
 * artigo vai citar, então o teste confere a calibração, não só um caso escolhido a dedo.
 */
class LinhaDeBaseTest {
    private val sp = ZoneId.of("America/Sao_Paulo")

    @Test fun `isolation forest da a maior nota ao ponto fora do padrao`() {
        // uso clássico (não supervisionado): o ponto estranho está nos dados e tem de sair com a
        // maior nota. Ponto novo fora da faixa é tratado na LinhaDeBase (checagem na raiz).
        val r = Random(1)
        val normais = List(300) { doubleArrayOf(10 + r.nextDouble(-2.0, 2.0), 10 + r.nextDouble(-2.0, 2.0)) }
        val estranho = doubleArrayOf(60.0, 5.0)
        val floresta = IsolationForest.treinar(normais + listOf(estranho), arvores = 100, amostra = 128, semente = 42)
        val fora = floresta.nota(estranho)
        assertTrue(fora > normais.maxOf { floresta.nota(it) })
        assertTrue(floresta.nota(doubleArrayOf(10.0, 10.0)) < 0.5)
    }

    @Test fun `mesma semente, mesmo resultado`() {
        val dados = List(50) { doubleArrayOf(it.toDouble(), (it % 7).toDouble()) }
        val a = IsolationForest.treinar(dados, 50, 32, semente = 7).nota(doubleArrayOf(3.0, 3.0))
        val b = IsolationForest.treinar(dados, 50, 32, semente = 7).nota(doubleArrayOf(3.0, 3.0))
        assertEquals(a, b, 0.0)
    }

    private var proximo = 0L

    /** Um fluxo "normal" do app: log-normal nos volumes e na duração, hora entre 8h e 23h. */
    private fun normal(r: Random, porta: Int = 443, telaDesligada: Boolean = r.nextDouble() < 0.2, hora: Int = 8 + r.nextInt(16)) =
        fluxo(
            bytesEnv = exp(7.0 + r.nextDouble(-1.0, 1.0)).toLong(), bytesRec = exp(10.0 + r.nextDouble(-1.5, 1.5)).toLong(),
            duracaoS = exp(2.0 + r.nextDouble(-1.0, 1.0)), porta = porta, hora = hora, telaDesligada = telaDesligada,
        )

    private fun fluxo(
        bytesEnv: Long, bytesRec: Long = 20_000, duracaoS: Double = 30.0, porta: Int = 443, hora: Int = 14,
        telaDesligada: Boolean = false, aberto: Boolean = false, minuto: Int = 0, sessao: Long = proximo % 5,
    ): LinhaFluxo {
        val inicio = ZonedDateTime.of(2026, 11, 16, hora, minuto, 0, 0, sp).toInstant().toEpochMilli() * 1000
        val id = proximo++
        return LinhaFluxo(
            sessao, id, 6, 4, "10.111.0.1", 40000, "1.2.3.4", porta, 10, "com.app", "App", "api.app.com", "SNI",
            bytesEnv, bytesRec, 1 + bytesRec / 1400, inicio, if (aberto) null else inicio + (duracaoS * 1e6).toLong(), 0,
            telaDesligada,
        )
    }

    private fun taxa(base: LinhaDeBase, xs: List<LinhaFluxo>) = base.avaliar(xs).size.toDouble() / xs.size

    @Test fun `alarme falso perto do alvo com o historico minimo`() {
        val r = Random(5)
        val base = LinhaDeBase.treinar(List(LinhaDeBase.MINIMO) { normal(r) }, sp)
        val frescos = List(3000) { normal(r) }
        val t = taxa(base, frescos)
        assertTrue("alarme falso = $t", t < 0.04) // alvo 1%; a revisão mediu 20% na versão anterior
    }

    @Test fun `porta nunca usada pelo app e anomala e o motivo e a porta`() {
        val r = Random(6)
        val base = LinhaDeBase.treinar(List(200) { normal(r, porta = 443) }, sp)
        val portaNova = List(200) { normal(r, porta = 4444) }
        assertTrue(taxa(base, portaNova) > 0.9)
        assertTrue(base.avaliar(portaNova).all { it.atributo == "frequencia_porta" })
    }

    @Test fun `tela desligada pela primeira vez e anomala, mas nao se o app ja faz isso`() {
        val r = Random(7)
        val semTela = LinhaDeBase.treinar(List(200) { normal(r, telaDesligada = false) }, sp)
        val primeiraVez = taxa(semTela, List(200) { normal(r, telaDesligada = true) })
        val comTela = LinhaDeBase.treinar(List(200) { normal(r) }, sp) // 20% com a tela desligada
        val costume = taxa(comTela, List(500) { normal(r, telaDesligada = true) })
        assertTrue("primeira vez = $primeiraVez", primeiraVez > 0.9)
        assertTrue("costume = $costume", costume < 0.06)
    }

    @Test fun `vazamento grande e apontado com o motivo certo`() {
        val r = Random(3)
        val base = LinhaDeBase.treinar(List(200) { normal(r) }, sp)
        val vazamento = fluxo(bytesEnv = 50_000_000, bytesRec = 20_000, duracaoS = 10.0)
        val a = base.avaliar(listOf(vazamento)).single()
        assertEquals("log_bytes_enviados", a.atributo)
        assertTrue(a.nota > a.limiar)
    }

    @Test fun `fluxo ainda aberto nao e julgado`() {
        val r = Random(4)
        val base = LinhaDeBase.treinar(List(200) { normal(r) }, sp)
        assertTrue(base.avaliar(listOf(fluxo(bytesEnv = 60, bytesRec = 0, aberto = true))).isEmpty())
    }

    @Test fun `fluxo cortado pelo fim da sessao nao e julgado`() {
        val r = Random(12)
        val base = LinhaDeBase.treinar(List(200) { normal(r) }, sp)
        val cortado = fluxo(bytesEnv = 50_000_000).copy(motivoFim = 4)
        assertTrue(base.notas(listOf(cortado)).isEmpty())
        val treinoComCortados = LinhaDeBase.treinar(List(200) { normal(r).copy(motivoFim = 4) }, sp)
        assertTrue(treinoComCortados.apps.isEmpty())
    }

    @Test fun `hora vira seno e cosseno (23h perto de 0h)`() {
        val r = Random(8)
        val base = LinhaDeBase.treinar(List(200) { normal(r) }, sp)
        val h23 = base.atributos(fluxo(1000, hora = 23))
        val h0 = base.atributos(fluxo(1000, hora = 0))
        val i = Atributos.NOMES.indexOf("hora_cos")
        assertEquals(h23[i], h0[i], 0.04)
    }

    /** Visto no aparelho: histórico de um minuto (14:51–14:52) fazia tudo às 15h virar anômalo. */
    @Test fun `faixa estreita de horario tem folga minima`() {
        val r = Random(10)
        val base = LinhaDeBase.treinar(List(200) { normal(r, hora = 14).copy() .let { x -> x } }.mapIndexed { i, x ->
            x.copy(inicioUs = x.inicioUs + (51 + i % 2) * 60_000_000L, fimUs = x.fimUs!! + (51 + i % 2) * 60_000_000L)
        }, sp)
        // o que importa: uma hora depois (dentro da folga) não alarma mais que no próprio horário
        val mesmoHorario = taxa(base, List(500) { normal(r, hora = 14).let { x -> x.copy(inicioUs = x.inicioUs + 51 * 60_000_000L, fimUs = x.fimUs!! + 51 * 60_000_000L) } })
        val depois = taxa(base, List(500) { normal(r, hora = 15) })
        val madrugada = taxa(base, List(100) { normal(r, hora = 3) })
        assertTrue("uma hora depois = $depois, no horário = $mesmoHorario", depois <= mesmoHorario + 0.02)
        assertTrue("madrugada = $madrugada", madrugada > 0.9)
    }

    @Test fun `historico de uma sessao so nao vira modelo`() {
        val r = Random(11)
        val umaSessao = List(300) { normal(r).copy(sessaoId = 42) }
        assertTrue(LinhaDeBase.treinar(umaSessao, sp).apps.isEmpty())
        val tresSessoes = umaSessao.mapIndexed { i, x -> x.copy(sessaoId = (i % 3).toLong()) }
        assertEquals(setOf("com.app"), LinhaDeBase.treinar(tresSessoes, sp).apps)
    }

    @Test fun `app sem historico suficiente nao e julgado`() {
        val r = Random(9)
        val base = LinhaDeBase.treinar(List(LinhaDeBase.MINIMO - 1) { normal(r) }, sp)
        assertTrue(base.avaliar(listOf(fluxo(bytesEnv = 50_000_000))).isEmpty())
    }
}
