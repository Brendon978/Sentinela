package com.brendon978.sentinela.ui.tema

import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ContrasteTest {
    @Test fun `preto e branco tem contraste 21 e cor igual tem 1`() {
        assertEquals(21.0, contraste(Color.Black, Color.White), 0.01)
        assertEquals(1.0, contraste(Color(0xFF3DF2A0), Color(0xFF3DF2A0)), 0.001)
    }

    /** Pares que viram texto ou ícone na tela: todos AA (≥ 4,5:1), nos dois temas. */
    @Test fun `paletas passam AA nos pares usados`() {
        for (p in listOf(Paleta.ESCURO, Paleta.CLARO)) {
            val pares = buildList {
                for (f in listOf(p.fundo, p.superficie, p.superficie2)) {
                    add("texto" to (p.texto to f)); add("textoSecundario" to (p.textoSecundario to f))
                    add("primaria" to (p.primaria to f)); add("secundaria" to (p.secundaria to f))
                    add("rede" to (p.rede to f)); add("privacidade" to (p.privacidade to f))
                    add("comportamento" to (p.comportamento to f)); add("novidade" to (p.novidade to f))
                    add("perigo" to (p.perigo to f))
                }
                add("sobrePrimaria" to (p.sobrePrimaria to p.primaria))
            }
            for ((nome, par) in pares) {
                val c = contraste(par.first, par.second)
                assertTrue("${if (p.claro) "claro" else "escuro"} $nome: $c", c >= 4.5)
            }
        }
    }

    /** Selos e botão de gravar: texto na própria cor sobre a mesma cor translúcida. */
    @Test fun `texto de selo e do botao passa AA sobre o fundo translucido`() {
        for (p in listOf(Paleta.ESCURO, Paleta.CLARO)) {
            val cores = mapOf(
                "primaria" to p.primaria, "secundaria" to p.secundaria, "textoSecundario" to p.textoSecundario,
                "rede" to p.rede, "privacidade" to p.privacidade, "comportamento" to p.comportamento,
                "novidade" to p.novidade, "perigo" to p.perigo,
            )
            for (f in listOf(p.fundo, p.superficie, p.superficie2)) for ((nome, c) in cores) {
                val v = contraste(c, composta(c, ALFA_SELO, f))
                assertTrue("${if (p.claro) "claro" else "escuro"} selo $nome: $v", v >= 4.5)
            }
            for ((nome, c) in listOf("primaria" to p.primaria, "perigo" to p.perigo)) {
                val v = contraste(c, composta(c, ALFA_BOTAO, p.superficie))
                assertTrue("${if (p.claro) "claro" else "escuro"} botão $nome: $v", v >= 4.5)
            }
        }
    }

    /** Aviso (texto principal sobre âmbar translúcido) e nome da camada sobre a própria cor translúcida. */
    @Test fun `aviso e bloco de camada passam AA`() {
        for (p in listOf(Paleta.ESCURO, Paleta.CLARO)) {
            val aviso = contraste(p.texto, composta(p.comportamento, ALFA_AVISO, p.superficie))
            assertTrue("aviso: $aviso", aviso >= 4.5)
            for (c in listOf(p.rede, p.primaria, p.textoSecundario, p.privacidade)) {
                val v = contraste(c, composta(c, ALFA_CAMADA, p.superficie))
                assertTrue("camada: $v", v >= 4.5)
            }
        }
    }
}
