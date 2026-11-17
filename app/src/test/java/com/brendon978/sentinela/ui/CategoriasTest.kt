package com.brendon978.sentinela.ui

import com.brendon978.sentinela.sessao.Regra
import org.junit.Assert.assertEquals
import org.junit.Test

class CategoriasTest {
    /** Tabela do design (docs/superpowers/specs/2026-11-17-sentinela-visual-design.md, "Formas e componentes"). */
    @Test fun `cada regra cai na categoria do design`() {
        val esperado = mapOf(
            Regra.DNS_ESCONDIDO to Categoria.REDE,
            Regra.PORTA_INCOMUM to Categoria.REDE,
            Regra.RASTREADOR to Categoria.PRIVACIDADE,
            Regra.MADRUGADA_OU_TELA_DESLIGADA to Categoria.COMPORTAMENTO,
            Regra.COMPORTAMENTO_ANOMALO to Categoria.COMPORTAMENTO,
            Regra.DOMINIO_NOVO to Categoria.NOVIDADE,
        )
        assertEquals(Regra.entries.toSet(), esperado.keys) // regra nova sem categoria quebra aqui
        for ((r, c) in esperado) assertEquals(r.name, c, categoria(r))
    }
}
