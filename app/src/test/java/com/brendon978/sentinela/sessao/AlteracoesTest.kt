package com.brendon978.sentinela.sessao

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AlteracoesTest {
    private fun l(id: Long, rec: Long = 1) = LinhaFluxo(
        0, id, 6, 4, "10.111.0.1", 40000, "1.1.1.1", 443, 10000, "com.a", "A", "a.com", "SNI",
        1, rec, 1, 0, null, null,
    )
    private val alerta = Alerta(Regra.RASTREADOR, "com.a", "A", 1, "x", 0)

    @Test fun `primeira vez vai tudo`() {
        val p = Alteracoes().desde(listOf(l(1), l(2)), listOf(alerta))
        assertEquals(listOf(1L, 2L), p.fluxos.map { it.fluxoId })
        assertEquals(listOf(alerta), p.alertas)
    }

    @Test fun `depois de confirmar so volta o que mudou ou e novo`() {
        val a = Alteracoes()
        a.confirmar(a.desde(listOf(l(1), l(2)), listOf(alerta)))
        val p = a.desde(listOf(l(1), l(2, rec = 99), l(3)), listOf(alerta))
        assertEquals(listOf(2L, 3L), p.fluxos.map { it.fluxoId })
        assertNull("alertas iguais não são regravados", p.alertas)
    }

    @Test fun `sem confirmar (gravacao falhou) volta tudo de novo`() {
        val a = Alteracoes()
        a.desde(listOf(l(1)), listOf(alerta))
        val p = a.desde(listOf(l(1)), listOf(alerta))
        assertEquals(listOf(1L), p.fluxos.map { it.fluxoId })
        assertEquals(listOf(alerta), p.alertas)
    }

    @Test fun `alerta novo regrava a lista`() {
        val a = Alteracoes()
        a.confirmar(a.desde(listOf(l(1)), listOf(alerta)))
        val outro = alerta.copy(regra = Regra.PORTA_INCOMUM)
        assertEquals(listOf(alerta, outro), a.desde(listOf(l(1)), listOf(alerta, outro)).alertas)
    }
}
