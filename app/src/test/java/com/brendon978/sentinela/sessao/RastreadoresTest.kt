package com.brendon978.sentinela.sessao

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RastreadoresTest {
    @Test fun `casa o dominio e os subdominios`() {
        assertEquals("Google Ads", Rastreadores.de("doubleclick.net")?.empresa)
        assertEquals("Google Ads", Rastreadores.de("ad.doubleclick.net")?.empresa)
        assertEquals("Google Ads", Rastreadores.de("AD.DoubleClick.NET.")?.empresa)
    }

    @Test fun `nao casa so por terminar com o mesmo texto`() {
        assertNull(Rastreadores.de("notdoubleclick.net"))
        assertNull(Rastreadores.de("doubleclick.net.exemplo.com"))
        assertNull(Rastreadores.de(null))
    }

    @Test fun `resumo por app soma e lista rastreadores`() {
        fun l(id: Long, pacote: String?, dominio: String?, env: Long, rec: Long) = LinhaFluxo(
            0, id, 6, 4, "10.111.0.1", 1, "1.1.1.1", 443, 1, pacote, pacote?.substringAfterLast('.'),
            dominio, "SNI", env, rec, 1, 0, null, null,
        )
        val r = PorApp.resumir(
            listOf(
                l(1, "com.jogo", "app-measurement.com", 10, 20),
                l(2, "com.jogo", "api.jogo.com", 100, 1000),
                l(3, "com.jogo", "api.jogo.com", 1, 1),
                l(4, "com.android.chrome", "www.exemplo.com", 5, 5),
                l(5, null, null, 1, 1),
            )
        )
        assertEquals(listOf("com.jogo", "com.android.chrome", null), r.map { it.pacote })
        val jogo = r[0]
        assertEquals(3, jogo.conexoes)
        assertEquals(111L, jogo.bytesEnviados)
        assertEquals(1021L, jogo.bytesRecebidos)
        assertEquals(setOf("app-measurement.com", "api.jogo.com"), jogo.dominios)
        assertEquals(setOf("app-measurement.com"), jogo.rastreadores)
    }
}
