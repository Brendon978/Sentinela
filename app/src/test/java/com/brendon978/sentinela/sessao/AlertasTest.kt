package com.brendon978.sentinela.sessao

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.ZoneId
import java.time.ZonedDateTime

class AlertasTest {
    private val sp = ZoneId.of("America/Sao_Paulo")
    private val utc = ZoneId.of("UTC")

    private fun us(z: ZoneId, h: Int, m: Int) = ZonedDateTime.of(2026, 11, 16, h, m, 0, 0, z).toInstant().toEpochMilli() * 1000

    private fun l(
        id: Long, pacote: String? = "com.app", dominio: String? = "api.app.com", porta: Int = 443, proto: Int = 6,
        ip: String = "93.184.215.14", inicioUs: Long = us(sp, 12, 0), telaDesligada: Boolean = false,
    ) = LinhaFluxo(
        0, id, proto, 4, "10.111.0.1", 40000, ip, porta, 10000, pacote, pacote, dominio, "SNI",
        1, 1, 1, inicioUs, null, null, telaDesligada,
    )

    private fun regras(linhas: List<LinhaFluxo>, fuso: ZoneId = sp, vistos: Set<Pair<String, String>> = emptySet()) =
        Alertas.avaliar(linhas, Alertas.Contexto(fuso, vistos, setOf("10.111.0.53", "fd00:5e:1::53"))).map { it.regra }

    @Test fun `madrugada nos limites e no fuso certo`() {
        assertEquals(listOf(Regra.MADRUGADA_OU_TELA_DESLIGADA), regras(listOf(l(1, inicioUs = us(sp, 4, 59)))))
        assertEquals(emptyList<Regra>(), regras(listOf(l(1, inicioUs = us(sp, 5, 0)))))
        assertEquals(listOf(Regra.MADRUGADA_OU_TELA_DESLIGADA), regras(listOf(l(1, inicioUs = us(sp, 0, 0)))))
        // 02:00 em UTC = 23:00 do dia anterior em São Paulo: só alerta se o fuso for UTC
        assertEquals(emptyList<Regra>(), regras(listOf(l(1, inicioUs = us(utc, 2, 0))), fuso = sp))
        assertEquals(listOf(Regra.MADRUGADA_OU_TELA_DESLIGADA), regras(listOf(l(1, inicioUs = us(utc, 2, 0))), fuso = utc))
    }

    @Test fun `tela desligada alerta a qualquer hora mas sistema nao`() {
        assertEquals(listOf(Regra.MADRUGADA_OU_TELA_DESLIGADA), regras(listOf(l(1, telaDesligada = true))))
        assertEquals(emptyList<Regra>(), regras(listOf(l(1, pacote = null, telaDesligada = true))))
    }

    @Test fun `dominio novo so depois que o app tem historico`() {
        val historico = setOf("com.app" to "api.app.com")
        assertEquals(emptyList<Regra>(), regras(listOf(l(1, dominio = "outro.com")), vistos = emptySet()))
        assertEquals(emptyList<Regra>(), regras(listOf(l(1, dominio = "api.app.com")), vistos = historico))
        assertEquals(listOf(Regra.DOMINIO_NOVO), regras(listOf(l(1, dominio = "outro.com")), vistos = historico))
    }

    @Test fun `rastreador`() {
        assertEquals(listOf(Regra.RASTREADOR), regras(listOf(l(1, dominio = "ads.doubleclick.net"))))
    }

    @Test fun `porta incomum e as portas normais`() {
        for (p in listOf(53, 80, 123, 443, 853, 5228, 3478, 3481)) assertEquals("porta $p", emptyList<Regra>(), regras(listOf(l(1, porta = p, dominio = null))).filter { it == Regra.PORTA_INCOMUM })
        assertEquals(listOf(Regra.PORTA_INCOMUM), regras(listOf(l(1, porta = 4444, dominio = null))))
        assertEquals(listOf(Regra.PORTA_INCOMUM), regras(listOf(l(1, porta = 3482, dominio = null))))
    }

    @Test fun `dns escondido por dot doh e dns direto`() {
        assertEquals(listOf(Regra.DNS_ESCONDIDO), regras(listOf(l(1, porta = 853, dominio = null))))
        assertEquals(listOf(Regra.DNS_ESCONDIDO), regras(listOf(l(1, dominio = "dns.google"))))
        assertEquals(listOf(Regra.DNS_ESCONDIDO), regras(listOf(l(1, dominio = null, ip = "1.1.1.1"))))
        assertEquals(listOf(Regra.DNS_ESCONDIDO), regras(listOf(l(1, porta = 53, proto = 17, dominio = null, ip = "8.8.8.8"))))
        // o DNS virtual é o caminho normal, inclusive a tentativa de DoT do próprio Android
        assertEquals(emptyList<Regra>(), regras(listOf(l(1, porta = 53, proto = 17, dominio = null, ip = "10.111.0.53"))))
        assertEquals(emptyList<Regra>(), regras(listOf(l(1, porta = 853, dominio = null, ip = "10.111.0.53"))))
        // o DNS real da rede (no contexto) também é caminho normal
        assertEquals(emptyList<Regra>(), Alertas.avaliar(
            listOf(l(1, porta = 53, proto = 17, dominio = null, ip = "192.168.77.1")),
            Alertas.Contexto(sp, emptySet(), setOf("10.111.0.53", "192.168.77.1")),
        ).map { it.regra })
    }

    @Test fun `um alerta por app e regra, com o primeiro fluxo`() {
        val a = Alertas.avaliar(
            listOf(l(1, dominio = "a.doubleclick.net"), l(2, dominio = "b.doubleclick.net"), l(3, pacote = "com.outro", dominio = "c.doubleclick.net")),
            Alertas.Contexto(sp, emptySet(), emptySet()),
        )
        assertEquals(2, a.size)
        assertEquals(1L, a.first { it.pacote == "com.app" }.fluxoId)
        assertTrue(a.first { it.pacote == "com.app" }.detalhe.contains("a.doubleclick.net"))
    }
}
