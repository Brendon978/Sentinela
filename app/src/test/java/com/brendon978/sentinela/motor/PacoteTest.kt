package com.brendon978.sentinela.motor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class PacoteTest {
    private fun hex(nome: String): ByteArray =
        File("../native/tests/fixtures/$nome.hex").readLines().filterNot { it.startsWith("#") }
            .joinToString("").replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun comCarimbo(q: Long, p: ByteArray) = ByteArray(8) { (q shr (8 * it)).toByte() } + p
    private val app = Ip(4, byteArrayOf(10, 111, 0, 1))

    @Test fun `carimbo e sentido do app`() {
        val p = Pacote.de(comCarimbo(1_700_000_000_000_001L, hex("v4_udp_simples")), app)
        assertEquals(1_700_000_000_000_001L, p.quandoUs)
        assertEquals(30, p.bytes.size)
        assertTrue(p.doApp)
    }

    @Test fun `resposta do servidor nao e do app`() {
        assertFalse(Pacote.de(comCarimbo(0, hex("montar_v4_udp")), app).doApp)
    }

    @Test fun `ipv6`() {
        val v6 = Ip(6, byteArrayOf(0xfd.toByte(), 0, 0, 0x5e, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1))
        assertTrue(Pacote.de(comCarimbo(0, hex("v6_udp_simples")), v6).doApp)
    }
}
