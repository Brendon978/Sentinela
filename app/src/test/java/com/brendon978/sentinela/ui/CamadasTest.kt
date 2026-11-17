package com.brendon978.sentinela.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class CamadasTest {
    // Formato de native/src/dissecar.c: "Resumo:", depois cada camada com nome sem recuo,
    // campos "  Campo: valor" e, nos dados, linhas de hex "  0000  xx xx …  ascii".
    private val texto = """
        Resumo: TCP 10.111.0.1:40000 → 93.184.215.14:443 517 bytes de dados

        IPv4
          Versão: 4
          TTL: 64
          Checksum: 0x1c2d [correto]
          Origem: 10.111.0.1
          Destino: 93.184.215.14

        TCP
          Porta de origem: 40000
          Flags: 0x018 (PSH ACK)

        TLS ClientHello
          SNI: www.exemplo.com
          ECH: não

        Dados (20 bytes)
          0000  16 03 01 02 00 01 00 01 fc 03 03 aa bb cc dd ee  ................
          0010  ff 00 11 22                                      ..."
          … (+3 bytes)
    """.trimIndent()

    @Test fun `separa resumo, camadas, campos e hex`() {
        val d = Camadas.separar(texto)
        assertEquals("TCP 10.111.0.1:40000 → 93.184.215.14:443 517 bytes de dados", d.resumo)
        assertEquals(listOf("IPv4", "TCP", "TLS ClientHello", "Dados (20 bytes)"), d.camadas.map { it.nome })
        assertEquals("Checksum" to "0x1c2d [correto]", d.camadas[0].campos[2])
        assertEquals("SNI" to "www.exemplo.com", d.camadas[2].campos[0])
        val dados = d.camadas[3]
        assertEquals(emptyList<Pair<String, String>>(), dados.campos)
        assertEquals(3, dados.hex.size)
        assertEquals("0000  16 03 01 02 00 01 00 01 fc 03 03 aa bb cc dd ee  ................", dados.hex[0])
        assertEquals("… (+3 bytes)", dados.hex[2])
    }

    @Test fun `pacote invalido so tem resumo`() {
        val d = Camadas.separar("Resumo: pacote inválido ou cortado (3 bytes)\n")
        assertEquals("pacote inválido ou cortado (3 bytes)", d.resumo)
        assertEquals(emptyList<Camada>(), d.camadas)
    }
}
