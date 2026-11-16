package com.brendon978.sentinela.sessao

import com.brendon978.sentinela.dados.EstadoSessaoSalva
import com.brendon978.sentinela.dados.SessaoSalva
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.ZoneId

class ExportacaoTest {
    private fun l(id: Long, ip: String, dominio: String?, rotulo: String? = "Chrome") = LinhaFluxo(
        0, id, 6, 4, "10.111.0.1", 40000, ip, 443, 10123, "com.android.chrome", rotulo, dominio, "SNI",
        100, 2000, 7, 1_700_000_000_000_000 + id * 1_000_000, 1_700_000_000_000_000 + id * 1_000_000 + 2_500_000, 0,
    )

    private val linhas = listOf(l(1, "93.184.215.14", "www.exemplo.com"), l(2, "93.184.215.14", "www.exemplo.com"), l(3, "1.2.3.4", null, "App, \"Pro\""))

    @Test fun `csv com cabecalho e uma linha por fluxo`() {
        val csv = Exportacao.csv(linhas, anonimizar = false, sal = ByteArray(16)).lines().filter { it.isNotEmpty() }
        assertEquals(
            "fluxo_id,inicio_utc,duracao_s,protocolo,ip_origem,porta_origem,ip_destino,porta_destino,pacote_app,app,dominio,origem_dominio,bytes_enviados,bytes_recebidos,pacotes,tela_desligada,motivo_fim,nota_ia,limiar_ia",
            csv[0],
        )
        assertEquals(4, csv.size)
        assertTrue(csv[1].startsWith("1,2023-11-14T22:13:21Z,2.500,TCP,10.111.0.1,40000,93.184.215.14,443,com.android.chrome,Chrome,www.exemplo.com,SNI,100,2000,7,0,FECHADO"))
        // vírgula e aspas dentro do campo seguem a RFC 4180
        assertTrue(csv[3].contains(",\"App, \"\"Pro\"\"\","))
    }

    @Test fun `anonimizado troca ip e dominio por pseudonimos estaveis`() {
        // sem o rótulo com vírgula: aqui as colunas são separadas por split simples
        val linhas = listOf(l(1, "93.184.215.14", "www.exemplo.com"), l(2, "93.184.215.14", "www.exemplo.com"), l(3, "1.2.3.4", null))
        val sal = ByteArray(16) { it.toByte() }
        val csv = Exportacao.csv(linhas, anonimizar = true, sal = sal)
        assertFalse(csv.contains("93.184.215.14"))
        assertFalse(csv.contains("1.2.3.4"))
        assertFalse(csv.contains("exemplo"))
        val campos = csv.lines().drop(1).filter { it.isNotEmpty() }.map { it.split(",") }
        assertEquals(campos[0][6], campos[1][6])           // mesmo IP, mesmo pseudônimo no arquivo
        assertNotEquals(campos[0][6], campos[2][6])        // IPs diferentes, pseudônimos diferentes
        assertTrue(campos[0][6].startsWith("ip-"))
        assertTrue(campos[0][10].startsWith("dom-"))
        assertEquals("", campos[2][10])                     // sem domínio continua vazio
        // outro sal (outra exportação), outros pseudônimos: não dá para cruzar arquivos
        val outro = Exportacao.csv(linhas, anonimizar = true, sal = ByteArray(16) { 9 })
        assertNotEquals(campos[0][6], outro.lines()[1].split(",")[6])
    }

    @Test fun `anonimizado tambem esconde a origem quando nao e o endereco do tun`() {
        // QUIC do Chrome às vezes sai com o IP do Wi-Fi do celular como origem (visto no aparelho)
        val comLan = listOf(l(1, "93.184.215.14", "a.com").copy(ipOrigem = "192.168.77.67"), l(2, "93.184.215.14", "a.com"))
        val csv = Exportacao.csv(comLan, anonimizar = true, sal = ByteArray(16))
        assertFalse(csv.contains("192.168.77.67"))
        assertTrue(csv.contains(",10.111.0.1,")) // o endereço do tun é igual em todo celular: fica
    }

    @Test fun `relatorio de sessao interrompida diz como o hash foi calculado`() {
        val s = SessaoSalva(7, 1_700_000_000_000, 1_700_000_090_000, "/x/s.pcap", "ab".repeat(32), 1, 1, 0, EstadoSessaoSalva.INTERROMPIDA)
        val texto = Relatorio.conteudo(s, emptyList(), emptyList(), "a", "v", ZoneId.of("UTC"), 0)
            .first { it.titulo == "Cadeia de custódia" }.linhas.joinToString("\n")
        assertTrue(texto.contains("interrompida"))
        assertFalse(texto.contains("ao encerrar a captura"))
    }

    @Test fun `quebra de linha do pdf termina mesmo com palavra maior que a linha`() {
        // mede 1 unidade por caractere; cabem 20
        val dominio = "a".repeat(200) + ".exemplo.com"
        val linhas = RelatorioPdf.quebrar("Domínio: $dominio", 20) { t, max -> minOf(t.length, max) }
        assertTrue(linhas.size in 2..30)
        assertEquals("Domínio: $dominio".replace(" ", ""), linhas.joinToString("").replace(" ", ""))
    }

    @Test fun `por app nao mistura dois grupos sem pacote`() {
        val semPacote = listOf(
            l(1, "10.111.0.53", null, "DNS do sistema").copy(pacoteApp = null),
            l(2, "1.2.3.4", null, null).copy(pacoteApp = null),
        )
        val r = PorApp.resumir(semPacote)
        assertEquals(setOf("DNS do sistema", "Sistema/desconhecido"), r.map { it.rotulo }.toSet())
    }

    @Test fun `relatorio tem integridade, cadeia de custodia, apps e alertas`() {
        val s = SessaoSalva(7, 1_700_000_000_000, 1_700_000_090_000, "/x/sessao-1700000000000.pcap", "ab".repeat(32), 326, 2_100_000, 0, EstadoSessaoSalva.CONCLUIDA)
        val alerta = Alerta(Regra.RASTREADOR, "com.android.chrome", "Chrome", 1, "x.doubleclick.net: Google Ads · anúncios", 1_700_000_001_000_000)
        val r = Relatorio.conteudo(s, linhas, listOf(alerta), aparelho = "samsung SM-S731B (Android 16)", versaoApp = "0.2.0",
            fuso = ZoneId.of("America/Sao_Paulo"), geradoEmMs = 1_700_000_100_000)
        val texto = r.joinToString("\n") { it.titulo + "\n" + it.linhas.joinToString("\n") }
        assertTrue(texto.contains("ab".repeat(32)))
        assertTrue(texto.contains("sessao-1700000000000.pcap"))
        assertTrue(texto.contains("14/11/2023 19:13:20 (America/Sao_Paulo)")) // início em hora local com o fuso dito
        assertTrue(texto.contains("326 pacotes"))
        assertTrue(texto.contains("Situação: concluída"))
        assertTrue(texto.contains("samsung SM-S731B (Android 16)"))
        assertTrue(texto.contains("Chrome"))
        assertTrue(texto.contains("Rastreador conhecido"))
        assertTrue(texto.contains("www.exemplo.com"))
        assertEquals(listOf("Identificação", "Integridade", "Cadeia de custódia", "Resumo por app", "Alertas", "Domínios"), r.map { it.titulo })
    }
}
