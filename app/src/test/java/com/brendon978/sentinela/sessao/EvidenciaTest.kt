package com.brendon978.sentinela.sessao

import com.brendon978.sentinela.motor.Ip
import com.brendon978.sentinela.motor.MotivoFim
import com.brendon978.sentinela.motor.Protocolo
import com.brendon978.sentinela.vpn.App
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class EvidenciaTest {
    @Test fun `sha256 do pcap confere com o sha256sum`() {
        // sha256sum native/tests/fixtures/pcap_tres.pcap
        val f = File("../native/tests/fixtures/pcap_tres.pcap")
        assertEquals("7be6a36624c2d2f3e9b2cb2a459e5ae8ed983a94130c461ee2b489ea18eb84a2", Evidencia.sha256(f))
    }

    @Test fun `sha256 de arquivo vazio`() {
        val f = File.createTempFile("vazio", ".pcap").apply { deleteOnExit() }
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Evidencia.sha256(f))
    }

    @Test fun `conta os pacotes do pcap como o capinfos`() {
        // capinfos -c native/tests/fixtures/pcap_tres.pcap -> 3
        assertEquals(3L, Evidencia.contarPacotes(File("../native/tests/fixtures/pcap_tres.pcap")))
    }

    @Test fun `pcap cortado conta so os registros inteiros`() {
        val inteiro = File("../native/tests/fixtures/pcap_tres.pcap").readBytes()
        val f = File.createTempFile("cortado", ".pcap").apply { deleteOnExit() }
        f.writeBytes(inteiro.copyOf(24 + 46 + 67 + 10))
        assertEquals(2L, Evidencia.contarPacotes(f))
    }

    @Test fun `linha no formato do sha256sum`() {
        // sha256sum -c aceita "<hash><espaço><espaço><nome>"
        assertEquals("abc123  sessao-1700000000000.pcap\n", Evidencia.linhaSha256("abc123", "sessao-1700000000000.pcap"))
    }

    @Test fun `conexao vira linha do banco`() {
        val c = Conexao(
            id = 7, protocolo = Protocolo.TCP,
            origem = Ip(4, byteArrayOf(10, 111, 0, 1)), portaOrigem = 40000,
            destino = Ip(4, byteArrayOf(93, -72, -41, 14)), portaDestino = 443,
            inicioUs = 1_700_000_000_000_000, app = App(10123, "com.android.chrome", "Chrome"),
            dominio = "www.exemplo.com", origemDominio = OrigemDominio.SNI,
            bytesEnviados = 10, bytesRecebidos = 20, pacotes = 3,
            fimUs = 1_700_000_001_000_000, motivo = MotivoFim.RESET,
        )
        val l = LinhaFluxo.de(42, c)
        assertEquals(42L, l.sessaoId)
        assertEquals(7L, l.fluxoId)
        assertEquals(6, l.protocolo)
        assertEquals(4, l.versaoIp)
        assertEquals("10.111.0.1", l.ipOrigem)
        assertEquals("93.184.215.14", l.ipDestino)
        assertEquals(10123, l.uid)
        assertEquals("com.android.chrome", l.pacoteApp)
        assertEquals("Chrome", l.rotuloApp)
        assertEquals("SNI", l.origemDominio)
        assertEquals(1, l.motivoFim)
        assertEquals(1_700_000_001_000_000L, l.fimUs)
    }
}
