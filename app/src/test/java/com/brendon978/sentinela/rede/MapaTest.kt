package com.brendon978.sentinela.rede

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MapaTest {
    @Test fun `resposta ssdp de um roteador`() {
        // formato da UPnP Device Architecture 1.1 §1.3.3 (cabeçalhos sem diferenciar maiúsculas)
        val r = Ssdp.ler(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\n" +
                "LOCATION: http://192.168.77.1:1900/rootDesc.xml\r\n" +
                "Server: Linux/5.4 UPnP/1.0 MiniUPnPd/2.1\r\nST: upnp:rootdevice\r\n" +
                "USN: uuid:abc::upnp:rootdevice\r\n\r\n",
            de = "192.168.77.1",
        )
        assertEquals("192.168.77.1", r?.ip)
        assertEquals("Linux/5.4 UPnP/1.0 MiniUPnPd/2.1", r?.servidor)
        assertEquals("http://192.168.77.1:1900/rootDesc.xml", r?.local)
        assertEquals("upnp:rootdevice", r?.tipo)
    }

    @Test fun `ssdp que nao e resposta valida`() {
        assertNull(Ssdp.ler("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n", "1.2.3.4"))
        assertNull(Ssdp.ler("lixo", "1.2.3.4"))
    }

    @Test fun `hosts de uma sub-rede sem rede, broadcast e o proprio celular`() {
        val h = SubRede.hosts("192.168.77.67", 24)
        assertEquals(253, h.size)
        assertEquals("192.168.77.1", h.first())
        assertEquals("192.168.77.254", h.last())
        assert("192.168.77.67" !in h)
        // rede maior que /24: varre só a /24 em volta do celular (varredura leve)
        val grande = SubRede.hosts("10.0.7.5", 16)
        assertEquals(253, grande.size)
        assertEquals("10.0.7.1", grande.first())
        assertEquals("10.0.7.254", grande.last())
        assertEquals(listOf("10.0.0.2"), SubRede.hosts("10.0.0.1", 30))
    }

    @Test fun `classifica pelo que o aparelho anuncia`() {
        assertEquals(TipoAparelho.ROTEADOR, Classificador.tipo(Aparelho("192.168.77.1", gateway = true)))
        assertEquals(TipoAparelho.TV_OU_STREAMING, Classificador.tipo(Aparelho("1.1.1.2", servicos = setOf("_googlecast._tcp"))))
        assertEquals(TipoAparelho.IMPRESSORA, Classificador.tipo(Aparelho("1.1.1.3", portas = setOf(9100))))
        assertEquals(TipoAparelho.CAMERA, Classificador.tipo(Aparelho("1.1.1.4", portas = setOf(554))))
        assertEquals(TipoAparelho.APPLE, Classificador.tipo(Aparelho("1.1.1.5", portas = setOf(62078))))
        assertEquals(TipoAparelho.COMPUTADOR_OU_NAS, Classificador.tipo(Aparelho("1.1.1.6", portas = setOf(445, 22))))
        assertEquals(TipoAparelho.DESCONHECIDO, Classificador.tipo(Aparelho("1.1.1.7", portas = setOf(443))))
    }

    @Test fun `junta os achados do mesmo ip e ordena por ip`() {
        val m = Mapa.juntar(listOf(
            Aparelho("192.168.77.20", portas = setOf(80)),
            Aparelho("192.168.77.3", nomes = setOf("Impressora HP"), servicos = setOf("_ipp._tcp")),
            Aparelho("192.168.77.20", nomes = setOf("Sala TV"), servicos = setOf("_googlecast._tcp"), portas = setOf(8009)),
        ))
        assertEquals(listOf("192.168.77.3", "192.168.77.20"), m.map { it.ip })
        assertEquals(setOf(80, 8009), m[1].portas)
        assertEquals(setOf("Sala TV"), m[1].nomes)
    }

    // outra VPN ligada: o mapa só segue pela rota normal se a VPN não leva a rede local
    @Test fun `vpn so com a faixa dela nao leva a rede local`() {
        // Tailscale sem exit node: só 100.64.0.0/10
        val rotas = listOf(RotasVpn.Rota("100.64.0.0", 10))
        assertEquals(false, RotasVpn.levaPelaVpn("192.168.0.101", rotas))
        assertEquals(true, RotasVpn.levaPelaVpn("100.79.223.93", rotas))
    }

    @Test fun `vpn com rota padrao leva tudo, menos o que ela exclui`() {
        // exit node: 0.0.0.0/0; com "acesso à rede local" a VPN exclui a faixa da LAN
        val tudo = listOf(RotasVpn.Rota("0.0.0.0", 0))
        assertEquals(true, RotasVpn.levaPelaVpn("192.168.0.101", tudo))
        val comLan = tudo + RotasVpn.Rota("192.168.0.0", 16, excluida = true)
        assertEquals(false, RotasVpn.levaPelaVpn("192.168.0.101", comLan))
        assertEquals(true, RotasVpn.levaPelaVpn("8.8.8.8", comLan))
    }

    @Test fun `sem rotas a vpn nao leva nada`() {
        assertEquals(false, RotasVpn.levaPelaVpn("192.168.0.1", emptyList()))
    }
}
