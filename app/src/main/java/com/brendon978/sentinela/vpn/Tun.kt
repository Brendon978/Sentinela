package com.brendon978.sentinela.vpn

/** Endereços da interface virtual (o "cabo" da VPN local). Um lugar só para o serviço e a exportação. */
object Tun {
    const val ENDERECO_V4 = "10.111.0.1"
    const val ENDERECO_V6 = "fd00:5e:1::1"
    val ENDERECOS = setOf(ENDERECO_V4, ENDERECO_V6)
    /** DNS que o tun anuncia aos apps; o motor repassa ao DNS real da rede. */
    val DNS_VIRTUAIS = arrayOf("10.111.0.53", "fd00:5e:1::53")
}
