package com.brendon978.sentinela.ui

/** Uma camada do pacote dissecado (IPv4, TCP, TLS ClientHello, DNS, Dados…). */
data class Camada(val nome: String, val campos: List<Pair<String, String>>, val hex: List<String>)

/** O texto do dissecador (native/src/dissecar.c) em resumo + camadas, para desenhar em blocos. */
data class Dissecado(val resumo: String, val camadas: List<Camada>)

object Camadas {
    private val HEX = Regex("^[0-9a-f]{4}  ")

    fun separar(texto: String): Dissecado {
        var resumo = ""
        val camadas = mutableListOf<Camada>()
        var nome: String? = null
        val campos = mutableListOf<Pair<String, String>>()
        val hex = mutableListOf<String>()
        fun fecha() {
            nome?.let { camadas += Camada(it, campos.toList(), hex.toList()) }
            campos.clear(); hex.clear()
        }
        for (linha in texto.lines()) {
            when {
                linha.startsWith("Resumo: ") -> resumo = linha.removePrefix("Resumo: ").trim()
                linha.isBlank() -> {}
                !linha.startsWith(" ") -> { fecha(); nome = linha.trim() }
                else -> {
                    val t = linha.trim()
                    val i = t.indexOf(": ")
                    if (HEX.containsMatchIn(t) || i < 0) hex += t else campos += t.substring(0, i) to t.substring(i + 2)
                }
            }
        }
        fecha()
        return Dissecado(resumo, camadas)
    }
}
