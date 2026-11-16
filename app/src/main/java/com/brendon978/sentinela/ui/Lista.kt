package com.brendon978.sentinela.ui

import com.brendon978.sentinela.sessao.Conexao
import com.brendon978.sentinela.sessao.LinhaFluxo
import java.util.Locale

/** Lógica das listas, sem Android: ordenar, filtrar e formatar. */
object Lista {
    /** Sessão ao vivo: o fluxo com novidade mais recente no topo. */
    fun aoVivo(conexoes: Collection<Conexao>): List<LinhaFluxo> =
        conexoes.sortedByDescending { it.ordem }.map { LinhaFluxo.de(0, it) }

    /** Texto procura em app, pacote, domínio, IPs e portas; `pacote` restringe a um app. */
    fun filtrar(linhas: List<LinhaFluxo>, texto: String, pacote: String?): List<LinhaFluxo> {
        val t = texto.trim().lowercase(Locale.ROOT)
        return linhas.filter { l ->
            (pacote == null || l.pacoteApp == pacote) && (t.isEmpty() || campos(l).any { it.contains(t) })
        }
    }

    private fun campos(l: LinhaFluxo) = listOfNotNull(
        l.rotuloApp, l.pacoteApp, l.dominio, l.ipDestino, l.ipOrigem,
        l.portaDestino.toString(), l.portaOrigem.toString(),
    ).map { it.lowercase(Locale.ROOT) }

    private val br = Locale.forLanguageTag("pt-BR")

    fun bytes(n: Long): String = when {
        n < 1024 -> "$n B"
        n < 1024L * 1024 -> String.format(br, "%.1f KB", n / 1024.0)
        n < 1024L * 1024 * 1024 -> String.format(br, "%.1f MB", n / (1024.0 * 1024))
        else -> String.format(br, "%.1f GB", n / (1024.0 * 1024 * 1024))
    }
}
