package com.brendon978.sentinela.sessao

import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import java.io.OutputStream

/** Desenha as seções do relatório num PDF A4 (sem biblioteca externa), com quebra de linha e de página. */
object RelatorioPdf {
    private const val RECUO = "    "

    /**
     * Quebra o texto em linhas que cabem na largura. `mede(t, largura)` diz quantos caracteres do
     * começo de t cabem (Paint.breakText). Quebra no último espaço quando dá; palavra maior que a
     * linha (domínio longo, sem espaço) é cortada no meio. Linhas de continuação levam recuo.
     */
    fun <L> quebrar(texto: String, largura: L, mede: (String, L) -> Int): List<String> {
        val linhas = mutableListOf<String>()
        var resto = texto
        while (true) {
            val cabe = mede(resto, largura).coerceIn(1, resto.length)
            var corte = cabe
            if (cabe < resto.length) {
                val espaco = resto.lastIndexOf(' ', cabe)
                // só vale quebrar num espaço depois do recuo (senão a linha sairia vazia)
                if (espaco > resto.indexOfFirst { it != ' ' }) corte = espaco
            }
            linhas += resto.substring(0, corte)
            if (corte >= resto.length) return linhas
            resto = RECUO + resto.substring(corte).trimStart()
        }
    }

    private const val LARGURA = 595 // A4 em pontos
    private const val ALTURA = 842
    private const val MARGEM = 40f

    fun escrever(titulo: String, secoes: List<Secao>, saida: OutputStream) {
        val doc = PdfDocument()
        val texto = Paint().apply { textSize = 9.5f; isAntiAlias = true }
        val negrito = Paint(texto).apply { typeface = Typeface.DEFAULT_BOLD; textSize = 12f }
        val grande = Paint(negrito).apply { textSize = 16f }
        val util = LARGURA - 2 * MARGEM
        var pagina: PdfDocument.Page? = null
        var y = 0f
        var numero = 0

        fun novaPagina() {
            pagina?.let { doc.finishPage(it) }
            numero++
            pagina = doc.startPage(PdfDocument.PageInfo.Builder(LARGURA, ALTURA, numero).create())
            y = MARGEM
            pagina!!.canvas.drawText("Sentinela — $titulo — página $numero", MARGEM, ALTURA - 20f, texto)
        }

        fun linha(t: String, p: Paint, antes: Float = 0f) {
            y += antes
            for (pedaco in quebrar(t, util) { s, w -> p.breakText(s, true, w, null) }) {
                if (y + p.textSize > ALTURA - 40f) novaPagina()
                y += p.textSize + 3f
                pagina!!.canvas.drawText(pedaco, MARGEM, y, p)
            }
        }

        novaPagina()
        linha("Relatório de captura — $titulo", grande)
        for (s in secoes) {
            linha(s.titulo, negrito, antes = 10f)
            s.linhas.forEach { linha(it, texto) }
        }
        pagina?.let { doc.finishPage(it) }
        doc.writeTo(saida)
        doc.close()
    }
}
