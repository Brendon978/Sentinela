package com.brendon978.sentinela.ui.tema

import androidx.compose.ui.graphics.Color

/**
 * Paleta do Sentinela, tirada do ícone (azul-petróleo, verde e ciano neon). Duas versões: escura
 * (padrão) e clara (para prints de artigo). Valores conferidos por ContrasteTest (AA ≥ 4,5).
 */
data class Paleta(
    val fundo: Color,
    val superficie: Color,
    val superficie2: Color,
    val borda: Color,
    val primaria: Color,
    val sobrePrimaria: Color,
    val secundaria: Color,
    val texto: Color,
    val textoSecundario: Color,
    /** Categorias de alerta (sem hierarquia de gravidade entre elas). */
    val rede: Color,
    val privacidade: Color,
    val comportamento: Color,
    val novidade: Color,
    /** Estado de perigo/erro e o "gravando". */
    val perigo: Color,
    val claro: Boolean,
) {
    companion object {
        val ESCURO = Paleta(
            fundo = Color(0xFF071A24), superficie = Color(0xFF0D2633), superficie2 = Color(0xFF12313F),
            borda = Color(0xFF1E4757), primaria = Color(0xFF3DF2A0), sobrePrimaria = Color(0xFF04261A),
            secundaria = Color(0xFF2FD3F5), texto = Color(0xFFE3F2F5), textoSecundario = Color(0xFF8FB3BD),
            rede = Color(0xFF2FD3F5), privacidade = Color(0xFFC4A0FF), comportamento = Color(0xFFFFB547),
            novidade = Color(0xFF3DF2A0), perigo = Color(0xFFFF7A86), claro = false,
        )
        val CLARO = Paleta(
            fundo = Color(0xFFF7FAFB), superficie = Color(0xFFFFFFFF), superficie2 = Color(0xFFEEF4F6),
            borda = Color(0xFFD5E2E6), primaria = Color(0xFF066A48), sobrePrimaria = Color(0xFFFFFFFF),
            secundaria = Color(0xFF08617A), texto = Color(0xFF0B1F27), textoSecundario = Color(0xFF3F5E68),
            rede = Color(0xFF08617A), privacidade = Color(0xFF6B3FC0), comportamento = Color(0xFF7F4C00),
            novidade = Color(0xFF066A48), perigo = Color(0xFFA81B28), claro = true,
        )
    }
}
