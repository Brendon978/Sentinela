package com.brendon978.sentinela.ui.tema

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.brendon978.sentinela.R

/** Títulos e números (Space Grotesk, OFL). */
val Grotesca = FontFamily(Font(R.font.space_grotesk_medium, FontWeight.Medium), Font(R.font.space_grotesk_bold, FontWeight.Bold))

/** Dados técnicos: IP, porta, hash, hex (JetBrains Mono, OFL). */
val Mono = FontFamily(Font(R.font.jetbrains_mono_regular, FontWeight.Normal), Font(R.font.jetbrains_mono_bold, FontWeight.Bold))

/** Cores do Sentinela além do esquema do Material (categorias, estado, bordas). */
val LocalPaleta = staticCompositionLocalOf { Paleta.ESCURO }

private val tipos = Typography().let { t ->
    fun TextStyle.grotesca(peso: FontWeight = FontWeight.Bold) = copy(fontFamily = Grotesca, fontWeight = peso)
    t.copy(
        displaySmall = t.displaySmall.grotesca(),
        headlineMedium = t.headlineMedium.grotesca(),
        headlineSmall = t.headlineSmall.grotesca(),
        titleLarge = t.titleLarge.grotesca(),
        titleMedium = t.titleMedium.grotesca(FontWeight.Medium),
        labelLarge = t.labelLarge.grotesca(FontWeight.Medium),
    )
}

/** Estilo dos dados técnicos. */
val TextoMono = TextStyle(fontFamily = Mono, fontSize = 13.sp)

@Composable
fun TemaSentinela(claro: Boolean, conteudo: @Composable () -> Unit) {
    val p = if (claro) Paleta.CLARO else Paleta.ESCURO
    val esquema = (if (claro) lightColorScheme() else darkColorScheme()).copy(
        primary = p.primaria, onPrimary = p.sobrePrimaria, secondary = p.secundaria,
        background = p.fundo, onBackground = p.texto, surface = p.superficie, onSurface = p.texto,
        surfaceVariant = p.superficie2, onSurfaceVariant = p.textoSecundario, outline = p.borda,
        error = p.perigo, surfaceContainer = p.superficie, surfaceContainerHigh = p.superficie2,
        surfaceContainerHighest = p.superficie2, surfaceContainerLow = p.superficie, outlineVariant = p.borda,
    )
    // ícones da barra de status escuros no tema claro (senão somem no fundo claro)
    val view = androidx.compose.ui.platform.LocalView.current
    if (!view.isInEditMode) androidx.compose.runtime.SideEffect {
        val janela = (view.context as? android.app.Activity)?.window ?: return@SideEffect
        androidx.core.view.WindowCompat.getInsetsController(janela, view).apply {
            isAppearanceLightStatusBars = claro
            isAppearanceLightNavigationBars = claro
        }
    }
    CompositionLocalProvider(LocalPaleta provides p) {
        MaterialTheme(colorScheme = esquema, typography = tipos, content = conteudo)
    }
}
