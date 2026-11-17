package com.brendon978.sentinela.ui

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.draw.clip
import androidx.compose.runtime.remember
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.clickable
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.brendon978.sentinela.ui.tema.LocalPaleta
import com.brendon978.sentinela.ui.tema.TextoMono

/** Cartão do Sentinela: canto 16 dp, borda fina, faixa lateral opcional (categoria do alerta). */
@Composable
fun Cartao(
    modifier: Modifier = Modifier,
    faixa: Color? = null,
    preenchimento: Dp = 14.dp,
    aoTocar: (() -> Unit)? = null,
    conteudo: @Composable () -> Unit,
) {
    val p = LocalPaleta.current
    val forma = RoundedCornerShape(16.dp)
    val corpo: @Composable () -> Unit = {
        Row(Modifier.height(IntrinsicSize.Min)) {
            if (faixa != null) Box(Modifier.width(4.dp).fillMaxHeight().background(faixa))
            Box(Modifier.padding(preenchimento)) { conteudo() }
        }
    }
    if (aoTocar != null) Surface(aoTocar, modifier.fillMaxWidth(), shape = forma, color = p.superficie, border = BorderStroke(1.dp, p.borda)) { corpo() }
    else Surface(modifier.fillMaxWidth(), shape = forma, color = p.superficie, border = BorderStroke(1.dp, p.borda)) { corpo() }
}

/** Selo em pílula, monoespaçado (origem do domínio, protocolo, estado). */
@Composable
fun Selo(texto: String, cor: Color = LocalPaleta.current.secundaria, modifier: Modifier = Modifier) {
    Text(
        texto,
        modifier = modifier.background(cor.copy(alpha = com.brendon978.sentinela.ui.tema.ALFA_SELO), RoundedCornerShape(50)).padding(horizontal = 8.dp, vertical = 2.dp),
        style = TextoMono.copy(fontSize = 11.sp, fontWeight = FontWeight.Bold),
        color = cor,
    )
}

/** Rótulo de seção ("SESSÕES SALVAS"). */
@Composable
fun RotuloSecao(texto: String, modifier: Modifier = Modifier) {
    Text(
        texto.uppercase(), modifier = modifier.padding(top = 8.dp),
        style = MaterialTheme.typography.labelLarge.copy(letterSpacing = 1.5.sp),
        color = LocalPaleta.current.textoSecundario,
    )
}

/** Número grande com rótulo pequeno embaixo (resumo da sessão). */
@Composable
fun ResumoNumero(valor: String, rotulo: String, cor: Color = LocalPaleta.current.texto, modifier: Modifier = Modifier) {
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Text(valor, style = MaterialTheme.typography.titleLarge, color = cor, maxLines = 1)
        Text(rotulo, style = MaterialTheme.typography.labelSmall, color = LocalPaleta.current.textoSecundario)
    }
}

/**
 * Fração de volume numa escala fixa logarítmica (1 B a 100 MB): não depende do maior da lista,
 * então a barra de uma linha só muda quando o volume dela muda (a lista ao vivo recompõe a cada lote).
 */
fun fracaoVolume(bytes: Long): Float =
    (kotlin.math.log10(bytes.coerceAtLeast(0) + 1.0) / 8.0).toFloat().coerceIn(0f, 1f)

/** Barra fina de volume. */
@Composable
fun BarraVolume(fracao: Float, cor: Color, modifier: Modifier = Modifier) {
    val p = LocalPaleta.current
    Box(modifier.fillMaxWidth().height(3.dp).background(p.superficie2, RoundedCornerShape(2.dp))) {
        Box(Modifier.fillMaxWidth(fracao.coerceIn(0.02f, 1f)).height(3.dp).background(cor, RoundedCornerShape(2.dp)))
    }
}

/** Anéis de radar saindo do centro; parados quando `ativo` é falso. */
@Composable
fun Pulso(cor: Color, ativo: Boolean, modifier: Modifier = Modifier) {
    // a fase é lida só no desenho: o pulso redesenha a cada quadro sem recompor a tela
    val fase = if (ativo) {
        rememberInfiniteTransition(label = "pulso")
            .animateFloat(0f, 1f, infiniteRepeatable(tween(1600, easing = LinearEasing), RepeatMode.Restart), label = "fase")
    } else null
    Canvas(modifier) {
        val raio = size.minDimension / 2
        if (fase != null) for (i in 0 until 3) {
            val f = (fase.value + i / 3f) % 1f
            drawCircle(cor.copy(alpha = (1f - f) * 0.5f), radius = raio * (0.55f + 0.45f * f), style = Stroke(2.dp.toPx()))
        } else drawCircle(cor.copy(alpha = 0.25f), radius = raio * 0.8f, style = Stroke(1.5.dp.toPx()))
    }
}

/** O símbolo do Sentinela: um olho com ondas de radar dos lados (traço simples, do ícone). */
@Composable
fun Marca(tamanho: Dp = 30.dp) {
    val p = LocalPaleta.current
    Canvas(Modifier.size(tamanho)) {
        val w = size.width; val h = size.height
        val traco = Stroke(w * 0.07f, cap = StrokeCap.Round)
        val olho = Path().apply {
            moveTo(w * 0.18f, h * 0.5f)
            quadraticTo(w * 0.5f, h * 0.18f, w * 0.82f, h * 0.5f)
            quadraticTo(w * 0.5f, h * 0.82f, w * 0.18f, h * 0.5f)
        }
        drawPath(olho, p.secundaria, style = traco)
        drawCircle(p.primaria, radius = w * 0.11f, center = Offset(w / 2, h / 2))
        ondas(p.primaria, w, h, esquerda = true)
        ondas(p.primaria, w, h, esquerda = false)
    }
}

private fun DrawScope.ondas(cor: Color, w: Float, h: Float, esquerda: Boolean) {
    for (i in 1..2) {
        val r = w * (0.1f + 0.08f * i)
        val cx = if (esquerda) w * 0.3f else w * 0.7f
        drawArc(
            cor.copy(alpha = 0.9f - 0.3f * i), startAngle = if (esquerda) 135f else -45f, sweepAngle = 90f, useCenter = false,
            topLeft = Offset(cx - r, h / 2 - r), size = Size(r * 2, r * 2), style = Stroke(w * 0.05f, cap = StrokeCap.Round),
        )
    }
}

/** Ícones de traço desenhados no Canvas (sem biblioteca de ícones). */
enum class Icone { SOL, LUA, RADAR, SETA, ESCUDO, CADEADO, OLHO, ESTRELA, ROTEADOR, TV, IMPRESSORA, CAMERA, MACA, COMPUTADOR, INTERROGACAO, DOWNLOAD }

@Composable
fun Desenho(icone: Icone, cor: Color, tamanho: Dp = 22.dp, modifier: Modifier = Modifier) {
    Canvas(modifier.size(tamanho)) {
        val w = size.width; val h = size.height
        val s = Stroke(w * 0.08f, cap = StrokeCap.Round)
        fun linha(x1: Float, y1: Float, x2: Float, y2: Float) =
            drawLine(cor, Offset(w * x1, h * y1), Offset(w * x2, h * y2), w * 0.08f, StrokeCap.Round)
        fun ret(x: Float, y: Float, rw: Float, rh: Float) =
            drawRoundRect(cor, Offset(w * x, h * y), Size(w * rw, h * rh), androidx.compose.ui.geometry.CornerRadius(w * 0.06f), style = s)
        when (icone) {
            Icone.SOL -> {
                drawCircle(cor, w * 0.18f, style = s)
                for (k in 0 until 8) {
                    val a = Math.toRadians(k * 45.0)
                    val c = kotlin.math.cos(a).toFloat(); val n = kotlin.math.sin(a).toFloat()
                    linha(0.5f + c * 0.32f, 0.5f + n * 0.32f, 0.5f + c * 0.44f, 0.5f + n * 0.44f)
                }
            }
            Icone.LUA -> {
                // lua crescente: círculo menos um círculo deslocado
                val lua = Path().apply {
                    addOval(androidx.compose.ui.geometry.Rect(w * 0.16f, h * 0.16f, w * 0.84f, h * 0.84f))
                }
                val corte = Path().apply {
                    addOval(androidx.compose.ui.geometry.Rect(w * 0.36f, h * 0.06f, w * 1.0f, h * 0.7f))
                }
                drawPath(Path.combine(androidx.compose.ui.graphics.PathOperation.Difference, lua, corte), cor)
            }
            Icone.RADAR -> {
                drawCircle(cor, w * 0.42f, style = s); drawCircle(cor, w * 0.24f, style = s)
                linha(0.5f, 0.5f, 0.82f, 0.25f); drawCircle(cor, w * 0.06f)
            }
            Icone.SETA -> { linha(0.38f, 0.22f, 0.66f, 0.5f); linha(0.66f, 0.5f, 0.38f, 0.78f) }
            Icone.ESCUDO -> {
                val path = Path().apply {
                    moveTo(w * 0.5f, h * 0.1f); lineTo(w * 0.85f, h * 0.24f); quadraticTo(w * 0.85f, h * 0.72f, w * 0.5f, h * 0.9f)
                    quadraticTo(w * 0.15f, h * 0.72f, w * 0.15f, h * 0.24f); close()
                }
                drawPath(path, cor, style = s)
            }
            Icone.CADEADO -> { ret(0.2f, 0.45f, 0.6f, 0.42f); drawArc(cor, 180f, 180f, false, Offset(w * 0.3f, h * 0.15f), Size(w * 0.4f, h * 0.6f), style = s) }
            Icone.OLHO -> {
                val olho = Path().apply {
                    moveTo(w * 0.08f, h * 0.5f); quadraticTo(w * 0.5f, h * 0.1f, w * 0.92f, h * 0.5f); quadraticTo(w * 0.5f, h * 0.9f, w * 0.08f, h * 0.5f)
                }
                drawPath(olho, cor, style = s); drawCircle(cor, w * 0.12f)
            }
            Icone.ESTRELA -> {
                val path = Path()
                for (k in 0 until 10) {
                    val r = if (k % 2 == 0) 0.44f else 0.2f
                    val a = Math.toRadians(-90.0 + k * 36.0)
                    val x = w * (0.5f + r * kotlin.math.cos(a).toFloat()); val y = h * (0.52f + r * kotlin.math.sin(a).toFloat())
                    if (k == 0) path.moveTo(x, y) else path.lineTo(x, y)
                }
                path.close(); drawPath(path, cor, style = s)
            }
            Icone.ROTEADOR -> { ret(0.12f, 0.55f, 0.76f, 0.3f); linha(0.3f, 0.55f, 0.22f, 0.2f); linha(0.7f, 0.55f, 0.78f, 0.2f); drawCircle(cor, w * 0.04f, Offset(w * 0.3f, h * 0.7f)) }
            Icone.TV -> { ret(0.1f, 0.2f, 0.8f, 0.52f); linha(0.35f, 0.85f, 0.65f, 0.85f) }
            Icone.IMPRESSORA -> { ret(0.12f, 0.38f, 0.76f, 0.32f); ret(0.28f, 0.12f, 0.44f, 0.26f); ret(0.28f, 0.6f, 0.44f, 0.28f) }
            Icone.CAMERA -> { ret(0.1f, 0.3f, 0.6f, 0.4f); linha(0.7f, 0.45f, 0.9f, 0.32f); linha(0.9f, 0.32f, 0.9f, 0.68f); linha(0.9f, 0.68f, 0.7f, 0.55f) }
            Icone.MACA -> { drawCircle(cor, w * 0.3f, Offset(w * 0.5f, h * 0.58f), style = s); linha(0.5f, 0.28f, 0.6f, 0.12f) }
            Icone.COMPUTADOR -> { ret(0.14f, 0.18f, 0.72f, 0.48f); linha(0.06f, 0.82f, 0.94f, 0.82f) }
            Icone.INTERROGACAO -> {
                drawArc(cor, 180f, 230f, false, Offset(w * 0.3f, h * 0.14f), Size(w * 0.4f, h * 0.36f), style = s)
                linha(0.5f, 0.5f, 0.5f, 0.64f); drawCircle(cor, w * 0.05f, Offset(w * 0.5f, h * 0.84f))
            }
            Icone.DOWNLOAD -> { linha(0.5f, 0.14f, 0.5f, 0.66f); linha(0.3f, 0.48f, 0.5f, 0.68f); linha(0.7f, 0.48f, 0.5f, 0.68f); linha(0.18f, 0.86f, 0.82f, 0.86f) }
        }
    }
}

/** Texto monoespaçado com a cor de destaque (hash, IP). */
@Composable
fun TextoTecnico(texto: String, cor: Color = LocalPaleta.current.texto, tamanho: Int = 13, modifier: Modifier = Modifier) {
    Text(texto, modifier, style = TextoMono.copy(fontSize = tamanho.sp), color = cor, maxLines = 1)
}

/** Botão quadrado com ícone (voltar, tema): alvo de toque de 48 dp e nome para o leitor de tela. */
@Composable
fun BotaoIcone(descricao: String, aoTocar: () -> Unit, conteudo: @Composable () -> Unit) {
    val p = LocalPaleta.current
    Box(
        Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(p.superficie2)
            .clickable(onClick = aoTocar).semantics { contentDescription = descricao; role = Role.Button },
        contentAlignment = Alignment.Center,
    ) { conteudo() }
}

/** Conexões, ↑, ↓ e alertas de uma sessão; somas feitas uma vez por lista (a lista ao vivo muda a cada lote). */
@Composable
fun ResumoSessao(linhas: List<com.brendon978.sentinela.sessao.LinhaFluxo>, alertas: Int) {
    val p = LocalPaleta.current
    val (env, rec) = remember(linhas) {
        var e = 0L; var r = 0L
        for (l in linhas) { e += l.bytesEnviados; r += l.bytesRecebidos }
        e to r
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
        ResumoNumero("${linhas.size}", "conexões")
        ResumoNumero(Lista.bytes(env), "enviados ↑", p.secundaria)
        ResumoNumero(Lista.bytes(rec), "recebidos ↓", p.primaria)
        ResumoNumero("$alertas", "alertas", if (alertas == 0) p.texto else p.comportamento)
    }
}

/** Selo da origem do nome (SNI, DNS ou ECH? quando não deu para desempatar). */
@Composable
fun SeloOrigem(origem: String, modifier: Modifier = Modifier) {
    val p = LocalPaleta.current
    val ech = origem == com.brendon978.sentinela.sessao.OrigemDominio.SNI_ECH.name
    Selo(
        when (origem) { com.brendon978.sentinela.sessao.OrigemDominio.SNI.name -> "SNI"; else -> if (ech) "ECH?" else "DNS" },
        if (ech) p.comportamento else p.secundaria, modifier,
    )
}
