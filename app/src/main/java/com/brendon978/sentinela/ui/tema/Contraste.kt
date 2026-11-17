package com.brendon978.sentinela.ui.tema

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.graphics.luminance

/** Razão de contraste WCAG 2.x entre duas cores opacas (1 a 21). */
fun contraste(a: Color, b: Color): Double {
    // luminance() do Compose é a luminância relativa da WCAG
    val (claro, escuro) = listOf(a.luminance().toDouble(), b.luminance().toDouble()).sortedDescending()
    return (claro + 0.05) / (escuro + 0.05)
}

/** Cor `frente` com transparência `alfa` pintada sobre `fundo` opaco (o fundo real de um selo). */
fun composta(frente: Color, alfa: Float, fundo: Color): Color = frente.copy(alpha = alfa).compositeOver(fundo)

/** Transparência do fundo dos selos e do botão de gravar (usada na tela e conferida no teste). */
const val ALFA_SELO = 0.12f
const val ALFA_BOTAO = 0.16f
/** Fundo dos avisos (texto principal por cima) e dos blocos de camada (nome na cor da camada). */
const val ALFA_AVISO = 0.14f
const val ALFA_CAMADA = 0.08f
