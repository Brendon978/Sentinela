package com.brendon978.sentinela.ui

import com.brendon978.sentinela.sessao.Regra

/**
 * Categoria de um alerta na tela (cor e ícone). Sem hierarquia de gravidade: o artigo compara
 * regras fixas com IA, e a tela não deve sugerir que uma é mais grave que a outra.
 */
enum class Categoria(val titulo: String) { REDE("Rede"), PRIVACIDADE("Privacidade"), COMPORTAMENTO("Comportamento"), NOVIDADE("Novidade") }

fun categoria(r: Regra): Categoria = when (r) {
    Regra.DNS_ESCONDIDO, Regra.PORTA_INCOMUM -> Categoria.REDE
    Regra.RASTREADOR -> Categoria.PRIVACIDADE
    Regra.MADRUGADA_OU_TELA_DESLIGADA, Regra.COMPORTAMENTO_ANOMALO -> Categoria.COMPORTAMENTO
    Regra.DOMINIO_NOVO -> Categoria.NOVIDADE
}

fun Categoria.cor(p: com.brendon978.sentinela.ui.tema.Paleta) = when (this) {
    Categoria.REDE -> p.rede
    Categoria.PRIVACIDADE -> p.privacidade
    Categoria.COMPORTAMENTO -> p.comportamento
    Categoria.NOVIDADE -> p.novidade
}

/** Formas diferentes por categoria: a tela continua legível em preto e branco. */
val Categoria.icone: Icone get() = when (this) {
    Categoria.REDE -> Icone.RADAR
    Categoria.PRIVACIDADE -> Icone.OLHO
    Categoria.COMPORTAMENTO -> Icone.ESCUDO
    Categoria.NOVIDADE -> Icone.ESTRELA
}
