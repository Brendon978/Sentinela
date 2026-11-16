package com.brendon978.sentinela.sessao

/**
 * O que a gravação parcial (a cada 5 s) precisa escrever: só as conexões novas ou diferentes da
 * última gravação que deu certo, e os alertas só quando a lista mudou. Numa sessão longa a maior
 * parte das conexões já terminou e não muda mais; regravar todas era o custo que crescia.
 * Uma instância por sessão; não é thread-safe (só o laço de gravação usa).
 */
class Alteracoes {
    /** `alertas` null = iguais aos já gravados. */
    data class Parcial(val fluxos: List<LinhaFluxo>, val alertas: List<Alerta>?)

    private val gravadas = HashMap<Long, LinhaFluxo>()
    private var alertasGravados: List<Alerta>? = null

    fun desde(linhas: List<LinhaFluxo>, alertas: List<Alerta>): Parcial = Parcial(
        linhas.filter { gravadas[it.fluxoId] != it },
        alertas.takeIf { it != alertasGravados },
    )

    /** A gravação deu certo: o que ela escreveu passa a ser a base da próxima comparação. */
    fun confirmar(p: Parcial) {
        for (l in p.fluxos) gravadas[l.fluxoId] = l
        p.alertas?.let { alertasGravados = it }
    }
}
