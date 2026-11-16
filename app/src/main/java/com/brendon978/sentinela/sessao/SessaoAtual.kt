package com.brendon978.sentinela.sessao

import com.brendon978.sentinela.motor.Evento
import com.brendon978.sentinela.ui.Lista
import com.brendon978.sentinela.vpn.App
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** O que as telas enxergam da gravação em andamento. */
data class EstadoSessao(
    val gravando: Boolean = false,
    val inicioMs: Long = 0,
    val caminhoPcap: String? = null,
    /** Conexões já como linhas, da mais ativa para a menos (calculadas uma vez por lote). */
    val linhas: List<LinhaFluxo> = emptyList(),
    val eventosPerdidos: Long = 0,
    /** DNS privado do sistema (DoT) ligado: as consultas podem não passar pelo DNS virtual. */
    val dnsPrivadoAtivo: Boolean = false,
    val erro: String? = null,
    val alertas: List<Alerta> = emptyList(),
)

/** O que sobra de uma gravação encerrada, para salvar (SessaoFinal). */
data class Gravacao(
    val inicioMs: Long,
    val caminhoPcap: String,
    val linhas: List<LinhaFluxo>,
    val alertas: List<Alerta>,
    val eventosPerdidos: Long,
)

/**
 * Estado da sessão em andamento, compartilhado entre o serviço de VPN (que escreve) e as
 * telas (que leem). Todas as escritas passam pelo mesmo cadeado.
 */
object SessaoAtual {
    private val cadeado = Any()
    private var agregador: Agregador? = null
    private var contexto: Alertas.Contexto? = null
    private val _estado = MutableStateFlow(EstadoSessao())
    val estado: StateFlow<EstadoSessao> = _estado.asStateFlow()

    fun iniciar(
        inicioMs: Long,
        caminhoPcap: String,
        dnsPrivado: Boolean,
        contextoAlertas: Alertas.Contexto,
        telaLigada: () -> Boolean,
        dono: (Evento.FluxoNovo) -> App?,
    ) = synchronized(cadeado) {
        agregador = Agregador(telaLigada, dono)
        contexto = contextoAlertas
        _estado.value = EstadoSessao(true, inicioMs, caminhoPcap, dnsPrivadoAtivo = dnsPrivado)
    }

    /** A rede mudou: os DNS que contam como "caminho normal" para os alertas também. */
    fun trocarDnsNormais(dns: Set<String>) = synchronized(cadeado) {
        contexto = contexto?.copy(dnsVirtuais = dns)
    }

    fun aplicar(eventos: List<Evento>) = synchronized(cadeado) {
        val a = agregador ?: return
        if (eventos.isEmpty()) return
        eventos.forEach(a::aplicar)
        val linhas = Lista.aoVivo(a.conexoes.values)
        // As regras só olham app, domínio, destino, porta e horário de início: bytes e fins de
        // fluxo (a maioria dos lotes) não mudam os alertas.
        val mudaAlertas = eventos.any { it is Evento.FluxoNovo || it is Evento.Sni || it is Evento.Dns }
        val alertas = if (mudaAlertas) contexto?.let { Alertas.avaliar(linhas, it) }.orEmpty() else _estado.value.alertas
        _estado.value = _estado.value.copy(linhas = linhas, eventosPerdidos = a.eventosPerdidos, alertas = alertas)
    }

    /** Fim da gravação: devolve o que salvar (null se não havia gravação). */
    fun terminar(): Gravacao? = synchronized(cadeado) {
        val e = _estado.value
        val caminho = e.caminhoPcap
        val g = if (agregador != null && caminho != null)
            Gravacao(e.inicioMs, caminho, e.linhas, e.alertas, e.eventosPerdidos) else null
        agregador = null
        contexto = null
        _estado.value = e.copy(gravando = false)
        g
    }

    fun falhou(mensagem: String) = synchronized(cadeado) {
        agregador = null
        contexto = null
        _estado.value = EstadoSessao(erro = mensagem)
    }
}
