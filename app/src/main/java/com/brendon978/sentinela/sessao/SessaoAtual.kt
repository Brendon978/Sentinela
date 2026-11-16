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
    /** Id da sessão no banco (criada no início da gravação). */
    val sessaoId: Long? = null,
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
    /** Apps com modelo de IA nesta sessão; null = a IA não terminou de treinar a tempo. */
    val iaApps: Int? = null,
    val sessaoId: Long,
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
        sessaoId: Long,
        inicioMs: Long,
        caminhoPcap: String,
        dnsPrivado: Boolean,
        contextoAlertas: Alertas.Contexto,
        telaLigada: () -> Boolean,
        dono: (Evento.FluxoNovo) -> App?,
    ) = synchronized(cadeado) {
        agregador = Agregador(telaLigada, dono)
        contexto = contextoAlertas
        _estado.value = EstadoSessao(true, sessaoId, inicioMs, caminhoPcap, dnsPrivadoAtivo = dnsPrivado)
    }

    /** O usuário mandou ignorar uma regra para um app: vale já para a sessão em andamento. */
    fun trocarExcecoes(excecoes: Set<Pair<String?, Regra>>) = mudarContexto { it.copy(excecoes = excecoes) }

    /** O modelo da IA terminou de treinar (em segundo plano, no início da gravação). */
    fun definirLinhaDeBase(base: com.brendon978.sentinela.ia.LinhaDeBase) = mudarContexto { it.copy(linhaDeBase = base) }

    /** Troca o contexto dos alertas e reavalia a sessão em andamento com ele. */
    private fun mudarContexto(muda: (Alertas.Contexto) -> Alertas.Contexto) = synchronized(cadeado) {
        val c = contexto?.let(muda) ?: return
        contexto = c
        _estado.value = _estado.value.copy(alertas = Alertas.avaliar(_estado.value.linhas, c))
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
        // fluxo (a maioria dos lotes) não mudam os alertas. Fim de fluxo só interessa à IA, que
        // julga apenas as conexões que acabaram de terminar.
        val c = contexto
        val alertas = when {
            c == null -> emptyList()
            eventos.any { it is Evento.FluxoNovo || it is Evento.Sni || it is Evento.Dns } -> Alertas.avaliar(linhas, c)
            c.linhaDeBase != null && eventos.any { it is Evento.FluxoFim } -> {
                val terminaram = eventos.mapNotNullTo(HashSet()) { (it as? Evento.FluxoFim)?.id }
                Alertas.acrescentarAnomalias(_estado.value.alertas, linhas.filter { it.fluxoId in terminaram }, c)
            }
            else -> _estado.value.alertas
        }
        _estado.value = _estado.value.copy(linhas = linhas, eventosPerdidos = a.eventosPerdidos, alertas = alertas)
    }

    /** Fim da gravação: devolve o que salvar (null se não havia gravação). */
    fun terminar(): Gravacao? = synchronized(cadeado) {
        val e = _estado.value
        val caminho = e.caminhoPcap
        val id = e.sessaoId
        // alertas finais com os bytes e durações completos (a IA olha esses números)
        val alertas = contexto?.let { Alertas.avaliar(e.linhas, it) } ?: e.alertas
        // a nota e o limiar de cada conexão julgada ficam guardados (o artigo mede com eles)
        val base = contexto?.linhaDeBase
        val notas = base?.notas(e.linhas).orEmpty().associateBy { it.fluxoId }
        val linhas = e.linhas.map { l -> notas[l.fluxoId]?.let { l.copy(notaIa = it.nota, limiarIa = it.limiar) } ?: l }
        val g = if (agregador != null && caminho != null && id != null)
            Gravacao(base?.apps?.size, id, e.inicioMs, caminho, linhas, alertas, e.eventosPerdidos) else null
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
