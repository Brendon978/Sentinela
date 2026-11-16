package com.brendon978.sentinela.sessao

import com.brendon978.sentinela.motor.Evento
import com.brendon978.sentinela.motor.Ip
import com.brendon978.sentinela.motor.MotivoFim
import com.brendon978.sentinela.motor.Protocolo
import com.brendon978.sentinela.vpn.App

enum class OrigemDominio { SNI, DNS, NENHUM }

data class Conexao(
    val id: Long,
    val protocolo: Protocolo,
    val origem: Ip,
    val portaOrigem: Int,
    val destino: Ip,
    val portaDestino: Int,
    val inicioUs: Long,
    val app: App?,
    val dominio: String? = null,
    val origemDominio: OrigemDominio = OrigemDominio.NENHUM,
    val bytesEnviados: Long = 0,
    val bytesRecebidos: Long = 0,
    val pacotes: Long = 0,
    val fimUs: Long? = null,
    val motivo: MotivoFim? = null,
    /** Cresce a cada novidade do fluxo: ordenar por ela põe o mais ativo no topo. */
    val ordem: Long = 0,
    /** A tela estava desligada quando o fluxo começou. */
    val telaDesligada: Boolean = false,
)

/**
 * Junta os eventos do motor numa visão de conexões. Domínio: o SNI do TLS, se houver; senão
 * o último nome que o DNS resolveu para aquele IP. Roda numa thread só (quem chama sincroniza).
 */
class Agregador(
    private val telaLigada: () -> Boolean = { true },
    private val dono: (Evento.FluxoNovo) -> App?,
) {
    private val porId = LinkedHashMap<Long, Conexao>()
    private val nomePorIp = HashMap<Ip, String>()
    private var relogio = 0L

    val conexoes: Map<Long, Conexao> get() = porId
    var eventosPerdidos = 0L
        private set

    /** Nomes que o DNS resolveu nesta sessão (IP -> nome). */
    val nomes: Map<Ip, String> get() = nomePorIp

    fun aplicar(e: Evento) {
        when (e) {
            is Evento.FluxoNovo -> {
                val nome = nomePorIp[e.destino]
                porId[e.id] = Conexao(
                    e.id, e.protocolo, e.origem, e.portaOrigem, e.destino, e.portaDestino, e.inicioUs, dono(e),
                    dominio = nome,
                    origemDominio = if (nome != null) OrigemDominio.DNS else OrigemDominio.NENHUM,
                    ordem = ++relogio,
                    telaDesligada = !telaLigada(),
                )
            }
            is Evento.FluxoBytes -> atualiza(e.id) {
                it.copy(bytesEnviados = e.bytesEnviados, bytesRecebidos = e.bytesRecebidos, pacotes = e.pacotes)
            }
            is Evento.FluxoFim -> atualiza(e.id) { it.copy(fimUs = e.fimUs, motivo = e.motivo) }
            is Evento.Sni -> atualiza(e.id) { it.copy(dominio = e.nome, origemDominio = OrigemDominio.SNI) }
            is Evento.Dns -> {
                e.enderecos.forEach { nomePorIp[it] = e.nome }
                val alvos = e.enderecos.toSet()
                porId.values.filter { it.origemDominio == OrigemDominio.NENHUM && it.destino in alvos }
                    .forEach { porId[it.id] = it.copy(dominio = e.nome, origemDominio = OrigemDominio.DNS) }
            }
            is Evento.Perda -> eventosPerdidos += e.descartados
        }
    }

    private inline fun atualiza(id: Long, muda: (Conexao) -> Conexao) {
        val c = porId[id] ?: return
        porId[id] = muda(c).copy(ordem = ++relogio)
    }
}
