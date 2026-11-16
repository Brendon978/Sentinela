package com.brendon978.sentinela.vpn

import android.util.Log
import com.brendon978.sentinela.ia.LinhaDeBase
import com.brendon978.sentinela.motor.Eventos
import com.brendon978.sentinela.sessao.Alerta
import com.brendon978.sentinela.sessao.Alteracoes
import com.brendon978.sentinela.sessao.EstadoSessao
import com.brendon978.sentinela.sessao.Gravacao
import com.brendon978.sentinela.sessao.LinhaFluxo
import com.brendon978.sentinela.sessao.SessaoAtual
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.ZoneId

/** De onde vêm os eventos do motor (no serviço, `Motor.eventos`). Lote vazio = nada agora. */
fun interface FonteEventos { fun lote(): ByteArray }

/** O que a captura precisa do banco. */
interface GravadorSessao {
    /** Ver [com.brendon978.sentinela.dados.Banco.gravarParcial]: só os fluxos mudados; alertas null = iguais. */
    fun gravarParcial(id: Long, fluxos: List<LinhaFluxo>, alertas: List<Alerta>?, agoraMs: Long, bytes: Long, eventosPerdidos: Long)
    fun historico(): List<LinhaFluxo>
}

/**
 * O trabalho de uma gravação em andamento, sem nada de Android: drenar os eventos do motor para
 * a [SessaoAtual] (a cada 100 ms), gravar a sessão no banco (a cada 5 s, em E/S, sem segurar a
 * drenagem) e treinar a IA com o histórico. O serviço cuida da VPN, do motor e das notificações.
 *
 * Parada, nesta ordem: [pararTrabalho] (espera a gravação em curso e cancela o treino), o serviço
 * para e encerra o motor, e [terminar] drena o que sobrou e devolve o que salvar.
 */
class Captura(
    private val escopo: CoroutineScope,
    private val sessaoId: Long,
    private val fonte: FonteEventos,
    private val gravador: GravadorSessao,
    private val io: CoroutineDispatcher,
    private val fuso: ZoneId,
    private val relogioMs: () -> Long,
    private val aoNovosAlertas: (Int) -> Unit = {},
    private val gravacaoMs: Long = 5_000,
) {
    private val cadeado = Any() // drenagem: a leitura e o terminar nunca ao mesmo tempo
    private var alertasAvisados = 0
    private val jobs = mutableListOf<Job>()

    fun iniciar() {
        jobs += escopo.launch {
            while (isActive) {
                delay(LEITURA_MS) // curto: o dono da conexão só é achado enquanto ela existe
                drenar()
            }
        }
        jobs += escopo.launch(io) {
            var gravado: EstadoSessao? = null
            val alteracoes = Alteracoes()
            while (isActive) {
                delay(gravacaoMs) // a cada 5 s a sessão vai para o banco
                val agora = relogioMs()
                val e = SessaoAtual.estado.value
                if (e === gravado) continue // o estado é imutável: mesma instância = nada mudou
                val bytes = e.linhas.sumOf { it.bytesEnviados + it.bytesRecebidos }
                val p = alteracoes.desde(e.linhas, e.alertas) // só o que mudou desde a última gravação
                runCatching { gravador.gravarParcial(sessaoId, p.fluxos, p.alertas, agora, bytes, e.eventosPerdidos) }
                    .onSuccess { gravado = e; alteracoes.confirmar(p) }
                    .onFailure { registrar("falha ao gravar a sessão em andamento", it) }
            }
        }
        // IA: treina o normal de cada app com as sessões anteriores, sem segurar o início
        jobs += escopo.launch {
            runCatching {
                val historico = withContext(io) { gravador.historico() }
                val base = LinhaDeBase.treinar(historico, fuso)
                ensureActive() // parou durante a conta: o modelo não entra
                SessaoAtual.definirLinhaDeBase(base)
            }.onFailure { if (it !is kotlinx.coroutines.CancellationException) registrar("IA sem linha de base", it) }
        }
    }

    /** Para a leitura, espera a gravação em curso e cancela o treino (não pode cair na próxima sessão). */
    suspend fun pararTrabalho() {
        jobs.forEach { it.cancel() } // cancela todos antes de esperar: param juntos
        jobs.forEach { it.join() }
        jobs.clear()
    }

    /** Depois de o motor encerrar: drena os eventos finais e fecha a sessão em memória. */
    fun terminar(): Gravacao? {
        drenar()
        return SessaoAtual.terminar()
    }

    /** Lê a fila inteira (o JNI entrega até 256 KiB por chamada). */
    private fun drenar() = synchronized(cadeado) {
        while (true) {
            val bytes = fonte.lote()
            if (bytes.isEmpty()) break
            val lote = Eventos.decodificar(bytes)
            lote.erro?.let { registrar("lote de eventos com erro: $it", null) }
            SessaoAtual.aplicar(lote.eventos)
        }
        val n = SessaoAtual.estado.value.alertas.size
        if (n > alertasAvisados) {
            alertasAvisados = n
            aoNovosAlertas(n)
        }
    }

    private fun registrar(msg: String, erro: Throwable?) {
        runCatching { Log.e(TAG, msg, erro) } // na JVM (testes) o Log não existe
    }

    private companion object {
        const val TAG = "Sentinela"
        const val LEITURA_MS = 100L
    }
}
