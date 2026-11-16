package com.brendon978.sentinela.sessao

import android.content.Context
import android.util.Log
import com.brendon978.sentinela.dados.Banco
import com.brendon978.sentinela.dados.EstadoSessaoSalva
import com.brendon978.sentinela.dados.SessaoSalva
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import kotlin.concurrent.thread

/**
 * Sessões salvas: fechar (SHA-256 do pcap, .sha256 ao lado e gravação no banco, fora da thread
 * principal) e apagar. O pcap já está fechado quando concluir é chamado (o motor fecha no encerrar).
 */
object SessaoFinal {
    private val _versao = MutableStateFlow(0L)
    /** Muda a cada sessão salva ou apagada: as telas recarregam a lista. */
    val versao: StateFlow<Long> = _versao.asStateFlow()

    /** Sessões gravando ou fechando neste processo: a recuperação não mexe nelas. */
    private val emUso = java.util.concurrent.ConcurrentHashMap.newKeySet<Long>()

    fun usando(id: Long) { emUso += id }
    fun liberou(id: Long) { emUso -= id }

    fun concluir(ctx: Context, g: Gravacao?) {
        if (g == null) return
        val app = ctx.applicationContext
        thread(name = "sentinela-fechar-sessao") {
            runCatching {
                val resumo = Evidencia.selar(g.caminhoPcap)
                val fimMs = System.currentTimeMillis()
                Banco(app).use { db ->
                    db.concluirSessao(
                        g.sessaoId, resumo.sha256,
                        pacotes = resumo.pacotes, // tudo o que está no arquivo, não só o dos fluxos
                        bytes = g.linhas.sumOf { it.bytesEnviados + it.bytesRecebidos },
                        fimMs = fimMs, eventosPerdidos = g.eventosPerdidos, fluxos = g.linhas, alertas = g.alertas,
                        iaApps = g.iaApps,
                    )
                }
                _versao.value++
            }.onFailure { Log.e("Sentinela", "falha ao salvar a sessão", it) }
            liberou(g.sessaoId)
        }
    }

    /**
     * Sessões que ficaram GRAVANDO sem gravação viva (o app morreu no meio) viram INTERROMPIDA,
     * com o hash e a contagem do que chegou ao pcap. As que estão em uso neste processo (gravando ou
     * fechando) ficam como estão. Chamar fora da thread principal.
     */
    fun recuperar(banco: Banco) {
        var mudou = false
        for (s in banco.sessoes()) {
            if (s.estado != EstadoSessaoSalva.GRAVANDO || s.id in emUso) continue
            runCatching { // uma sessão com problema não impede as outras nem derruba o app
                val r = if (File(s.caminhoPcap).exists()) Evidencia.selar(s.caminhoPcap) else Evidencia.Resumo("", 0)
                banco.marcarInterrompida(s.id, r.sha256, r.pacotes)
                mudou = true
            }.onFailure { Log.e("Sentinela", "falha ao recuperar a sessão ${s.id}", it) }
        }
        if (mudou) _versao.value++ // só recarrega a lista quando alguma sessão mudou
    }

    /** Apaga a sessão do banco e os dois arquivos dela. Chamar fora da thread principal. */
    fun apagar(banco: Banco, s: SessaoSalva) {
        banco.apagarSessao(s.id)
        File(s.caminhoPcap).delete()
        Evidencia.arquivoSha256(s.caminhoPcap).delete()
        _versao.value++
    }
}
