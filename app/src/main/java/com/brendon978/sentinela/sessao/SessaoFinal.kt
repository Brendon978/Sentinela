package com.brendon978.sentinela.sessao

import android.content.Context
import android.util.Log
import com.brendon978.sentinela.dados.Banco
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

    fun concluir(ctx: Context, g: Gravacao?) {
        if (g == null) return
        val app = ctx.applicationContext
        thread(name = "sentinela-fechar-sessao") {
            runCatching {
                val pcap = File(g.caminhoPcap)
                val resumo = Evidencia.resumir(pcap)
                Evidencia.arquivoSha256(g.caminhoPcap).writeText(Evidencia.linhaSha256(resumo.sha256, pcap.name))
                val fimMs = System.currentTimeMillis()
                val sessao = SessaoSalva(
                    0, g.inicioMs, fimMs, g.caminhoPcap, resumo.sha256,
                    pacotes = resumo.pacotes, // tudo o que está no arquivo, não só o dos fluxos
                    bytes = g.linhas.sumOf { it.bytesEnviados + it.bytesRecebidos },
                    eventosPerdidos = g.eventosPerdidos,
                )
                Banco(app).use { db -> db.salvarSessao(sessao, g.linhas, fimMs, g.alertas) }
                _versao.value++
            }.onFailure { Log.e("Sentinela", "falha ao salvar a sessão", it) }
        }
    }

    /** Apaga a sessão do banco e os dois arquivos dela. Chamar fora da thread principal. */
    fun apagar(banco: Banco, s: SessaoSalva) {
        banco.apagarSessao(s.id)
        File(s.caminhoPcap).delete()
        Evidencia.arquivoSha256(s.caminhoPcap).delete()
        _versao.value++
    }
}
