package com.brendon978.sentinela

import android.Manifest
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.ui.graphics.Color
import com.brendon978.sentinela.dados.Banco
import com.brendon978.sentinela.dados.SessaoSalva
import androidx.lifecycle.lifecycleScope
import com.brendon978.sentinela.motor.Ip
import com.brendon978.sentinela.motor.Motor
import com.brendon978.sentinela.motor.Pacote
import com.brendon978.sentinela.sessao.Alerta
import com.brendon978.sentinela.sessao.Evidencia
import com.brendon978.sentinela.ui.ListaPacotes
import com.brendon978.sentinela.ui.MAX_PACOTES_TELA
import kotlinx.coroutines.launch
import java.net.InetAddress
import com.brendon978.sentinela.sessao.LinhaFluxo
import com.brendon978.sentinela.sessao.SessaoAtual
import com.brendon978.sentinela.sessao.SessaoFinal
import com.brendon978.sentinela.ui.TelaConexao
import com.brendon978.sentinela.ui.TelaConexoes
import com.brendon978.sentinela.ui.TelaInicio
import com.brendon978.sentinela.ui.dataHora
import com.brendon978.sentinela.vpn.SessaoService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** Navegação simples por estado: início → conexões (ao vivo ou salva) → detalhe. */
sealed interface Tela {
    data object Inicio : Tela
    data object AoVivo : Tela
    data class Salva(val sessao: SessaoSalva) : Tela
    data class Detalhe(val linha: LinhaFluxo, val volta: Tela, val caminhoPcap: String?) : Tela
}

class MainActivity : ComponentActivity() {
    private var forcarTcpPendente = false
    private var exportando: SessaoSalva? = null

    private val pedirVpn = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) SessaoService.iniciar(this, forcarTcpPendente)
    }
    private val pedirNotificacao = registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

    private val salvarPcap = registerForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.tcpdump.pcap")) { uri ->
        val s = exportando ?: return@registerForActivityResult
        if (uri != null) copiar(File(s.caminhoPcap), uri)
        salvarSha.launch(Evidencia.arquivoSha256(s.caminhoPcap).name)
    }
    private val salvarSha = registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        val s = exportando ?: return@registerForActivityResult
        exportando = null
        val sha = Evidencia.arquivoSha256(s.caminhoPcap)
        if (uri != null && sha.exists()) copiar(sha, uri)
    }

    /** Pacotes da conexão já dissecados (roda fora da thread principal). */
    private fun lerPacotes(t: Tela.Detalhe): List<Pair<Pacote, String>> {
        val caminho = t.caminhoPcap ?: return emptyList()
        if (!File(caminho).exists()) return emptyList()
        val l = t.linha
        val ipApp = Ip(l.versaoIp, InetAddress.getByName(l.ipOrigem).address)
        return Motor.lerPacotes(
            caminho, l.protocolo, l.ipOrigem, l.portaOrigem, l.ipDestino, l.portaDestino,
            l.inicioUs, l.fimUs ?: 0, MAX_PACOTES_TELA,
        ).map { Pacote.de(it, ipApp).let { p -> p to Motor.dissecar(p.bytes) } }
    }

    private fun copiar(origem: File, destino: Uri) {
        contentResolver.openOutputStream(destino)?.use { saida -> origem.inputStream().use { it.copyTo(saida) } }
    }

    private fun gravar(forcarTcp: Boolean) {
        pedirNotificacao.launch(Manifest.permission.POST_NOTIFICATIONS)
        forcarTcpPendente = forcarTcp
        val pedido = VpnService.prepare(this)
        if (pedido != null) pedirVpn.launch(pedido) else SessaoService.iniciar(this, forcarTcp)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val banco = Banco(applicationContext)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Color(0xFFB388FF))) {
                Surface(Modifier.fillMaxSize()) {
                  Box(Modifier.safeDrawingPadding()) {
                    var tela by remember { mutableStateOf<Tela>(Tela.Inicio) }
                    var forcarTcp by remember { mutableStateOf(false) }
                    val estado by SessaoAtual.estado.collectAsState()
                    val versao by SessaoFinal.versao.collectAsState()
                    var sessoes by remember { mutableStateOf(emptyList<SessaoSalva>()) }
                    LaunchedEffect(versao) { sessoes = withContext(Dispatchers.IO) { banco.sessoes() } }

                    BackHandler(tela != Tela.Inicio) {
                        tela = when (val t = tela) { is Tela.Detalhe -> t.volta; else -> Tela.Inicio }
                    }
                    when (val t = tela) {
                        Tela.Inicio -> TelaInicio(
                            estado, sessoes, forcarTcp, { forcarTcp = it },
                            aoGravar = { gravar(forcarTcp) },
                            aoParar = { SessaoService.parar(this@MainActivity) },
                            aoAbrirAoVivo = { tela = Tela.AoVivo },
                            aoAbrirSessao = { tela = Tela.Salva(it) },
                            aoExportar = { s ->
                                exportando = s
                                salvarPcap.launch(File(s.caminhoPcap).name)
                            },
                            aoApagar = { s -> lifecycleScope.launch(Dispatchers.IO) { SessaoFinal.apagar(banco, s) } },
                        )
                        Tela.AoVivo -> TelaConexoes(
                            "Ao vivo", estado.linhas, estado.alertas, { tela = Tela.Inicio },
                        ) { tela = Tela.Detalhe(it, Tela.AoVivo, estado.caminhoPcap) }
                        is Tela.Salva -> {
                            var linhas by remember(t) { mutableStateOf(emptyList<LinhaFluxo>()) }
                            var alertas by remember(t) { mutableStateOf(emptyList<Alerta>()) }
                            LaunchedEffect(t) {
                                withContext(Dispatchers.IO) {
                                    linhas = banco.fluxos(t.sessao.id)
                                    alertas = banco.alertas(t.sessao.id)
                                }
                            }
                            TelaConexoes(dataHora(t.sessao.inicioMs), linhas, alertas, { tela = Tela.Inicio }) {
                                tela = Tela.Detalhe(it, t, t.sessao.caminhoPcap)
                            }
                        }
                        is Tela.Detalhe -> {
                            var pacotes by remember(t) { mutableStateOf<List<Pair<Pacote, String>>?>(null) }
                            LaunchedEffect(t) {
                                pacotes = withContext(Dispatchers.IO) { lerPacotes(t) }
                            }
                            TelaConexao(t.linha, { tela = t.volta }) {
                                ListaPacotes(pacotes)
                            }
                        }
                    }
                  }
                }
            }
        }
    }
}
