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
import com.brendon978.sentinela.sessao.Regra
import com.brendon978.sentinela.sessao.Evidencia
import com.brendon978.sentinela.sessao.Exportacao
import com.brendon978.sentinela.sessao.Relatorio
import com.brendon978.sentinela.sessao.RelatorioPdf
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
    data object Rede : Tela
    data class Salva(val sessao: SessaoSalva) : Tela
    data class Detalhe(val linha: LinhaFluxo, val volta: Tela, val caminhoPcap: String?) : Tela
}

class MainActivity : ComponentActivity() {
    private var forcarTcpPendente = false
    private var exportando: SessaoSalva? = null

    private val pedirVpn = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) SessaoService.iniciar(this, forcarTcpPendente)
    }
    private val pedirPermissoes = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        depoisDasPermissoes?.invoke()
        depoisDasPermissoes = null
    }
    private var depoisDasPermissoes: (() -> Unit)? = null

    /** Rede local (Android 17+) para o mapa e para o repasse do tráfego à LAN; notificações para gravar. */
    private fun comPermissoes(vararg extra: String, depois: () -> Unit) {
        val faltam = (listOf(PERMISSAO_REDE_LOCAL) + extra).filter {
            checkSelfPermission(it) != android.content.pm.PackageManager.PERMISSION_GRANTED
        }
        if (faltam.isEmpty()) return depois()
        depoisDasPermissoes = depois
        pedirPermissoes.launch(faltam.toTypedArray())
    }

    private val salvarPcap = registerForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.tcpdump.pcap")) { uri ->
        val s = exportando ?: return@registerForActivityResult
        if (uri != null) copiar(File(s.caminhoPcap), uri)
        salvarSha.launch(Evidencia.arquivoSha256(s.caminhoPcap).name)
    }
    private enum class Formato { CSV, CSV_ANONIMO, PDF }
    private var formatoPendente = Formato.CSV
    private lateinit var banco: Banco

    private val salvarCsv = registerForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { uri ->
        val s = exportando ?: return@registerForActivityResult
        exportando = null
        if (uri != null) escreverEm(uri) {
            val linhas = banco.fluxos(s.id)
            val anonimo = formatoPendente == Formato.CSV_ANONIMO
            val sal = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
            it.write(Exportacao.csv(linhas, anonimo, sal).toByteArray())
        }
    }

    private val salvarPdf = registerForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        val s = exportando ?: return@registerForActivityResult
        exportando = null
        if (uri != null) escreverEm(uri) {
            val secoes = Relatorio.conteudo(
                s, banco.fluxos(s.id), banco.alertas(s.id),
                aparelho = "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL} (Android ${android.os.Build.VERSION.RELEASE})",
                versaoApp = packageManager.getPackageInfo(packageName, 0).versionName ?: "?",
                fuso = java.time.ZoneId.systemDefault(), geradoEmMs = System.currentTimeMillis(),
            )
            RelatorioPdf.escrever(dataHora(s.inicioMs), secoes, it)
        }
    }

    /** Gera o arquivo fora da thread principal e grava no destino escolhido pelo usuário. */
    private fun escreverEm(uri: Uri, gerar: (java.io.OutputStream) -> Unit) {
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching { contentResolver.openOutputStream(uri)?.use(gerar) }
                .onFailure { android.util.Log.e("Sentinela", "falha ao exportar", it) }
        }
    }

    private fun exportar(s: SessaoSalva, formato: Formato?) {
        exportando = s
        val base = File(s.caminhoPcap).nameWithoutExtension
        when (formato) {
            null -> salvarPcap.launch(File(s.caminhoPcap).name)
            Formato.CSV -> { formatoPendente = formato; salvarCsv.launch("$base.csv") }
            Formato.CSV_ANONIMO -> { formatoPendente = formato; salvarCsv.launch("$base-anonimo.csv") }
            Formato.PDF -> salvarPdf.launch("$base-relatorio.pdf")
        }
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

    private fun gravar(forcarTcp: Boolean) = comPermissoes(Manifest.permission.POST_NOTIFICATIONS) {
        forcarTcpPendente = forcarTcp
        val pedido = VpnService.prepare(this)
        if (pedido != null) pedirVpn.launch(pedido) else SessaoService.iniciar(this, forcarTcp)
    }

    private companion object {
        const val PERMISSAO_REDE_LOCAL = "android.permission.ACCESS_LOCAL_NETWORK"
    }

    override fun onDestroy() {
        if (::banco.isInitialized) banco.close()
        super.onDestroy()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        banco = Banco(applicationContext)
        // Sessão que ficou pela metade (o app morreu gravando) vira "interrompida", com hash.
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching { SessaoFinal.recuperar(banco) }
        }
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Color(0xFFB388FF))) {
                Surface(Modifier.fillMaxSize()) {
                  Box(Modifier.safeDrawingPadding()) {
                    var tela by remember { mutableStateOf<Tela>(Tela.Inicio) }
                    var escolhendoExportacao by remember { mutableStateOf<SessaoSalva?>(null) }
                    var aparelhos by remember { mutableStateOf<List<com.brendon978.sentinela.rede.Aparelho>?>(null) }
                    var statusRede by remember { mutableStateOf<String?>(null) }
                    var varrendo by remember { mutableStateOf(false) }
                    var forcarTcp by remember { mutableStateOf(false) }
                    val estado by SessaoAtual.estado.collectAsState()
                    val versao by SessaoFinal.versao.collectAsState()
                    var sessoes by remember { mutableStateOf(emptyList<SessaoSalva>()) }
                    var excecoes by remember { mutableStateOf(emptySet<Pair<String?, Regra>>()) }
                    LaunchedEffect(versao) { sessoes = withContext(Dispatchers.IO) { banco.sessoes() } }
                    LaunchedEffect(Unit) { excecoes = withContext(Dispatchers.IO) { banco.excecoes() } }
                    fun mudarExcecao(e: Pair<String?, Regra>, ignorar: Boolean) = lifecycleScope.launch(Dispatchers.IO) {
                        if (ignorar) banco.adicionarExcecao(e.first, e.second) else banco.removerExcecao(e.first, e.second)
                        val novas = banco.excecoes()
                        SessaoAtual.trocarExcecoes(novas)
                        excecoes = novas
                    }

                    escolhendoExportacao?.let { s ->
                        androidx.compose.material3.AlertDialog(
                            onDismissRequest = { escolhendoExportacao = null },
                            title = { androidx.compose.material3.Text("Exportar sessão") },
                            text = {
                                androidx.compose.foundation.layout.Column {
                                    listOf(
                                        "Captura (.pcap + .sha256)" to null, "Conexões em CSV" to Formato.CSV,
                                        "Conexões em CSV anonimizado" to Formato.CSV_ANONIMO, "Relatório em PDF" to Formato.PDF,
                                    ).forEach { (rotulo, f) ->
                                        androidx.compose.material3.TextButton(onClick = { escolhendoExportacao = null; exportar(s, f) }) {
                                            androidx.compose.material3.Text(rotulo)
                                        }
                                    }
                                }
                            },
                            confirmButton = {},
                            dismissButton = {
                                androidx.compose.material3.TextButton(onClick = { escolhendoExportacao = null }) {
                                    androidx.compose.material3.Text("Cancelar")
                                }
                            },
                        )
                    }
                    BackHandler(tela != Tela.Inicio) {
                        tela = when (val t = tela) { is Tela.Detalhe -> t.volta; else -> Tela.Inicio }
                    }
                    when (val t = tela) {
                        Tela.Inicio -> TelaInicio(
                            estado, sessoes, forcarTcp, { forcarTcp = it },
                            aoGravar = { gravar(forcarTcp) },
                            aoParar = { SessaoService.parar(this@MainActivity) },
                            aoAbrirAoVivo = { tela = Tela.AoVivo },
                            aoAbrirRede = { tela = Tela.Rede },
                            aoAbrirSessao = { tela = Tela.Salva(it) },
                            aoExportar = { s -> escolhendoExportacao = s },
                            aoApagar = { s -> lifecycleScope.launch(Dispatchers.IO) { SessaoFinal.apagar(banco, s) } },
                            excecoes = excecoes,
                            aoDesfazerExcecao = { mudarExcecao(it, ignorar = false) },
                        )
                        Tela.Rede -> com.brendon978.sentinela.ui.TelaRede(aparelhos, statusRede, varrendo, { tela = Tela.Inicio }) {
                          comPermissoes {
                            varrendo = true
                            statusRede = "Começando…"
                            lifecycleScope.launch {
                                val varredor = com.brendon978.sentinela.rede.Varredor(this@MainActivity)
                                runCatching { varredor.mapear { statusRede = it } }
                                    .onSuccess {
                                        aparelhos = it
                                        statusRede = (if (it.size == 1) "1 aparelho encontrado" else "${it.size} aparelhos encontrados") +
                                            (varredor.aviso?.let { a -> "\n$a" } ?: "")
                                    }
                                    .onFailure { statusRede = it.message ?: "Falhou: $it" }
                                varrendo = false
                            }
                          }
                        }
                        Tela.AoVivo -> TelaConexoes(
                            "Ao vivo", estado.linhas, estado.alertas, { tela = Tela.Inicio },
                            aoIgnorar = { mudarExcecao(it.pacote to it.regra, ignorar = true) },
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
                            TelaConexoes(
                                dataHora(t.sessao.inicioMs), linhas, alertas.filter { (it.pacote to it.regra) !in excecoes },
                                { tela = Tela.Inicio }, aoIgnorar = { mudarExcecao(it.pacote to it.regra, ignorar = true) },
                            ) {
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
