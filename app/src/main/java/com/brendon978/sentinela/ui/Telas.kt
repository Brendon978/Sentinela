package com.brendon978.sentinela.ui

import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import androidx.compose.foundation.rememberScrollState
import com.brendon978.sentinela.dados.EstadoSessaoSalva
import com.brendon978.sentinela.dados.SessaoSalva
import com.brendon978.sentinela.motor.Pacote
import com.brendon978.sentinela.sessao.Alerta
import com.brendon978.sentinela.sessao.PorApp
import com.brendon978.sentinela.sessao.ResumoApp
import com.brendon978.sentinela.sessao.EstadoSessao
import com.brendon978.sentinela.sessao.LinhaFluxo
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val formatoData = SimpleDateFormat("dd/MM/yyyy HH:mm:ss", Locale.forLanguageTag("pt-BR"))

fun dataHora(ms: Long): String = formatoData.format(Date(ms))

// ---------------------------------------------------------------- início

@Composable
fun TelaInicio(
    estado: EstadoSessao,
    sessoes: List<SessaoSalva>,
    forcarTcp: Boolean,
    aoMudarForcarTcp: (Boolean) -> Unit,
    aoGravar: () -> Unit,
    aoParar: () -> Unit,
    aoAbrirAoVivo: () -> Unit,
    aoAbrirRede: () -> Unit,
    aoAbrirSessao: (SessaoSalva) -> Unit,
    aoExportar: (SessaoSalva) -> Unit,
    aoApagar: (SessaoSalva) -> Unit,
    excecoes: Set<Pair<String?, com.brendon978.sentinela.sessao.Regra>> = emptySet(),
    aoDesfazerExcecao: (Pair<String?, com.brendon978.sentinela.sessao.Regra>) -> Unit = {},
) {
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            Text("Sentinela", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text("Captura do tráfego deste celular", style = MaterialTheme.typography.bodyMedium)
        }
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (estado.gravando) {
                        Text("Gravando desde ${dataHora(estado.inicioMs)}", fontWeight = FontWeight.SemiBold)
                        Text("${estado.linhas.size} conexões")
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = aoParar) { Text("Parar") }
                            OutlinedButton(onClick = aoAbrirAoVivo) { Text("Ver ao vivo") }
                        }
                    } else {
                        Button(onClick = aoGravar, modifier = Modifier.fillMaxWidth()) { Text("Gravar") }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text("Forçar TCP")
                                Text(
                                    "Bloqueia QUIC (UDP 443) para os apps usarem TCP e o nome do site aparecer.",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            Switch(checked = forcarTcp, onCheckedChange = aoMudarForcarTcp)
                        }
                    }
                    if (estado.dnsPrivadoAtivo) Aviso("O DNS privado do Android está ligado: alguns nomes podem não aparecer.")
                    if (estado.eventosPerdidos > 0) Aviso("${estado.eventosPerdidos} eventos se perderam (fila cheia).")
                    estado.erro?.let { Aviso(it) }
                }
            }
        }
        if (excecoes.isNotEmpty()) {
            item { Text("Alertas ignorados", style = MaterialTheme.typography.titleMedium) }
            items(excecoes.toList()) { e ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(e.second.titulo, style = MaterialTheme.typography.bodyMedium)
                        Text(e.first ?: com.brendon978.sentinela.vpn.App.SEM_APP, style = MaterialTheme.typography.bodySmall)
                    }
                    TextButton(onClick = { aoDesfazerExcecao(e) }) { Text("Desfazer") }
                }
            }
        }
        item { OutlinedButton(onClick = aoAbrirRede, modifier = Modifier.fillMaxWidth()) { Text("Mapa da rede Wi-Fi") } }
        item { Text("Sessões salvas", style = MaterialTheme.typography.titleMedium) }
        if (sessoes.isEmpty()) item { Text("Nenhuma ainda.", style = MaterialTheme.typography.bodySmall) }
        items(sessoes, key = { it.id }) { s ->
            Card(Modifier.fillMaxWidth().clickable { aoAbrirSessao(s) }) {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(dataHora(s.inicioMs), fontWeight = FontWeight.SemiBold)
                        when (s.estado) {
                            EstadoSessaoSalva.GRAVANDO -> Selo("gravando")
                            EstadoSessaoSalva.INTERROMPIDA -> Selo("interrompida")
                            EstadoSessaoSalva.CONCLUIDA -> {}
                        }
                    }
                    val duracao = (s.fimMs - s.inicioMs) / 1000
                    Text("${duracao / 60} min ${duracao % 60} s · ${s.pacotes} pacotes · ${Lista.bytes(s.bytes)}")
                    Text("SHA-256 ${s.sha256.take(16)}…", fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                    if (s.estado != EstadoSessaoSalva.GRAVANDO) Row { // gravando: o arquivo ainda está aberto
                        TextButton(onClick = { aoExportar(s) }) { Text("Exportar") }
                        TextButton(onClick = { aoApagar(s) }) { Text("Apagar") }
                    }
                }
            }
        }
    }
}

@Composable
private fun Aviso(texto: String) {
    Text(
        texto,
        modifier = Modifier.fillMaxWidth().background(Color(0x33FFB300), RoundedCornerShape(6.dp)).padding(8.dp),
        style = MaterialTheme.typography.bodySmall,
    )
}

// ---------------------------------------------------------------- conexões

enum class Aba(val titulo: String) { CONEXOES("Conexões"), POR_APP("Por app"), ALERTAS("Alertas") }

/** Uma sessão (ao vivo ou salva): conexões, resumo por app e alertas. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun TelaConexoes(
    titulo: String,
    linhas: List<LinhaFluxo>,
    alertas: List<Alerta>,
    aoVoltar: () -> Unit,
    aoIgnorar: (Alerta) -> Unit = {},
    aoAbrir: (LinhaFluxo) -> Unit,
) {
    var aba by remember { mutableStateOf(Aba.CONEXOES) }
    var perguntaIgnorar by remember { mutableStateOf<Alerta?>(null) }
    perguntaIgnorar?.let { a ->
        AlertDialog(
            onDismissRequest = { perguntaIgnorar = null },
            title = { Text("Ignorar este alerta?") },
            text = { Text("Não avisar mais \"${a.regra.titulo}\" para ${a.rotulo}. Dá para desfazer na tela inicial.") },
            confirmButton = { TextButton(onClick = { aoIgnorar(a); perguntaIgnorar = null }) { Text("Ignorar") } },
            dismissButton = { TextButton(onClick = { perguntaIgnorar = null }) { Text("Cancelar") } },
        )
    }
    var texto by remember { mutableStateOf("") }
    var pacote by remember { mutableStateOf<String?>(null) }
    val filtradas = remember(linhas, texto, pacote) { Lista.filtrar(linhas, texto, pacote) }
    Column(Modifier.fillMaxSize().padding(horizontal = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = aoVoltar) { Text("← Voltar") }
            Text(titulo, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Aba.entries.forEach { a ->
                val rotulo = if (a == Aba.ALERTAS && alertas.isNotEmpty()) "${a.titulo} (${alertas.size})" else a.titulo
                if (a == aba) Button(onClick = {}) { Text(rotulo) } else OutlinedButton(onClick = { aba = a }) { Text(rotulo) }
            }
        }
        when (aba) {
            Aba.CONEXOES -> {
                OutlinedTextField(
                    value = texto, onValueChange = { texto = it }, singleLine = true,
                    label = { Text("Buscar app, domínio, IP ou porta") }, modifier = Modifier.fillMaxWidth(),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("${filtradas.size} de ${linhas.size}", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(4.dp))
                    if (pacote != null) TextButton(onClick = { pacote = null }) { Text("× só $pacote") }
                }
                LazyColumn {
                    items(filtradas, key = { it.fluxoId }) { l ->
                        LinhaConexao(l, Modifier.clickable { aoAbrir(l) })
                        HorizontalDivider()
                    }
                }
            }
            Aba.POR_APP -> {
                val resumo = remember(linhas) { PorApp.resumir(linhas) }
                LazyColumn(Modifier.padding(top = 8.dp)) {
                    items(resumo, key = { it.chave }) { r ->
                        LinhaApp(r, Modifier.clickable { pacote = r.pacote; aba = Aba.CONEXOES })
                        HorizontalDivider()
                    }
                }
            }
            Aba.ALERTAS -> {
                if (alertas.isEmpty()) Text("Nenhum alerta.", modifier = Modifier.padding(8.dp))
                LazyColumn(Modifier.padding(top = 8.dp)) {
                    items(alertas) { a ->
                        Column(
                            Modifier.fillMaxWidth().padding(vertical = 6.dp).combinedClickable(
                                onClick = { linhas.firstOrNull { it.fluxoId == a.fluxoId }?.let(aoAbrir) },
                                onLongClick = { perguntaIgnorar = a },
                            ),
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                IconeApp(a.pacote)
                                Spacer(Modifier.width(10.dp))
                                Column {
                                    Text(a.regra.titulo, fontWeight = FontWeight.SemiBold)
                                    Text(a.rotulo, style = MaterialTheme.typography.bodySmall)
                                }
                            }
                            Text(a.detalhe, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 2.dp))
                            Text(dataHora(a.quandoUs / 1000), style = MaterialTheme.typography.bodySmall)
                        }
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}

@Composable
private fun LinhaApp(r: ResumoApp, modifier: Modifier = Modifier) {
    Row(modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        IconeApp(r.pacote)
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(r.rotulo, fontWeight = FontWeight.SemiBold)
            Text("${r.conexoes} conexões · ${r.dominios.size} domínios", style = MaterialTheme.typography.bodySmall)
            if (r.rastreadores.isNotEmpty())
                Text(
                    "${r.rastreadores.size} rastreador(es): ${r.rastreadores.joinToString(", ")}",
                    style = MaterialTheme.typography.bodySmall, color = Color(0xFFFFB300),
                )
        }
        Column(horizontalAlignment = Alignment.End) {
            Text("↑ ${Lista.bytes(r.bytesEnviados)}", style = MaterialTheme.typography.bodySmall)
            Text("↓ ${Lista.bytes(r.bytesRecebidos)}", style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun LinhaConexao(l: LinhaFluxo, modifier: Modifier = Modifier) {
    Row(modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        IconeApp(l.pacoteApp)
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(l.rotulo, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(l.dominio ?: l.ipDestino, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, false))
                if (l.dominio != null) Selo(
                    when (l.origemDominio) { "SNI" -> "SNI"; "SNI_ECH" -> "SNI·ECH"; else -> "DNS" }
                )
            }
            Text(
                "${l.nomeProtocolo} ${l.ipDestino}:${l.portaDestino}" + if (l.fimUs != null) " · encerrada" else "",
                style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
            )
        }
        Column(horizontalAlignment = Alignment.End) {
            Text("↑ ${Lista.bytes(l.bytesEnviados)}", style = MaterialTheme.typography.bodySmall)
            Text("↓ ${Lista.bytes(l.bytesRecebidos)}", style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun Selo(texto: String) {
    Text(
        texto, fontSize = 10.sp,
        modifier = Modifier.padding(start = 4.dp).background(Color(0x553B1F6E), RoundedCornerShape(4.dp)).padding(horizontal = 4.dp),
    )
}

@Composable
fun IconeApp(pacote: String?) {
    val ctx = LocalContext.current
    val icone by produceState<Drawable?>(null, pacote) {
        value = pacote?.let { runCatching { ctx.packageManager.getApplicationIcon(it) }.getOrNull() }
    }
    val bitmap = remember(icone) { icone?.toBitmap(96, 96)?.asImageBitmap() }
    if (bitmap != null) Image(bitmap, contentDescription = null, modifier = Modifier.size(36.dp))
    else Box(Modifier.size(36.dp).background(Color(0xFF3B1F6E), RoundedCornerShape(8.dp)))
}

// ---------------------------------------------------------------- detalhe (Tarefa 12 acrescenta os pacotes)

@Composable
fun TelaConexao(l: LinhaFluxo, aoVoltar: () -> Unit, extra: @Composable () -> Unit = {}) {
    LazyColumn(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        item { TextButton(onClick = aoVoltar) { Text("← Voltar") } }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconeApp(l.pacoteApp)
                Spacer(Modifier.width(10.dp))
                Column {
                    Text(l.rotulo, style = MaterialTheme.typography.titleMedium)
                    Text(l.pacoteApp ?: "uid ${l.uid}", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        val campos = listOf(
            "Domínio" to (l.dominio?.let { "$it (${l.origemDominio})" } ?: "—"),
            "Protocolo" to "${l.nomeProtocolo} / IPv${l.versaoIp}",
            "Origem" to "${l.ipOrigem}:${l.portaOrigem}",
            "Destino" to "${l.ipDestino}:${l.portaDestino}",
            "Enviado" to Lista.bytes(l.bytesEnviados),
            "Recebido" to Lista.bytes(l.bytesRecebidos),
            "Pacotes" to l.pacotes.toString(),
            "Início" to dataHora(l.inicioUs / 1000),
            "Fim" to (l.fimUs?.let { dataHora(it / 1000) } ?: "aberta"),
        )
        items(campos) { (k, v) ->
            Row { Text(k, Modifier.width(96.dp), fontWeight = FontWeight.SemiBold); Text(v, fontFamily = FontFamily.Monospace) }
        }
        item { extra() }
    }
}

// ---------------------------------------------------------------- pacotes de uma conexão (Tarefa 12)

private val formatoHora = SimpleDateFormat("HH:mm:ss.SSS", Locale.forLanguageTag("pt-BR"))

@Composable
fun ListaPacotes(pacotes: List<Pair<Pacote, String>>?) {
    var aberto by remember { mutableStateOf(-1) }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("Pacotes", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 12.dp))
        when {
            pacotes == null -> Text("Carregando…", style = MaterialTheme.typography.bodySmall)
            pacotes.isEmpty() -> Text("Nenhum pacote no arquivo da sessão.", style = MaterialTheme.typography.bodySmall)
        }
        pacotes?.forEachIndexed { i, (p, arvore) ->
            val resumo = arvore.lineSequence().firstOrNull()?.removePrefix("Resumo: ").orEmpty()
            Column(
                Modifier.fillMaxWidth().clickable { aberto = if (aberto == i) -1 else i }
                    .background(Color(0x22FFFFFF), RoundedCornerShape(6.dp)).padding(8.dp),
            ) {
                Text(
                    "${if (p.doApp) "↑" else "↓"} ${formatoHora.format(Date(p.quandoUs / 1000))} · ${p.bytes.size} B",
                    fontWeight = FontWeight.SemiBold, fontSize = 13.sp,
                )
                Text(resumo, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                if (aberto == i) {
                    Text(
                        arvore.lineSequence().drop(1).joinToString("\n").trim(),
                        fontFamily = FontFamily.Monospace, fontSize = 11.sp, softWrap = false,
                        modifier = Modifier.padding(top = 6.dp)
                            .horizontalScroll(rememberScrollState()),
                    )
                }
            }
        }
        if (pacotes != null && pacotes.size >= MAX_PACOTES_TELA)
            Text("Mostrando os primeiros $MAX_PACOTES_TELA pacotes.", style = MaterialTheme.typography.bodySmall)
    }
}

const val MAX_PACOTES_TELA = 200

// ---------------------------------------------------------------- mapa da rede (v1.1)

@Composable
fun TelaRede(
    aparelhos: List<com.brendon978.sentinela.rede.Aparelho>?,
    status: String?,
    varrendo: Boolean,
    aoVoltar: () -> Unit,
    aoMapear: () -> Unit,
) {
    var confirmando by remember { mutableStateOf(false) }
    if (confirmando) {
        AlertDialog(
            onDismissRequest = { confirmando = false },
            title = { Text("Mapear esta rede?") },
            text = {
                Text(
                    "Só faça isso na sua rede ou com autorização do dono. Varrer aparelhos de uma rede " +
                        "alheia pode ser crime (Lei 12.737/2012).",
                )
            },
            confirmButton = { TextButton(onClick = { confirmando = false; aoMapear() }) { Text("É minha / tenho autorização") } },
            dismissButton = { TextButton(onClick = { confirmando = false }) { Text("Cancelar") } },
        )
    }
    LazyColumn(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = aoVoltar) { Text("← Voltar") }
                Text("Mapa da rede", style = MaterialTheme.typography.titleMedium)
            }
            Text(
                "Aparelhos do Wi-Fi atual, pelo que eles anunciam (mDNS, SSDP) e por algumas portas abertas.",
                style = MaterialTheme.typography.bodySmall,
            )
            Button(onClick = { confirmando = true }, enabled = !varrendo, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                Text(if (varrendo) "Mapeando…" else "Mapear")
            }
            status?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp)) }
        }
        items(aparelhos.orEmpty(), key = { it.ip }) { a ->
            val tipo = com.brendon978.sentinela.rede.Classificador.tipo(a)
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(10.dp)) {
                    Row {
                        Text(tipo.nome, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                        Text(a.ip, fontFamily = FontFamily.Monospace)
                    }
                    if (a.nomes.isNotEmpty()) Text(a.nomes.joinToString(", "))
                    if (a.servicos.isNotEmpty()) Text("Anuncia: ${a.servicos.joinToString(", ")}", style = MaterialTheme.typography.bodySmall)
                    if (a.portas.isNotEmpty()) Text("Portas abertas: ${a.portas.sorted().joinToString(", ")}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    a.servidor?.let { Text("UPnP: $it", style = MaterialTheme.typography.bodySmall) }
                }
            }
        }
    }
}
