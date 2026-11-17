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
import androidx.compose.material3.MaterialTheme
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
import com.brendon978.sentinela.ui.tema.LocalPaleta
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.selection.selectable
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.graphics.graphicsLayer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val formatoData = SimpleDateFormat("dd/MM/yyyy HH:mm:ss", Locale.forLanguageTag("pt-BR"))

fun dataHora(ms: Long): String = formatoData.format(Date(ms))

/** "1 conexão", "2 conexões". */
fun plural(n: Int, um: String, varios: String) = "$n ${if (n == 1) um else varios}"

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
    temaClaro: Boolean = false,
    aoTrocarTema: (Boolean) -> Unit = {},
) {
    val p = LocalPaleta.current
    LazyColumn(
        Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Marca(34.dp)
                Column(Modifier.weight(1f).padding(start = 10.dp)) {
                    Text("Sentinela", style = MaterialTheme.typography.headlineSmall)
                    Text("Captura e evidência do tráfego deste celular", style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
                }
                BotaoIcone(if (temaClaro) "Usar tema escuro" else "Usar tema claro", { aoTrocarTema(!temaClaro) }) {
                    Desenho(if (temaClaro) Icone.LUA else Icone.SOL, p.textoSecundario, 20.dp)
                }
            }
        }
        item { CartaoGravacao(estado, forcarTcp, aoMudarForcarTcp, aoGravar, aoParar, aoAbrirAoVivo) }
        item {
            Cartao(aoTocar = aoAbrirRede) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Desenho(Icone.RADAR, p.secundaria, 26.dp)
                    Column(Modifier.weight(1f).padding(start = 12.dp)) {
                        Text("Mapa da rede Wi-Fi", style = MaterialTheme.typography.titleMedium)
                        Text("Aparelhos que se anunciam e portas abertas", style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
                    }
                    Desenho(Icone.SETA, p.textoSecundario, 18.dp)
                }
            }
        }
        if (excecoes.isNotEmpty()) {
            item { RotuloSecao("Alertas ignorados") }
            items(excecoes.toList()) { e ->
                Cartao {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(e.second.titulo, style = MaterialTheme.typography.bodyMedium)
                            TextoTecnico(e.first ?: com.brendon978.sentinela.vpn.App.SEM_APP, p.textoSecundario, 12)
                        }
                        TextButton(onClick = { aoDesfazerExcecao(e) }) { Text("Desfazer") }
                    }
                }
            }
        }
        item { RotuloSecao("Sessões salvas") }
        if (sessoes.isEmpty()) item {
            Text("Nenhuma ainda. Grave uma sessão para ela aparecer aqui, com o hash do arquivo.",
                style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
        }
        items(sessoes, key = { it.id }) { s -> CartaoSessao(s, aoAbrirSessao, aoExportar, aoApagar) }
    }
}

@Composable
private fun CartaoGravacao(
    estado: EstadoSessao,
    forcarTcp: Boolean,
    aoMudarForcarTcp: (Boolean) -> Unit,
    aoGravar: () -> Unit,
    aoParar: () -> Unit,
    aoAbrirAoVivo: () -> Unit,
) {
    val p = LocalPaleta.current
    Cartao {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
            val cor = if (estado.gravando) p.perigo else p.primaria
            Box(Modifier.size(176.dp), contentAlignment = Alignment.Center) {
                Pulso(cor, estado.gravando, Modifier.fillMaxSize())
                Box(
                    Modifier.size(112.dp).clip(CircleShape).background(cor.copy(alpha = com.brendon978.sentinela.ui.tema.ALFA_BOTAO))
                        .border(2.dp, cor, CircleShape).clickable { if (estado.gravando) aoParar() else aoGravar() },
                    contentAlignment = Alignment.Center,
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        if (estado.gravando) Box(Modifier.size(18.dp).background(cor, RoundedCornerShape(4.dp)))
                        else Box(Modifier.size(20.dp).background(cor, CircleShape))
                        Text(
                            if (estado.gravando) "PARAR" else "GRAVAR",
                            style = MaterialTheme.typography.labelLarge.copy(letterSpacing = 2.sp), color = cor,
                            modifier = Modifier.padding(top = 6.dp),
                        )
                    }
                }
            }
            if (estado.gravando) {
                Relogio(estado.inicioMs)
                ResumoSessao(estado.linhas, estado.alertas.size)
                Button(onClick = aoAbrirAoVivo, modifier = Modifier.fillMaxWidth()) { Text("Ver ao vivo") }
            } else {
                Text("Pronto para gravar", style = MaterialTheme.typography.titleMedium)
                Text(
                    "VPN local, sem root: o tráfego dos apps passa pelo Sentinela e vira um .pcap com SHA-256.",
                    style = MaterialTheme.typography.bodySmall, color = p.textoSecundario,
                )
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Forçar TCP", style = MaterialTheme.typography.bodyMedium)
                        Text("Bloqueia QUIC (UDP 443) para o nome do site aparecer no SNI.",
                            style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
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

/** "REC 00:01:23": só ele recompõe a cada segundo. */
@Composable
private fun Relogio(inicioMs: Long) {
    val p = LocalPaleta.current
    val agora by produceState(System.currentTimeMillis()) { while (true) { value = System.currentTimeMillis(); kotlinx.coroutines.delay(1000) } }
    val seg = ((agora - inicioMs) / 1000).coerceAtLeast(0)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(8.dp).background(p.perigo, CircleShape))
        TextoTecnico("  REC  %02d:%02d:%02d".format(seg / 3600, seg / 60 % 60, seg % 60), p.perigo, 14)
    }
}

@Composable
private fun CartaoSessao(
    s: SessaoSalva,
    aoAbrirSessao: (SessaoSalva) -> Unit,
    aoExportar: (SessaoSalva) -> Unit,
    aoApagar: (SessaoSalva) -> Unit,
) {
    val p = LocalPaleta.current
    Cartao(aoTocar = { aoAbrirSessao(s) }) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(dataHora(s.inicioMs), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                when (s.estado) {
                    EstadoSessaoSalva.GRAVANDO -> Selo("gravando", p.perigo)
                    EstadoSessaoSalva.INTERROMPIDA -> Selo("interrompida", p.comportamento)
                    EstadoSessaoSalva.CONCLUIDA -> Selo("concluída", p.primaria)
                }
            }
            val duracao = (s.fimMs - s.inicioMs) / 1000
            Text(
                "${duracao / 60} min ${duracao % 60} s · ${s.pacotes} pacotes · ${Lista.bytes(s.bytes)}",
                style = MaterialTheme.typography.bodySmall, color = p.textoSecundario,
            )
            Row(
                Modifier.fillMaxWidth().background(p.superficie2, RoundedCornerShape(8.dp)).padding(horizontal = 10.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Desenho(Icone.CADEADO, p.primaria, 14.dp)
                TextoTecnico(" SHA-256 ", p.textoSecundario, 11)
                TextoTecnico(s.sha256.take(24).ifEmpty { "—" } + if (s.sha256.length > 24) "…" else "", p.primaria, 12)
            }
            if (s.estado != EstadoSessaoSalva.GRAVANDO) Row { // gravando: o arquivo ainda está aberto
                TextButton(onClick = { aoExportar(s) }) { Text("Exportar") }
                TextButton(onClick = { aoApagar(s) }) { Text("Apagar", color = p.perigo) }
            }
        }
    }
}

@Composable
private fun Aviso(texto: String) {
    val p = LocalPaleta.current
    Text(
        texto,
        modifier = Modifier.fillMaxWidth().background(p.comportamento.copy(alpha = com.brendon978.sentinela.ui.tema.ALFA_AVISO), RoundedCornerShape(8.dp)).padding(10.dp),
        style = MaterialTheme.typography.bodySmall, color = p.texto,
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
    gravando: Boolean = false,
    aoAbrir: (LinhaFluxo) -> Unit,
) {
    val p = LocalPaleta.current
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
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Cabecalho(titulo, aoVoltar) { if (gravando) Selo("● REC", p.perigo) }
        Cartao {
            ResumoSessao(linhas, alertas.size)
        }
        Segmentos(Aba.entries.map { if (it == Aba.ALERTAS && alertas.isNotEmpty()) "${it.titulo} ${alertas.size}" else it.titulo }, aba.ordinal) {
            aba = Aba.entries[it]
        }
        when (aba) {
            Aba.CONEXOES -> {
                OutlinedTextField(
                    value = texto, onValueChange = { texto = it }, singleLine = true,
                    placeholder = { Text("Buscar app, domínio, IP ou porta") }, modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextoTecnico("${filtradas.size} de ${linhas.size}", p.textoSecundario, 12)
                    if (pacote != null) TextButton(onClick = { pacote = null }) { Text("× só $pacote") }
                }
                LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp), contentPadding = PaddingValues(bottom = 16.dp)) {
                    items(filtradas, key = { it.fluxoId }) { l -> LinhaConexao(l) { aoAbrir(l) } }
                }
            }
            Aba.POR_APP -> {
                val resumo = remember(linhas) { PorApp.resumir(linhas) }
                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp), contentPadding = PaddingValues(bottom = 16.dp)) {
                    items(resumo, key = { it.chave }) { r -> LinhaApp(r) { pacote = r.pacote; aba = Aba.CONEXOES } }
                }
            }
            Aba.ALERTAS -> {
                if (alertas.isEmpty()) Text("Nenhum alerta nesta sessão.", style = MaterialTheme.typography.bodyMedium, color = p.textoSecundario)
                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp), contentPadding = PaddingValues(bottom = 16.dp)) {
                    items(alertas) { a ->
                        CartaoAlerta(
                            a,
                            Modifier.combinedClickable(
                                onClick = { linhas.firstOrNull { it.fluxoId == a.fluxoId }?.let(aoAbrir) },
                                onLongClick = { perguntaIgnorar = a },
                            ),
                        )
                    }
                }
            }
        }
    }
}

/** Barra de topo das telas internas: voltar, título e um extra à direita. */
@Composable
fun Cabecalho(titulo: String, aoVoltar: () -> Unit, extra: @Composable () -> Unit = {}) {
    val p = LocalPaleta.current
    Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        BotaoIcone("Voltar", aoVoltar) { Desenho(Icone.SETA, p.texto, 18.dp, Modifier.graphicsLayer(rotationZ = 180f)) }
        Text(
            titulo, style = MaterialTheme.typography.titleLarge, maxLines = 1, overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f).padding(horizontal = 12.dp),
        )
        extra()
    }
}

/** Abas em controle segmentado. */
@Composable
fun Segmentos(rotulos: List<String>, escolhido: Int, aoEscolher: (Int) -> Unit) {
    val p = LocalPaleta.current
    Row(
        Modifier.fillMaxWidth().background(p.superficie2, RoundedCornerShape(14.dp)).padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        rotulos.forEachIndexed { i, r ->
            val ativo = i == escolhido
            Box(
                Modifier.weight(1f).clip(RoundedCornerShape(10.dp))
                    .background(if (ativo) p.primaria else Color.Transparent)
                    .selectable(selected = ativo, role = Role.Tab) { aoEscolher(i) }.padding(vertical = 10.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(r, style = MaterialTheme.typography.labelLarge, color = if (ativo) p.sobrePrimaria else p.textoSecundario, maxLines = 1)
            }
        }
    }
}

@Composable
private fun CartaoAlerta(a: Alerta, modifier: Modifier = Modifier) {
    val p = LocalPaleta.current
    val c = categoria(a.regra)
    val cor = c.cor(p)
    Cartao(modifier, faixa = cor) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Desenho(c.icone, cor, 18.dp)
                Selo(c.titulo.uppercase(), cor, Modifier.padding(start = 8.dp))
                if (a.regra == com.brendon978.sentinela.sessao.Regra.COMPORTAMENTO_ANOMALO) Selo("IA", p.secundaria, Modifier.padding(start = 6.dp))
                Spacer(Modifier.weight(1f))
                TextoTecnico(dataHora(a.quandoUs / 1000), p.textoSecundario, 11)
            }
            Text(a.regra.titulo, style = MaterialTheme.typography.titleMedium)
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconeApp(a.pacote, 24.dp)
                Text(a.rotulo, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(start = 8.dp))
            }
            Text(a.detalhe, style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
        }
    }
}

@Composable
private fun LinhaApp(r: ResumoApp, aoTocar: () -> Unit) {
    val p = LocalPaleta.current
    Cartao(aoTocar = aoTocar) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconeApp(r.pacote)
                Column(Modifier.weight(1f).padding(start = 10.dp)) {
                    Text(r.rotulo, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text("${plural(r.conexoes, "conexão", "conexões")} · ${plural(r.dominios.size, "domínio", "domínios")}", style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
                }
                Bytes(r.bytesEnviados, r.bytesRecebidos)
            }
            BarraVolume(fracaoVolume(r.bytesEnviados + r.bytesRecebidos), p.secundaria)
            if (r.rastreadores.isNotEmpty()) Row(verticalAlignment = Alignment.CenterVertically) {
                Desenho(Icone.OLHO, p.privacidade, 14.dp)
                Text(
                    " ${plural(r.rastreadores.size, "rastreador", "rastreadores")}: ${r.rastreadores.joinToString(", ")}",
                    style = MaterialTheme.typography.bodySmall, color = p.privacidade, maxLines = 2, overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun LinhaConexao(l: LinhaFluxo, aoTocar: () -> Unit) {
    val p = LocalPaleta.current
    val aberta = l.fimUs == null
    Cartao(preenchimento = 10.dp, aoTocar = aoTocar) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconeApp(l.pacoteApp, 30.dp)
                Column(Modifier.weight(1f).padding(horizontal = 10.dp)) {
                    Text(
                        l.dominio ?: l.ipDestino, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold,
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                        color = if (aberta) p.texto else p.textoSecundario,
                    )
                    // aberta/encerrada também em texto (não só pela cor) e o app pelo nome
                    Text(
                        l.rotulo + if (aberta) "" else " · encerrada", style = MaterialTheme.typography.bodySmall,
                        color = p.textoSecundario, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                }
                Bytes(l.bytesEnviados, l.bytesRecebidos)
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (l.dominio != null) SeloOrigem(l.origemDominio, Modifier.padding(end = 6.dp))
                TextoTecnico("${l.nomeProtocolo} ${l.ipDestino}:${l.portaDestino}", p.textoSecundario, 11)
            }
            BarraVolume(fracaoVolume(l.bytesEnviados + l.bytesRecebidos), if (aberta) p.primaria else p.borda)
        }
    }
}

@Composable
private fun Bytes(enviados: Long, recebidos: Long) {
    val p = LocalPaleta.current
    Column(horizontalAlignment = Alignment.End) {
        TextoTecnico("↑ ${Lista.bytes(enviados)}", p.secundaria, 12)
        TextoTecnico("↓ ${Lista.bytes(recebidos)}", p.primaria, 12)
    }
}

@Composable
fun IconeApp(pacote: String?, tamanho: androidx.compose.ui.unit.Dp = 36.dp) {
    val ctx = LocalContext.current
    val bitmap by produceState(pacote?.let { IconesDeApp.cache.get(it) }, pacote) {
        if (pacote != null && value == null) value = withContext(Dispatchers.IO) { IconesDeApp.carregar(ctx, pacote) }
    }
    val b = bitmap
    if (b != null) Image(b, contentDescription = null, modifier = Modifier.size(tamanho))
    else Box(
        Modifier.size(tamanho).background(LocalPaleta.current.superficie2, RoundedCornerShape(10.dp)),
        contentAlignment = Alignment.Center,
    ) { Desenho(Icone.INTERROGACAO, LocalPaleta.current.textoSecundario, tamanho / 2) } // sem ícone: neutro, não a marca do Sentinela
}

/** Ícones dos apps, lidos fora da thread principal e guardados (muitas linhas são do mesmo app). */
private object IconesDeApp {
    val cache = android.util.LruCache<String, androidx.compose.ui.graphics.ImageBitmap>(64)
    fun carregar(ctx: android.content.Context, pacote: String) = runCatching {
        ctx.packageManager.getApplicationIcon(pacote).toBitmap(96, 96).asImageBitmap()
    }.getOrNull()?.also { cache.put(pacote, it) }
}

// ---------------------------------------------------------------- detalhe (Tarefa 12 acrescenta os pacotes)

@Composable
fun TelaConexao(l: LinhaFluxo, aoVoltar: () -> Unit, extra: @Composable () -> Unit = {}) {
    val p = LocalPaleta.current
    LazyColumn(
        Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item { Cabecalho("Conexão", aoVoltar) { if (l.fimUs == null) Selo("aberta", p.primaria) else Selo("encerrada", p.textoSecundario) } }
        item {
            Cartao {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconeApp(l.pacoteApp, 44.dp)
                        Column(Modifier.weight(1f).padding(start = 12.dp)) {
                            Text(l.rotulo, style = MaterialTheme.typography.titleMedium)
                            TextoTecnico(l.pacoteApp ?: "uid ${l.uid}", p.textoSecundario, 11)
                        }
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            l.dominio ?: l.ipDestino, style = MaterialTheme.typography.titleLarge,
                            maxLines = 2, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, false),
                        )
                        if (l.dominio != null) SeloOrigem(l.origemDominio, Modifier.padding(start = 8.dp))
                    }
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                        ResumoNumero(Lista.bytes(l.bytesEnviados), "enviados ↑", p.secundaria)
                        ResumoNumero(Lista.bytes(l.bytesRecebidos), "recebidos ↓", p.primaria)
                        ResumoNumero("${l.pacotes}", "pacotes")
                    }
                    val campos = listOf(
                        "Protocolo" to "${l.nomeProtocolo} / IPv${l.versaoIp}",
                        "Origem" to "${l.ipOrigem}:${l.portaOrigem}",
                        "Destino" to "${l.ipDestino}:${l.portaDestino}",
                        "Início" to dataHora(l.inicioUs / 1000),
                        "Fim" to (l.fimUs?.let { dataHora(it / 1000) } ?: "—"),
                    )
                    Column(
                        Modifier.fillMaxWidth().background(p.superficie2, RoundedCornerShape(10.dp)).padding(10.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        campos.forEach { (k, v) ->
                            Row {
                                Text(k, Modifier.width(88.dp), style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
                                TextoTecnico(v, p.texto, 12)
                            }
                        }
                    }
                }
            }
        }
        item { extra() }
    }
}

// ---------------------------------------------------------------- pacotes de uma conexão (Tarefa 12)

private val formatoHora = SimpleDateFormat("HH:mm:ss.SSS", Locale.forLanguageTag("pt-BR"))

/** Cor de cada camada, como no Wireshark: rede, transporte, aplicação e dados brutos. */
private fun corDaCamada(nome: String, p: com.brendon978.sentinela.ui.tema.Paleta) = when {
    nome.startsWith("IPv") -> p.rede
    nome == "TCP" || nome == "UDP" -> p.primaria
    nome.startsWith("Dados") -> p.textoSecundario
    else -> p.privacidade // DNS, TLS
}

@Composable
fun ListaPacotes(pacotes: List<Pair<Pacote, String>>?) {
    val p = LocalPaleta.current
    var aberto by remember { mutableStateOf(-1) }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        RotuloSecao("Pacotes")
        when {
            pacotes == null -> Text("Carregando…", style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
            pacotes.isEmpty() -> Text("Nenhum pacote no arquivo da sessão.", style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
        }
        pacotes?.forEachIndexed { i, (pacote, arvore) ->
            val resumo = remember(arvore) { arvore.lineSequence().firstOrNull()?.removePrefix("Resumo: ").orEmpty() }
            val cor = if (pacote.doApp) p.secundaria else p.primaria
            Cartao(preenchimento = 10.dp, faixa = cor, aoTocar = { aberto = if (aberto == i) -1 else i }) {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        TextoTecnico(if (pacote.doApp) "↑ saiu" else "↓ chegou", cor, 12)
                        TextoTecnico("  ${formatoHora.format(Date(pacote.quandoUs / 1000))}", p.textoSecundario, 12, Modifier.weight(1f))
                        TextoTecnico("${pacote.bytes.size} B", p.texto, 12)
                    }
                    Text(resumo, style = TextoMonoPequeno, color = p.texto)
                    if (aberto == i) Camadas.separar(arvore).camadas.forEach { c -> BlocoCamada(c, corDaCamada(c.nome, p)) }
                }
            }
        }
        if (pacotes != null && pacotes.size >= MAX_PACOTES_TELA)
            Text("Mostrando os primeiros $MAX_PACOTES_TELA pacotes.", style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
    }
}

private val TextoMonoPequeno = com.brendon978.sentinela.ui.tema.TextoMono.copy(fontSize = 11.sp)

@Composable
private fun BlocoCamada(c: Camada, cor: Color) {
    val p = LocalPaleta.current
    Column(
        Modifier.fillMaxWidth().background(cor.copy(alpha = com.brendon978.sentinela.ui.tema.ALFA_CAMADA), RoundedCornerShape(10.dp))
            .border(1.dp, cor.copy(alpha = 0.35f), RoundedCornerShape(10.dp)).padding(10.dp),
        verticalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        Text(c.nome, style = MaterialTheme.typography.labelLarge, color = cor)
        c.campos.forEach { (k, v) ->
            Row {
                Text(k, Modifier.width(156.dp), style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
                Text(v, style = TextoMonoPequeno, color = p.texto)
            }
        }
        if (c.hex.isNotEmpty()) Text(
            c.hex.joinToString("\n"), style = TextoMonoPequeno.copy(fontSize = 10.sp), color = p.texto, softWrap = false,
            modifier = Modifier.horizontalScroll(rememberScrollState()),
        )
    }
}

const val MAX_PACOTES_TELA = 200

// ---------------------------------------------------------------- mapa da rede (v1.1)

private val com.brendon978.sentinela.rede.TipoAparelho.icone: Icone get() = when (this) {
    com.brendon978.sentinela.rede.TipoAparelho.ROTEADOR -> Icone.ROTEADOR
    com.brendon978.sentinela.rede.TipoAparelho.TV_OU_STREAMING -> Icone.TV
    com.brendon978.sentinela.rede.TipoAparelho.IMPRESSORA -> Icone.IMPRESSORA
    com.brendon978.sentinela.rede.TipoAparelho.CAMERA -> Icone.CAMERA
    com.brendon978.sentinela.rede.TipoAparelho.APPLE -> Icone.MACA
    com.brendon978.sentinela.rede.TipoAparelho.COMPUTADOR_OU_NAS -> Icone.COMPUTADOR
    com.brendon978.sentinela.rede.TipoAparelho.DESCONHECIDO -> Icone.INTERROGACAO
}

@Composable
fun TelaRede(
    aparelhos: List<com.brendon978.sentinela.rede.Aparelho>?,
    status: String?,
    varrendo: Boolean,
    aoVoltar: () -> Unit,
    aoMapear: () -> Unit,
) {
    val p = LocalPaleta.current
    var confirmando by remember { mutableStateOf(false) }
    if (confirmando) {
        AlertDialog(
            onDismissRequest = { confirmando = false },
            icon = { Desenho(Icone.ESCUDO, p.comportamento, 28.dp) },
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
    LazyColumn(
        Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item { Cabecalho("Mapa da rede", aoVoltar) }
        item {
            Cartao {
                Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Box(Modifier.size(120.dp), contentAlignment = Alignment.Center) {
                        Pulso(p.secundaria, varrendo, Modifier.fillMaxSize())
                        Desenho(Icone.RADAR, p.secundaria, 44.dp)
                    }
                    Text(
                        "Aparelhos do Wi-Fi atual, pelo que eles anunciam (mDNS, SSDP) e por algumas portas abertas.",
                        style = MaterialTheme.typography.bodySmall, color = p.textoSecundario,
                    )
                    Button(onClick = { confirmando = true }, enabled = !varrendo, modifier = Modifier.fillMaxWidth()) {
                        Text(if (varrendo) "Mapeando…" else "Mapear")
                    }
                    status?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = p.texto) }
                }
            }
        }
        items(aparelhos.orEmpty(), key = { it.ip }) { a ->
            val tipo = com.brendon978.sentinela.rede.Classificador.tipo(a)
            Cartao {
                Row(verticalAlignment = Alignment.Top) {
                    Box(
                        Modifier.size(44.dp).background(p.superficie2, RoundedCornerShape(12.dp)),
                        contentAlignment = Alignment.Center,
                    ) { Desenho(tipo.icone, if (a.gateway) p.primaria else p.secundaria, 26.dp) }
                    Column(Modifier.weight(1f).padding(start = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(tipo.nome, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                            TextoTecnico(a.ip, p.texto, 13)
                        }
                        if (a.nomes.isNotEmpty()) Text(a.nomes.joinToString(", "), style = MaterialTheme.typography.bodyMedium)
                        if (a.servicos.isNotEmpty())
                            Text("Anuncia: ${a.servicos.joinToString(", ")}", style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
                        if (a.portas.isNotEmpty()) FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            a.portas.sorted().forEach { Selo("$it", p.secundaria) }
                        }
                        a.servidor?.let { Text("UPnP: $it", style = MaterialTheme.typography.bodySmall, color = p.textoSecundario) }
                    }
                }
            }
        }
    }
}

/** Formatos de exportação além da captura (.pcap + .sha256, que é o null). */
enum class Formato { CSV, CSV_ANONIMO, PDF }

/** Escolha do formato de exportação de uma sessão salva. */
@Composable
fun DialogoExportacao(aoEscolher: (Formato?) -> Unit, aoCancelar: () -> Unit) {
    val p = LocalPaleta.current
    val opcoes = listOf(
        Triple(Icone.CADEADO, "Captura (.pcap + .sha256)", "A evidência original; abre no Wireshark e confere com sha256sum") to null,
        Triple(Icone.DOWNLOAD, "Conexões em CSV", "Uma linha por conexão, para planilha ou Python") to Formato.CSV,
        Triple(Icone.ESCUDO, "CSV anonimizado", "IPs e domínios trocados por pseudônimos (HMAC)") to Formato.CSV_ANONIMO,
        Triple(Icone.DOWNLOAD, "Relatório em PDF", "Hash, cadeia de custódia, apps, alertas e domínios") to Formato.PDF,
    )
    AlertDialog(
        onDismissRequest = aoCancelar,
        title = { Text("Exportar sessão") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                opcoes.forEach { (o, f) ->
                    Row(
                        Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(p.superficie)
                            .clickable { aoEscolher(f) }.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Desenho(o.first, p.primaria, 22.dp)
                        Column(Modifier.padding(start = 12.dp)) {
                            Text(o.second, style = MaterialTheme.typography.titleMedium)
                            Text(o.third, style = MaterialTheme.typography.bodySmall, color = p.textoSecundario)
                        }
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = aoCancelar) { Text("Cancelar") } },
    )
}
