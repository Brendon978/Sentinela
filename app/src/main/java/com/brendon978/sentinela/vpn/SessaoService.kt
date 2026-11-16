package com.brendon978.sentinela.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.Network
import android.net.NetworkRequest
import android.net.VpnService
import android.os.PowerManager
import android.util.Log
import com.brendon978.sentinela.MainActivity
import com.brendon978.sentinela.dados.Banco
import com.brendon978.sentinela.motor.Eventos
import com.brendon978.sentinela.motor.Ip
import com.brendon978.sentinela.sessao.Alertas
import com.brendon978.sentinela.motor.Motor
import com.brendon978.sentinela.sessao.SessaoAtual
import com.brendon978.sentinela.sessao.SessaoFinal
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.time.ZoneId

/**
 * A VPN local da sessão de captura. Liga só quando o usuário manda gravar e desliga ao parar
 * (o Android só aceita uma VPN por vez: enquanto grava, o Tailscale fica de fora).
 *
 * Endereços do tun: 10.111.0.1/32 e fd00:5e:1::1/128, rota padrão IPv4 e IPv6, DNS virtual
 * 10.111.0.53 e fd00:5e:1::53 (o motor repassa ao DNS real da rede). O próprio app fica fora
 * da VPN, para os sockets do motor não voltarem para o tun.
 */
class SessaoService : VpnService() {
    companion object {
        private const val TAG = "Sentinela"
        const val ACAO_INICIAR = "com.brendon978.sentinela.INICIAR"
        const val ACAO_PARAR = "com.brendon978.sentinela.PARAR"
        const val EXTRA_FORCAR_TCP = "forcarTcp"
        private const val CANAL = "captura"
        private const val NOTIFICACAO = 1
        private const val CANAL_ALERTAS = "alertas"
        private const val NOTIFICACAO_ALERTAS = 2

        fun iniciar(ctx: Context, forcarTcp: Boolean) {
            ctx.startForegroundService(
                Intent(ctx, SessaoService::class.java).setAction(ACAO_INICIAR).putExtra(EXTRA_FORCAR_TCP, forcarTcp)
            )
        }

        fun parar(ctx: Context) {
            ctx.startService(Intent(ctx, SessaoService::class.java).setAction(ACAO_PARAR))
        }
    }

    private val escopo = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val cadeado = Any()
    private var handle = 0L
    private var threadMotor: Thread? = null
    private var leitura: Job? = null
    private var receptorTela: BroadcastReceiver? = null
    /** Uma parada em andamento: nada de iniciar outra sessão nem parar de novo até ela acabar. */
    private var parando = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACAO_INICIAR -> {
                emPrimeiroPlano()
                val ocupado = synchronized(cadeado) { handle != 0L || parando }
                if (!ocupado) iniciarCaptura(intent.getBooleanExtra(EXTRA_FORCAR_TCP, false))
            }
            ACAO_PARAR -> escopo.launch { pararCaptura() } // fora da thread principal: join e hash demoram
        }
        return START_NOT_STICKY
    }

    /** O usuário revogou a VPN nas configurações, ou outro app de VPN assumiu. */
    override fun onRevoke() {
        escopo.launch { pararCaptura() }
    }

    override fun onDestroy() {
        // Sem esperar: o serviço está morrendo. A parada segue numa thread própria.
        Thread({ pararCaptura() }, "sentinela-parar").start()
        super.onDestroy()
    }

    // ------------------------------------------------------------------ início

    private fun iniciarCaptura(forcarTcp: Boolean) {
        val cm = getSystemService(ConnectivityManager::class.java)
        val rede = redeReal(cm)
        val lp: LinkProperties? = rede?.let { cm.getLinkProperties(it) }
        val dnsReais = dnsDe(lp)
        if (dnsReais.isEmpty()) return falha("Sem rede: não achei servidor DNS para usar.")

        val inicioMs = System.currentTimeMillis()
        val pasta = File(filesDir, "sessoes").apply { mkdirs() }
        val pcap = File(pasta, "sessao-$inicioMs.pcap")

        // IPv6 só entra no tun se a rede de verdade tem rota IPv6 global. Sem isso, cada
        // tentativa IPv6 dos apps viraria uma conexão recusada na lista (o motor não teria
        // por onde sair) antes de o app cair para IPv4.
        val temIpv6 = lp?.routes.orEmpty().any {
            it.isDefaultRoute && it.destination.address is Inet6Address
        } && lp?.linkAddresses.orEmpty().any {
            it.address is Inet6Address && !it.address.isLinkLocalAddress
        }
        val pfd = try {
            Builder().apply {
                setSession("Sentinela")
                setMtu(1500)
                addAddress(Tun.ENDERECO_V4, 32)
                addRoute("0.0.0.0", 0)
                addDnsServer(Tun.DNS_VIRTUAIS[0])
                if (temIpv6) {
                    addAddress(Tun.ENDERECO_V6, 128)
                    addRoute("::", 0)
                    addDnsServer(Tun.DNS_VIRTUAIS[1])
                }
                addDisallowedApplication(packageName)
            }.establish()
        } catch (e: Exception) {
            Log.e(TAG, "falha ao montar a VPN", e)
            null
        } ?: return falha("O Android não autorizou a VPN.")

        val h = Motor.criar(pcap.absolutePath, Tun.DNS_VIRTUAIS, dnsReais.toTypedArray(), forcarTcp)
        if (h == 0L) {
            pfd.close()
            return falha("O motor não iniciou (não abriu o arquivo da captura).")
        }

        val dono = DonoDaConexao(
            { proto, local, remoto -> cm.getConnectionOwnerUid(proto, local, remoto) },
            object : FontePacotes {
                override fun pacotes(uid: Int) = packageManager.getPackagesForUid(uid)?.toList().orEmpty()
                override fun rotulo(pacote: String) = runCatching {
                    packageManager.getApplicationLabel(packageManager.getApplicationInfo(pacote, PackageManager.ApplicationInfoFlags.of(0))).toString()
                }.getOrNull()
            },
            Tun.DNS_VIRTUAIS.map { Ip(if (':' in it) 6 else 4, InetAddress.getByName(it).address) }.toSet(),
        )
        val banco = Banco(this).also { this.banco = it }
        val vistos = runCatching { banco.dominiosVistos() }.getOrDefault(emptySet())
        val sessaoId = banco.abrirSessao(inicioMs, pcap.absolutePath).also { SessaoFinal.usando(it) }
        val excecoes = runCatching { banco.excecoes() }.getOrDefault(emptySet())
        val contexto = Alertas.Contexto(ZoneId.systemDefault(), vistos, Tun.DNS_VIRTUAIS.toSet() + dnsReais, excecoes)
        // Estado real da tela no início (não o que sobrou da sessão anterior).
        EstadoTela.ligada = getSystemService(PowerManager::class.java).isInteractive
        SessaoAtual.iniciar(
            sessaoId, inicioMs, pcap.absolutePath, lp?.isPrivateDnsActive == true, contexto, { EstadoTela.ligada }, dono::dono,
        )
        observarTela()

        // A leitura nasce antes da thread do motor: se o motor falhar na hora, a parada já a acha.
        leitura = escopo.launch {
            var ultimaGravacao = System.currentTimeMillis()
            var gravado: com.brendon978.sentinela.sessao.EstadoSessao? = null
            while (isActive) {
                delay(100) // curto: o dono da conexão só é achado enquanto ela existe
                drenar()
                val agora = System.currentTimeMillis()
                if (agora - ultimaGravacao >= 5000) { // a cada 5 s a lista vai para o banco
                    ultimaGravacao = agora
                    val e = SessaoAtual.estado.value
                    if (e !== gravado) // nada mudou em 5 s (o estado é imutável): não regrava
                        runCatching { banco.gravarParcial(sessaoId, e.linhas, e.alertas, agora, e.eventosPerdidos) }
                            .onSuccess { gravado = e }
                            .onFailure { Log.e(TAG, "falha ao gravar a sessão em andamento", it) }
                }
            }
        }
        observarRede(cm)
        // IA: treina o normal de cada app com as sessões anteriores, sem segurar o início
        treino = escopo.launch { // Default: o treino é conta; só a leitura do banco é E/S
            runCatching {
                val historico = withContext(Dispatchers.IO) { banco.historico() }
                SessaoAtual.definirLinhaDeBase(com.brendon978.sentinela.ia.LinhaDeBase.treinar(historico, ZoneId.systemDefault()))
            }.onFailure { Log.w(TAG, "IA sem linha de base", it) }
        }
        synchronized(cadeado) {
            handle = h
            alertasAvisados = 0
            val fd = pfd.detachFd() // daqui em diante o motor é o dono do fd
            threadMotor = Thread({
                val r = Motor.rodar(h, fd)
                if (r != 0) {
                    Log.w(TAG, "motor parou com erro ($r); encerrando a sessão")
                    escopo.launch { pararCaptura() }
                }
            }, "sentinela-motor").also { it.start() }
        }
    }

    private var observadorRede: ConnectivityManager.NetworkCallback? = null
    private var banco: Banco? = null
    private var treino: Job? = null

    /** A rede real mudou (ex.: Wi-Fi -> dados): o motor passa a usar o DNS da rede nova. */
    private fun observarRede(cm: ConnectivityManager) {
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(rede: Network, lp: LinkProperties) = atualizar()
            override fun onLost(rede: Network) = atualizar()
            private fun atualizar() {
                val real = redeReal(cm) ?: return
                val dns = dnsDe(cm.getLinkProperties(real))
                if (dns.isEmpty()) return
                synchronized(cadeado) { if (handle != 0L) Motor.trocarDns(handle, dns.toTypedArray()) }
                SessaoAtual.trocarDnsNormais(Tun.DNS_VIRTUAIS.toSet() + dns)
            }
        }
        val pedido = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        runCatching { cm.registerNetworkCallback(pedido, cb) }.onSuccess { observadorRede = cb }
    }

    /** IPv4 primeiro, depois IPv6 global; link-local (fe80::%wlan0) não serve sem a interface. */
    private fun dnsDe(lp: LinkProperties?): List<String> = lp?.dnsServers.orEmpty()
        .filterNot { it.isLinkLocalAddress }
        .sortedBy { if (it is Inet4Address) 0 else 1 }
        .mapNotNull { it.hostAddress }

    /**
     * A rede de verdade, mesmo se a ativa for outra VPN (ex.: Tailscale): é por ela que os
     * sockets do motor vão sair depois que a nossa VPN derrubar a outra. Preferência: a ativa
     * (se não for VPN); senão Wi-Fi validado; senão qualquer validada; senão qualquer com internet.
     */
    private fun redeReal(cm: ConnectivityManager): Network? {
        fun caps(n: Network) = cm.getNetworkCapabilities(n)
        cm.activeNetwork?.let { if (caps(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true) return it }
        val reais = cm.allNetworks.filter {
            val c = caps(it)
            c != null && c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        val validadas = reais.filter { caps(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true }
        return validadas.firstOrNull { caps(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true }
            ?: validadas.firstOrNull() ?: reais.firstOrNull()
    }

    /** Lê a fila inteira (o JNI entrega até 256 KiB por chamada). */
    private fun drenarTudo(h: Long) {
        while (true) {
            val bytes = Motor.eventos(h)
            if (bytes.isEmpty()) return
            val lote = Eventos.decodificar(bytes)
            lote.erro?.let { Log.e(TAG, "lote de eventos com erro: $it") }
            SessaoAtual.aplicar(lote.eventos)
        }
    }

    private var alertasAvisados = 0

    private fun drenar() = synchronized(cadeado) {
        val h = handle
        if (h == 0L) return
        drenarTudo(h)
        val n = SessaoAtual.estado.value.alertas.size
        if (n > alertasAvisados) {
            alertasAvisados = n
            avisarAlertas(n)
        }
    }

    /** Uma notificação só, atualizada com o total de alertas da sessão. */
    private fun avisarAlertas(n: Int) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CANAL_ALERTAS, "Alertas", NotificationManager.IMPORTANCE_DEFAULT))
        val abrir = PendingIntent.getActivity(
            this, 1, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val ultimo = SessaoAtual.estado.value.alertas.lastOrNull()
        nm.notify(
            NOTIFICACAO_ALERTAS,
            Notification.Builder(this, CANAL_ALERTAS)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(if (n == 1) "1 alerta nesta sessão" else "$n alertas nesta sessão")
                .setContentText(ultimo?.let { "${it.rotulo}: ${it.regra.titulo}" } ?: "")
                .setContentIntent(abrir)
                .setOnlyAlertOnce(true)
                .build(),
        )
    }

    // ------------------------------------------------------------------ fim

    private fun pararCaptura() {
        // Toma o motor de uma vez: quem chegar depois (revogação + erro do motor ao mesmo
        // tempo, por exemplo) não acha nada para parar e não libera o motor duas vezes.
        val h: Long
        val t: Thread?
        synchronized(cadeado) {
            h = handle
            t = threadMotor
            if (h == 0L || parando) {
                if (!parando) encerrarServico()
                return
            }
            parando = true
            handle = 0L
            threadMotor = null
        }
        try {
            // espera a leitura acabar: a gravação de 5 s não pode correr junto com o fechamento;
            // o treino da IA desta sessão também para (não pode cair na próxima)
            runBlocking { leitura?.cancelAndJoin(); treino?.cancelAndJoin() }
            Motor.parar(h)
            t?.join(10_000)
            if (t?.isAlive == true) {
                // Contrato: destruir só depois que rodar voltou. Vaza o motor em vez de quebrar.
                Log.e(TAG, "o motor não parou em 10 s; deixando-o sem destruir")
                SessaoAtual.falhou("O motor não respondeu ao parar.")
            } else {
                Motor.encerrar(h) // emite os fins dos fluxos abertos e fecha o pcap
                drenarTudo(h)
                Motor.destruir(h)
                SessaoFinal.concluir(this, SessaoAtual.terminar())
            }
            receptorTela?.let { runCatching { unregisterReceiver(it) } }
            receptorTela = null
            observadorRede?.let { cb ->
                runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(cb) }
            }
            observadorRede = null
            banco?.close()
            banco = null
        } finally {
            synchronized(cadeado) { parando = false }
            encerrarServico()
        }
    }

    private fun encerrarServico() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun falha(msg: String) {
        Log.e(TAG, msg)
        SessaoAtual.falhou(msg)
        encerrarServico()
    }

    // ------------------------------------------------------------------ tela e notificação

    private fun observarTela() {
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                EstadoTela.ligada = i.action == Intent.ACTION_SCREEN_ON
            }
        }
        registerReceiver(r, IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        })
        receptorTela = r
    }

    private fun emPrimeiroPlano() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CANAL, "Captura", NotificationManager.IMPORTANCE_LOW))
        val parar = PendingIntent.getService(
            this, 0, Intent(this, SessaoService::class.java).setAction(ACAO_PARAR), PendingIntent.FLAG_IMMUTABLE,
        )
        val n: Notification = Notification.Builder(this, CANAL)
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentTitle("Sentinela gravando")
            .setContentText("Capturando o tráfego deste celular")
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Parar", parar).build())
            .build()
        // VPN configurada pelo usuário pode usar systemExempted; se o sistema recusar, specialUse.
        try {
            startForeground(NOTIFICACAO, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } catch (e: Exception) {
            Log.w(TAG, "systemExempted recusado; usando specialUse", e)
            startForeground(NOTIFICACAO, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        }
    }
}

/** Tela ligada ou desligada, para a regra de alerta "tela desligada" (Tarefa 14). */
object EstadoTela {
    @Volatile var ligada: Boolean = true
}
