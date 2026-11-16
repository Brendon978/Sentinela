package com.brendon978.sentinela.sessao

import com.brendon978.sentinela.vpn.App
import java.util.Locale

data class Rastreador(val dominio: String, val empresa: String, val categoria: String)

/**
 * Lista própria e curta de domínios de rastreamento, anúncio e telemetria muito conhecidos
 * (fonte e critérios em docs/rastreadores.md). Casamento por sufixo de domínio: `ad.x.com`
 * casa com `x.com`, mas `notx.com` não.
 */
object Rastreadores {
    private const val ANUNCIO = "anúncios"
    private const val ANALISE = "análise de uso"
    private const val ATRIBUICAO = "atribuição de instalação"
    private const val DIAGNOSTICO = "diagnóstico de falhas"
    private const val ENGAJAMENTO = "notificações e engajamento"

    private val lista = listOf(
        Rastreador("doubleclick.net", "Google Ads", ANUNCIO),
        Rastreador("googlesyndication.com", "Google Ads", ANUNCIO),
        Rastreador("googleadservices.com", "Google Ads", ANUNCIO),
        Rastreador("adservice.google.com", "Google Ads", ANUNCIO),
        Rastreador("google-analytics.com", "Google Analytics", ANALISE),
        Rastreador("app-measurement.com", "Google/Firebase Analytics", ANALISE),
        Rastreador("crashlytics.com", "Firebase Crashlytics", DIAGNOSTICO),
        Rastreador("an.facebook.com", "Meta Audience Network", ANUNCIO),
        Rastreador("connect.facebook.net", "Meta Pixel", ANALISE),
        Rastreador("appsflyer.com", "AppsFlyer", ATRIBUICAO),
        Rastreador("appsflyersdk.com", "AppsFlyer", ATRIBUICAO),
        Rastreador("adjust.com", "Adjust", ATRIBUICAO),
        Rastreador("adjust.io", "Adjust", ATRIBUICAO),
        Rastreador("branch.io", "Branch", ATRIBUICAO),
        Rastreador("kochava.com", "Kochava", ATRIBUICAO),
        Rastreador("singular.net", "Singular", ATRIBUICAO),
        Rastreador("onesignal.com", "OneSignal", ENGAJAMENTO),
        Rastreador("braze.com", "Braze", ENGAJAMENTO),
        Rastreador("appboy.com", "Braze", ENGAJAMENTO),
        Rastreador("clevertap-prod.com", "CleverTap", ENGAJAMENTO),
        Rastreador("moengage.com", "MoEngage", ENGAJAMENTO),
        Rastreador("amplitude.com", "Amplitude", ANALISE),
        Rastreador("mixpanel.com", "Mixpanel", ANALISE),
        Rastreador("segment.io", "Segment", ANALISE),
        Rastreador("hotjar.com", "Hotjar", ANALISE),
        Rastreador("clarity.ms", "Microsoft Clarity", ANALISE),
        Rastreador("scorecardresearch.com", "comScore", ANALISE),
        Rastreador("quantserve.com", "Quantcast", ANALISE),
        Rastreador("appmetrica.yandex.net", "Yandex AppMetrica", ANALISE),
        Rastreador("analytics.tiktok.com", "TikTok", ANALISE),
        Rastreador("pangle.io", "Pangle (ByteDance)", ANUNCIO),
        Rastreador("pangleglobal.com", "Pangle (ByteDance)", ANUNCIO),
        Rastreador("unityads.unity3d.com", "Unity Ads", ANUNCIO),
        Rastreador("applovin.com", "AppLovin", ANUNCIO),
        Rastreador("applvn.com", "AppLovin", ANUNCIO),
        Rastreador("supersonicads.com", "ironSource", ANUNCIO),
        Rastreador("ironsrc.mobi", "ironSource", ANUNCIO),
        Rastreador("inmobi.com", "InMobi", ANUNCIO),
        Rastreador("vungle.com", "Vungle/Liftoff", ANUNCIO),
        Rastreador("chartboost.com", "Chartboost", ANUNCIO),
        Rastreador("adcolony.com", "AdColony", ANUNCIO),
        Rastreador("mintegral.com", "Mintegral", ANUNCIO),
        Rastreador("startappservice.com", "Start.io", ANUNCIO),
        Rastreador("smaato.net", "Smaato", ANUNCIO),
        Rastreador("moatads.com", "Moat (Oracle)", ANUNCIO),
        Rastreador("taboola.com", "Taboola", ANUNCIO),
        Rastreador("outbrain.com", "Outbrain", ANUNCIO),
        Rastreador("criteo.com", "Criteo", ANUNCIO),
        Rastreador("criteo.net", "Criteo", ANUNCIO),
        Rastreador("adnxs.com", "Xandr (Microsoft)", ANUNCIO),
        Rastreador("rubiconproject.com", "Magnite", ANUNCIO),
        Rastreador("pubmatic.com", "PubMatic", ANUNCIO),
        Rastreador("openx.net", "OpenX", ANUNCIO),
        Rastreador("adform.net", "Adform", ANUNCIO),
        Rastreador("amazon-adsystem.com", "Amazon Ads", ANUNCIO),
        Rastreador("ads-twitter.com", "X/Twitter Ads", ANUNCIO),
        Rastreador("tr.snapchat.com", "Snap (pixel)", ANALISE),
        Rastreador("sentry.io", "Sentry", DIAGNOSTICO),
        Rastreador("bugsnag.com", "Bugsnag", DIAGNOSTICO),
        Rastreador("nr-data.net", "New Relic", DIAGNOSTICO),
    )

    private val porDominio = lista.associateBy { it.dominio }

    fun de(dominio: String?): Rastreador? {
        var d = dominio?.lowercase(Locale.ROOT)?.trimEnd('.') ?: return null
        while (true) {
            porDominio[d]?.let { return it }
            val ponto = d.indexOf('.')
            if (ponto < 0) return null
            d = d.substring(ponto + 1) // sobe um nível: ad.x.com -> x.com
        }
    }
}

data class ResumoApp(
    val pacote: String?,
    val rotulo: String,
    val conexoes: Int,
    val bytesEnviados: Long,
    val bytesRecebidos: Long,
    val dominios: Set<String>,
    val rastreadores: Set<String>,
)

object PorApp {
    /** Agrupa por app (pacote; sem pacote = sistema/desconhecido), do que mais trafegou ao que menos. */
    fun resumir(linhas: List<LinhaFluxo>): List<ResumoApp> =
        linhas.groupBy { it.pacoteApp }.map { (pacote, ls) ->
            val dominios = ls.mapNotNull { it.dominio }.toSet()
            ResumoApp(
                pacote, ls.firstNotNullOfOrNull { it.rotuloApp } ?: App.SEM_APP, ls.size,
                ls.sumOf { it.bytesEnviados }, ls.sumOf { it.bytesRecebidos },
                dominios, dominios.filter { Rastreadores.de(it) != null }.toSet(),
            )
        }.sortedByDescending { it.bytesEnviados + it.bytesRecebidos }
}
