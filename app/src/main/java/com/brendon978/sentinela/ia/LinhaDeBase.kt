package com.brendon978.sentinela.ia

import com.brendon978.sentinela.sessao.LinhaFluxo
import java.time.Instant
import java.time.ZoneId
import kotlin.math.PI
import kotlin.math.ceil
import kotlin.math.cos
import kotlin.math.ln
import kotlin.math.pow
import kotlin.math.sin
import kotlin.random.Random

/**
 * Isolation Forest (Liu, Ting e Zhou, 2008): ponto anômalo é o que se isola com poucos cortes
 * aleatórios. Cada árvore corta uma subamostra por um atributo e um valor sorteados até isolar os
 * pontos; a nota vem do tamanho médio do caminho até o ponto nas árvores. Nota perto de 1 =
 * anômalo; bem abaixo de 0,5 = normal. Aula 10, seção 4.
 *
 * Além da nota, cada árvore "vota" no atributo do último corte que o ponto atravessou: o mais
 * votado é o motivo mostrado ao usuário (vem do próprio modelo, não de uma regra à parte).
 */
class IsolationForest private constructor(private val arvores: List<No>, private val amostra: Int) {
    private sealed interface No
    private class Folha(val tamanho: Int) : No
    private class Corte(val atributo: Int, val valor: Double, val esq: No, val dir: No) : No

    /** Nota de anomalia em (0, 1]. */
    fun nota(x: DoubleArray): Double = notaComMotivo(x).first

    /** Nota e o atributo mais votado pelas árvores (-1 se nenhuma árvore cortou). */
    fun notaComMotivo(x: DoubleArray): Pair<Double, Int> {
        val votos = IntArray(x.size)
        var soma = 0.0
        for (a in arvores) {
            var no = a
            var prof = 0
            var ultimo = -1
            while (no is Corte) {
                ultimo = no.atributo
                no = if (x[no.atributo] < no.valor) no.esq else no.dir
                prof++
            }
            soma += prof + c((no as Folha).tamanho)
            if (ultimo >= 0) votos[ultimo]++
        }
        val motivo = votos.indices.maxBy { votos[it] }.takeIf { votos[it] > 0 } ?: -1
        return 2.0.pow(-(soma / arvores.size) / c(amostra)) to motivo
    }

    companion object {
        private const val EULER = 0.5772156649

        /** Caminho médio de uma busca sem sucesso numa árvore binária de n pontos (normaliza a nota). */
        fun c(n: Int): Double = if (n <= 1) 0.0 else 2 * (ln(n - 1.0) + EULER) - 2.0 * (n - 1) / n

        fun treinar(dados: List<DoubleArray>, arvores: Int, amostra: Int, semente: Long): IsolationForest {
            val r = Random(semente)
            val psi = minOf(amostra, dados.size)
            val altura = ceil(ln(psi.toDouble()) / ln(2.0)).toInt().coerceAtLeast(1)
            val indices = IntArray(dados.size) { it }
            return IsolationForest(List(arvores) { construir(subamostra(dados, indices, psi, r), 0, altura, r) }, psi)
        }

        /** psi pontos sem repetição: Fisher-Yates parcial (só as psi primeiras trocas), sem copiar a lista toda. */
        private fun subamostra(dados: List<DoubleArray>, indices: IntArray, psi: Int, r: Random): List<DoubleArray> {
            for (i in 0 until psi) {
                val j = i + r.nextInt(indices.size - i)
                val t = indices[i]; indices[i] = indices[j]; indices[j] = t
            }
            return List(psi) { dados[indices[it]] }
        }

        private fun construir(xs: List<DoubleArray>, prof: Int, limite: Int, r: Random): No {
            if (prof >= limite || xs.size <= 1) return Folha(xs.size)
            val variam = xs[0].indices.filter { i -> xs.any { it[i] != xs[0][i] } }
            if (variam.isEmpty()) return Folha(xs.size)
            val a = variam[r.nextInt(variam.size)]
            val min = xs.minOf { it[a] }
            val max = xs.maxOf { it[a] }
            val v = min + r.nextDouble() * (max - min)
            val (esq, dir) = xs.partition { it[a] < v }
            if (esq.isEmpty() || dir.isEmpty()) return Folha(xs.size)
            return Corte(a, v, construir(esq, prof + 1, limite, r), construir(dir, prof + 1, limite, r))
        }
    }
}

/** Os nomes dos números que descrevem uma conexão (aula 10, seção 3). */
object Atributos {
    const val BYTES_ENVIADOS = 0
    const val BYTES_RECEBIDOS = 1
    const val PACOTES = 2
    const val DURACAO = 3
    const val HORA_SEN = 4
    const val HORA_COS = 5
    const val FREQUENCIA_PORTA = 6
    const val FREQUENCIA_TELA = 7
    val NOMES = listOf(
        "log_bytes_enviados", "log_bytes_recebidos", "log_pacotes", "log_duracao",
        "hora_sen", "hora_cos", // hora no círculo: 23h fica perto de 0h
        "frequencia_porta",     // fração do histórico do app naquela porta (0 = porta nunca usada)
        "frequencia_tela",      // fração do histórico do app com a tela no mesmo estado
    )
}

/**
 * Nota de uma conexão encerrada de um app com modelo. É anômala quando nota > limiar.
 * `indice` é o atributo que mais pesou (posição em [Atributos.NOMES]; -1 = nenhum).
 */
data class Achado(val fluxoId: Long, val pacote: String?, val nota: Double, val limiar: Double, val indice: Int) {
    val atributo: String get() = Atributos.NOMES.getOrElse(indice) { "desconhecido" }
}

/**
 * Linha de base por app: um Isolation Forest para cada app com histórico suficiente (conexões
 * encerradas de sessões anteriores). App novo ou com pouco histórico não é julgado: sem passado,
 * não há "normal" para comparar. Só conexões encerradas são julgadas (volume e duração completos).
 *
 * Decisões (revisão independente de 2026-11-16, com experimento):
 * - Porta e tela são categorias: entram como frequência no histórico do app e só contam quando
 *   nunca apareceram (frequência 0). Na floresta, um valor minoritário mas conhecido (a porta 80
 *   de 10% das conexões, a tela desligada de 20%) virava "raro" e dava 14% de alarme falso.
 *   A floresta usa só os atributos contínuos (volume, pacotes, duração, hora).
 * - Novidade fora da faixa conhecida: na raiz, valor além de [min − 50% da faixa, max + 50% da
 *   faixa] do histórico (ou diferente, quando o atributo foi sempre igual) conta como isolado no
 *   primeiro corte. Só na raiz e com folga: aplicado em todo nó, inflava o alarme falso a 20%.
 * - Limiar calibrado num pedaço do histórico separado do treino (20%): o p99 das notas de pontos
 *   que o modelo não viu, com piso de 0,6.
 * - A folga da faixa tem um piso por atributo, e o app precisa de histórico em 3 sessões ou mais:
 *   no aparelho, um histórico de 1 minuto fez todas as conexões da hora seguinte virarem anômalas.
 */
class LinhaDeBase private constructor(private val modelos: Map<String, Modelo>, private val fuso: ZoneId) {
    private class Modelo(
        val floresta: IsolationForest?,       // null quando nenhum atributo varia o bastante
        val usados: IntArray,                 // atributos contínuos que entram na floresta
        val limiar: Double,
        val min: DoubleArray,
        val max: DoubleArray,
        val portas: Map<Int, Double>,
        val telaDesligada: Double,
    )

    val apps: Set<String> get() = modelos.keys

    /** Conexão encerrada não muda mais: a nota é calculada uma vez por fluxo (vale para esta sessão). */
    private val memo = java.util.concurrent.ConcurrentHashMap<Long, Achado>()

    /** Nota e limiar de cada conexão encerrada de um app com modelo (para guardar e exportar). */
    fun notas(linhas: List<LinhaFluxo>): List<Achado> = linhas.mapNotNull { l ->
        val pacote = l.pacoteApp ?: return@mapNotNull null
        val m = modelos[pacote] ?: return@mapNotNull null
        if (!l.completa) return@mapNotNull null
        memo[l.fluxoId]?.let { return@mapNotNull it }
        val x = atributos(l, m)
        val fora = foraDaFaixa(x, m)
        val (nota, motivo) = when {
            fora >= 0 -> NOTA_ISOLADO_NA_RAIZ to fora
            m.floresta == null -> 0.0 to -1
            else -> m.floresta.notaComMotivo(DoubleArray(m.usados.size) { x[m.usados[it]] })
                .let { (n, i) -> n to (if (i >= 0) m.usados[i] else -1) }
        }
        Achado(l.fluxoId, pacote, nota, m.limiar, motivo)
            .also { memo[l.fluxoId] = it }
    }

    /** Só as anômalas (nota acima do limiar do app). */
    fun avaliar(linhas: List<LinhaFluxo>): List<Achado> =
        notas(linhas).filter { it.nota > it.limiar }

    /** Atributos de uma conexão no modelo do app dela (para teste e exportação). */
    fun atributos(l: LinhaFluxo): DoubleArray =
        modelos[l.pacoteApp]?.let { atributos(l, it) } ?: base(l, fuso, emptyMap(), 0.0)

    private fun atributos(l: LinhaFluxo, m: Modelo) = base(l, fuso, m.portas, m.telaDesligada)

    /** Índice do atributo novo (categoria nunca vista ou contínuo além da faixa com folga), ou -1. */
    private fun foraDaFaixa(x: DoubleArray, m: Modelo): Int {
        for (i in CATEGORICOS) if (x[i] == 0.0) return i
        var pior = -1
        var excesso = 0.0
        for (i in CONTINUOS) {
            val faixa = m.max[i] - m.min[i]
            // folga proporcional à faixa, mas nunca menor que o piso do atributo: histórico de
            // poucos minutos não pode tornar "anômala" uma conexão uma hora depois
            val folga = maxOf(FOLGA * faixa, PISO_FOLGA[i])
            val e = maxOf(m.min[i] - folga - x[i], x[i] - (m.max[i] + folga)) / maxOf(faixa, PISO_FOLGA[i])
            if (e > 0 && e > excesso) { excesso = e; pior = i }
        }
        return pior
    }

    companion object {
        const val LIMIAR_MINIMO = 0.6
        /** Nota de quem é novo de verdade (isolado já no primeiro corte de uma árvore de 256). */
        private val NOTA_ISOLADO_NA_RAIZ = 2.0.pow(-1.0 / IsolationForest.c(256))
        const val MINIMO = 100
        /** "Normal" aprendido de uma sessão só não é normal: o histórico do app vem de ao menos 3. */
        const val MINIMO_SESSOES = 3
        private const val FOLGA = 0.5
        private const val PARTE_CALIBRACAO = 0.2
        /** Os seis primeiros atributos são contínuos (vão para a floresta); os dois últimos, categorias. */
        private val CONTINUOS = 0..5
        /** Folga mínima por atributo contínuo: 1,5 em log ≈ 4,5× no volume/duração; 0,5 em seno/cosseno ≈ 2 h. */
        private val PISO_FOLGA = doubleArrayOf(1.5, 1.5, 1.5, 1.5, 0.5, 0.5)
        private val CATEGORICOS = 6..7

        private fun base(l: LinhaFluxo, fuso: ZoneId, portas: Map<Int, Double>, telaDesligada: Double): DoubleArray {
            val hora = Instant.ofEpochMilli(l.inicioUs / 1000).atZone(fuso).let { it.hour + it.minute / 60.0 }
            val angulo = 2 * PI * hora / 24
            val duracao = l.fimUs?.let { (it - l.inicioUs) / 1e6 } ?: 0.0
            return doubleArrayOf(
                ln(1.0 + l.bytesEnviados), ln(1.0 + l.bytesRecebidos), ln(1.0 + l.pacotes), ln(1.0 + duracao),
                sin(angulo), cos(angulo),
                portas[l.portaDestino] ?: 0.0,
                if (l.telaDesligada) telaDesligada else 1 - telaDesligada,
            )
        }

        fun treinar(historico: List<LinhaFluxo>, fuso: ZoneId): LinhaDeBase {
            val modelos = historico.filter { it.pacoteApp != null && it.completa }.groupBy { it.pacoteApp!! }
                .filterValues { ls -> ls.size >= MINIMO && ls.map { it.sessaoId }.distinct().size >= MINIMO_SESSOES }
                .mapValues { (pacote, ls) ->
                    val portas = ls.groupingBy { it.portaDestino }.eachCount().mapValues { it.value.toDouble() / ls.size }
                    val tela = ls.count { it.telaDesligada }.toDouble() / ls.size
                    val r = Random(pacote.hashCode().toLong())
                    val embaralhado = ls.shuffled(r)
                    val nCal = (ls.size * PARTE_CALIBRACAO).toInt()
                    val treino = embaralhado.drop(nCal).map { base(it, fuso, portas, tela) }
                    val calibracao = embaralhado.take(nCal).map { base(it, fuso, portas, tela) }
                    val todos = treino + calibracao
                    val min = DoubleArray(todos[0].size) { i -> todos.minOf { it[i] } }
                    val max = DoubleArray(todos[0].size) { i -> todos.maxOf { it[i] } }
                    // atributo que quase não varia no histórico (faixa menor que o piso) fica de fora
                    // da floresta: conta só pela checagem de novidade, com folga
                    val usados = CONTINUOS.filter { max[it] - min[it] >= PISO_FOLGA[it] }.toIntArray()
                    fun proj(v: DoubleArray) = DoubleArray(usados.size) { v[usados[it]] }
                    val f = if (usados.isEmpty()) null
                    else IsolationForest.treinar(treino.map(::proj), arvores = 100, amostra = 256, semente = pacote.hashCode().toLong())
                    val notas = if (f == null) listOf(0.0) else calibracao.map { f.nota(proj(it)) }.sorted()
                    val p99 = notas[((notas.size - 1) * 0.99).toInt()]
                    Modelo(f, usados, maxOf(LIMIAR_MINIMO, p99), min, max, portas, tela)
                }
            return LinhaDeBase(modelos, fuso)
        }
    }
}
