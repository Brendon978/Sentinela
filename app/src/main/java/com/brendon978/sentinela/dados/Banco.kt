package com.brendon978.sentinela.dados

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.brendon978.sentinela.sessao.Alerta
import com.brendon978.sentinela.sessao.LinhaFluxo
import com.brendon978.sentinela.sessao.Regra

enum class EstadoSessaoSalva { GRAVANDO, CONCLUIDA, INTERROMPIDA }

/** Sessão salva, como aparece na lista. */
data class SessaoSalva(
    val id: Long,
    val inicioMs: Long,
    val fimMs: Long,
    val caminhoPcap: String,
    val sha256: String,
    val pacotes: Long,
    val bytes: Long,
    val eventosPerdidos: Long,
    val estado: EstadoSessaoSalva = EstadoSessaoSalva.CONCLUIDA,
    val iaApps: Int? = null,
)

/**
 * Banco local (contrato C4 do plano). SQLiteOpenHelper direto, sem Room: o esquema é pequeno
 * e assim não entra gerador de código no build.
 */
class Banco(ctx: Context, nome: String = "sentinela.db") : SQLiteOpenHelper(ctx, nome, null, 5),
    com.brendon978.sentinela.vpn.GravadorSessao {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE sessao (
                id INTEGER PRIMARY KEY AUTOINCREMENT, inicio_ms INTEGER NOT NULL, fim_ms INTEGER NOT NULL,
                caminho_pcap TEXT NOT NULL, sha256 TEXT NOT NULL, pacotes INTEGER NOT NULL,
                bytes INTEGER NOT NULL, eventos_perdidos INTEGER NOT NULL, estado TEXT NOT NULL DEFAULT 'CONCLUIDA',
                ia_apps INTEGER)"""
        )
        db.execSQL(
            """CREATE TABLE fluxo (
                sessao_id INTEGER NOT NULL REFERENCES sessao(id) ON DELETE CASCADE, fluxo_id INTEGER NOT NULL,
                proto INTEGER NOT NULL, versao_ip INTEGER NOT NULL, ip_origem TEXT NOT NULL, porta_origem INTEGER NOT NULL,
                ip_destino TEXT NOT NULL, porta_destino INTEGER NOT NULL, uid INTEGER NOT NULL, pacote_app TEXT,
                rotulo_app TEXT, dominio TEXT, origem_dominio TEXT NOT NULL, bytes_env INTEGER NOT NULL,
                bytes_rec INTEGER NOT NULL, pacotes INTEGER NOT NULL, inicio_us INTEGER NOT NULL, fim_us INTEGER,
                motivo_fim INTEGER, tela_desligada INTEGER NOT NULL DEFAULT 0, nota_ia REAL, limiar_ia REAL,
                PRIMARY KEY (sessao_id, fluxo_id))"""
        )
        db.execSQL(
            """CREATE TABLE dominio_visto (
                pacote_app TEXT NOT NULL, dominio TEXT NOT NULL, primeira_vez_ms INTEGER NOT NULL,
                PRIMARY KEY (pacote_app, dominio))"""
        )
        db.execSQL(
            """CREATE TABLE alerta (
                id INTEGER PRIMARY KEY AUTOINCREMENT, sessao_id INTEGER NOT NULL REFERENCES sessao(id) ON DELETE CASCADE,
                fluxo_id INTEGER, regra TEXT NOT NULL, pacote_app TEXT, rotulo_app TEXT, detalhe TEXT NOT NULL,
                quando_ms INTEGER NOT NULL)"""
        )
        criarExcecao(db)
    }

    private fun criarExcecao(db: SQLiteDatabase) = db.execSQL(
        "CREATE TABLE IF NOT EXISTS excecao (pacote_app TEXT NOT NULL, regra TEXT NOT NULL, PRIMARY KEY (pacote_app, regra))"
    )

    override fun onConfigure(db: SQLiteDatabase) {
        db.setForeignKeyConstraintsEnabled(true)
    }

    override fun onUpgrade(db: SQLiteDatabase, antiga: Int, nova: Int) {
        if (antiga < 2) {
            db.execSQL("ALTER TABLE fluxo ADD COLUMN tela_desligada INTEGER NOT NULL DEFAULT 0")
            db.execSQL("ALTER TABLE alerta ADD COLUMN rotulo_app TEXT")
        }
        if (antiga < 3) db.execSQL("ALTER TABLE sessao ADD COLUMN estado TEXT NOT NULL DEFAULT 'CONCLUIDA'")
        if (antiga < 4) criarExcecao(db)
        if (antiga < 5) {
            db.execSQL("ALTER TABLE fluxo ADD COLUMN nota_ia REAL")
            db.execSQL("ALTER TABLE fluxo ADD COLUMN limiar_ia REAL")
            db.execSQL("ALTER TABLE sessao ADD COLUMN ia_apps INTEGER")
        }
    }

    /** Grava uma sessão já pronta de uma vez (abrir + concluir). */
    fun salvarSessao(s: SessaoSalva, fluxos: List<LinhaFluxo>, agoraMs: Long, alertas: List<Alerta> = emptyList()): Long {
        val id = abrirSessao(s.inicioMs, s.caminhoPcap)
        concluirSessao(id, s.sha256, s.pacotes, s.bytes, s.fimMs, s.eventosPerdidos, fluxos, alertas, agoraMs)
        return id
    }

    /** Cria a sessão no começo da gravação (estado GRAVANDO): um crash no meio não a perde. */
    fun abrirSessao(inicioMs: Long, caminhoPcap: String): Long = writableDatabase.insertOrThrow("sessao", null, ContentValues().apply {
        put("inicio_ms", inicioMs); put("fim_ms", inicioMs); put("caminho_pcap", caminhoPcap); put("sha256", "")
        put("pacotes", 0); put("bytes", 0); put("eventos_perdidos", 0); put("estado", EstadoSessaoSalva.GRAVANDO.name)
    })

    /**
     * Gravação de 5 s: `fluxos` são só os novos ou mudados (os outros ficam como estão), `alertas`
     * null = iguais aos já gravados, `bytes` = total da sessão (não dá para somar só os mudados).
     */
    override fun gravarParcial(
        id: Long, fluxos: List<LinhaFluxo>, alertas: List<Alerta>?, agoraMs: Long, bytes: Long, eventosPerdidos: Long,
    ): Unit = transacao { db ->
        gravarFluxos(db, id, fluxos)
        alertas?.let { gravarAlertas(db, id, it) }
        db.update("sessao", ContentValues().apply {
            put("fim_ms", agoraMs); put("bytes", bytes)
            put("eventos_perdidos", eventosPerdidos)
        }, "id = ? AND estado = ?", arrayOf(id.toString(), EstadoSessaoSalva.GRAVANDO.name))
    }

    /** Fecha a sessão: últimos fluxos e alertas, hash, contagens e o que o app aprendeu de domínios. */
    fun concluirSessao(
        id: Long, sha256: String, pacotes: Long, bytes: Long, fimMs: Long, eventosPerdidos: Long,
        fluxos: List<LinhaFluxo>, alertas: List<Alerta>, agoraMs: Long = fimMs, iaApps: Int? = null,
    ) = transacao { db ->
        db.update("sessao", ContentValues().apply { put("ia_apps", iaApps) }, "id = ?", arrayOf(id.toString()))
        gravarFluxos(db, id, fluxos)
        gravarAlertas(db, id, alertas)
        for (f in fluxos) if (f.pacoteApp != null && f.dominio != null) {
            db.insertWithOnConflict("dominio_visto", null, ContentValues().apply {
                put("pacote_app", f.pacoteApp); put("dominio", f.dominio); put("primeira_vez_ms", agoraMs)
            }, SQLiteDatabase.CONFLICT_IGNORE)
        }
        fechar(db, id, EstadoSessaoSalva.CONCLUIDA, sha256, pacotes, fimMs, bytes, eventosPerdidos)
    }

    /** A gravação morreu no meio: fica com o hash e a contagem do que chegou ao pcap. Só vale
     *  para sessão ainda GRAVANDO (uma concluída nunca vira interrompida). */
    fun marcarInterrompida(id: Long, sha256: String, pacotes: Long) = transacao { db ->
        fechar(db, id, EstadoSessaoSalva.INTERROMPIDA, sha256, pacotes, null, null, null, soSeGravando = true)
    }

    private fun fechar(
        db: SQLiteDatabase, id: Long, estado: EstadoSessaoSalva, sha256: String, pacotes: Long,
        fimMs: Long?, bytes: Long?, perdidos: Long?, soSeGravando: Boolean = false,
    ) {
        val valores = ContentValues().apply {
            put("estado", estado.name); put("sha256", sha256); put("pacotes", pacotes)
            fimMs?.let { put("fim_ms", it) }; bytes?.let { put("bytes", it) }; perdidos?.let { put("eventos_perdidos", it) }
        }
        if (soSeGravando) db.update("sessao", valores, "id = ? AND estado = ?", arrayOf(id.toString(), EstadoSessaoSalva.GRAVANDO.name))
        else db.update("sessao", valores, "id = ?", arrayOf(id.toString()))
    }

    private fun gravarFluxos(db: SQLiteDatabase, id: Long, fluxos: List<LinhaFluxo>) {
        for (f in fluxos) {
            db.insertWithOnConflict("fluxo", null, ContentValues().apply {
                // sessao_id é o id desta sessão, não f.sessaoId
                put("sessao_id", id); put("fluxo_id", f.fluxoId); put("proto", f.protocolo)
                put("versao_ip", f.versaoIp); put("ip_origem", f.ipOrigem); put("porta_origem", f.portaOrigem)
                put("ip_destino", f.ipDestino); put("porta_destino", f.portaDestino); put("uid", f.uid)
                put("pacote_app", f.pacoteApp); put("rotulo_app", f.rotuloApp); put("dominio", f.dominio)
                put("origem_dominio", f.origemDominio); put("bytes_env", f.bytesEnviados)
                put("bytes_rec", f.bytesRecebidos); put("pacotes", f.pacotes); put("inicio_us", f.inicioUs)
                put("fim_us", f.fimUs); put("motivo_fim", f.motivoFim)
                put("tela_desligada", if (f.telaDesligada) 1 else 0)
                put("nota_ia", f.notaIa); put("limiar_ia", f.limiarIa)
            }, SQLiteDatabase.CONFLICT_REPLACE)
        }
    }

    private fun gravarAlertas(db: SQLiteDatabase, id: Long, alertas: List<Alerta>) {
        db.delete("alerta", "sessao_id = ?", arrayOf(id.toString()))
        for (a in alertas) {
            db.insertOrThrow("alerta", null, ContentValues().apply {
                put("sessao_id", id); put("fluxo_id", a.fluxoId); put("regra", a.regra.name)
                put("pacote_app", a.pacote); put("rotulo_app", a.rotulo); put("detalhe", a.detalhe)
                put("quando_ms", a.quandoUs / 1000)
            })
        }
    }

    private inline fun <T> transacao(bloco: (SQLiteDatabase) -> T): T {
        val db = writableDatabase
        db.beginTransaction()
        try {
            return bloco(db).also { db.setTransactionSuccessful() }
        } finally {
            db.endTransaction()
        }
    }

    fun sessoes(): List<SessaoSalva> = readableDatabase.rawQuery(
        "SELECT id, inicio_ms, fim_ms, caminho_pcap, sha256, pacotes, bytes, eventos_perdidos, estado, ia_apps FROM sessao ORDER BY inicio_ms DESC",
        null,
    ).use { c ->
        buildList {
            while (c.moveToNext()) add(
                SessaoSalva(
                    c.getLong(0), c.getLong(1), c.getLong(2), c.getString(3), c.getString(4), c.getLong(5), c.getLong(6),
                    c.getLong(7), runCatching { EstadoSessaoSalva.valueOf(c.getString(8)) }.getOrDefault(EstadoSessaoSalva.CONCLUIDA),
                    if (c.isNull(9)) null else c.getInt(9),
                )
            )
        }
    }

    fun fluxos(sessaoId: Long): List<LinhaFluxo> =
        lerFluxos("WHERE f.sessao_id = ? ORDER BY f.inicio_us", arrayOf(sessaoId.toString())) { true }

    /** Lê fluxos (com `f` = fluxo e `s` = sessao no SQL), guardando os que passam no filtro, até o limite. */
    private fun lerFluxos(
        resto: String, args: Array<String>?, limite: Int = Int.MAX_VALUE, guardar: (LinhaFluxo) -> Boolean,
    ): List<LinhaFluxo> = readableDatabase.rawQuery(
        """SELECT f.sessao_id, f.fluxo_id, f.proto, f.versao_ip, f.ip_origem, f.porta_origem, f.ip_destino,
                  f.porta_destino, f.uid, f.pacote_app, f.rotulo_app, f.dominio, f.origem_dominio, f.bytes_env,
                  f.bytes_rec, f.pacotes, f.inicio_us, f.fim_us, f.motivo_fim, f.tela_desligada, f.nota_ia, f.limiar_ia
           FROM fluxo f JOIN sessao s ON s.id = f.sessao_id $resto""",
        args,
    ).use { c ->
        buildList {
            while (size < limite && c.moveToNext()) {
                val l = LinhaFluxo(
                    c.getLong(0), c.getLong(1), c.getInt(2), c.getInt(3), c.getString(4), c.getInt(5), c.getString(6),
                    c.getInt(7), c.getInt(8), c.getStringOrNull(9), c.getStringOrNull(10), c.getStringOrNull(11),
                    c.getString(12), c.getLong(13), c.getLong(14), c.getLong(15), c.getLong(16),
                    if (c.isNull(17)) null else c.getLong(17), if (c.isNull(18)) null else c.getInt(18),
                    c.getInt(19) != 0,
                    if (c.isNull(20)) null else c.getDouble(20), if (c.isNull(21)) null else c.getDouble(21),
                )
                if (guardar(l)) add(l)
            }
        }
    }

    fun alertas(sessaoId: Long): List<Alerta> = readableDatabase.rawQuery(
        "SELECT regra, pacote_app, rotulo_app, fluxo_id, detalhe, quando_ms FROM alerta WHERE sessao_id = ? ORDER BY quando_ms",
        arrayOf(sessaoId.toString()),
    ).use { c ->
        buildList {
            while (c.moveToNext()) {
                val regra = runCatching { Regra.valueOf(c.getString(0)) }.getOrNull() ?: continue
                add(Alerta(regra, c.getStringOrNull(1), c.getStringOrNull(2) ?: com.brendon978.sentinela.vpn.App.SEM_APP, c.getLong(3), c.getString(4), c.getLong(5) * 1000))
            }
        }
    }

    /** Regras que o usuário mandou ignorar para um app. Sem app (sistema) usa pacote "". */
    fun excecoes(): Set<Pair<String?, Regra>> = readableDatabase.rawQuery("SELECT pacote_app, regra FROM excecao", null).use { c ->
        buildSet {
            while (c.moveToNext()) {
                val regra = runCatching { Regra.valueOf(c.getString(1)) }.getOrNull() ?: continue
                add(c.getString(0).ifEmpty { null } to regra)
            }
        }
    }

    fun adicionarExcecao(pacote: String?, regra: Regra) {
        writableDatabase.insertWithOnConflict("excecao", null, ContentValues().apply {
            put("pacote_app", pacote ?: ""); put("regra", regra.name)
        }, SQLiteDatabase.CONFLICT_IGNORE)
    }

    fun removerExcecao(pacote: String?, regra: Regra) {
        writableDatabase.delete("excecao", "pacote_app = ? AND regra = ?", arrayOf(pacote ?: "", regra.name))
    }

    /**
     * Treino da IA: conexões encerradas de sessões CONCLUÍDAS (interrompidas têm fluxos abertos,
     * com volume parcial), as mais recentes primeiro, sem as que a própria IA já acusou (um
     * vazamento visto uma vez não pode virar "normal" nas próximas sessões).
     */
    override fun historico(): List<LinhaFluxo> = historico(20_000)

    fun historico(limite: Int): List<LinhaFluxo> = lerFluxos(
        "WHERE s.estado = 'CONCLUIDA' ORDER BY s.inicio_ms DESC, f.inicio_us", null, limite,
    ) { it.completa && !it.acusadaPelaIa } // a nota fica guardada em toda conexão julgada, com alerta ou não

    /** Domínios que um app já usou em sessões anteriores (para o alerta de domínio novo). */
    fun dominiosVistos(): Set<Pair<String, String>> = readableDatabase.rawQuery(
        "SELECT pacote_app, dominio FROM dominio_visto", null,
    ).use { c -> buildSet { while (c.moveToNext()) add(c.getString(0) to c.getString(1)) } }

    fun apagarSessao(id: Long) {
        writableDatabase.delete("sessao", "id = ?", arrayOf(id.toString()))
    }

    private fun android.database.Cursor.getStringOrNull(i: Int): String? = if (isNull(i)) null else getString(i)
}
