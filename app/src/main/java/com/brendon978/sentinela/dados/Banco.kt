package com.brendon978.sentinela.dados

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.brendon978.sentinela.sessao.Alerta
import com.brendon978.sentinela.sessao.LinhaFluxo
import com.brendon978.sentinela.sessao.Regra

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
)

/**
 * Banco local (contrato C4 do plano). SQLiteOpenHelper direto, sem Room: o esquema é pequeno
 * e assim não entra gerador de código no build.
 */
class Banco(ctx: Context, nome: String = "sentinela.db") : SQLiteOpenHelper(ctx, nome, null, 2) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE sessao (
                id INTEGER PRIMARY KEY AUTOINCREMENT, inicio_ms INTEGER NOT NULL, fim_ms INTEGER NOT NULL,
                caminho_pcap TEXT NOT NULL, sha256 TEXT NOT NULL, pacotes INTEGER NOT NULL,
                bytes INTEGER NOT NULL, eventos_perdidos INTEGER NOT NULL)"""
        )
        db.execSQL(
            """CREATE TABLE fluxo (
                sessao_id INTEGER NOT NULL REFERENCES sessao(id) ON DELETE CASCADE, fluxo_id INTEGER NOT NULL,
                proto INTEGER NOT NULL, versao_ip INTEGER NOT NULL, ip_origem TEXT NOT NULL, porta_origem INTEGER NOT NULL,
                ip_destino TEXT NOT NULL, porta_destino INTEGER NOT NULL, uid INTEGER NOT NULL, pacote_app TEXT,
                rotulo_app TEXT, dominio TEXT, origem_dominio TEXT NOT NULL, bytes_env INTEGER NOT NULL,
                bytes_rec INTEGER NOT NULL, pacotes INTEGER NOT NULL, inicio_us INTEGER NOT NULL, fim_us INTEGER,
                motivo_fim INTEGER, tela_desligada INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (sessao_id, fluxo_id))"""
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
    }

    override fun onConfigure(db: SQLiteDatabase) {
        db.setForeignKeyConstraintsEnabled(true)
    }

    override fun onUpgrade(db: SQLiteDatabase, antiga: Int, nova: Int) {
        if (antiga < 2) {
            db.execSQL("ALTER TABLE fluxo ADD COLUMN tela_desligada INTEGER NOT NULL DEFAULT 0")
            db.execSQL("ALTER TABLE alerta ADD COLUMN rotulo_app TEXT")
        }
    }

    /** Grava a sessão e os fluxos numa transação; o id da sessão é gerado aqui. */
    fun salvarSessao(s: SessaoSalva, fluxos: List<LinhaFluxo>, agoraMs: Long, alertas: List<Alerta> = emptyList()): Long {
        val db = writableDatabase
        db.beginTransaction()
        try {
            val id = db.insertOrThrow("sessao", null, ContentValues().apply {
                put("inicio_ms", s.inicioMs); put("fim_ms", s.fimMs); put("caminho_pcap", s.caminhoPcap)
                put("sha256", s.sha256); put("pacotes", s.pacotes); put("bytes", s.bytes)
                put("eventos_perdidos", s.eventosPerdidos)
            })
            for (f in fluxos) {
                db.insertOrThrow("fluxo", null, ContentValues().apply {
                    // sessao_id é o id gerado agora, não f.sessaoId
                    put("sessao_id", id); put("fluxo_id", f.fluxoId); put("proto", f.protocolo)
                    put("versao_ip", f.versaoIp); put("ip_origem", f.ipOrigem); put("porta_origem", f.portaOrigem)
                    put("ip_destino", f.ipDestino); put("porta_destino", f.portaDestino); put("uid", f.uid)
                    put("pacote_app", f.pacoteApp); put("rotulo_app", f.rotuloApp); put("dominio", f.dominio)
                    put("origem_dominio", f.origemDominio); put("bytes_env", f.bytesEnviados)
                    put("bytes_rec", f.bytesRecebidos); put("pacotes", f.pacotes); put("inicio_us", f.inicioUs)
                    put("fim_us", f.fimUs); put("motivo_fim", f.motivoFim)
                    put("tela_desligada", if (f.telaDesligada) 1 else 0)
                })
                if (f.pacoteApp != null && f.dominio != null) {
                    db.insertWithOnConflict("dominio_visto", null, ContentValues().apply {
                        put("pacote_app", f.pacoteApp); put("dominio", f.dominio); put("primeira_vez_ms", agoraMs)
                    }, SQLiteDatabase.CONFLICT_IGNORE)
                }
            }
            for (a in alertas) {
                db.insertOrThrow("alerta", null, ContentValues().apply {
                    put("sessao_id", id); put("fluxo_id", a.fluxoId); put("regra", a.regra.name)
                    put("pacote_app", a.pacote); put("detalhe", a.detalhe); put("quando_ms", a.quandoUs / 1000)
                    put("rotulo_app", a.rotulo)
                })
            }
            db.setTransactionSuccessful()
            return id
        } finally {
            db.endTransaction()
        }
    }

    fun sessoes(): List<SessaoSalva> = readableDatabase.rawQuery(
        "SELECT id, inicio_ms, fim_ms, caminho_pcap, sha256, pacotes, bytes, eventos_perdidos FROM sessao ORDER BY inicio_ms DESC",
        null,
    ).use { c ->
        buildList {
            while (c.moveToNext()) add(
                SessaoSalva(c.getLong(0), c.getLong(1), c.getLong(2), c.getString(3), c.getString(4), c.getLong(5), c.getLong(6), c.getLong(7))
            )
        }
    }

    fun fluxos(sessaoId: Long): List<LinhaFluxo> = readableDatabase.rawQuery(
        """SELECT fluxo_id, proto, versao_ip, ip_origem, porta_origem, ip_destino, porta_destino, uid, pacote_app,
                  rotulo_app, dominio, origem_dominio, bytes_env, bytes_rec, pacotes, inicio_us, fim_us, motivo_fim,
                  tela_desligada
           FROM fluxo WHERE sessao_id = ? ORDER BY inicio_us""",
        arrayOf(sessaoId.toString()),
    ).use { c ->
        buildList {
            while (c.moveToNext()) add(
                LinhaFluxo(
                    sessaoId, c.getLong(0), c.getInt(1), c.getInt(2), c.getString(3), c.getInt(4), c.getString(5),
                    c.getInt(6), c.getInt(7), c.getStringOrNull(8), c.getStringOrNull(9), c.getStringOrNull(10),
                    c.getString(11), c.getLong(12), c.getLong(13), c.getLong(14), c.getLong(15),
                    if (c.isNull(16)) null else c.getLong(16), if (c.isNull(17)) null else c.getInt(17),
                    c.getInt(18) != 0,
                )
            )
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

    /** Domínios que um app já usou em sessões anteriores (para o alerta de domínio novo). */
    fun dominiosVistos(): Set<Pair<String, String>> = readableDatabase.rawQuery(
        "SELECT pacote_app, dominio FROM dominio_visto", null,
    ).use { c -> buildSet { while (c.moveToNext()) add(c.getString(0) to c.getString(1)) } }

    fun apagarSessao(id: Long) {
        writableDatabase.delete("sessao", "id = ?", arrayOf(id.toString()))
    }

    private fun android.database.Cursor.getStringOrNull(i: Int): String? = if (isNull(i)) null else getString(i)
}
