package com.brendon978.sentinela.motor

import java.io.ByteArrayOutputStream

/** Lote de eventos C2 montado à mão (little-endian): u8 tipo | u16 tamanho | corpo. Só para testes. */
class Lote {
    private val out = ByteArrayOutputStream()
    fun registro(tipo: Int, corpo: ByteArray) = apply {
        out.write(tipo)
        out.write(corpo.size and 0xff)
        out.write(corpo.size shr 8)
        out.write(corpo)
    }
    fun bytes(): ByteArray = out.toByteArray()
}

/** Corpo de um evento C2, campo a campo. */
class Corpo {
    private val out = ByteArrayOutputStream()
    fun u8(v: Int) = apply { out.write(v) }
    fun u16(v: Int) = apply { out.write(v and 0xff); out.write(v shr 8 and 0xff) }
    fun u32(v: Long) = apply { for (i in 0 until 4) out.write((v shr (8 * i)).toInt() and 0xff) }
    fun u64(v: Long) = apply { for (i in 0 until 8) out.write((v shr (8 * i)).toInt() and 0xff) }
    fun ip(vararg b: Int) = apply { val ip = ByteArray(16); b.forEachIndexed { i, x -> ip[i] = x.toByte() }; out.write(ip) }
    fun texto(s: String) = apply { out.write(s.toByteArray()) }
    fun bytes(): ByteArray = out.toByteArray()
}
