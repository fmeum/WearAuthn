package me.henneke.wearauthn

import android.text.TextUtils
import android.util.Base64
import com.google.android.gms.common.util.Hex
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

private const val TAG = "Utils"

infix fun Boolean.implies(that: Boolean): Boolean {
    return !(this && !that)
}

fun Boolean.bytes() = byteArrayOf(if (this) 0x01 else 0x00)

fun Byte.bytes() = byteArrayOf(this)

@ExperimentalUnsignedTypes
fun UByte.bytes() = byteArrayOf(this.toByte())

fun Short.bytes(): ByteArray =
    ByteBuffer.allocate(java.lang.Short.BYTES)
        .putShort(this)
        .array()

@ExperimentalUnsignedTypes
fun UShort.bytes() =
    ByteBuffer.allocate(java.lang.Long.BYTES)
        .putLong(this.toLong())
        .array()
        .sliceArray((java.lang.Long.BYTES - java.lang.Short.BYTES) until java.lang.Long.BYTES)

@ExperimentalUnsignedTypes
fun UInt.bytes() =
    ByteBuffer.allocate(java.lang.Long.BYTES)
        .putLong(this.toLong())
        .array()
        .sliceArray((java.lang.Long.BYTES - Integer.BYTES) until java.lang.Long.BYTES)

@ExperimentalUnsignedTypes
fun uShortOf(bytes: ByteArray, offset: Int = 0): UShort {
    val padding = ByteArray(Integer.BYTES - java.lang.Short.BYTES)
    return ByteBuffer.wrap(padding + bytes).getInt(offset).toUShort()
}

@ExperimentalUnsignedTypes
fun uIntOf(bytes: ByteArray, offset: Int = 0): UInt {
    val padding = ByteArray(java.lang.Long.BYTES - Integer.BYTES)
    return ByteBuffer.wrap(padding + bytes).getLong(offset).toUInt()
}

fun ByteArray.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(this)
fun String.sha256(): ByteArray = this.toByteArray().sha256()
fun String.sha256Hex(): String = Hex.bytesToStringUppercase(this.sha256())

fun String.base64(): ByteArray? = try {
    Base64.decode(this, Base64.NO_WRAP or Base64.URL_SAFE)
} catch (e: IllegalArgumentException) {
    null
}

fun ByteArray.base64(): String = Base64.encodeToString(this, Base64.NO_WRAP or Base64.URL_SAFE)

fun ByteArray.decodeToStringOrNull(): String? = try {
        StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(this)).toString()
    } catch (ex: CharacterCodingException) {
        null
    }

fun String.escapeHtml(): String = TextUtils.htmlEncode(this)

fun String.truncate(targetLength: Int): String =
    if (length > targetLength) this.take(targetLength - 1) + "…" else this

fun String.breakAt(lineBreaks: List<Int>): String? {
    if (this == "")
        return ""
    val lineRanges = (listOf(0) + lineBreaks + listOf(length)).zipWithNext()
    if (!lineRanges.all { (start, end) -> start < end })
        return null

    return lineRanges.joinToString(separator = "") { (start, end) ->
        val line = substring(start until end)
        if (line.last() == '\n' || end == length)
            line
        else
            line + '\n'
    }
}
