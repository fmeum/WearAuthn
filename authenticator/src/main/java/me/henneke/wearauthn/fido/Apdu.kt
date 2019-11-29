package me.henneke.wearauthn.fido

import kotlin.math.max
import kotlin.math.min

@ExperimentalUnsignedTypes
enum class StatusWord(val value: UByteArray) {
    NO_ERROR(ubyteArrayOf(0x90u, 0x00u)),
    MEMORY_FAILURE(ubyteArrayOf(0x65u, 0x01u)),
    CONDITIONS_NOT_SATISFIED(ubyteArrayOf(0x69u, 0x85u)),
    WRONG_DATA(ubyteArrayOf(0x6Au, 0x80u)),
    WRONG_LENGTH(ubyteArrayOf(0x67u, 0x00u)),
    CLA_NOT_SUPPORTED(ubyteArrayOf(0x6Eu, 0x00u)),
    INS_NOT_SUPPORTED(ubyteArrayOf(0x6Du, 0x00u)),
    INCORRECT_PARAMETERS(ubyteArrayOf(0x6Au, 0x00u)),
}

@ExperimentalUnsignedTypes
data class ApduException(val statusWord: StatusWord) : Throwable()

@ExperimentalUnsignedTypes
class CommandApdu(bytes: UByteArray) {
    val cla: UByte
    val ins: UByte
    val p1: UByte
    val p2: UByte
    val lc: Int
        get() = data.size
    val le: Int
    val data: UByteArray

    init {
        if (bytes.size < 4) {
            throw ApduException(StatusWord.WRONG_LENGTH)
        }
        cla = bytes[0]
        ins = bytes[1]
        p1 = bytes[2]
        p2 = bytes[3]

        val bodyLength = bytes.size - 4
        if (bodyLength == 0) {
            // Case 1
            data = UByteArray(0)
            le = 0
        } else if (bodyLength == 1) {
            // Case 2S
            data = UByteArray(0)
            val leRaw = bytes[4].toInt()
            le = if (leRaw != 0) leRaw else 256
        } else if (bodyLength == 1 + bytes[4].toInt()) {
            // Case 3S (bytes[4] != 0 implicit)
            data = bytes.sliceArray(5 until bytes.size)
            le = 0
        } else if (bodyLength == 2 + bytes[4].toInt()) {
            // Case 4S (bytes[4] != 0 implicit)
            data = bytes.sliceArray(5 until bytes.size - 1)
            val leRaw = bytes[bytes.size - 1].toInt()
            le = if (leRaw != 0) leRaw else 256
        } else if (bodyLength == 3 && bytes[4] == 0.toUByte()) {
            // Case 2E
            data = UByteArray(0)
            val leRaw = (bytes[5].toInt() shl 8) + bytes[6].toInt()
            le = if (leRaw != 0) leRaw else 65536
        } else if (bodyLength > 3 &&
            bodyLength == 3 + (bytes[5].toInt() shl 8) + bytes[6].toInt() &&
            bytes[4] == 0.toUByte()) {
            // Case 3E
            data = bytes.sliceArray(7 until bytes.size)
            le = 0
        } else if (bodyLength > 5 &&
            bodyLength == 5 + (bytes[5].toInt() shl 8) + bytes[6].toInt() &&
            bytes[4] == 0.toUByte()) {
            // Case 4E
            data = bytes.sliceArray(7 until bytes.size - 2)
            val leRaw = (bytes[bytes.size - 2].toInt() shl 8) + bytes[bytes.size - 1].toInt()
            le = if (leRaw != 0) leRaw else 65536
        } else {
            throw ApduException(StatusWord.WRONG_LENGTH)
        }
    }

    fun headerEquals(header: UByteArray): Boolean {
        return header.size == 4 && cla == header[0] && ins == header[1] && p1 == header[2] && p2 == header[3]
    }
}

@ExperimentalUnsignedTypes
class ResponseApdu(private val data: UByteArray, private val statusWord: StatusWord) {
    private var pos: Int = 0
    private val remainingBytes: Int
        get() = max(data.size - pos, 0)

    fun hasNext(): Boolean {
        return remainingBytes > 0
    }

    fun next(expectedLength: Int): UByteArray {
        val nextResponseLength = min(expectedLength, remainingBytes)
        val nextResponse = data.sliceArray(pos until pos + nextResponseLength)
        pos += nextResponseLength
        return if (hasNext()) {
            nextResponse + ubyteArrayOf(0x61u, if (remainingBytes >= 256) 0x00u else remainingBytes.toUByte())
        } else {
            nextResponse + statusWord.value
        }
    }

    fun next(): UByteArray {
        return next(remainingBytes)
    }
}

