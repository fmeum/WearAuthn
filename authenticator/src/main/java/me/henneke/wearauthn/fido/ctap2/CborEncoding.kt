package me.henneke.wearauthn.fido.ctap2

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer


interface CborValue {
    fun writeAsCbor(out: ByteArrayOutputStream)

    fun toCbor(): ByteArray {
        val out = ByteArrayOutputStream()
        writeAsCbor(out)
        return out.toByteArray()
    }

}

interface CborBoxedValue<out T> : CborValue {
    val value: T
}

@ExperimentalUnsignedTypes
inline class CborUnsignedInteger(override val value: ULong) :
    CborBoxedValue<ULong> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        value.writeAsCbor(out, MajorType.UNSIGNED_INTEGER)
    }
}

@ExperimentalUnsignedTypes
inline class CborNegativeInteger(override val value: ULong) :
    CborBoxedValue<ULong> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        value.writeAsCbor(out, MajorType.NEGATIVE_INTEGER)
    }
}

@ExperimentalUnsignedTypes
inline class CborLong(override val value: Long) :
    CborBoxedValue<Long> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        if (value >= 0)
            CborUnsignedInteger(value.toULong()).writeAsCbor(out)
        else
            CborNegativeInteger((-(value + 1)).toULong()).writeAsCbor(out)
    }
}

@ExperimentalUnsignedTypes
inline class CborTextString(override val value: String) :
    CborBoxedValue<String> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        val array = value.toByteArray()
        array.size.toULong().writeAsCbor(out, MajorType.TEXT_STRING)
        out.write(array)
    }
}

@ExperimentalUnsignedTypes
data class CborByteString(override val value: ByteArray) :
    CborBoxedValue<ByteArray> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        value.size.toULong().writeAsCbor(out, MajorType.BYTE_STRING)
        out.write(value)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CborByteString

        if (!value.contentEquals(other.value)) return false

        return true
    }

    override fun hashCode(): Int {
        return value.contentHashCode()
    }
}

@ExperimentalUnsignedTypes
data class CborArray(override val value: Array<CborValue>) :
    CborBoxedValue<Array<CborValue>> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        value.size.toULong().writeAsCbor(out, MajorType.ARRAY)
        for (element in value)
            element.writeAsCbor(out)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CborArray

        if (!value.contentEquals(other.value)) return false

        return true
    }

    override fun hashCode(): Int {
        return value.contentHashCode()
    }
}

@ExperimentalUnsignedTypes
inline class CborTextStringMap(override val value: Map<String, CborValue>) :
    CborBoxedValue<Map<String, CborValue>> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        CborMap(value.mapKeys {
            CborTextString(
                it.key
            )
        }).writeAsCbor(out)
    }
}

@ExperimentalUnsignedTypes
inline class CborLongMap(override val value: Map<Long, CborValue>) :
    CborBoxedValue<Map<Long, CborValue>> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        CborMap(value.mapKeys {
            CborLong(
                it.key
            )
        }).writeAsCbor(out)
    }
}

@ExperimentalUnsignedTypes
inline class CborMap(override val value: Map<CborValue, CborValue>) :
    CborBoxedValue<Map<CborValue, CborValue>> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        value.size.toULong().writeAsCbor(out, MajorType.MAP)
        value.entries.asSequence()
            .map { entry -> Pair(entry.key.toCbor(), entry.value) }
            .sortedWith(compareBy(ByteArrayComparator) { it.first })
            .forEach { (key, entry) ->
                out.write(key)
                entry.writeAsCbor(out)
            }
    }
}

@ExperimentalUnsignedTypes
inline class CborSimpleValue(override val value: UByte) :
    CborBoxedValue<UByte> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        if (value >= 32U)
            out.write(SIMPLE_VALUE.toInt())
        out.write(value.toInt())
    }
}

@ExperimentalUnsignedTypes
inline class CborFloatingPointNumber(override val value: Double) :
    CborBoxedValue<Double> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        out.write(SIMPLE_VALUE_DOUBLE.toInt())
        out.write(value.toBits().toULong().toBytes())
    }
}

@ExperimentalUnsignedTypes
inline class CborBoolean(override val value: Boolean) :
    CborBoxedValue<Boolean> {
    override fun writeAsCbor(out: ByteArrayOutputStream) {
        if (value)
            out.write(SIMPLE_VALUE_TRUE.toInt())
        else
            out.write(SIMPLE_VALUE_FALSE.toInt())
    }
}

@ExperimentalUnsignedTypes
object CborNull : CborBoxedValue<Nothing?> {
    override val value = null

    override fun writeAsCbor(out: ByteArrayOutputStream) {
        out.write(SIMPLE_VALUE_NULL.toInt())
    }
}

@ExperimentalUnsignedTypes
object CborUndefined : CborBoxedValue<Nothing> {
    override val value
        get() = throw UninitializedPropertyAccessException()

    override fun writeAsCbor(out: ByteArrayOutputStream) {
        out.write(SIMPLE_VALUE_UNDEFINED.toInt())
    }
}

private object ByteArrayComparator : Comparator<ByteArray> {
    override fun compare(a: ByteArray, b: ByteArray): Int {
        var res = a.size.compareTo(b.size)
        if (res != 0)
            return res

        for (i in a.indices) {
            res = a[i].compareTo(b[i])
            if (res != 0)
                return res
        }
        return 0
    }
}

@ExperimentalUnsignedTypes
private fun UByte.toBytes() = byteArrayOf(this.toByte())

@ExperimentalUnsignedTypes
private fun UShort.toBytes(): ByteArray =
    ByteBuffer.allocate(Short.SIZE_BYTES)
        .putShort(this.toShort())
        .array()

@ExperimentalUnsignedTypes
private fun UInt.toBytes(): ByteArray =
    ByteBuffer.allocate(Int.SIZE_BYTES)
        .putInt(this.toInt())
        .array()

@ExperimentalUnsignedTypes
private fun ULong.toBytes(): ByteArray =
    ByteBuffer.allocate(Long.SIZE_BYTES)
        .putLong(this.toLong())
        .array()

@ExperimentalUnsignedTypes
private fun ULong.writeAsCbor(out: ByteArrayOutputStream, majorType: MajorType) {
    val initialByte: UByte
    val additionalBytes: ByteArray
    when (this) {
        in 0U..23U -> {
            initialByte = majorType.mask or this.toUByte()
            additionalBytes = byteArrayOf()
        }
        in 24U..UByte.MAX_VALUE.toUInt() -> {
            initialByte = majorType.mask or 24U
            additionalBytes = this.toUByte().toBytes()
        }
        in UByte.MAX_VALUE.toUInt() + 1U..UShort.MAX_VALUE.toUInt() -> {
            initialByte = majorType.mask or 25U
            additionalBytes = this.toUShort().toBytes()
        }
        in UShort.MAX_VALUE.toUInt() + 1U..UInt.MAX_VALUE -> {
            initialByte = majorType.mask or 26U
            additionalBytes = this.toUInt().toBytes()
        }
        else -> {
            initialByte = majorType.mask or 27U
            additionalBytes = this.toBytes()
        }
    }

    out.write(ubyteArrayOf(initialByte).toByteArray())
    out.write(additionalBytes)
}

