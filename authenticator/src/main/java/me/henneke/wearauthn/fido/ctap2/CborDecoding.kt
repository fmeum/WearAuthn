package me.henneke.wearauthn.fido.ctap2

import me.henneke.wearauthn.decodeToStringOrNull
import kotlin.experimental.and


@ExperimentalUnsignedTypes
fun fromCborToEnd(iter: Iterator<Byte>): CborValue? {
    return fromCbor(iter).takeUnless { iter.hasNext() }
}

@ExperimentalUnsignedTypes
fun fromCborToEnd(bytes: ByteArray): CborValue? {
    return fromCborToEnd(bytes.iterator())
}

@ExperimentalUnsignedTypes
fun fromCbor(bytes: Iterable<Byte>): CborValue? {
    val iter = bytes.iterator()
    return fromCbor(iter).takeUnless { iter.hasNext() }
}

@ExperimentalUnsignedTypes
private fun fromCbor(iter: Iterator<Byte>): CborValue? {
    with(iter) {
        if (!hasNext())
            return null
        val initialByte = next()
        val additionalInfo = initialByte and 0x1f
        val value: ULong = when (additionalInfo) {
            in 0..23 -> {
                additionalInfo.toULong()
            }
            24.toByte() -> {
                nextInteger(UByte.SIZE_BYTES)?.takeUnless { it <= 23.toULong() }
            }
            25.toByte() -> {
                nextInteger(UShort.SIZE_BYTES)?.takeUnless { it <= UByte.MAX_VALUE }
            }
            26.toByte() -> {
                nextInteger(UInt.SIZE_BYTES)?.takeUnless { it <= UShort.MAX_VALUE }
            }
            27.toByte() -> {
                nextInteger(ULong.SIZE_BYTES)?.takeUnless { it <= UInt.MAX_VALUE }
            }
            else -> null
        }
            ?: return null
        return when (val majorType = (initialByte.toUByte().toUInt() shr 5).toUByte()) {
            MajorType.UNSIGNED_INTEGER.value -> {
                if (value <= Long.MAX_VALUE.toULong()) CborLong(
                    value.toLong()
                )
                else CborUnsignedInteger(value)
            }
            MajorType.NEGATIVE_INTEGER.value -> {
                if (value <= Long.MAX_VALUE.toULong()) CborLong(
                    -1 - value.toLong()
                )
                else CborNegativeInteger(value)
            }
            MajorType.BYTE_STRING.value, MajorType.TEXT_STRING.value -> {
                if (value > Int.MAX_VALUE.toULong())
                    return null
                val array = ByteArray(value.toInt()) {
                    if (!hasNext())
                        return null
                    next()
                }
                if (majorType == MajorType.BYTE_STRING.value) {
                    CborByteString(array)
                } else {
                    CborTextString(array.decodeToStringOrNull() ?: return null)
                }
            }
            MajorType.ARRAY.value -> {
                if (value > Int.MAX_VALUE.toULong())
                    return null
                val array = Array(value.toInt()) {
                    fromCbor(iter) ?: return null
                }
                CborArray(array)
            }
            MajorType.MAP.value -> {
                if (value > Int.MAX_VALUE.toULong())
                    return null
                val size = value.toInt()
                val map = HashMap<CborValue, CborValue>(size)
                repeat(size) {
                    val key = fromCbor(this) ?: return null
                    if (map.containsKey(key))
                        return null
                    map[key] = fromCbor(this) ?: return null
                }
                when {
                    map.keys.all { it is CborTextString } ->
                        CborTextStringMap(map.mapKeys { (it.key as CborTextString).value })
                    map.keys.all { it is CborLong } ->
                        CborLongMap(map.mapKeys { (it.key as CborLong).value })
                    else -> CborMap(map)
                }
            }
            MajorType.SIMPLE.value -> {
                when (additionalInfo) {
                    in 0..19 -> CborSimpleValue(
                        additionalInfo.toUByte()
                    )
                    20.toByte() -> CborBoolean(false)
                    21.toByte() -> CborBoolean(true)
                    22.toByte() -> CborNull
                    23.toByte() -> CborUndefined
                    24.toByte() ->
                        CborSimpleValue(value.toUByte()).takeUnless { value < 32.toULong() }
                    // TODO: Support half-precision floating point numbers.
                    25.toByte() -> CborUndefined
                    26.toByte() -> CborFloatingPointNumber(
                        Float.fromBits(
                            value.toInt()
                        ).toDouble()
                    )
                    27.toByte() -> CborFloatingPointNumber(
                        Double.fromBits(
                            value.toLong()
                        )
                    )
                    else -> null
                }
            }
            else -> null
        }
    }
}

@ExperimentalUnsignedTypes
private fun Iterator<Byte>.nextInteger(numBytes: Int): ULong? {
    var value: ULong = 0U
    require(numBytes in 1..8)
    repeat(numBytes) {
        if (!hasNext())
            return null
        value = (value shl 8) + next().toUByte().toULong()
    }
    return value
}

