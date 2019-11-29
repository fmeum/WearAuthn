@file:Suppress("EXPERIMENTAL_UNSIGNED_LITERALS")

package me.henneke.wearauthn.fido.ctap2

@ExperimentalUnsignedTypes
enum class MajorType(val value: UByte) {
    UNSIGNED_INTEGER(0u),
    NEGATIVE_INTEGER(1u),
    BYTE_STRING(2u),
    TEXT_STRING(3u),
    ARRAY(4u),
    MAP(5u),
    SIMPLE(7u);

    val mask: UByte
        get() = (value.toInt() shl 5).toUByte()
}

@ExperimentalUnsignedTypes
val SIMPLE_VALUE_FALSE = MajorType.SIMPLE.mask or 20u
@ExperimentalUnsignedTypes
val SIMPLE_VALUE_TRUE = MajorType.SIMPLE.mask or 21u
@ExperimentalUnsignedTypes
val SIMPLE_VALUE_NULL = MajorType.SIMPLE.mask or 22u
@ExperimentalUnsignedTypes
val SIMPLE_VALUE_UNDEFINED = MajorType.SIMPLE.mask or 23u
@ExperimentalUnsignedTypes
val SIMPLE_VALUE = MajorType.SIMPLE.mask or 24u
@ExperimentalUnsignedTypes
val SIMPLE_VALUE_DOUBLE = MajorType.SIMPLE.mask or 27u

