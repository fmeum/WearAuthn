package me.henneke.wearauthn.fido.ctap2

import io.kotlintest.shouldBe
import io.kotlintest.specs.StringSpec


@ExperimentalUnsignedTypes
private fun ByteArray.hex() = joinToString("") {
    it.toUByte().toString(16).padStart(2, '0')
}

@ExperimentalUnsignedTypes
class CborEncodingTests : StringSpec({
    "Non-negative integers encode correctly" {
        CborLong(0).toCbor().hex() shouldBe "00"
        CborLong(1).toCbor().hex() shouldBe "01"
        CborLong(10).toCbor().hex() shouldBe "0a"
        CborLong(23).toCbor().hex() shouldBe "17"
        CborLong(24).toCbor().hex() shouldBe "1818"
        CborLong(25).toCbor().hex() shouldBe "1819"
        CborLong(100).toCbor().hex() shouldBe "1864"
        CborLong(1000).toCbor().hex() shouldBe "1903e8"
        CborLong(1000000).toCbor().hex() shouldBe "1a000f4240"
        CborLong(1000000000000).toCbor().hex() shouldBe "1b000000e8d4a51000"
        CborLong(Long.MAX_VALUE).toCbor().hex() shouldBe "1b7fffffffffffffff"
        CborUnsignedInteger(ULong.MAX_VALUE).toCbor().hex() shouldBe "1bffffffffffffffff"
    }

    "Negative integers encode correctly" {
        CborLong(-1).toCbor().hex() shouldBe "20"
        CborLong(-10).toCbor().hex() shouldBe "29"
        CborLong(-100).toCbor().hex() shouldBe "3863"
        CborLong(-1000).toCbor().hex() shouldBe "3903e7"
        CborNegativeInteger(Long.MAX_VALUE.toULong()).toCbor().hex() shouldBe "3b7fffffffffffffff"
        CborNegativeInteger(ULong.MAX_VALUE.toULong()).toCbor().hex() shouldBe "3bffffffffffffffff"
    }

    "Booleans should encode correctly" {
        CborBoolean(false).toCbor().hex() shouldBe "f4"
        CborBoolean(true).toCbor().hex() shouldBe "f5"
    }

    "null should encode correctly" {
        CborNull.toCbor().hex() shouldBe "f6"
    }

    "undefined should encode correctly" {
        CborUndefined.toCbor().hex() shouldBe "f7"
    }

    "Byte strings should encode correctly" {
        CborByteString(byteArrayOf()).toCbor().hex() shouldBe "40"
        CborByteString(byteArrayOf(0x01, 0x02, 0x03, 0x04)).toCbor().hex() shouldBe "4401020304"
    }

    "Text strings should encode correctly" {
        CborTextString("").toCbor().hex() shouldBe "60"
        CborTextString("a").toCbor().hex() shouldBe "6161"
        CborTextString("IETF").toCbor().hex() shouldBe "6449455446"
        CborTextString("\u6c34").toCbor().hex() shouldBe "63e6b0b4"
        CborTextString("\ud800\udd51").toCbor().hex() shouldBe "64f0908591"
    }

    "Maps should encode correctly" {
        CborLongMap(mapOf()).toCbor().hex() shouldBe "a0"
        CborTextStringMap(mapOf()).toCbor().hex() shouldBe "a0"
        CborLongMap(mapOf(3L to CborLong(4), 1L to CborLong(2))).toCbor().hex() shouldBe "a201020304"
    }
})

