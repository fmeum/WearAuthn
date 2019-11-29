package me.henneke.wearauthn.fido.hid

import me.henneke.wearauthn.fido.StatusWord

const val HID_REPORT_SIZE = 62

val HID_REPORT_DESC = byteArrayOf(
    0x06.toByte(), 0xD0.toByte(), 0xF1.toByte(), // Usage Page (FIDO_USAGE_PAGE, 2 bytes)
    0x09.toByte(), 0x01.toByte(),                // Usage (FIDO_USAGE_U2FHID)
    0xA1.toByte(), 0x01.toByte(),                // Collection (Application)

    0x09.toByte(), 0x20.toByte(),                // Usage (FIDO_USAGE_DATA_IN)
    0x15.toByte(), 0x00.toByte(),                // Logical Minimum (0)
    0x26.toByte(), 0xFF.toByte(), 0x00.toByte(), // Logical Maximum (255, 2 bytes)
    0x75.toByte(), 0x08.toByte(),                // Report Size (8)
    0x95.toByte(), HID_REPORT_SIZE.toByte(),     // Report Count (variable)
    0x81.toByte(), 0x02.toByte(),                // Input (Data, Absolute, Variable)

    0x09.toByte(), 0x21.toByte(),                // Usage (FIDO_USAGE_DATA_OUT)
    0x15.toByte(), 0x00.toByte(),                // Logical Minimum (0)
    0x26.toByte(), 0xFF.toByte(), 0x00.toByte(), // Logical Maximum (255, 2 bytes)
    0x75.toByte(), 0x08.toByte(),                // Report Size (8)
    0x95.toByte(), HID_REPORT_SIZE.toByte(),     // Report Count (variable)
    0x91.toByte(), 0x02.toByte(),                // Output (Data, Absolute, Variable)

    0xC0.toByte()                                // End Collection
)

internal const val INIT_PACKET_PAYLOAD_SIZE = HID_REPORT_SIZE - 7
internal const val CONT_PACKET_PAYLOAD_SIZE = HID_REPORT_SIZE - 5
@ExperimentalUnsignedTypes
internal val MAX_PAYLOAD_LENGTH = (INIT_PACKET_PAYLOAD_SIZE + 128 * CONT_PACKET_PAYLOAD_SIZE).toUInt()

@ExperimentalUnsignedTypes
internal const val INIT_CMD_NONCE_LENGTH: UShort = 8u
internal const val CAPABILITY_WINK: Byte = 0x01
internal const val CAPABILITY_CBOR: Byte = 0x04
internal val INIT_CMD_TRAILER = byteArrayOf(
    2,  // U2FHID protocol version
    0,  // Version - major
    0,  // Version - minor
    0,  // Version - build
    CAPABILITY_CBOR  // Capabilities flag
)

@ExperimentalUnsignedTypes
internal const val BROADCAST_CHANNEL_ID = UInt.MAX_VALUE
internal const val MESSAGE_TYPE_MASK: Byte = 0x80.toByte()
internal const val MESSAGE_TYPE_INIT: Byte = 0x80.toByte()

internal const val HID_CONT_TIMEOUT_MS = 500.toLong()
internal const val HID_MSG_TIMEOUT_MS = 3_000.toLong()
const val HID_USER_PRESENCE_TIMEOUT_MS = 60_000.toLong()
internal const val HID_KEEPALIVE_INTERVAL_MS = 75.toLong()

internal const val COMMAND_MASK: Byte = 0x7F.toByte()

internal enum class CtapHidCommand(val code: Byte) {
    Ping(0x01.toByte()),
    Msg(0x03.toByte()),
    Init(0x06.toByte()),
    Cbor(0x10.toByte()),
    Cancel(0x11.toByte()),
    Keepalive(0x3b.toByte()),
    Error(0x3f.toByte());

    companion object {
        private val map = values().associateBy { it.code }
        fun fromByte(code: Byte) = map[code]
    }
}

internal enum class CtapHidStatus(val code: Byte) {
    PROCESSING(0x01.toByte()),
    UPNEEDED(0x02.toByte());
}

@ExperimentalUnsignedTypes
internal enum class CtapHidError(val code: Byte) {
    None(0),
    InvalidCmd(1),
    InvalidPar(2),
    InvalidLen(3),
    InvalidSeq(4),
    MsgTimeout(5),
    ChannelBusy(6),
    InvalidCid(11),
    Other(127),
}

@ExperimentalUnsignedTypes
internal data class CtapHidException(val error: CtapHidError, val channelId: UInt?) : Throwable()

internal val U2F_LEGACY_VERSION_COMMAND_APDU = byteArrayOf(0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
@ExperimentalUnsignedTypes
internal val U2F_LEGACY_VERSION_RESPONSE = "U2F_V2".toByteArray() + StatusWord.NO_ERROR.value.toByteArray()
