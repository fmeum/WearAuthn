package me.henneke.wearauthn.bthid

import me.henneke.wearauthn.fido.hid.HID_REPORT_SIZE

object Constants {
    const val SDP_NAME = "WearAuthn"
    const val SDP_DESCRIPTION = "FIDO2/U2F Security Key"
    const val SDP_PROVIDER = "WearAuthn"
    const val QOS_TOKEN_RATE = 1000
    const val QOS_TOKEN_BUCKET_SIZE = HID_REPORT_SIZE + 1
    const val QOS_PEAK_BANDWIDTH = 2000
    const val QOS_LATENCY = 5000
}
