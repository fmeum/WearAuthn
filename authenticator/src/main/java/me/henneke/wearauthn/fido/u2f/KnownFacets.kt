package me.henneke.wearauthn.fido.u2f

import com.google.android.gms.common.util.Hex
import me.henneke.wearauthn.sha256Hex

private const val TAG = "KnownFacets"

private val knownFacets = mapOf(
    "https://www.dropbox.com/u2f-app-id.json".sha256Hex() to "Dropbox", // U2F
    "www.dropbox.com".sha256Hex() to "Dropbox", // WebAuthn
    "https://www.gstatic.com/securitykey/origins.json".sha256Hex() to "Google", // U2F
    "google.com".sha256Hex() to "Google", // WebAuthn
    "webauthn.io".sha256Hex() to "WebAuthn.io",
    "demo.yubico.com".sha256Hex() to "YubicoDemo",
    "https://github.com/u2f/trusted_facets".sha256Hex() to "GitHub", // U2F
    "github.com".sha256Hex() to "GitHub" // WebAuthn
)

private val knownDummyRequests: List<ByteArray> = listOf(
    ByteArray(32) {0}, // Firefox challenge & appId
    ByteArray(32) {'A'.toByte()}, // Chrome appId
    ByteArray(32) {'B'.toByte()} // Chrome challenge
)

fun resolveAppIdHash(application: ByteArray): String? {
    val appId = Hex.bytesToStringUppercase(application)
    return knownFacets[appId]
}

fun isDummyRequest(application: ByteArray, challenge: ByteArray): Boolean {
    return knownDummyRequests.any {
        it.contentEquals(application) || it.contentEquals(challenge)
    }
}