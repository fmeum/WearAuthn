package me.henneke.wearauthn.fido.nfc

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.Handler
import android.os.VibrationEffect
import android.widget.Toast
import com.google.android.gms.common.util.Hex
import kotlinx.coroutines.*
import me.henneke.wearauthn.Logging
import me.henneke.wearauthn.R
import me.henneke.wearauthn.d
import me.henneke.wearauthn.fido.ApduException
import me.henneke.wearauthn.fido.CommandApdu
import me.henneke.wearauthn.fido.ResponseApdu
import me.henneke.wearauthn.fido.StatusWord
import me.henneke.wearauthn.fido.context.AuthenticatorContext
import me.henneke.wearauthn.fido.context.AuthenticatorSpecialStatus
import me.henneke.wearauthn.fido.context.AuthenticatorSpecialStatus.RESET
import me.henneke.wearauthn.fido.context.AuthenticatorSpecialStatus.USER_NOT_AUTHENTICATED
import me.henneke.wearauthn.fido.context.RequestInfo
import me.henneke.wearauthn.fido.ctap2.Authenticator
import me.henneke.wearauthn.ui.isDoNotDisturbEnabled
import me.henneke.wearauthn.ui.keyguardManager
import me.henneke.wearauthn.ui.showToast
import me.henneke.wearauthn.ui.vibrator
import me.henneke.wearauthn.v
import java.lang.Runnable
import kotlin.coroutines.CoroutineContext
import me.henneke.wearauthn.fido.u2f.Authenticator as U2fAuthenticator
import me.henneke.wearauthn.fido.u2f.Request as U2fRequest

@ExperimentalUnsignedTypes
class NfcAuthenticatorService : HostApduService(), CoroutineScope {

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + SupervisorJob()

    private val SELECT_FIDO_APDUS = setOf(
        ubyteArrayOf(
            0x00u, 0xA4u, 0x04u, 0x00u, 0x08u, 0xA0u, 0x00u, 0x00u, 0x06u, 0x47u, 0x2Fu, 0x00u,
            0x01u, 0x00u
        ),
        ubyteArrayOf(
            0x00u, 0xA4u, 0x04u, 0x00u, 0x08u, 0xA0u, 0x00u, 0x00u, 0x06u, 0x47u, 0x2Fu, 0x00u,
            0x01u
        )
    )
    private val DESELECT_FIDO_APDU_HEADER = ubyteArrayOf(0x80u, 0x12u, 0x01u, 0x00u)
    private val GET_RESPONSE_APDU_HEADERS = setOf(
        ubyteArrayOf(0x00u, 0xC0u, 0x00u, 0x00u),
        ubyteArrayOf(0x80u, 0xC0u, 0x00u, 0x00u)
    )
    private val CTAP_VERSION_STRING_BYTES = "U2F_V2".toByteArray().asUByteArray()

    private val NFCCTAP_MSG_CHAINING_HEADER = ubyteArrayOf(0x90u, 0x10u, 0x00u, 0x00u)
    private val NFCCTAP_MSG_HEADERS = setOf(
        ubyteArrayOf(0x80u, 0x10u, 0x00u, 0x00u),
        ubyteArrayOf(0x80u, 0x10u, 0x80u, 0x00u) // Indicates support for NFCCTAP_GETRESPONSE
    )

    private val handler = Handler()

    private var isSelected: Boolean = false
    private var lastResponseApdu: ResponseApdu? = null
    private var chainedRequestBuffer = ubyteArrayOf()
    private var onDeactivatedMessage: String? = null
    private var confirmDeviceCredentialOnDeactivated: Boolean = false
    private var vibrationTimeout = Runnable { cancelVibration() }

    private lateinit var authenticatorContext: NfcAuthenticatorContext

    override fun onCreate() {
        super.onCreate()
        authenticatorContext = NfcAuthenticatorContext()
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? {
        // Always allow usage on devices without a secure screen lock.
        if (keyguardManager?.isDeviceLocked == true) {
            notifyUnhandled()
            showToast(getString(R.string.unlock_to_use_nfc))
            return null
        }
        v { "<- ${Hex.bytesToStringUppercase(commandApdu)}" }
        val rawCommandApdu = commandApdu.asUByteArray()
        if (SELECT_FIDO_APDUS.any { rawCommandApdu.contentEquals(it) }) {
            isSelected = true
            initiateVibration()
            lastResponseApdu = null
            chainedRequestBuffer = ubyteArrayOf()
            onDeactivatedMessage = null
            return (CTAP_VERSION_STRING_BYTES + StatusWord.NO_ERROR.value).asByteArray().also {
                v { "-> ${Hex.bytesToStringUppercase(it)}" }
            }
        }
        if (!isSelected) {
            return StatusWord.CONDITIONS_NOT_SATISFIED.value.asByteArray().also {
                v { "-> ${Hex.bytesToStringUppercase(it)}" }
            }
        }
        val apdu = CommandApdu(rawCommandApdu)
        if (apdu.headerEquals(DESELECT_FIDO_APDU_HEADER)) {
            isSelected = false
            return StatusWord.NO_ERROR.value.asByteArray().also {
                v { "-> ${Hex.bytesToStringUppercase(it)}" }
            }
        }
        launch {
            val response = try {
                handleRequestApdu(apdu)
            } catch (error: ApduException) {
                d {
                    "Unable to handle APDU with header ${Hex.bytesToStringUppercase(
                        rawCommandApdu.asByteArray().sliceArray(0..3)
                    )}; returned ${error.statusWord}"
                }
                lastResponseApdu = null
                error.statusWord.value
            }
            v { "-> ${Hex.bytesToStringUppercase(response.asByteArray())}" }
            sendResponseApdu(response.asByteArray())
        }
        resetVibrationTimeout()
        return null
    }

    private suspend fun handleRequestApdu(apdu: CommandApdu): UByteArray {
        if (GET_RESPONSE_APDU_HEADERS.any { apdu.headerEquals(it) }) {
            if (apdu.lc != 0)
                throw ApduException(StatusWord.WRONG_LENGTH)
            lastResponseApdu?.let {
                if (!it.hasNext())
                    throw ApduException(StatusWord.CONDITIONS_NOT_SATISFIED)
                return it.next(apdu.le)
            } ?: throw ApduException(StatusWord.CONDITIONS_NOT_SATISFIED)
        }
        lastResponseApdu = when {
            apdu.headerEquals(NFCCTAP_MSG_CHAINING_HEADER) -> {
                if (chainedRequestBuffer.size + apdu.data.size > 65536)
                    throw ApduException(StatusWord.WRONG_LENGTH)
                chainedRequestBuffer += apdu.data
                ResponseApdu(
                    ubyteArrayOf(),
                    StatusWord.NO_ERROR
                )
            }
            NFCCTAP_MSG_HEADERS.any { apdu.headerEquals(it) } -> {
                if (chainedRequestBuffer.size + apdu.data.size > 65536)
                    throw ApduException(StatusWord.WRONG_LENGTH)
                val ctapRawRequest = (chainedRequestBuffer + apdu.data).asByteArray()
                val ctapRawResponse = Authenticator.handle(authenticatorContext, ctapRawRequest)
                ResponseApdu(
                    ctapRawResponse.asUByteArray(),
                    StatusWord.NO_ERROR
                )
            }
            else -> {
                // Everything else is either a U2F (CTAP1) request or an error.
                val u2fRequest = U2fRequest.parse(apdu)
                val (requestInfo, cont) = U2fAuthenticator.handle(authenticatorContext, u2fRequest)
                if (requestInfo != null)
                    authenticatorContext.notifyUser(requestInfo)
                // User presence is always certain via NFC, always continue
                val u2fResponse = cont()
                Logging.v(U2fAuthenticator.TAG) { "-> $u2fResponse" }
                ResponseApdu(
                    u2fResponse.data,
                    u2fResponse.statusWord
                )
            }
        }
        if (!apdu.headerEquals(NFCCTAP_MSG_CHAINING_HEADER))
            chainedRequestBuffer = ubyteArrayOf()
        return lastResponseApdu!!.next(apdu.le)
    }

    override fun onDeactivated(reason: Int) {
        isSelected = false
        handler.removeCallbacks(vibrationTimeout)
        cancelVibration()

        if (onDeactivatedMessage != null) {
            showOnDeactivatedMessage()
        }
        if (confirmDeviceCredentialOnDeactivated) {
            confirmDeviceCredentialOnDeactivated = false
            launch {
                authenticatorContext.confirmDeviceCredential()
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        coroutineContext.cancelChildren()
    }

    private fun initiateVibration() {
        if (isDoNotDisturbEnabled(this))
            return
        vibrator?.vibrate(VibrationEffect.createOneShot(2_000, VibrationEffect.DEFAULT_AMPLITUDE))
    }

    private fun cancelVibration() {
        vibrator?.cancel()
    }

    private fun resetVibrationTimeout() {
        val alreadySuccessful =
            onDeactivatedMessage != null && !(lastResponseApdu?.hasNext() ?: false)
        if (!alreadySuccessful) {
            handler.removeCallbacks(vibrationTimeout)
            handler.postDelayed(vibrationTimeout, 300)
        }
    }

    private fun showOnDeactivatedMessage() {
        onDeactivatedMessage?.let { showToast(it, Toast.LENGTH_LONG) }
        launch {
            authenticatorContext.refreshCachedWebAuthnCredentialIfNecessary()
        }
    }

    inner class NfcAuthenticatorContext :
        AuthenticatorContext(applicationContext, isHidTransport = false) {

        override fun notifyUser(info: RequestInfo) {
            onDeactivatedMessage = info.successMessage
        }

        override fun handleSpecialStatus(specialStatus: AuthenticatorSpecialStatus) {
            when (specialStatus) {
                RESET -> {
                    onDeactivatedMessage = getString(R.string.reset_via_bluetooth_only)
                }
                USER_NOT_AUTHENTICATED -> {
                    onDeactivatedMessage = getString(R.string.verify_screen_lock_and_retry)
                    confirmDeviceCredentialOnDeactivated = true
                }
            }
        }

        override suspend fun confirmRequestWithUser(info: RequestInfo): Boolean {
            // User presence is always certain with NFC transport.
            return true
        }

        override suspend fun confirmTransactionWithUser(rpId: String, prompt: String): String? {
            throw IllegalStateException("Transaction confirmation not possible via NFC")
        }
    }

    companion object : Logging {
        override val TAG = "NfcAuthenticatorService"
    }
}
