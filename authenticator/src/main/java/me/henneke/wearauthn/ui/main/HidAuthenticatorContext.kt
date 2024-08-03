package me.henneke.wearauthn.ui.main

import android.app.Activity
import android.content.DialogInterface
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import me.henneke.wearauthn.R
import me.henneke.wearauthn.breakAt
import me.henneke.wearauthn.fido.context.AuthenticatorContext
import me.henneke.wearauthn.fido.context.AuthenticatorSpecialStatus
import me.henneke.wearauthn.fido.context.AuthenticatorStatus
import me.henneke.wearauthn.fido.context.RequestInfo
import me.henneke.wearauthn.fido.hid.HID_USER_PRESENCE_TIMEOUT_MS
import me.henneke.wearauthn.ui.TimedAcceptDenyDialog
import kotlin.coroutines.resume

@ExperimentalUnsignedTypes
class HidAuthenticatorContext(private val activity: Activity) :
    AuthenticatorContext(activity, isHidTransport = true) {
    override fun notifyUser(info: RequestInfo) {
        // No-op for HID transport since we already asked for confirmation during
        // confirmWithUser
    }

    override fun handleSpecialStatus(specialStatus: AuthenticatorSpecialStatus) {
        // No-op for HID transport since we always ask for confirmation before encountering
        // a special status.
    }

    /**
     * Returns true if the user confirms the request, false if the user denies it explicitly and
     * null if the confirmation dialog times out.
     */
    override suspend fun confirmRequestWithUser(info: RequestInfo): Boolean? {
        return try {
            status = AuthenticatorStatus.WAITING_FOR_UP
            withContext(Dispatchers.Main) {
                val dialog =
                    TimedAcceptDenyDialog(activity).apply {
                        create()
                        setIcon(R.drawable.ic_launcher_outline)
                        setMessage(info.confirmationPrompt)
                        setTimeout(HID_USER_PRESENCE_TIMEOUT_MS)
                        setVibrateOnShow(true)
                        setWakeOnShow(true)
                    }
                suspendCancellableCoroutine { continuation ->
                    dialog.apply {
                        setPositiveButton { _, _ -> continuation.resume(true) }
                        setNegativeButton { _, _ -> continuation.resume(false) }
                        setTimeoutListener { continuation.resume(null) }
                    }.show()
                    continuation.invokeOnCancellation {
                        dialog.dismiss()
                    }
                }
            }
        } finally {
            status = AuthenticatorStatus.PROCESSING
        }
    }

    override suspend fun confirmTransactionWithUser(rpId: String, prompt: String): String? {
        return try {
            status = AuthenticatorStatus.WAITING_FOR_UP
            withContext(Dispatchers.Main) {
                val dialog =
                    TimedAcceptDenyDialog(activity).apply {
                        create()
                        setIcon(R.drawable.ic_launcher_outline)
                        setTitle(rpId)
                        setMessage(prompt)
                        setTimeout(HID_USER_PRESENCE_TIMEOUT_MS)
                        setVibrateOnShow(true)
                        setWakeOnShow(true)
                    }
                suspendCancellableCoroutine { continuation ->
                    dialog.apply {
                        setPositiveButton { _, _ ->
                            val lineBreaks = messageLineBreaks
                            if (lineBreaks == null)
                                continuation.resume(null)
                            else
                                continuation.resume(prompt.breakAt(lineBreaks))
                        }
                        setNegativeButton { _, _ ->
                            continuation.resume(null)
                        }
                    }.show()
                    continuation.invokeOnCancellation {
                        dialog.dismiss()
                    }
                }
            }
        } finally {
            status = AuthenticatorStatus.PROCESSING
        }
    }
}
