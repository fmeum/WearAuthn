package me.henneke.wearauthn.ui.main

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothProfile
import android.content.ComponentName
import android.content.DialogInterface
import android.content.Intent
import android.os.Bundle
import android.support.wearable.activity.WearableActivity
import android.support.wearable.complications.ComplicationProviderService
import android.support.wearable.complications.ProviderUpdateRequester
import android.text.Html
import android.text.TextUtils
import android.text.format.DateFormat
import android.util.Log
import android.view.View
import kotlinx.android.synthetic.main.activity_authenticator_attached.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import me.henneke.wearauthn.R
import me.henneke.wearauthn.breakAt
import me.henneke.wearauthn.bthid.*
import me.henneke.wearauthn.complication.ShortcutComplicationProviderService
import me.henneke.wearauthn.fido.context.AuthenticatorContext
import me.henneke.wearauthn.fido.context.AuthenticatorSpecialStatus
import me.henneke.wearauthn.fido.context.AuthenticatorStatus
import me.henneke.wearauthn.fido.context.RequestInfo
import me.henneke.wearauthn.fido.hid.HID_USER_PRESENCE_TIMEOUT_MS
import me.henneke.wearauthn.fido.hid.TransactionManager
import me.henneke.wearauthn.ui.TimedAcceptDenyDialog
import me.henneke.wearauthn.ui.openUrlOnPhone
import java.util.*
import kotlin.coroutines.resume

private const val TAG = "AuthenticatorAttachedActivity"

@ExperimentalUnsignedTypes
class AuthenticatorAttachedActivity : WearableActivity() {

    private var transactionManager: TransactionManager? = null
    private var hidDeviceProfile: HidDeviceProfile? = null

    private lateinit var viewsToHideOnAmbient: List<View>

    @ExperimentalCoroutinesApi
    private val hidIntrDataListener = object : HidIntrDataListener {
        override fun onIntrData(
            device: BluetoothDevice,
            reportId: Byte,
            data: ByteArray,
            host: InputHostWrapper
        ) {
            transactionManager?.handleReport(data) {
                for (rawReport in it) {
                    host.sendReport(device, reportId.toInt(), rawReport)
                }
            }
        }
    }

    private val hidProfileListener = object : HidDataSender.ProfileListener {
        override fun onDeviceStateChanged(device: BluetoothDevice, state: Int) {
            when (state) {
                BluetoothProfile.STATE_DISCONNECTING, BluetoothProfile.STATE_DISCONNECTED -> {
                    finish()
                }
                BluetoothProfile.STATE_CONNECTING -> {
                    val connectingToDeviceMessage =
                        getString(
                            R.string.connecting_to_device_message,
                            TextUtils.htmlEncode(device.identifier)
                        )
                    connectedToDeviceView.text =
                        Html.fromHtml(connectingToDeviceMessage, Html.FROM_HTML_MODE_LEGACY)
                }
                BluetoothProfile.STATE_CONNECTED -> {
                    val connectedToDeviceMessage =
                        getString(
                            R.string.connected_to_device_message,
                            TextUtils.htmlEncode(device.identifier)
                        )
                    connectedToDeviceView.text =
                        Html.fromHtml(connectedToDeviceMessage, Html.FROM_HTML_MODE_LEGACY)
                }
            }
        }

        override fun onAppUnregistered() {}

        override fun onServiceStateChanged(proxy: BluetoothProfile?) {}
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_authenticator_attached)

        setAmbientEnabled()
        viewsToHideOnAmbient = listOf(explanationView, setupOpenOnPhoneButton)
        textClock.paint.isAntiAlias = false

        setupOpenOnPhoneButton.setOnClickListener {
            openUrlOnPhone(this, getString(R.string.url_setup))
        }

        authenticatorContext.commitContext(this)
    }

    @ExperimentalCoroutinesApi
    override fun onStart() {
        super.onStart()

        if (!isBluetoothEnabled) {
            startActivityForResult(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE), 1)
        }

        transactionManager = TransactionManager(authenticatorContext)
        hidDeviceProfile = HidDataSender.register(this, hidProfileListener, hidIntrDataListener)
        if (hidDeviceProfile == null) {
            finish()
            return
        }

        if (hidDeviceProfile!!.connectedDevices.isEmpty() && intent.hasExtra(EXTRA_DEVICE)) {
            if (intent.hasExtra(ComplicationProviderService.EXTRA_COMPLICATION_ID)) {
                ProviderUpdateRequester(
                    this,
                    ComponentName(this, ShortcutComplicationProviderService::class.java)
                ).requestUpdateAll()
            }
            val device = intent.getParcelableExtra<BluetoothDevice>(EXTRA_DEVICE)
            if (device == null || device !in defaultAdapter.bondedDevices) {
                startActivity(Intent(this, AuthenticatorActivity::class.java))
                finish()
                return
            }
            // Simulate a change to connecting state for the device to update GUI immediately.
            hidProfileListener.onDeviceStateChanged(device, BluetoothProfile.STATE_CONNECTING)
            HidDataSender.requestConnect(device)
        } else if (hidDeviceProfile!!.connectedDevices.isEmpty()) {
            finish()
        } else {
            check(hidDeviceProfile!!.connectedDevices.size == 1)
            val connectedDevice = hidDeviceProfile!!.connectedDevices[0]
            // Simulate a change to connected state for the currently connected device.
            hidProfileListener.onDeviceStateChanged(
                connectedDevice,
                BluetoothProfile.STATE_CONNECTED
            )
        }
    }

    @ExperimentalCoroutinesApi
    override fun onStop() {
        super.onStop()

        // Do not disconnect if another activity is launched by the authenticator.
        if (authenticatorContext.status != AuthenticatorStatus.IDLE) {
            Log.e(TAG, "onStop() called during authenticator action")
            return
        }

        HidDataSender.requestConnect(null)

        transactionManager = null
        HidDataSender.unregister(hidProfileListener, hidIntrDataListener)
        hidDeviceProfile = null
    }

    override fun onEnterAmbient(ambientDetails: Bundle?) {
        super.onEnterAmbient(ambientDetails)
        connectedToDeviceView.paint.isAntiAlias = false
        for (view in viewsToHideOnAmbient) {
            view.visibility = View.INVISIBLE
        }
        textClock.visibility = View.VISIBLE
        updateTime()
    }

    private fun updateTime() {
        textClock.text = DateFormat.getTimeFormat(this).format(Date())
    }

    override fun onUpdateAmbient() {
        super.onUpdateAmbient()
        updateTime()
    }

    override fun onExitAmbient() {
        super.onExitAmbient()
        connectedToDeviceView.paint.isAntiAlias = true
        for (view in viewsToHideOnAmbient) {
            view.visibility = View.VISIBLE
        }
        textClock.visibility = View.INVISIBLE
    }

    private val authenticatorContext =
        object : AuthenticatorContext(isHidTransport = true) {
            override fun notifyUser(info: RequestInfo) {
                // No-op for HID transport since we already asked for confirmation during
                // confirmWithUser
            }

            override fun handleSpecialStatus(specialStatus: AuthenticatorSpecialStatus) {
                // No-op for HID transport since we always ask for confirmation before encountering
                // a special status.
            }

            override suspend fun confirmRequestWithUser(info: RequestInfo): Boolean {
                return try {
                    status = AuthenticatorStatus.WAITING_FOR_UP
                    withContext(Dispatchers.Main) {
                        val dialog =
                            TimedAcceptDenyDialog(this@AuthenticatorAttachedActivity)
                                .apply {
                                    setIcon(R.drawable.ic_launcher_outline)
                                    setMessage(info.confirmationPrompt)
                                    setTimeout(HID_USER_PRESENCE_TIMEOUT_MS)
                                    setVibrateOnShow(true)
                                    setWakeOnShow(true)
                                }
                        suspendCancellableCoroutine<Boolean> { continuation ->
                            dialog.apply {
                                setPositiveButton(DialogInterface.OnClickListener { _, _ ->
                                    continuation.resume(true)
                                })
                                setNegativeButton(DialogInterface.OnClickListener { _, _ ->
                                    continuation.resume(false)
                                })
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
                            TimedAcceptDenyDialog(this@AuthenticatorAttachedActivity)
                                .apply {
                                    setIcon(R.drawable.ic_launcher_outline)
                                    setTitle(rpId)
                                    setMessage(prompt)
                                    setTimeout(HID_USER_PRESENCE_TIMEOUT_MS)
                                    setVibrateOnShow(true)
                                    setWakeOnShow(true)
                                }
                        suspendCancellableCoroutine<String?> { continuation ->
                            dialog.apply {
                                setPositiveButton(DialogInterface.OnClickListener { _, _ ->
                                    val lineBreaks = messageLineBreaks
                                    if (lineBreaks == null)
                                        continuation.resume(null)
                                    else
                                        continuation.resume(prompt.breakAt(lineBreaks))
                                })
                                setNegativeButton(DialogInterface.OnClickListener { _, _ ->
                                    continuation.resume(null)
                                })
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

    companion object {
        public const val EXTRA_DEVICE = "me.henneke.wearauthn.extra.DEVICE"
    }
}
