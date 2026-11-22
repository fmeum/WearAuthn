package me.henneke.wearauthn.ui.main

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothProfile
import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.support.wearable.activity.WearableActivity
import android.support.wearable.complications.ComplicationProviderService
import android.support.wearable.complications.ProviderUpdateRequester
import android.text.Html
import android.text.TextUtils
import android.text.format.DateFormat
import android.widget.Toast
import android.view.View
import com.google.android.gms.common.util.Hex
import me.henneke.wearauthn.Logging
import me.henneke.wearauthn.R
import me.henneke.wearauthn.bthid.HidDataSender
import me.henneke.wearauthn.bthid.HidDeviceProfile
import me.henneke.wearauthn.bthid.HidIntrDataListener
import me.henneke.wearauthn.bthid.InputHostWrapper
import me.henneke.wearauthn.bthid.defaultAdapter
import me.henneke.wearauthn.bthid.identifier
import me.henneke.wearauthn.bthid.lastAttachedDeviceAddress
import me.henneke.wearauthn.bthid.rememberAttachedDevice
import me.henneke.wearauthn.bthid.isBluetoothEnabled
import me.henneke.wearauthn.complication.ShortcutComplicationProviderService
import me.henneke.wearauthn.d
import me.henneke.wearauthn.databinding.ActivityAuthenticatorAttachedBinding
import me.henneke.wearauthn.e
import me.henneke.wearauthn.fido.context.AuthenticatorStatus
import me.henneke.wearauthn.fido.hid.TransactionManager
import me.henneke.wearauthn.i
import me.henneke.wearauthn.v
import me.henneke.wearauthn.w
import java.util.Date

@ExperimentalUnsignedTypes
class AuthenticatorAttachedActivity : WearableActivity() {

    private val startedAt = SystemClock.elapsedRealtime()

    private val handler = Handler(Looper.getMainLooper())

    /** Device passed by the tile / watch face trampoline, if this screen was opened by a shortcut. */
    private var shortcutDevice: BluetoothDevice? = null

    /** How many silent reconnects we already attempted for a shortcut launch. */
    private var reconnectAttempts = 0
    private var everConnected = false
    private var activityStopped = false
    private var pendingReconnect: Runnable? = null

    private lateinit var binding: ActivityAuthenticatorAttachedBinding

    private var transactionManager: TransactionManager? = null
    private var hidDeviceProfile: HidDeviceProfile? = null
    private lateinit var authenticatorContext: HidAuthenticatorContext

    private lateinit var viewsToHideOnAmbient: List<View>

    private val hidIntrDataListener = object : HidIntrDataListener {
        override fun onIntrData(
            device: BluetoothDevice,
            reportId: Byte,
            data: ByteArray,
            host: InputHostWrapper
        ) {
            i { "Received report" }
            d { "Report ID: $reportId" }
            v { "<- ${Hex.bytesToStringUppercase(data)}" }
            transactionManager?.handleReport(data) {
                for (rawReport in it) {
                    v { "-> ${Hex.bytesToStringUppercase(rawReport)}" }
                    host.sendReport(device, reportId.toInt(), rawReport)
                }
            }
        }
    }

    private val hidProfileListener: HidDataSender.ProfileListener = object : HidDataSender.ProfileListener {
        override fun onConnectionStateChanged(device: BluetoothDevice, state: Int) {
            when (state) {
                BluetoothProfile.STATE_DISCONNECTING, BluetoothProfile.STATE_DISCONNECTED -> {
                    i { "Disconnected (stopped=$activityStopped, attempts=$reconnectAttempts)" }
                    if (activityStopped) {
                        // Nobody is looking at this screen any more; the main screen owns the
                        // session now, so just get out of the way without touching the link.
                        finish()
                        return
                    }
                    // A shortcut launch can drop right after the first handshake (the HID app
                    // re-registers while the host is still connecting). Retry silently instead of
                    // dumping the user back to the watch face and asking for a second tap.
                    val target = shortcutDevice
                    if (target != null && device == target && reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
                        reconnectAttempts++
                        scheduleReconnect(target)
                        return
                    }
                    if (target != null &&
                        !everConnected &&
                        SystemClock.elapsedRealtime() - startedAt < FAILURE_NOTICE_WINDOW_MS
                    ) {
                        Toast.makeText(
                            this@AuthenticatorAttachedActivity,
                            getString(R.string.shortcut_connect_failed, device.identifier),
                            Toast.LENGTH_LONG
                        ).show()
                    }
                    finish()
                }
                BluetoothProfile.STATE_CONNECTING -> {
                    i { "Connecting..." }
                    showConnecting(device)
                }
                BluetoothProfile.STATE_CONNECTED -> {
                    i { "Connected"}
                    everConnected = true
                    pendingReconnect?.let { handler.removeCallbacks(it) }
                    pendingReconnect = null
                    rememberAttachedDevice(device)
                    binding.statusDot.visibility = View.VISIBLE
                    val connectedToDeviceMessage =
                        getString(
                            R.string.connected_to_device_message,
                            TextUtils.htmlEncode(device.identifier)
                        )
                    binding.connectedToDeviceView.text =
                        Html.fromHtml(connectedToDeviceMessage, Html.FROM_HTML_MODE_LEGACY)
                }
            }
        }

        override fun onAppStatusChanged(registered: Boolean) {
            if (!registered) {
                i { "App no longer registered; finishing" }
                finish()
            }
        }

        override fun onServiceStateChanged(proxy: BluetoothProfile?) {}
    }

    /** Show the "connecting" state without going through the profile listener (avoids a self reference). */
    private fun showConnecting(device: BluetoothDevice) {
        if (!this::binding.isInitialized) return
        binding.statusDot.visibility = View.GONE
        binding.connectedToDeviceView.text = Html.fromHtml(
            getString(R.string.connecting_to_device_message, TextUtils.htmlEncode(device.identifier)),
            Html.FROM_HTML_MODE_LEGACY
        )
    }

    /** Silent retry so a shortcut tap does not need a second tap when the first handshake drops. */
    private fun scheduleReconnect(device: BluetoothDevice) {
        pendingReconnect?.let { handler.removeCallbacks(it) }
        val runnable = Runnable {
            pendingReconnect = null
            if (isFinishing || activityStopped) return@Runnable
            i { "Retrying connection to ${device.identifier}" }
            showConnecting(device)
            HidDataSender.requestConnect(device)
        }
        pendingReconnect = runnable
        handler.postDelayed(runnable, RECONNECT_DELAY_MS)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAuthenticatorAttachedBinding.inflate(layoutInflater)
        setContentView(binding.root)

        shortcutDevice = intent.getParcelableExtra<BluetoothDevice>(EXTRA_DEVICE)

        setAmbientEnabled()
        viewsToHideOnAmbient =
            listOf(binding.statusDot, binding.explanationView)
        binding.textClock.paint.isAntiAlias = false


        authenticatorContext = HidAuthenticatorContext(this)
        hidDeviceProfile = HidDataSender.register(this, hidProfileListener, hidIntrDataListener)
    }

    @SuppressLint("MissingPermission")
    override fun onStart() {
        super.onStart()

        activityStopped = false
        handler.removeCallbacks(releaseRunnable)
        HidScreenState.attachedVisible = true
        HidDataSender.setIoListener(hidIntrDataListener)

        if (!isBluetoothEnabled) {
            startActivityForResult(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE), 1)
        }

        transactionManager = TransactionManager(authenticatorContext)
        if (hidDeviceProfile == null) {
            e { "hidDeviceProfile is null; falling back to the main menu" }
            // Never disappear silently: a tap that cannot attach has to end up somewhere visible.
            startActivity(Intent(this, AuthenticatorActivity::class.java))
            finish()
            return
        }

        if (hidDeviceProfile!!.connectedDevices.isEmpty() && intent.hasExtra(EXTRA_DEVICE)) {
            if (intent.hasExtra(ComplicationProviderService.EXTRA_COMPLICATION_ID)) {
                i { "Updating complication" }
                ProviderUpdateRequester(
                    this,
                    ComponentName(this, ShortcutComplicationProviderService::class.java)
                ).requestUpdateAll()
            }
            val device = intent.getParcelableExtra<BluetoothDevice>(EXTRA_DEVICE)
            if (device == null || device !in defaultAdapter.bondedDevices) {
                i { "No device extra or no longer bonded; finishing" }
                startActivity(Intent(this, AuthenticatorActivity::class.java))
                finish()
                return
            }
            // Simulate a change to connecting state in order to update the UI immediately.
            hidProfileListener.onConnectionStateChanged(device, BluetoothProfile.STATE_CONNECTING)
            HidDataSender.requestConnect(device)
        } else if (hidDeviceProfile!!.connectedDevices.isEmpty()) {
            e { "Started without connected device or device extra; falling back to the main menu" }
            startActivity(Intent(this, AuthenticatorActivity::class.java))
            finish()
        } else {
            check(hidDeviceProfile!!.connectedDevices.size == 1)
            val connectedDevice = hidDeviceProfile!!.connectedDevices[0]
            // Simulate a change to connected state for the currently connected device to update UI.
            hidProfileListener.onConnectionStateChanged(
                connectedDevice,
                BluetoothProfile.STATE_CONNECTED
            )
            // A shortcut may have cached a link that the host has already dropped; asking again
            // is a no-op when it is genuinely up, and repairs the state when it is not.
            shortcutDevice?.let { HidDataSender.requestConnect(it) }
        }
    }

    override fun onStop() {
        super.onStop()

        activityStopped = true
        pendingReconnect?.let { handler.removeCallbacks(it) }
        pendingReconnect = null

        // The link stays up on purpose: returning to the main screen must leave the host able to
        // reach the watch (the main screen keeps its own TransactionManager for that). Only the
        // interrupt-data session moves, so a backgrounded screen never answers twice.
        HidScreenState.attachedVisible = false
        HidDataSender.setIoListener(null)
        transactionManager = null

        // If the main list came up we keep the link (that is the whole point of the handoff).
        // If nobody came up (swiped to the watch face, tile bounced away) the session is
        // released shortly after, as before.
        handler.removeCallbacks(releaseRunnable)
        handler.postDelayed(releaseRunnable, RELEASE_GRACE_MS)
    }

    private val releaseRunnable = Runnable {
        if (!HidScreenState.someoneCanHandleRequests) {
            i { "No screen is visible; releasing the HID session" }
            HidDataSender.requestConnect(null)
        }
    }

    override fun onEnterAmbient(ambientDetails: Bundle?) {
        super.onEnterAmbient(ambientDetails)
        binding.connectedToDeviceView.paint.isAntiAlias = false
        for (view in viewsToHideOnAmbient) {
            view.visibility = View.INVISIBLE
        }
        binding.textClock.visibility = View.VISIBLE
        updateTime()
    }

    private fun updateTime() {
        binding.textClock.text = DateFormat.getTimeFormat(this).format(Date())
    }

    override fun onUpdateAmbient() {
        super.onUpdateAmbient()
        updateTime()
    }

    override fun onExitAmbient() {
        super.onExitAmbient()
        binding.connectedToDeviceView.paint.isAntiAlias = true
        for (view in viewsToHideOnAmbient) {
            view.visibility = View.VISIBLE
        }
        binding.textClock.visibility = View.INVISIBLE
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacksAndMessages(null)
        HidDataSender.unregister(hidProfileListener, hidIntrDataListener)
    }

    companion object : Logging {
        override val TAG = "AuthenticatorAttachedActivity"
        const val EXTRA_DEVICE = "me.henneke.wearauthn.extra.DEVICE"

        /** Silent reconnects allowed for a shortcut launch that drops right after handshake. */
        private const val MAX_RECONNECT_ATTEMPTS = 2
        private const val RECONNECT_DELAY_MS = 1_500L

        /** Only a failure inside this window is reported as "could not connect". */
        private const val FAILURE_NOTICE_WINDOW_MS = 10_000L

        /** Grace period for the main list to come up before an unattended session is released. */
        private const val RELEASE_GRACE_MS = 1_800L
    }
}
