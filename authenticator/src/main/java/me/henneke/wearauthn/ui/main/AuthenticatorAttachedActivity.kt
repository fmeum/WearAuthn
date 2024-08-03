package me.henneke.wearauthn.ui.main

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothProfile
import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.support.wearable.activity.WearableActivity
import android.support.wearable.complications.ComplicationProviderService
import android.support.wearable.complications.ProviderUpdateRequester
import android.text.Html
import android.text.TextUtils
import android.text.format.DateFormat
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
import me.henneke.wearauthn.bthid.isBluetoothEnabled
import me.henneke.wearauthn.complication.ShortcutComplicationProviderService
import me.henneke.wearauthn.d
import me.henneke.wearauthn.databinding.ActivityAuthenticatorAttachedBinding
import me.henneke.wearauthn.e
import me.henneke.wearauthn.fido.context.AuthenticatorStatus
import me.henneke.wearauthn.fido.hid.TransactionManager
import me.henneke.wearauthn.i
import me.henneke.wearauthn.ui.openUrlOnPhone
import me.henneke.wearauthn.v
import me.henneke.wearauthn.w
import java.util.Date

@ExperimentalUnsignedTypes
class AuthenticatorAttachedActivity : WearableActivity() {

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

    private val hidProfileListener = object : HidDataSender.ProfileListener {
        override fun onConnectionStateChanged(device: BluetoothDevice, state: Int) {
            when (state) {
                BluetoothProfile.STATE_DISCONNECTING, BluetoothProfile.STATE_DISCONNECTED -> {
                    i { "Disconnecting; finishing" }
                    finish()
                }
                BluetoothProfile.STATE_CONNECTING -> {
                    i { "Connecting..." }
                    val connectingToDeviceMessage =
                        getString(
                            R.string.connecting_to_device_message,
                            TextUtils.htmlEncode(device.identifier)
                        )
                    binding.connectedToDeviceView.text =
                        Html.fromHtml(connectingToDeviceMessage, Html.FROM_HTML_MODE_LEGACY)
                }
                BluetoothProfile.STATE_CONNECTED -> {
                    i { "Connected"}
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAuthenticatorAttachedBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setAmbientEnabled()
        viewsToHideOnAmbient = listOf(binding.explanationView, binding.setupOpenOnPhoneButton)
        binding.textClock.paint.isAntiAlias = false

        binding.setupOpenOnPhoneButton.setOnClickListener {
            openUrlOnPhone(this, getString(R.string.url_setup))
        }

        authenticatorContext = HidAuthenticatorContext(this)
        hidDeviceProfile = HidDataSender.register(this, hidProfileListener, hidIntrDataListener)
    }

    @SuppressLint("MissingPermission")
    override fun onStart() {
        super.onStart()

        if (!isBluetoothEnabled) {
            startActivityForResult(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE), 1)
        }

        transactionManager = TransactionManager(authenticatorContext)
        if (hidDeviceProfile == null) {
            e { "hidDeviceProfile is null" }
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
            e { "Started without connected device or device extra; finishing" }
            finish()
        } else {
            check(hidDeviceProfile!!.connectedDevices.size == 1)
            val connectedDevice = hidDeviceProfile!!.connectedDevices[0]
            // Simulate a change to connected state for the currently connected device to update UI.
            hidProfileListener.onConnectionStateChanged(
                connectedDevice,
                BluetoothProfile.STATE_CONNECTED
            )
        }
    }

    override fun onStop() {
        super.onStop()

        // Do not disconnect if another activity is launched by the authenticator.
        if (authenticatorContext.status != AuthenticatorStatus.IDLE) {
            w { "onStop() called during authenticator action" }
            return
        }

        HidDataSender.requestConnect(null)
        transactionManager = null
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
        HidDataSender.unregister(hidProfileListener, hidIntrDataListener)
    }

    companion object : Logging {
        override val TAG = "AuthenticatorAttachedActivity"
        const val EXTRA_DEVICE = "me.henneke.wearauthn.extra.DEVICE"
    }
}
