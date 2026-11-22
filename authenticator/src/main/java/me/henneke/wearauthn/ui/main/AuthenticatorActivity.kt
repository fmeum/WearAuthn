package me.henneke.wearauthn.ui.main

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothClass
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothProfile
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.nfc.NfcManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import android.provider.Settings
import android.support.wearable.view.AcceptDenyDialog
import android.text.Html
import android.view.View
import android.widget.LinearLayout
import androidx.core.content.ContextCompat
import android.support.wearable.activity.WearableActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import me.henneke.wearauthn.BuildConfig
import me.henneke.wearauthn.R
import me.henneke.wearauthn.bthid.HidDataSender
import me.henneke.wearauthn.bthid.HidDeviceProfile
import me.henneke.wearauthn.bthid.HidIntrDataListener
import me.henneke.wearauthn.bthid.InputHostWrapper
import me.henneke.wearauthn.bthid.canUseAuthenticator
import me.henneke.wearauthn.bthid.identifier
import me.henneke.wearauthn.databinding.ActivityAuthenticatorMainBinding
import me.henneke.wearauthn.databinding.ItemMainRowBinding
import me.henneke.wearauthn.fido.context.AuthenticatorContext
import me.henneke.wearauthn.fido.context.armUserVerificationFuse
import me.henneke.wearauthn.fido.context.getUserVerificationState
import me.henneke.wearauthn.fido.hid.TransactionManager
import me.henneke.wearauthn.sync.UnlockComplicationListenerService
import me.henneke.wearauthn.ui.ConfirmDeviceCredentialActivity
import me.henneke.wearauthn.ui.EXTRA_CONFIRM_DEVICE_CREDENTIAL_RECEIVER
import me.henneke.wearauthn.ui.bluetoothAdapter
import me.henneke.wearauthn.ui.hasBluetoothPermissions
import me.henneke.wearauthn.ui.openPhoneAppOrListing
import me.henneke.wearauthn.ui.showToast
import kotlin.coroutines.CoroutineContext

/**
 * Main screen as a Wear Material 3 Expressive list: 5.2 % side margin, 16.64 % top margin,
 * full-width pill rows that hug their content, 4dp between rows of a group, 8dp under a caption,
 * 16dp between groups. Each row's leading chip carries one of the three accent containers; the
 * only colour outside that system is the green that means "attached".
 */
@Suppress("DEPRECATION")
@ExperimentalUnsignedTypes
class AuthenticatorActivity : WearableActivity(), CoroutineScope {

    private val TAG = "AuthenticatorActivity"

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + SupervisorJob()

    private lateinit var binding: ActivityAuthenticatorMainBinding

    private var hidDeviceProfile: HidDeviceProfile? = null

    /**
     * The main screen owns the CTAP session whenever the attached screen is not in front. That is
     * what keeps an already-attached host usable after the user navigates back: the link is not
     * torn down, and requests from the host still reach a live [TransactionManager].
     */
    private var transactionManager: TransactionManager? = null
    private var hidAuthenticatorContext: HidAuthenticatorContext? = null
    private var attachedActivityLaunched = false
    private var renderScheduled = false
    private var hasUpdatedInAmbientMode = false

    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAuthenticatorMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        // Enable rotary wheel scrolling.
        binding.root.requestFocus()
        registerHidDeviceProfile()
        hidAuthenticatorContext = HidAuthenticatorContext(this)
        transactionManager = TransactionManager(hidAuthenticatorContext!!)
        setAmbientEnabled()
    }

    private fun registerHidDeviceProfile() {
        if (hasBluetoothPermissions && bluetoothAdapter != null && hidDeviceProfile == null) {
            hidDeviceProfile = HidDataSender.register(this, hidProfileListener, null)
        }
    }

    override fun onResume() {
        super.onResume()
        mainHandler.removeCallbacks(releaseRunnable)
        HidScreenState.mainVisible = true
        attachedActivityLaunched = false
        registerReceiver(
            bluetoothBroadcastReceiver, IntentFilter().apply {
                addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
                addAction(BluetoothAdapter.ACTION_SCAN_MODE_CHANGED)
                addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
                addAction(BluetoothDevice.ACTION_CLASS_CHANGED)
                addAction(BluetoothDevice.ACTION_NAME_CHANGED)
            }
        )
        registerHidDeviceProfile()
        // Take over interrupt data while this screen is in front; the attached screen hands it
        // back in onStop.
        HidDataSender.setIoListener(hidIoListener)
        launch {
            AuthenticatorContext.initAuthenticator(applicationContext)
            AuthenticatorContext.refreshCachedWebAuthnCredentialIfNecessary(applicationContext)
        }
        render()
    }

    override fun onStop() {
        super.onStop()
        // Grace period: if the attached screen is taking over, it has already claimed the
        // session and this does nothing. If the user went to the watch face, release it.
        mainHandler.removeCallbacks(releaseRunnable)
        mainHandler.postDelayed(releaseRunnable, RELEASE_GRACE_MS)
    }

    private val releaseRunnable = Runnable {
        if (!HidScreenState.someoneCanHandleRequests) {
            HidDataSender.requestConnect(null)
        }
    }

    override fun onPause() {
        super.onPause()
        HidScreenState.mainVisible = false
        // Release the session so a screen that is taking over (the attached view) can claim it.
        HidDataSender.setIoListener(null)
        try {
            unregisterReceiver(bluetoothBroadcastReceiver)
        } catch (e: IllegalArgumentException) {
            android.util.Log.w(TAG, "Bluetooth receiver was not registered: ${e.message}")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        mainHandler.removeCallbacksAndMessages(null)
        HidDataSender.setIoListener(null)
        transactionManager = null
        hidAuthenticatorContext = null
        if (hidDeviceProfile != null) {
            HidDataSender.unregister(hidProfileListener, null)
            hidDeviceProfile = null
        }
        coroutineContext.cancel()
    }

    override fun onEnterAmbient(ambientDetails: Bundle?) {
        super.onEnterAmbient(ambientDetails)
        hasUpdatedInAmbientMode = false
    }

    override fun onUpdateAmbient() {
        super.onUpdateAmbient()
        // Keep the original behaviour: the list is not worth burning pixels for.
        if (hasUpdatedInAmbientMode) {
            finish()
        } else {
            hasUpdatedInAmbientMode = true
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQUEST_CODE_ATTACHED -> attachedActivityLaunched = false
            REQUEST_CODE_MAKE_DISCOVERABLE -> scheduleRender()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_CODE_REQUEST_BLUETOOTH_PERMISSIONS) {
            if (grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                registerHidDeviceProfile()
                scheduleRender()
            } else {
                showToast(getString(R.string.status_bluetooth_permissions_required))
            }
        }
    }

    // ------------------------------------------------------------------ rendering

    private fun scheduleRender() {
        if (renderScheduled) return
        renderScheduled = true
        mainHandler.post {
            renderScheduled = false
            if (!isFinishing) render()
        }
    }

    private fun render() {
        binding.deviceContainer.removeAllViews()
        binding.actionContainer.removeAllViews()
        renderDevices()
        renderActions()
    }

    private fun tint(id: Int): Int = ContextCompat.getColor(this, id)

    private fun row(
        container: LinearLayout,
        iconRes: Int,
        title: String,
        subtitle: String?,
        chip: Chip,
        showChevron: Boolean = false,
        subtitleColor: Int = tint(R.color.m3_on_surface_variant),
        enabled: Boolean = true,
        onClick: (() -> Unit)? = null
    ): ItemMainRowBinding {
        val item = ItemMainRowBinding.inflate(layoutInflater, container, false)

        item.rowChip.setBackgroundResource(chip.drawable)
        item.rowChip.setBackgroundTintList(ColorStateList.valueOf(tint(chip.container)))
        item.rowIcon.setImageResource(iconRes)
        item.rowIcon.setColorFilter(tint(chip.onContainer))

        item.rowTitle.text = title
        if (subtitle.isNullOrEmpty()) {
            item.rowSubtitle.visibility = View.GONE
        } else {
            item.rowSubtitle.visibility = View.VISIBLE
            item.rowSubtitle.text = subtitle
            item.rowSubtitle.setTextColor(subtitleColor)
        }
        item.rowChevron.visibility = if (showChevron) View.VISIBLE else View.GONE

        item.root.isEnabled = enabled
        item.root.alpha = if (enabled) 1f else 0.45f
        if (enabled && onClick != null) {
            item.root.setOnClickListener { onClick() }
        } else {
            item.root.isClickable = false
        }

        val params = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { bottomMargin = dp(4) }
        container.addView(item.root, params)
        return item
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    /** Phones pair over the same HID profile, so the row has to say which one it is. */
    @SuppressLint("MissingPermission")
    private fun deviceIcon(device: BluetoothDevice): Int =
        when (device.bluetoothClass?.majorDeviceClass) {
            BluetoothClass.Device.Major.PHONE -> R.drawable.ic_phone
            else -> R.drawable.ic_computer
        }

    @SuppressLint("MissingPermission")
    private fun renderDevices() {
        if (!hasBluetoothPermissions) {
            row(
                binding.deviceContainer,
                R.drawable.ic_bluetooth,
                getString(R.string.bluetooth_permissions_explanation),
                getString(R.string.status_bluetooth_permissions_required),
                Chip.PRIMARY,
                showChevron = true
            ) {
                requestPermissions(
                    arrayOf(
                        Manifest.permission.BLUETOOTH_CONNECT,
                        Manifest.permission.BLUETOOTH_SCAN,
                        Manifest.permission.BLUETOOTH_ADVERTISE,
                        Manifest.permission.BLUETOOTH,
                    ),
                    REQUEST_CODE_REQUEST_BLUETOOTH_PERMISSIONS
                )
            }
            return
        }

        when (bluetoothAdapter?.state ?: BluetoothAdapter.STATE_OFF) {
            BluetoothAdapter.STATE_OFF, BluetoothAdapter.STATE_TURNING_OFF -> {
                row(
                    binding.deviceContainer,
                    R.drawable.ic_bluetooth,
                    getString(R.string.preference_bluetooth_settings_title),
                    getString(R.string.status_bluetooth_tap_to_enable),
                    Chip.PRIMARY,
                    showChevron = true
                ) {
                    startActivityForResult(
                        Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE),
                        REQUEST_CODE_ENABLE_BLUETOOTH
                    )
                }
                return
            }

            BluetoothAdapter.STATE_TURNING_ON -> {
                row(
                    binding.deviceContainer,
                    R.drawable.ic_bluetooth,
                    getString(R.string.preference_bluetooth_settings_title),
                    getString(R.string.status_bluetooth_connecting),
                    Chip.PRIMARY
                )
                return
            }
        }

        val devices = bluetoothAdapter?.bondedDevices?.filter { it.canUseAuthenticator } ?: emptyList()
        if (devices.isEmpty()) {
            row(
                binding.deviceContainer,
                R.drawable.ic_computer,
                getString(R.string.main_empty_devices),
                getString(R.string.status_bluetooth_tap_and_pair),
                Chip.PRIMARY,
                showChevron = true
            ) {
                startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
            }
            return
        }

        for (device in devices) {
            val state = hidDeviceProfile?.getConnectionState(device) ?: BluetoothProfile.STATE_DISCONNECTED
            val connected = state == BluetoothProfile.STATE_CONNECTED
            row(
                binding.deviceContainer,
                deviceIcon(device),
                device.identifier,
                when (state) {
                    BluetoothProfile.STATE_CONNECTED -> getString(R.string.status_bluetooth_connected_dot)
                    BluetoothProfile.STATE_CONNECTING -> getString(R.string.status_bluetooth_connecting)
                    else -> null
                },
                if (connected) Chip.CONNECTED else Chip.PRIMARY,
                showChevron = !connected,
                subtitleColor = if (connected) tint(R.color.m3_connected) else tint(R.color.m3_on_surface_variant),
                enabled = state != BluetoothProfile.STATE_CONNECTING
            ) {
                if (state == BluetoothProfile.STATE_CONNECTED) {
                    // The link is already up (it survives returning to this screen); there will
                    // be no CONNECTED event to wait for, so open the session screen directly.
                    openAttached(device)
                } else {
                    HidDataSender.requestConnect(device)
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun renderActions() {
        val userVerificationState = getUserVerificationState(this)
        val scanning = hasBluetoothPermissions &&
            bluetoothAdapter?.scanMode == BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE

        row(
            binding.actionContainer,
            R.drawable.ic_bluetooth,
            getString(R.string.preference_discoverable_title),
            getString(
                if (scanning) R.string.preference_discoverable_summary_on
                else R.string.preference_discoverable_summary_off
            ),
            if (scanning) Chip.CONNECTED else Chip.PRIMARY,
            subtitleColor = if (scanning) tint(R.color.m3_connected) else tint(R.color.m3_on_surface_variant),
            enabled = scanning || (hasBluetoothPermissions && bluetoothAdapter?.isEnabled == true),
            showChevron = !scanning
        ) {
            startActivityForResult(
                Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE).apply {
                    putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 60)
                },
                REQUEST_CODE_MAKE_DISCOVERABLE
            )
        }

        val nfcManager = getSystemService(NfcManager::class.java)
        val nfcEnabled = nfcManager?.defaultAdapter?.isEnabled
        row(
            binding.actionContainer,
            R.drawable.ic_btn_nfc,
            getString(R.string.preference_nfc_title),
            when (nfcEnabled) {
                true -> getString(R.string.status_nfc_explanation)
                false -> getString(R.string.status_nfc_tap_and_enable)
                null -> getString(R.string.status_nfc_not_available)
            },
            Chip.PRIMARY,
            showChevron = nfcEnabled == false,
            enabled = nfcEnabled != null
        ) {
            startActivity(Intent(Settings.ACTION_NFC_SETTINGS))
        }

        row(
            binding.actionContainer,
            R.drawable.ic_key,
            getString(R.string.preference_credential_management_title),
            if (userVerificationState == false) {
                getString(R.string.preference_manage_credentials_summary_disabled)
            } else null,
            Chip.PRIMARY,
            showChevron = userVerificationState != false,
            enabled = userVerificationState != false
        ) {
            startActivity(
                Intent(this, ConfirmDeviceCredentialActivity::class.java).apply {
                    putExtra(
                        EXTRA_CONFIRM_DEVICE_CREDENTIAL_RECEIVER,
                        object : ResultReceiver(Handler()) {
                            override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                                if (resultCode == Activity.RESULT_OK) {
                                    startActivity(
                                        Intent(
                                            this@AuthenticatorActivity,
                                            ResidentCredentialsList::class.java
                                        )
                                    )
                                }
                            }
                        }
                    )
                }
            )
        }

        row(
            binding.actionContainer,
            R.drawable.ic_btn_lock,
            getString(R.string.preference_single_factor_mode_title),
            when (userVerificationState) {
                true -> getString(R.string.preference_single_factor_mode_summary_active)
                false -> if (AuthenticatorContext.isScreenLockEnabled(this)) {
                    getString(R.string.preference_single_factor_mode_summary_available)
                } else {
                    getString(R.string.preference_single_factor_mode_summary_enable_lock)
                }
                null -> getString(R.string.preference_single_factor_mode_summary_disabled)
            },
            if (userVerificationState == true) Chip.CONNECTED else Chip.PRIMARY,
            showChevron = userVerificationState != null &&
                (userVerificationState || AuthenticatorContext.isScreenLockEnabled(this)),
            enabled = userVerificationState != null &&
                (userVerificationState || AuthenticatorContext.isScreenLockEnabled(this))
        ) {
            startActivity(Intent(this, PasswordlessModeActivity::class.java))
        }

        row(
            binding.actionContainer,
            R.drawable.ic_info,
            getString(R.string.preference_about_title),
            BuildConfig.VERSION_NAME,
            Chip.PRIMARY,
            showChevron = true
        ) {
            startActivity(
                Intent(this, AboutActivity::class.java).apply {
                    `package` = BuildConfig.APPLICATION_ID
                }
            )
        }

        val purchased = UnlockComplicationListenerService.isComplicationEnabled(this)
        row(
            binding.actionContainer,
            R.drawable.ic_btn_favorite,
            getString(
                if (purchased) R.string.preference_support_purchased_title
                else R.string.preference_support_not_purchased_title
            ),
            getString(
                if (purchased) R.string.preference_support_purchased_summary
                else R.string.preference_support_not_purchased_summary
            ),
            Chip.PRIMARY,
            showChevron = true
        ) {
            launch { openPhoneAppOrListing(this@AuthenticatorActivity) }
        }
    }

    private enum class Chip(val container: Int, val onContainer: Int, val drawable: Int) {
        PRIMARY(R.color.m3_primary_container, R.color.m3_on_primary_container, R.drawable.bg_chip_primary),
        SECONDARY(R.color.m3_secondary_container, R.color.m3_on_secondary_container, R.drawable.bg_chip_secondary),
        TERTIARY(R.color.m3_tertiary_container, R.color.m3_on_tertiary_container, R.drawable.bg_chip_tertiary),
        CONNECTED(R.color.m3_connected, R.color.m3_connected_container, R.drawable.bg_chip_connected)
    }

    // ------------------------------------------------------------------ listeners

    private val hidIoListener = object : HidIntrDataListener {
        override fun onIntrData(
            device: BluetoothDevice,
            reportId: Byte,
            data: ByteArray,
            host: InputHostWrapper
        ) {
            transactionManager?.handleReport(data) { rawReports ->
                for (rawReport in rawReports) {
                    host.sendReport(device, reportId.toInt(), rawReport)
                }
            }
        }
    }

    private val hidProfileListener = object : HidDataSender.ProfileListener {
        override fun onAppStatusChanged(registered: Boolean) {
            if (!registered) {
                finish()
                return
            }
            scheduleRender()
        }

        override fun onConnectionStateChanged(device: BluetoothDevice, state: Int) {
            scheduleRender()
            if (state == BluetoothProfile.STATE_CONNECTED) {
                openAttached(device)
            }
        }

        override fun onServiceStateChanged(proxy: BluetoothProfile?) {
            scheduleRender()
        }
    }

    private fun openAttached(device: BluetoothDevice) {
        if (attachedActivityLaunched || isFinishing) return
        attachedActivityLaunched = true
        startActivityForResult(
            Intent(this, AuthenticatorAttachedActivity::class.java)
                .apply { putExtra(AuthenticatorAttachedActivity.EXTRA_DEVICE, device) },
            REQUEST_CODE_ATTACHED
        )
    }

    private val bluetoothBroadcastReceiver = object : BroadcastReceiver() {
        @SuppressLint("MissingPermission")
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent == null) return
            // Every advertised change ends up in the same rebuild; the row set is tiny.
            scheduleRender()
        }
    }

    companion object {
        private const val REQUEST_CODE_ENABLE_BLUETOOTH = 1
        private const val REQUEST_CODE_REQUEST_BLUETOOTH_PERMISSIONS = 2
        private const val REQUEST_CODE_MAKE_DISCOVERABLE = 3
        private const val REQUEST_CODE_ATTACHED = 4

    /** Grace period for a screen to take over before an unattended session is released. */
    private const val RELEASE_GRACE_MS = 1_800L
    }
}
