// Based on PairedDevicesFragment.java of WearMouse, which comes with the following copyright notice
// and is licensed under the Apache License, Version 2.0:
// Copyright 2018 Google LLC All Rights Reserved.


package me.henneke.wearauthn.ui.main

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothProfile
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.nfc.NfcManager
import android.os.Bundle
import android.os.Handler
import android.os.ResultReceiver
import android.preference.ListPreference
import android.preference.Preference
import android.preference.PreferenceFragment
import android.preference.SwitchPreference
import android.support.wearable.view.AcceptDenyDialog
import android.text.Html
import android.view.View
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import me.henneke.wearauthn.LogLevel
import me.henneke.wearauthn.Logging
import me.henneke.wearauthn.R
import me.henneke.wearauthn.bthid.HidDataSender
import me.henneke.wearauthn.bthid.HidDeviceProfile
import me.henneke.wearauthn.bthid.canUseAuthenticator
import me.henneke.wearauthn.bthid.hasCompatibleBondedDevice
import me.henneke.wearauthn.fido.context.AuthenticatorContext
import me.henneke.wearauthn.fido.context.armUserVerificationFuse
import me.henneke.wearauthn.fido.context.getUserVerificationState
import me.henneke.wearauthn.i
import me.henneke.wearauthn.isDeveloperModeEnabled
import me.henneke.wearauthn.sync.UnlockComplicationListenerService
import me.henneke.wearauthn.ui.ConfirmDeviceCredentialActivity
import me.henneke.wearauthn.ui.EXTRA_CONFIRM_DEVICE_CREDENTIAL_RECEIVER
import me.henneke.wearauthn.ui.bluetoothAdapter
import me.henneke.wearauthn.ui.defaultSharedPreferences
import me.henneke.wearauthn.ui.hasBluetoothPermissions
import me.henneke.wearauthn.ui.openPhoneAppOrListing
import me.henneke.wearauthn.ui.showToast
import me.henneke.wearauthn.w
import kotlin.coroutines.CoroutineContext

@ExperimentalUnsignedTypes
class AuthenticatorMainMenu : PreferenceFragment(), CoroutineScope, Logging {

    override val TAG = "AuthenticatorMainMenu"

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + SupervisorJob()

    private var hidDeviceProfile: HidDeviceProfile? = null

    private val bondedDeviceEntries = mutableSetOf<AuthenticatorHostDeviceEntry>()

    private lateinit var bluetoothSettingsPreference: Preference
    private lateinit var discoverableSwitchPreference: SwitchPreference
    private lateinit var bluetoothPermissionsPreference: Preference
    private lateinit var nfcSettingsPreference: Preference
    private lateinit var singleFactorModeSwitchPreference: SwitchPreference
    private lateinit var manageCredentialsPreference: Preference
    private lateinit var supportPreference: Preference

    override fun onAttach(context: Context) {
        super.onAttach(context)
        registerHidDeviceProfile()
    }

    private fun registerHidDeviceProfile() {
        if (context.hasBluetoothPermissions && context.bluetoothAdapter != null && hidDeviceProfile == null) {
            hidDeviceProfile = HidDataSender.register(context, hidProfileListener, null)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        addPreferencesFromResource(R.xml.preferences_authenticator)
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        // Enable rotary wheel scrolling.
        view?.requestFocus()
    }

    override fun onViewCreated(view: View?, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        bluetoothSettingsPreference =
            findPreference(getString(R.string.preference_bluetooth_settings_key))
        discoverableSwitchPreference =
            findPreference(getString(R.string.preference_discoverable_key)) as SwitchPreference
        bluetoothPermissionsPreference =
            findPreference(getString(R.string.preference_bluetooth_permissions_key))
        bluetoothPermissionsPreference.setOnPreferenceClickListener {
            if (!context.hasBluetoothPermissions) {
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
            true
        }
        nfcSettingsPreference = findPreference(getString(R.string.preference_nfc_settings_key))
        singleFactorModeSwitchPreference =
            findPreference(getString(R.string.preference_single_factor_mode_key)) as SwitchPreference
        manageCredentialsPreference =
            findPreference(getString(R.string.preference_credential_management_key))
        supportPreference = findPreference(getString(R.string.preference_support_key))
    }

    override fun onResume() {
        super.onResume()
        context?.registerReceiver(
            bluetoothBroadcastReceiver, IntentFilter().apply {
                addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
                addAction(BluetoothAdapter.ACTION_SCAN_MODE_CHANGED)
                addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
                addAction(BluetoothDevice.ACTION_CLASS_CHANGED)
                addAction(BluetoothDevice.ACTION_NAME_CHANGED)
            }
        )
        updateBluetoothStateAndDeviceEntries()
        updateNfcState()
        updateUserVerificationPreferencesState()
        updateDiscoverableState()
        supportPreference.apply {
            val askForSupport = !UnlockComplicationListenerService.isComplicationEnabled(context)
            setTitle(if (askForSupport) R.string.preference_support_not_purchased_title else R.string.preference_support_purchased_title)
            setSummary(if (askForSupport) R.string.preference_support_not_purchased_summary else R.string.preference_support_purchased_summary)
            setOnPreferenceClickListener {
                launch {
                    openPhoneAppOrListing(activity!!)
                }
                true
            }
        }
        updateLogLevelSwitcher()
    }

    override fun onPause() {
        super.onPause()
        context?.unregisterReceiver(bluetoothBroadcastReceiver)
    }

    override fun onDetach() {
        super.onDetach()
        if (hidDeviceProfile != null) {
            HidDataSender.unregister(hidProfileListener, null)
            hidDeviceProfile = null
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        when (requestCode) {
            REQUEST_CODE_MAKE_DISCOVERABLE -> {
                if (resultCode != Activity.RESULT_OK) {
                    discoverableSwitchPreference.isChecked = false
                    discoverableSwitchPreference.isEnabled = true
                }
            }
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        when (requestCode) {
            REQUEST_CODE_REQUEST_BLUETOOTH_PERMISSIONS -> {
                if (grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                    updateBluetoothStateAndDeviceEntries()
                    updateDiscoverableState()
                    registerHidDeviceProfile()
                } else {
                    activity.showToast(context.getString(R.string.status_bluetooth_permissions_required))
                }
            }
        }
    }

    private fun addEntryForDevice(device: BluetoothDevice) {
        if (!device.canUseAuthenticator || hidDeviceProfile == null)
            return
        AuthenticatorHostDeviceEntry(
            activity!!,
            device,
            hidDeviceProfile!!
        ).let { entry ->
            bondedDeviceEntries.add(entry)
            preferenceScreen.addPreference(entry)
        }
    }

    private fun findEntryForDevice(device: BluetoothDevice): AuthenticatorHostDeviceEntry? {
        return findPreference(device.address) as AuthenticatorHostDeviceEntry?
    }

    private fun removeEntry(entry: AuthenticatorHostDeviceEntry) {
        preferenceScreen.removePreference(entry)
        bondedDeviceEntries.remove(entry)
    }

    private fun removeEntryForDevice(device: BluetoothDevice) {
        findEntryForDevice(device)?.let { entry -> removeEntry(entry) }
    }

    @SuppressLint("MissingPermission")
    private fun createBluetoothDeviceEntries() {
        if (context.hasBluetoothPermissions) {
            for (device in context.bluetoothAdapter?.bondedDevices ?: emptySet()) {
                addEntryForDevice(device)
            }
        } else {
            preferenceScreen.addPreference(bluetoothPermissionsPreference)
        }
    }

    private fun clearBluetoothDeviceEntries() {
        preferenceScreen.removePreference(bluetoothPermissionsPreference)
        for (entry in bondedDeviceEntries) {
            preferenceScreen.removePreference(entry)
        }
        bondedDeviceEntries.clear()
    }

    private fun updateNfcState() {
        val nfcManager = context.getSystemService(NfcManager::class.java) ?: null
        nfcSettingsPreference.apply {
            when (nfcManager?.defaultAdapter?.isEnabled) {
                true -> {
                    icon = null
                    isEnabled = true
                    title = null
                    setSummary(R.string.status_nfc_explanation)
                    setOnPreferenceClickListener { true }
                }

                false -> {
                    icon = context.getDrawable(R.drawable.ic_btn_settings)
                    isEnabled = true
                    setTitle(R.string.preference_nfc_title)
                    setSummary(R.string.status_nfc_tap_and_enable)
                    onPreferenceClickListener = null
                }

                null -> {
                    icon = null
                    isEnabled = false
                    setTitle(R.string.preference_nfc_title)
                    setSummary(R.string.status_nfc_not_available)
                    setOnPreferenceClickListener { true }
                }
            }
        }
    }

    private fun updateBluetoothStateAndDeviceEntries() {
        clearBluetoothDeviceEntries()
        bluetoothSettingsPreference.apply {
            when (context.bluetoothAdapter?.state ?: BluetoothAdapter.STATE_OFF) {
                BluetoothAdapter.STATE_ON -> {
                    if (context.hasBluetoothPermissions && hasCompatibleBondedDevice) {
                        summary = null
                    } else {
                        setSummary(R.string.status_bluetooth_tap_and_pair)
                    }
                    onPreferenceClickListener = null
                    createBluetoothDeviceEntries()
                    discoverableSwitchPreference.isEnabled = true
                }

                BluetoothAdapter.STATE_OFF, BluetoothAdapter.STATE_TURNING_OFF -> {
                    setSummary(R.string.status_bluetooth_tap_to_enable)
                    setOnPreferenceClickListener {
                        startActivityForResult(
                            Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE),
                            REQUEST_CODE_ENABLE_BLUETOOTH
                        )
                        true
                    }
                    discoverableSwitchPreference.isEnabled = false
                }

                BluetoothAdapter.STATE_TURNING_ON -> {
                    summary = null
                    onPreferenceClickListener = null
                    discoverableSwitchPreference.isEnabled = false
                }
            }
        }
        discoverableSwitchPreference.apply {
            when (context.bluetoothAdapter?.state ?: BluetoothAdapter.STATE_OFF) {
                BluetoothAdapter.STATE_ON -> {
                    updateDiscoverableState()
                    setOnPreferenceClickListener {
                        startActivityForResult(
                            Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE).apply {
                                putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 60)
                            },
                            REQUEST_CODE_MAKE_DISCOVERABLE
                        )
                        it.isEnabled = false
                        true
                    }
                }

                else -> {
                    isEnabled = false
                    isChecked = false
                    onPreferenceClickListener = null
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun updateDiscoverableState() {
        if (!context.hasBluetoothPermissions) {
            discoverableSwitchPreference.isEnabled = false
            discoverableSwitchPreference.isChecked = false
            return
        }
        val scanMode = context.bluetoothAdapter?.scanMode ?: BluetoothAdapter.SCAN_MODE_NONE
        if (scanMode == BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE) {
            discoverableSwitchPreference.isEnabled = false
            discoverableSwitchPreference.isChecked = true
        } else {
            discoverableSwitchPreference.isEnabled = true
            discoverableSwitchPreference.isChecked = false
        }
    }

    private fun updateUserVerificationPreferencesState() {
        val userVerificationState = getUserVerificationState(context)
        singleFactorModeSwitchPreference.apply {
            when (userVerificationState) {
                true -> {
                    isEnabled = false
                    isChecked = true
                    setSummary(R.string.preference_single_factor_mode_summary_active)
                }

                false -> {
                    isChecked = false
                    if (AuthenticatorContext.isScreenLockEnabled(context)) {
                        isEnabled = true
                        setSummary(R.string.preference_single_factor_mode_summary_available)
                        setOnPreferenceChangeListener { _, _ ->
                            isEnabled = false
                            AcceptDenyDialog(context).run {
                                setTitle(R.string.prompt_single_factor_mode_title)
                                setMessage(
                                    Html.fromHtml(
                                        getString(R.string.prompt_single_factor_mode_message),
                                        Html.FROM_HTML_MODE_LEGACY
                                    )
                                )
                                setPositiveButton { _, _ ->
                                    val intent =
                                        Intent(
                                            context,
                                            ConfirmDeviceCredentialActivity::class.java
                                        ).apply {
                                            putExtra(
                                                EXTRA_CONFIRM_DEVICE_CREDENTIAL_RECEIVER,
                                                object : ResultReceiver(Handler()) {
                                                    override fun onReceiveResult(
                                                        resultCode: Int,
                                                        resultData: Bundle?
                                                    ) {
                                                        if (resultCode == Activity.RESULT_OK)
                                                            armUserVerificationFuse(context)
                                                    }
                                                })
                                        }
                                    context.startActivity(intent)
                                }
                                setNegativeButton { _, _ -> updateUserVerificationPreferencesState() }
                                setOnCancelListener { updateUserVerificationPreferencesState() }
                                show()
                            }
                            false
                        }
                    } else {
                        isEnabled = false
                        setSummary(R.string.preference_single_factor_mode_summary_enable_lock)
                    }
                }

                null -> {
                    isEnabled = false
                    isChecked = false
                    setSummary(R.string.preference_single_factor_mode_summary_disabled)
                }
            }
        }
        manageCredentialsPreference.apply {
            if (userVerificationState != false) {
                isEnabled = true
                setIcon(R.drawable.ic_btn_key)
                summary = null
            } else {
                isEnabled = false
                icon = null
                summary = getString(R.string.preference_manage_credentials_summary_disabled)
            }
            setOnPreferenceClickListener {
                val intent =
                    Intent(
                        context,
                        ConfirmDeviceCredentialActivity::class.java
                    ).apply {
                        putExtra(
                            EXTRA_CONFIRM_DEVICE_CREDENTIAL_RECEIVER,
                            object : ResultReceiver(Handler()) {
                                override fun onReceiveResult(
                                    resultCode: Int,
                                    resultData: Bundle?
                                ) {
                                    if (resultCode == Activity.RESULT_OK)
                                        context.startActivity(
                                            Intent(
                                                context,
                                                ResidentCredentialsList::class.java
                                            )
                                        )
                                }
                            })
                    }
                context.startActivity(intent)
                true
            }
        }
    }

    private fun updateLogLevelSwitcher() {
        findPreference(getString(R.string.preference_log_level_key))?.let {
            preferenceScreen.removePreference(it)
        }
        if (!context.isDeveloperModeEnabled)
            return
        preferenceScreen.addPreference(ListPreference(activity!!).apply {
            key = getString(R.string.preference_log_level_key)
            setIcon(R.drawable.ic_btn_bug_report)
            setTitle(R.string.preference_log_level_title)
            order = context.resources.getInteger(R.integer.order_device_list_log_level)
            entries = LogLevel.entries.map { it.name }.asReversed().toTypedArray()
            entryValues = LogLevel.entries.map { it.name }.asReversed().toTypedArray()
            setDefaultValue(LogLevel.Disabled.name)
            setDialogIcon(R.drawable.ic_bug_report)
            setDialogTitle(R.string.preference_log_level_dialog_title)
            summary = context.defaultSharedPreferences.getString(
                getString(R.string.preference_log_level_key),
                LogLevel.Disabled.name
            )
            setOnPreferenceChangeListener { preference, newValue ->
                Logging.init(context.applicationContext, newValue as? String)
                preference.summary = newValue as? String
                true
            }
        })
    }

    private val hidProfileListener = object : HidDataSender.ProfileListener {
        override fun onAppStatusChanged(registered: Boolean) {
            i { "onAppStatusChanged($registered)" }
            if (!registered)
                activity?.finish()
            for (entry in bondedDeviceEntries) {
                entry.updateProfileConnectionState()
            }
        }

        override fun onConnectionStateChanged(device: BluetoothDevice, state: Int) {
            i { "onDeviceStateChanged(_, $state)" }
            findEntryForDevice(device)?.updateProfileConnectionState()
            when (state) {
                BluetoothProfile.STATE_CONNECTED -> {
                    startActivityForResult(
                        Intent(
                            this@AuthenticatorMainMenu.context,
                            AuthenticatorAttachedActivity::class.java
                        ), 1
                    )
                }
            }
        }

        override fun onServiceStateChanged(proxy: BluetoothProfile?) {
            i { "onServiceStateChanged(_)" }
            for (entry in bondedDeviceEntries) {
                entry.updateProfileConnectionState()
            }
        }
    }

    private val bluetoothBroadcastReceiver = object : BroadcastReceiver() {
        @SuppressLint("MissingPermission")
        override fun onReceive(context: Context?, intent: Intent?) {
            if (context == null || intent == null) {
                w { "bluetoothBroadcastReceiver received null context or intent" }
                return
            }
            if (intent.action == BluetoothAdapter.ACTION_STATE_CHANGED) {
                updateBluetoothStateAndDeviceEntries()
                return
            }
            val device =
                intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE) ?: return
            when (intent.action) {
                BluetoothAdapter.ACTION_SCAN_MODE_CHANGED -> {
                    intent.getIntExtra(
                        BluetoothAdapter.EXTRA_SCAN_MODE,
                        BluetoothAdapter.SCAN_MODE_NONE
                    )
                    updateDiscoverableState()
                }

                BluetoothDevice.ACTION_BOND_STATE_CHANGED -> {
                    if (context.hasBluetoothPermissions) {
                        removeEntryForDevice(device)
                        if (device.bondState == BluetoothDevice.BOND_BONDED) {
                            addEntryForDevice(device)
                        }
                    }
                }

                BluetoothDevice.ACTION_CLASS_CHANGED -> {
                    findEntryForDevice(device)?.updateClass()
                }

                BluetoothDevice.ACTION_NAME_CHANGED -> {
                    findEntryForDevice(device)?.updateName()
                }
            }
        }
    }

    companion object {
        private const val REQUEST_CODE_ENABLE_BLUETOOTH = 1
        private const val REQUEST_CODE_MAKE_DISCOVERABLE = 2
        private const val REQUEST_CODE_REQUEST_BLUETOOTH_PERMISSIONS = 3
    }
}
