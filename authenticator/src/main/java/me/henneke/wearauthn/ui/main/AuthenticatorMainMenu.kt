// Based on PairedDevicesFragment.java of WearMouse, which comes with the following copyright notice
// and is licensed under the Apache License, Version 2.0:
// Copyright 2018 Google LLC All Rights Reserved.


package me.henneke.wearauthn.ui.main

import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothProfile
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcManager
import android.os.Bundle
import android.os.Handler
import android.os.ResultReceiver
import android.preference.Preference
import android.preference.PreferenceFragment
import android.preference.SwitchPreference
import android.support.wearable.view.AcceptDenyDialog
import android.text.Html
import android.util.Log
import android.view.View
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import me.henneke.wearauthn.R
import me.henneke.wearauthn.bthid.*
import me.henneke.wearauthn.fido.context.AuthenticatorContext
import me.henneke.wearauthn.fido.context.armUserVerificationFuse
import me.henneke.wearauthn.fido.context.getUserVerificationState
import me.henneke.wearauthn.ui.ConfirmDeviceCredentialActivity
import me.henneke.wearauthn.ui.EXTRA_CONFIRM_DEVICE_CREDENTIAL_RECEIVER
import kotlin.coroutines.CoroutineContext

private const val TAG = "AuthenticatorMainMenu"

@ExperimentalUnsignedTypes
class AuthenticatorMainMenu : PreferenceFragment(), CoroutineScope {

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + SupervisorJob()

    private lateinit var hidDeviceProfile: HidDeviceProfile

    private val bondedDeviceEntries = mutableSetOf<AuthenticatorHostDeviceEntry>()

    private lateinit var bluetoothSettingsPreference: Preference
    private lateinit var discoverableSwitchPreference: SwitchPreference
    private lateinit var nfcSettingsPreference: Preference
    private lateinit var singleFactorModeSwitchPreference: SwitchPreference
    private lateinit var manageCredentialsPreference: Preference

    private val REQUEST_CODE_ENABLE_BLUETOOTH = 1
    private val REQUEST_CODE_MAKE_DISCOVERABLE = 2

    override fun onAttach(context: Context) {
        super.onAttach(context)
        // Crashes if there is no Bluetooth adapter (i.e. in emulator).
        hidDeviceProfile = HidDataSender.register(context, hidProfileListener, null)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        addPreferencesFromResource(R.xml.preferences_authenticator)
    }

    override fun onViewCreated(view: View?, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        bluetoothSettingsPreference =
            findPreference(getString(R.string.preference_bluetooth_settings))
        discoverableSwitchPreference =
            findPreference(getString(R.string.preference_discoverable)) as SwitchPreference
        nfcSettingsPreference = findPreference(getString(R.string.preference_nfc_settings))
        singleFactorModeSwitchPreference =
            findPreference(getString(R.string.preference_single_factor_mode)) as SwitchPreference
        manageCredentialsPreference =
            findPreference(getString(R.string.preference_credential_management))
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
        updateDiscoverableState(BluetoothAdapter.getDefaultAdapter().scanMode)
    }

    override fun onPause() {
        super.onPause()
        context?.unregisterReceiver(bluetoothBroadcastReceiver)
    }

    override fun onDetach() {
        super.onDetach()
        HidDataSender.unregister(hidProfileListener, null)
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

    private fun addEntryForDevice(device: BluetoothDevice) {
        if (!device.canUseAuthenticator)
            return
        AuthenticatorHostDeviceEntry(
            activity!!,
            device,
            hidDeviceProfile
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

    private fun createBondedDeviceEntries() {
        for (device in BluetoothAdapter.getDefaultAdapter().bondedDevices) {
            addEntryForDevice(device)
        }
    }

    private fun clearBondedDeviceEntries() {
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
                    setTitle(R.string.title_nfc_preference)
                    setSummary(R.string.status_nfc_tap_and_enable)
                    onPreferenceClickListener = null
                }
                null -> {
                    icon = null
                    isEnabled = false
                    setTitle(R.string.title_nfc_preference)
                    setSummary(R.string.status_nfc_not_available)
                    setOnPreferenceClickListener { true }
                }
            }
        }
    }

    private fun updateBluetoothStateAndDeviceEntries() {
        clearBondedDeviceEntries()
        bluetoothSettingsPreference.apply {
            when (BluetoothAdapter.getDefaultAdapter().state) {
                BluetoothAdapter.STATE_ON -> {
                    if (hasCompatibleBondedDevice) {
                        summary = null
                    } else {
                        setSummary(R.string.status_bluetooth_tap_and_pair)
                    }
                    onPreferenceClickListener = null
                    createBondedDeviceEntries()
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
            when (BluetoothAdapter.getDefaultAdapter().state) {
                BluetoothAdapter.STATE_ON -> {
                    updateDiscoverableState(BluetoothAdapter.getDefaultAdapter().scanMode)
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

    private fun updateDiscoverableState(scanMode: Int) {
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
                    setSummary(R.string.summary_single_factor_mode_active)
                }
                false -> {
                    isChecked = false
                    if (AuthenticatorContext.isScreenLockEnabled(context)) {
                        isEnabled = true
                        setSummary(R.string.summary_single_factor_mode_available)
                        setOnPreferenceChangeListener { _, _ ->
                            isEnabled = false
                            AcceptDenyDialog(context).run {
                                setTitle(R.string.title_single_factor_mode_prompt)
                                setMessage(
                                    Html.fromHtml(
                                        getString(R.string.message_single_factor_mode_prompt),
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
                        setSummary(R.string.summary_single_factor_mode_enable_lock)
                    }
                }
                null -> {
                    isEnabled = false
                    isChecked = false
                    setSummary(R.string.summary_single_factor_mode_disabled)
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
                summary = getString(R.string.summary_manage_credentials_disabled)
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

    private val hidProfileListener = object : HidDataSender.ProfileListener {
        override fun onAppUnregistered() {
            Log.i(TAG, "onAppUnregistered()")
            activity?.finish()
        }

        override fun onDeviceStateChanged(device: BluetoothDevice, state: Int) {
            Log.i(TAG, "onDeviceStateChanged(${device.name}, $state)")
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
            Log.i(TAG, "onServiceStateChanged($proxy)")
            if (proxy == null) {
                return
            }
            for (entry in bondedDeviceEntries) {
                entry.updateProfileConnectionState()
            }
        }
    }

    private val bluetoothBroadcastReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (context == null || intent == null) {
                Log.w(TAG, "bluetoothBroadcastReceiver received null context or intent")
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
                    val scanMode = intent.getIntExtra(
                        BluetoothAdapter.EXTRA_SCAN_MODE,
                        BluetoothAdapter.SCAN_MODE_NONE
                    )
                    updateDiscoverableState(scanMode)
                }
                BluetoothDevice.ACTION_BOND_STATE_CHANGED -> {
                    removeEntryForDevice(device)
                    if (device.bondState == BluetoothDevice.BOND_BONDED) {
                        addEntryForDevice(device)
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
}
