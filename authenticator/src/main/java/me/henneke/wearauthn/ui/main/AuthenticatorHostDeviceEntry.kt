package me.henneke.wearauthn.ui.main

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothProfile
import android.content.Context
import me.henneke.wearauthn.R
import me.henneke.wearauthn.bthid.HidDataSender
import me.henneke.wearauthn.bthid.HidDeviceProfile
import me.henneke.wearauthn.bthid.canUseAuthenticatorViaBluetooth
import me.henneke.wearauthn.ui.BluetoothDevicePreference


class AuthenticatorHostDeviceEntry(context: Context, device: BluetoothDevice, private val hidDeviceProfile: HidDeviceProfile) : BluetoothDevicePreference(context, device) {

    init {
        updateProfileConnectionState()
    }

    fun updateProfileConnectionState() {
        if (!device.canUseAuthenticatorViaBluetooth) {
            return
        }
        when (hidDeviceProfile.getConnectionState(device)) {
            BluetoothProfile.STATE_DISCONNECTED -> {
                isEnabled = true
                summary = null
            }
            BluetoothProfile.STATE_CONNECTING -> {
                isEnabled = false
                setSummary(R.string.status_bluetooth_connecting)
            }
            BluetoothProfile.STATE_CONNECTED -> {
                isEnabled = true
                setSummary(R.string.status_bluetooth_connected)
            }
            BluetoothProfile.STATE_DISCONNECTING -> {
                isEnabled = false
                summary = null
            }
        }
        notifyChanged()
    }

    override fun onClick() {
        HidDataSender.requestConnect(device)
    }
}

