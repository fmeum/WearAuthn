package me.henneke.wearauthn.bthid.api28

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothHidDevice
import android.bluetooth.BluetoothProfile
import android.os.Build
import androidx.annotation.MainThread
import me.henneke.wearauthn.bthid.HidDeviceProfile
import me.henneke.wearauthn.bthid.canUseAuthenticatorViaBluetooth

/** Wrapper for BluetoothHidDevice profile that manages paired HID Host devices.  */
@TargetApi(Build.VERSION_CODES.P)
@SuppressLint("MissingPermission")
class HidDeviceProfile28(bluetoothAdapter: BluetoothAdapter) : HidDeviceProfile(bluetoothAdapter) {

    private var service: BluetoothHidDevice? = null

    override val connectedDevices: List<BluetoothDevice>
        get() = service?.connectedDevices ?: emptyList()
    override val profileId = BluetoothProfile.HID_DEVICE

    override fun getConnectionState(device: BluetoothDevice): Int {
        return service?.getConnectionState(device) ?: BluetoothProfile.STATE_DISCONNECTED
    }

    override fun connect(device: BluetoothDevice) {
        service?.run {
            if (device.canUseAuthenticatorViaBluetooth) {
                connect(device)
            }
        }
    }

    override fun disconnect(device: BluetoothDevice) {
        service?.run {
            if (device.canUseAuthenticatorViaBluetooth) {
                disconnect(device)
            }
        }
    }

    @MainThread
    override fun getDevicesMatchingConnectionStates(states: IntArray): List<BluetoothDevice> {
        return service?.getDevicesMatchingConnectionStates(states) ?: emptyList()
    }

    override fun onServiceStateChanged(proxy: BluetoothProfile?) {
        service = proxy as? BluetoothHidDevice
        super.onServiceStateChanged(proxy)
    }
}
