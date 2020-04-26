package me.henneke.wearauthn.bthid.api28

import android.annotation.TargetApi
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothHidDevice
import android.bluetooth.BluetoothProfile
import android.os.Build
import me.henneke.wearauthn.bthid.HidDeviceApp

private const val TAG = "HidDeviceApp28"

/** Helper class that holds all data about the HID Device's SDP record and wraps data sending.  */
@TargetApi(Build.VERSION_CODES.P)
class HidDeviceApp28 : HidDeviceApp() {

    /** Callback to receive the HID Device's SDP record state.  */
    private val callback = object : BluetoothHidDevice.Callback() {
        override fun onAppStatusChanged(pluggedDevice: BluetoothDevice?, registered: Boolean) {
            this@HidDeviceApp28.registered = registered
            this@HidDeviceApp28.onAppStatusChanged(registered)
        }

        override fun onConnectionStateChanged(device: BluetoothDevice, state: Int) {
            this@HidDeviceApp28.onConnectionStateChanged(device, state)
        }

        override fun onGetReport(
            device: BluetoothDevice, type: Byte, id: Byte, bufferSize: Int
        ) {
            inputHost?.reportError(device, BluetoothHidDevice.ERROR_RSP_UNSUPPORTED_REQ)
        }

        override fun onSetReport(device: BluetoothDevice, type: Byte, id: Byte, data: ByteArray) {
            inputHost?.reportError(device, BluetoothHidDevice.ERROR_RSP_SUCCESS)
        }

        override fun onInterruptData(device: BluetoothDevice?, reportId: Byte, data: ByteArray?) {
            inputHost?.let { host ->
                if (device != null && data != null) {
                    ioListener?.onIntrData(device, reportId, data, host)
                }
            }
        }

        // Override methods to prevent logging.
        override fun onSetProtocol(device: BluetoothDevice?, protocol: Byte) {}
        override fun onVirtualCableUnplug(device: BluetoothDevice?) {}
    }

    override var inputHost: InputHostWrapper28? = null
    private var registered: Boolean = false

    override fun registerApp(inputHost: BluetoothProfile) {
        this.inputHost = InputHostWrapper28(inputHost)
        this.inputHost!!.registerApp(callback)
    }

    override fun unregisterApp() {
        inputHost?.run {
            if (registered)
                unregisterApp()
        }
        inputHost = null
    }
}
