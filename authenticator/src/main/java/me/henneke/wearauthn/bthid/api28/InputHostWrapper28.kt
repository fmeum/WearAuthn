package me.henneke.wearauthn.bthid.api28

import android.annotation.TargetApi
import android.bluetooth.*
import android.os.Build
import me.henneke.wearauthn.bthid.Constants
import me.henneke.wearauthn.bthid.InputHostWrapper
import me.henneke.wearauthn.fido.hid.HID_REPORT_DESC

/** Wrapper around the final BluetoothHidDevice class to make it mockable.  */
@TargetApi(Build.VERSION_CODES.P)
class InputHostWrapper28(inputHost: BluetoothProfile) : InputHostWrapper {
    private val sdp = BluetoothHidDeviceAppSdpSettings(
        Constants.SDP_NAME,
        Constants.SDP_DESCRIPTION,
        Constants.SDP_PROVIDER,
        BluetoothHidDevice.SUBCLASS1_COMBO,
        HID_REPORT_DESC
    )

    private val qos = BluetoothHidDeviceAppQosSettings(
        BluetoothHidDeviceAppQosSettings.SERVICE_BEST_EFFORT,
        Constants.QOS_TOKEN_RATE,
        Constants.QOS_TOKEN_BUCKET_SIZE,
        Constants.QOS_PEAK_BANDWIDTH,
        Constants.QOS_LATENCY,
        BluetoothHidDeviceAppQosSettings.MAX
    )

    private val inputHost: BluetoothHidDevice = inputHost as BluetoothHidDevice

    fun registerApp(callback: BluetoothHidDevice.Callback): Boolean {
        return inputHost.registerApp(sdp, null, qos, { it.run() }, callback)
    }

    fun unregisterApp(): Boolean {
        return inputHost.unregisterApp()
    }

    override fun sendReport(device: BluetoothDevice, id: Int, data: ByteArray): Boolean {
        return inputHost.sendReport(device, id, data)
    }

    override fun replyReport(
        device: BluetoothDevice,
        type: Byte,
        id: Byte,
        data: ByteArray
    ): Boolean {
        return inputHost.replyReport(device, type, id, data)
    }

    override fun reportError(device: BluetoothDevice, error: Byte): Boolean {
        return inputHost.reportError(device, error)
    }
}
