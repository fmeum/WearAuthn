package me.henneke.wearauthn.bthid

import android.bluetooth.BluetoothDevice

/** Wrapper around the final InputHost class to make it mockable.  */
interface InputHostWrapper {
    fun sendReport(device: BluetoothDevice, id: Int, data: ByteArray): Boolean

    fun replyReport(device: BluetoothDevice, type: Byte, id: Byte, data: ByteArray): Boolean

    fun reportError(device: BluetoothDevice, error: Byte): Boolean
}
