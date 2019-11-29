package me.henneke.wearauthn.bthid

import android.bluetooth.BluetoothDevice

interface HidIntrDataListener {
    fun onIntrData(device: BluetoothDevice, reportId: Byte, data: ByteArray, host: InputHostWrapper)
}