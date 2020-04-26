// Based on HidDeviceProfile.java of WearMouse, which comes with the following copyright notice
// and is licensed under the Apache License, Version 2.0:
// Copyright 2018 Google LLC All Rights Reserved.

package me.henneke.wearauthn.bthid

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothProfile
import android.content.Context
import androidx.annotation.MainThread

/** Wrapper for BluetoothInputHost profile that manages paired HID Host devices.  */
abstract class HidDeviceProfile(private val bluetoothAdapter: BluetoothAdapter) {
    private var serviceStateListener: ServiceStateListener? = null
    private var service: BluetoothProfile? = null

    /**
     * Get all devices that are in the "Connected" state.
     *
     * @return Connected devices list.
     */
    internal abstract val connectedDevices: List<BluetoothDevice>

    protected abstract val profileId: Int

    /**
     * Initiate the connection to the profile proxy service.
     *
     * @param context Context that is required to establish the service connection.
     * @param listener Callback that will receive the profile proxy object.
     */
    @MainThread
    internal fun registerServiceListener(context: Context, listener: ServiceStateListener) {
        serviceStateListener = listener
        bluetoothAdapter.getProfileProxy(context.applicationContext, ServiceListener(), profileId)
    }

    /** Close the profile service connection.  */
    internal fun unregisterServiceListener() {
        if (service != null) {
            bluetoothAdapter.closeProfileProxy(profileId, service)
            service = null
        }
        serviceStateListener = null
    }

    /**
     * Examine the device for current connection status.
     *
     * @param device Remote Bluetooth device to examine.
     * @return A Bluetooth profile connection state.
     */
    internal abstract fun getConnectionState(device: BluetoothDevice): Int

    /**
     * Initiate the connection to the remote HID Host device.
     *
     * @param device Device to connect to.
     */
    internal abstract fun connect(device: BluetoothDevice)

    /**
     * Close the connection with the remote HID Host device.
     *
     * @param device Device to disconnect from.
     */
    internal abstract fun disconnect(device: BluetoothDevice)

    /**
     * Get all devices that match one of the specified connection states.
     *
     * @param states List of states we are interested in.
     * @return List of devices that match one of the states.
     */
    internal abstract fun getDevicesMatchingConnectionStates(states: IntArray): List<BluetoothDevice>

    /** Used to call back when a profile proxy connection state has changed.  */
    interface ServiceStateListener {
        /**
         * Callback to receive the new profile proxy object.
         *
         * @param proxy Profile proxy object or `null` if the service was disconnected.
         */
        fun onServiceStateChanged(proxy: BluetoothProfile?)
    }

    private inner class ServiceListener : BluetoothProfile.ServiceListener {
        override fun onServiceConnected(profile: Int, proxy: BluetoothProfile) {
            if (serviceStateListener != null) {
                service = proxy
                onServiceStateChanged(service)
            } else {
                bluetoothAdapter.closeProfileProxy(profileId, proxy)
            }
        }

        override fun onServiceDisconnected(profile: Int) {
            service = null
            onServiceStateChanged(null)
        }
    }

    protected open fun onServiceStateChanged(proxy: BluetoothProfile?) {
        serviceStateListener?.onServiceStateChanged(proxy)
    }
}
