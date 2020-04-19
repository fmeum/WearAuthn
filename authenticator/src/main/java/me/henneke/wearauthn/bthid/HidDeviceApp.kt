// Based on HidDeviceApp.java of WearMouse, which comes with the following copyright notice
// and is licensed under the Apache License, Version 2.0:
// Copyright 2018 Google LLC All Rights Reserved.

package me.henneke.wearauthn.bthid

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothProfile
import android.os.Handler
import android.os.Looper

private const val TAG = "HidDeviceApp"

/** Helper class that holds all data about the HID Device's SDP record and wraps data sending.  */
abstract class HidDeviceApp {

    private val mainThreadHandler = Handler(Looper.getMainLooper())

    private var device: BluetoothDevice? = null
    private var deviceStateListener: DeviceStateListener? = null

    protected var ioListener: HidIntrDataListener? = null
    protected abstract val inputHost: InputHostWrapper?

    var isRegistered: Boolean = false
        private set

    /** Used to call back when a device connection state has changed.  */
    interface DeviceStateListener {
        /**
         * Callback that receives the new device connection state.
         *
         * @param device Device that was connected or disconnected.
         * @param state New connection state, see [BluetoothProfile.EXTRA_STATE].
         */
        fun onDeviceStateChanged(device: BluetoothDevice, state: Int)

        /** Callback that receives the app events.  */
        fun onAppStatusChanged(registered: Boolean)
    }

    /**
     * Start listening for device connection state changes.
     *
     * @param listener Callback that will receive the new device connection state.
     */
    internal fun registerDeviceListener(listener: DeviceStateListener) {
        deviceStateListener = listener
    }

    /** Stop listening for device connection state changes.  */
    internal fun unregisterDeviceListener() {
        deviceStateListener = null
    }

    internal fun registerIoListener(listener: HidIntrDataListener) {
        ioListener = listener
    }

    internal fun unregisterIoListener() {
        ioListener = null
    }

    /**
     * Register the HID Device's SDP record.
     *
     * @param inputHost Interface for managing the paired HID Host devices and sending the data.
     */
    abstract fun registerApp(inputHost: BluetoothProfile)

    /** Unregister the HID Device's SDP record.  */
    abstract fun unregisterApp()

    /**
     * Notify that we have a new HID Host to send the data to.
     *
     * @param device New device or `null` if we should stop sending any data.
     */
    fun setDevice(device: BluetoothDevice?) {
        this.device = device
    }

    fun onConnectionStateChanged(device: BluetoothDevice, state: Int) {
        mainThreadHandler.post { deviceStateListener?.onDeviceStateChanged(device, state) }
    }

    fun onAppStatusChanged(registered: Boolean) {
        isRegistered = registered
        mainThreadHandler.post { deviceStateListener?.onAppStatusChanged(registered) }
    }

}

