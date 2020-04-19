// Based on HidDataSender.java of WearMouse, which comes with the following copyright notice
// and is licensed under the Apache License, Version 2.0:
// Copyright 2018 Google LLC All Rights Reserved.

package me.henneke.wearauthn.bthid

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.util.ArraySet
import androidx.annotation.GuardedBy
import me.henneke.wearauthn.bthid.api28.HidDeviceApp28
import me.henneke.wearauthn.bthid.api28.HidDeviceProfile28

private const val TAG = "HidDataSender"

/** Central point for enabling the HID SDP record and sending all data.  */
object HidDataSender {

    private val hidDeviceApp: HidDeviceApp
    private val hidDeviceProfile: HidDeviceProfile

    init {
        val bluetoothAdapter = BluetoothAdapter.getDefaultAdapter()
        hidDeviceApp = HidDeviceApp28()
        hidDeviceProfile = HidDeviceProfile28(bluetoothAdapter)
    }

    private val lock = Any()

    @GuardedBy("lock")
    private var ioListener: HidIntrDataListener? = null

    @GuardedBy("lock")
    private val profileListeners = ArraySet<ProfileListener>()

    @GuardedBy("lock")
    private var connectedDevice: BluetoothDevice? = null

    @GuardedBy("lock")
    private var waitingForDevice: BluetoothDevice? = null

    @GuardedBy("lock")
    var isAppRegistered: Boolean = false
        private set

    private val managingProfileListener = object : ProfileListener {
        override fun onServiceStateChanged(proxy: BluetoothProfile?) {
            synchronized(lock) {
                if (proxy == null) {
                    if (isAppRegistered) {
                        // Service has disconnected before we could unregister the app.
                        // Notify listeners, update the UI and internal state.
                        onAppStatusChanged(false)
                    }
                } else {
                    hidDeviceApp.registerApp(proxy)
                }
                updateDeviceList()
                for (listener in profileListeners) {
                    listener.onServiceStateChanged(proxy)
                }
            }
        }

        override fun onConnectionStateChanged(device: BluetoothDevice, state: Int) {
            synchronized(lock) {
                when (state) {
                    BluetoothProfile.STATE_CONNECTED -> {
                        // A new connection was established. If we weren't expecting that, it
                        // must be an incoming one. In that case, we shouldn't try to disconnect
                        // from it.
                        waitingForDevice = device
                    }
                    BluetoothProfile.STATE_DISCONNECTED -> {
                        // If we are being disconnected from a device we were waiting to connect to,
                        // we ran into a connection timeout and should stop waiting.
                        if (device == waitingForDevice) {
                            waitingForDevice = null
                        }
                    }
                }
                updateDeviceList()
                for (listener in profileListeners) {
                    listener.onConnectionStateChanged(device, state)
                }
            }
        }

        override fun onAppStatusChanged(registered: Boolean) {
            synchronized(lock) {
                if (registered == isAppRegistered) {
                    // We are already in the correct state.
                    return
                }
                isAppRegistered = registered

                for (listener in profileListeners) {
                    listener.onAppStatusChanged(registered)
                }
                if (registered && waitingForDevice != null) {
                    // Fulfill the postponed request to connect now that the app is registered.
                    requestConnect(waitingForDevice)
                }
            }
        }
    }

    /** Compound interface that listens to both device and service state changes.  */
    interface ProfileListener : HidDeviceApp.DeviceStateListener,
        HidDeviceProfile.ServiceStateListener

    /**
     * Ensure that the HID Device SDP record is registered and start listening for the profile proxy
     * and HID Host connection state changes.
     *
     * @param context Context that is required to get the HID profile proxy.
     * @param profileListener Callback that will receive the profile events.
     * @param ioListener Callback that will receive requests from connected devices.
     * @return Interface for managing the paired HID Host devices.
     */
    fun register(
        context: Context,
        profileListener: ProfileListener,
        ioListener: HidIntrDataListener?
    ): HidDeviceProfile {
        synchronized(lock) {
            if (ioListener != null) {
                this.ioListener = ioListener
                hidDeviceApp.registerIoListener(ioListener)
            }

            if (!profileListeners.add(profileListener)) {
                // This user is already registered
                return hidDeviceProfile
            }
            if (profileListeners.size > 1) {
                // There are already some users
                return hidDeviceProfile
            }

            hidDeviceProfile.registerServiceListener(
                context.applicationContext,
                managingProfileListener
            )
            hidDeviceApp.registerDeviceListener(managingProfileListener)
        }
        return hidDeviceProfile
    }

    /**
     * Stop listening for the profile events. When the last profileListener is unregistered, the SD record
     * for HID Device will also be unregistered.
     *
     * @param profileListener Callback for profile events.
     * @param ioListener Callback for device requests.
     */
    fun unregister(profileListener: ProfileListener, ioListener: HidIntrDataListener?) {
        synchronized(lock) {
            if (this.ioListener == ioListener) {
                this.ioListener = null
                hidDeviceApp.unregisterIoListener()
            }

            if (!profileListeners.remove(profileListener)) {
                // This user was removed before
                return
            }
            if (!profileListeners.isEmpty()) {
                // Some users are still left
                return
            }

            hidDeviceApp.unregisterDeviceListener()

            for (device in hidDeviceProfile.connectedDevices) {
                hidDeviceProfile.disconnect(device)
            }

            hidDeviceApp.setDevice(null)
            hidDeviceApp.unregisterApp()

            hidDeviceProfile.unregisterServiceListener()

            connectedDevice = null
            waitingForDevice = null
        }
    }

    /**
     * Initiate connection sequence for the specified HID Host. If another device is already
     * connected, it will be disconnected first. If the parameter is `null`, then the service
     * will only disconnect from the current device.
     *
     * @param device New HID Host to connect to or `null` to disconnect.
     */
    fun requestConnect(device: BluetoothDevice?) {
        waitingForDevice = device
        if (!isAppRegistered) {
            // Request will be fulfilled as soon as the app becomes registered.
            return
        }

        connectedDevice = null
        updateDeviceList()

        if (device != null && device == connectedDevice) {
            for (listener in profileListeners) {
                listener.onConnectionStateChanged(device, BluetoothProfile.STATE_CONNECTED)
            }
        }
    }

    private fun updateDeviceList() {
        var connected: BluetoothDevice? = null

        // If we are connected to some device, but want to connect to another (or disconnect
        // completely), then we should disconnect all other devices first.
        for (device in hidDeviceProfile.connectedDevices) {
            if (device == waitingForDevice || device == connectedDevice) {
                connected = device
            } else {
                hidDeviceProfile.disconnect(device)
            }
        }

        // If there is nothing going on, and we want to connect, then do it.
        waitingForDevice?.let {
            if (hidDeviceProfile
                    .getDevicesMatchingConnectionStates(
                        intArrayOf(
                            BluetoothProfile.STATE_CONNECTED,
                            BluetoothProfile.STATE_CONNECTING,
                            BluetoothProfile.STATE_DISCONNECTING
                        )
                    )
                    .isEmpty()
            ) {
                hidDeviceProfile.connect(it)
            }
        }

        if (connectedDevice == null && connected != null) {
            connectedDevice = connected
            waitingForDevice = null
        } else if (connectedDevice != null && connected == null) {
            connectedDevice = null
        }
        hidDeviceApp.setDevice(connectedDevice)
    }


}
