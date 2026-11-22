package me.henneke.wearauthn.tile

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Context
import me.henneke.wearauthn.bthid.canUseAuthenticator
import me.henneke.wearauthn.bthid.canUseAuthenticatorViaBluetooth
import me.henneke.wearauthn.bthid.lastAttachedDeviceAddress
import me.henneke.wearauthn.ui.hasBluetoothPermissions

/**
 * Which host a shortcut should act on. Shared by the tile (to render its label) and by
 * [ShortcutLaunchActivity] (to act on a tap), so what the tile promises is what a tap does.
 *
 * Order: an explicitly stored address (watch face complication instance), then the host last
 * attached to successfully, then "the only usable host" if there happens to be exactly one.
 */
@SuppressLint("MissingPermission")
fun Context.resolveShortcutDevice(explicitAddress: String? = null): BluetoothDevice? {
    if (!hasBluetoothPermissions) return null
    val bonded = getSystemService(BluetoothManager::class.java)?.adapter?.bondedDevices.orEmpty()

    explicitAddress
        ?.takeIf { BluetoothAdapter.checkBluetoothAddress(it) }
        ?.let { address -> bonded.firstOrNull { it.address == address } }
        ?.let { return it }

    lastAttachedDeviceAddress
        ?.let { address -> bonded.firstOrNull { it.address == address } }
        ?.let { return it }

    return bonded
        .filter { it.canUseAuthenticator }
        .filter { it.canUseAuthenticatorViaBluetooth }
        .singleOrNull()
}
