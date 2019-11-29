package me.henneke.wearauthn.complication

import android.app.PendingIntent
import android.bluetooth.BluetoothAdapter
import android.content.Context
import android.content.Intent
import android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK
import android.content.Intent.FLAG_ACTIVITY_NEW_TASK
import android.graphics.drawable.Icon
import android.support.wearable.complications.ComplicationData
import android.support.wearable.complications.ComplicationManager
import android.support.wearable.complications.ComplicationProviderService
import android.support.wearable.complications.ComplicationText
import android.util.Log
import androidx.core.content.edit
import me.henneke.wearauthn.BuildConfig
import me.henneke.wearauthn.R
import me.henneke.wearauthn.bthid.identifier
import me.henneke.wearauthn.ui.defaultSharedPreferences
import me.henneke.wearauthn.ui.main.AuthenticatorAttachedActivity


private const val TAG = "ShortcutComplicationProviderService"

private fun abbreviate(name: String): String {
    if (name.length <= 7) {
        return name
    }
    return "${name.take(3)}…${name.takeLast(3)}"
}

class ShortcutComplicationProviderService : ComplicationProviderService() {

    @ExperimentalUnsignedTypes
    override fun onComplicationUpdate(
        complicationId: Int, dataType: Int, complicationManager: ComplicationManager
    ) {
        Log.i(TAG, "Updating complication $complicationId of type $dataType")

        val deviceShortcut = getDeviceShortcut(this, complicationId)
        val defaultAdapter = BluetoothAdapter.getDefaultAdapter()
        val device =
            if (BluetoothAdapter.checkBluetoothAddress(deviceShortcut))
                defaultAdapter.getRemoteDevice(deviceShortcut)
            else null
        val invalidDevice = device == null || device !in defaultAdapter.bondedDevices

        val launchIntent = if (invalidDevice) {
            packageManager.getLaunchIntentForPackage(BuildConfig.APPLICATION_ID)
        } else {
            Intent(this, AuthenticatorAttachedActivity::class.java)
                .putExtra(AuthenticatorAttachedActivity.EXTRA_DEVICE, device)
                .putExtra(EXTRA_COMPLICATION_ID, complicationId)
                .setFlags(FLAG_ACTIVITY_CLEAR_TASK or FLAG_ACTIVITY_NEW_TASK)
        }

        val complicationPendingIntent = PendingIntent.getActivity(
            this,
            complicationId,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT
        )

        val complicationData = when (dataType) {
            ComplicationData.TYPE_SHORT_TEXT -> {
                val label = if (invalidDevice) "INVALID" else abbreviate(device!!.identifier)
                ComplicationData.Builder(ComplicationData.TYPE_SHORT_TEXT)
                    .setIcon(Icon.createWithResource(this, R.drawable.ic_launcher_outline))
                    .setShortText(ComplicationText.plainText(label))
                    .setTapAction(complicationPendingIntent)
                    .build()
            }
            ComplicationData.TYPE_LONG_TEXT -> {
                val label = if (invalidDevice) "Invalid device" else device!!.identifier
                ComplicationData.Builder(ComplicationData.TYPE_LONG_TEXT)
                    .setIcon(Icon.createWithResource(this, R.drawable.ic_launcher_outline))
                    .setLongText(ComplicationText.plainText(label))
                    .setTapAction(complicationPendingIntent)
                    .build()
            }
            ComplicationData.TYPE_ICON -> {
                ComplicationData.Builder(ComplicationData.TYPE_ICON)
                    .setIcon(Icon.createWithResource(this, R.drawable.ic_launcher_outline))
                    .setTapAction(complicationPendingIntent)
                    .build()
            }
            else -> null
        }

        if (complicationData != null) {
            complicationManager.updateComplicationData(complicationId, complicationData)
        } else {
            complicationManager.noUpdateRequired(complicationId)
        }
    }

    companion object {
        private const val SETTING_DEVICE_SHORTCUT =
            "me.henneke.wearauthn.complication.setting.DEVICE_SHORTCUT_ID_"

        fun setDeviceShortcut(context: Context, complicationId: Int, device: String) {
            context.defaultSharedPreferences.edit {
                putString(SETTING_DEVICE_SHORTCUT + complicationId, device)
            }
        }

        fun getDeviceShortcut(context: Context, complicationId: Int): String? {
            return context.defaultSharedPreferences.getString(
                SETTING_DEVICE_SHORTCUT + complicationId, null
            )
        }
    }
}
