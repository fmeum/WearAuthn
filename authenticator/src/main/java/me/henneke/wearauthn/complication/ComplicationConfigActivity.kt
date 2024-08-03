package me.henneke.wearauthn.complication

import android.annotation.SuppressLint
import android.app.Activity
import android.os.Bundle
import android.preference.Preference
import android.preference.PreferenceFragment
import android.preference.PreferenceScreen
import android.support.wearable.complications.ComplicationProviderService
import android.support.wearable.preference.WearablePreferenceActivity
import me.henneke.wearauthn.R
import me.henneke.wearauthn.bthid.canUseAuthenticator
import me.henneke.wearauthn.bthid.defaultAdapter
import me.henneke.wearauthn.ui.BluetoothDevicePreference
import me.henneke.wearauthn.ui.hasBluetoothPermissions


class ComplicationConfigActivity : WearablePreferenceActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val shortcutPicker = ShortcutPicker().apply {
            arguments = intent.extras
            check(arguments.containsKey(ComplicationProviderService.EXTRA_CONFIG_COMPLICATION_ID)) { "No complication ID provided." }
        }
        startPreferenceFragment(shortcutPicker, false)
    }
}

class ShortcutPicker : PreferenceFragment() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        preferenceScreen = preferenceManager.createPreferenceScreen(context)
        preferenceScreen.setTitle(R.string.preference_screen_title_shortcut_picker)
    }

    override fun onPreferenceTreeClick(
        preferenceScreen: PreferenceScreen?,
        preference: Preference?
    ): Boolean {
        return if (preference != null) {
            ShortcutComplicationProviderService.setDeviceShortcut(
                context,
                arguments.getInt(ComplicationProviderService.EXTRA_CONFIG_COMPLICATION_ID),
                preference.key
            )
            activity.apply {
                setResult(Activity.RESULT_OK)
                finish()
            }
            true
        } else {
            super.onPreferenceTreeClick(preferenceScreen, preference)
        }
    }

    override fun onResume() {
        super.onResume()
        createPreferences()
    }

    override fun onPause() {
        super.onPause()
        clearPreferences()
    }

    @SuppressLint("MissingPermission")
    private fun createPreferences() {
        for (device in if (context.hasBluetoothPermissions) defaultAdapter.bondedDevices else emptySet()) {
            if (!device.canUseAuthenticator)
                continue
            preferenceScreen.addPreference(BluetoothDevicePreference(context, device))
        }
    }

    private fun clearPreferences() {
        preferenceScreen.removeAll()
    }
}
