package me.henneke.wearauthn.tile

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import android.util.Log
import me.henneke.wearauthn.R
import me.henneke.wearauthn.ui.main.AuthenticatorActivity
import me.henneke.wearauthn.ui.main.AuthenticatorAttachedActivity

/**
 * Invisible trampoline shared by the tile and the watch face complication.
 *
 * Tiles can only launch an activity by ComponentName (no Parcelable extras), so the device
 * selection is resolved here; the complication additionally passes the address it stored for
 * its own instance (a String, so it survives the trip). The resolution rules live in
 * [resolveShortcutDevice] so the tile can label itself with the same answer.
 */
class ShortcutLaunchActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val target = resolveTargetIntent()
        Log.i(TAG, "Shortcut tap resolved to ${target.component?.shortClassName}")
        startActivity(target)
        if (!target.hasExtra(AuthenticatorAttachedActivity.EXTRA_DEVICE)) {
            Toast.makeText(this, getString(R.string.shortcut_no_device), Toast.LENGTH_SHORT).show()
        }
        finish()
    }

    private fun resolveTargetIntent(): Intent {
        val device = resolveShortcutDevice(intent.getStringExtra(EXTRA_DEVICE_ADDRESS))
        return if (device != null) {
            Intent(this, AuthenticatorAttachedActivity::class.java)
                .putExtra(AuthenticatorAttachedActivity.EXTRA_DEVICE, device)
        } else {
            Intent(this, AuthenticatorActivity::class.java)
        }
    }

    companion object {
        private const val TAG = "ShortcutLaunchActivity"
        const val EXTRA_DEVICE_ADDRESS = "me.henneke.wearauthn.EXTRA_DEVICE_ADDRESS"
    }
}
