package me.henneke.wearauthn.companion

import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.WearableListenerService

class LaunchFromWatchListenerService: WearableListenerService() {
    override fun onMessageReceived(event: MessageEvent) {
        if (event.path != "/launch")
            return
        startActivity(packageManager.getLaunchIntentForPackage(BuildConfig.APPLICATION_ID))
    }
}
