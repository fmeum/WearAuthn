package me.henneke.wearauthn.sync

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ComponentName
import android.content.pm.PackageManager
import android.os.Build
import com.google.android.gms.wearable.DataEventBuffer
import com.google.android.gms.wearable.DataMapItem
import com.google.android.gms.wearable.Wearable
import com.google.android.gms.wearable.WearableListenerService
import me.henneke.wearauthn.R
import me.henneke.wearauthn.complication.ShortcutComplicationProviderService
import me.henneke.wearauthn.ui.notificationManager

class UnlockComplicationListenerService : WearableListenerService() {
    private val UNLOCKED_CHANNEL = "UNLOCKED"
    private val COMPLICATION_UNLOCKED_ID = 100

    override fun onCreate() {
        super.onCreate()
        setupNotificationChannel()
    }

    private fun setupNotificationChannel() {
        val name = getString(R.string.name_unlocked_channel)
        val description = getString(R.string.description_unlocked_channel)
        val channel = NotificationChannel(UNLOCKED_CHANNEL, name, NotificationManager.IMPORTANCE_DEFAULT)
        channel.description = description
        notificationManager?.createNotificationChannel(channel)
    }

    @ExperimentalUnsignedTypes
    override fun onDataChanged(dataEvents: DataEventBuffer) {
        dataEvents.map { it.dataItem }
            .forEach { item ->
                if (item.uri.path != "/unlock-complication")
                    return
                val nodeId = item.uri.host ?: return
                val map = DataMapItem.fromDataItem(item)
                val enableComplication = map.dataMap.getBoolean("complicationUnlockPurchased")
                if (enableComplication && !isComplicationEnabled()) {
                    val notification = Notification.Builder(this, UNLOCKED_CHANNEL).run {
                        setSmallIcon(R.drawable.ic_launcher_outline)
                        setContentTitle(getString(R.string.title_complication_unlocked_notification))
                        setContentText(getString(R.string.text_complication_unlocked_notification))
                        build()
                    }
                    notificationManager?.notify(COMPLICATION_UNLOCKED_ID, notification)
                    setComplicationStatus(enableComplication)
                    Wearable.getMessageClient(this)
                        .sendMessage(nodeId, "/ack-unlock-complication", Build.MODEL.toByteArray())
                }
            }
    }

    private fun isComplicationEnabled(): Boolean {
        val component =
            ComponentName(applicationContext, ShortcutComplicationProviderService::class.java)
        return applicationContext.packageManager.getComponentEnabledSetting(component) == PackageManager.COMPONENT_ENABLED_STATE_ENABLED
    }

    private fun setComplicationStatus(enable: Boolean) {
        val component =
            ComponentName(applicationContext, ShortcutComplicationProviderService::class.java)
        val status = if (enable) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        else PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
        applicationContext.packageManager.setComponentEnabledSetting(
            component,
            status,
            PackageManager.DONT_KILL_APP
        )
    }

    companion object {
        private const val TAG = "UnlockComplicationListenerService"
    }

}