package me.henneke.wearauthn.sync

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.google.android.gms.wearable.DataEventBuffer
import com.google.android.gms.wearable.DataMapItem
import com.google.android.gms.wearable.Wearable
import com.google.android.gms.wearable.WearableListenerService
import me.henneke.wearauthn.complication.ShortcutComplicationProviderService

class UnlockComplicationListenerService : WearableListenerService() {
    @ExperimentalUnsignedTypes
    override fun onDataChanged(dataEvents: DataEventBuffer) {
        dataEvents.map { it.dataItem }
            .forEach { item ->
                if (item.uri.path != "/unlock-complication")
                    return
                val nodeId = item.uri.host ?: return
                val map = DataMapItem.fromDataItem(item)
                val enableComplication = map.dataMap.getBoolean("complicationUnlockPurchased")
                if (enableComplication && !isComplicationEnabled) {
                    setComplicationStatus(enableComplication)
                    Wearable.getMessageClient(this)
                        .sendMessage(nodeId, "/ack-unlock-complication", Build.MODEL.toByteArray())
                }
            }
    }

    private val isComplicationEnabled: Boolean
        get() = isComplicationEnabled(applicationContext)

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

        fun isComplicationEnabled(context: Context): Boolean {
            val component =
                ComponentName(context, ShortcutComplicationProviderService::class.java)
            return context.packageManager.getComponentEnabledSetting(component) == PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        }
    }
}