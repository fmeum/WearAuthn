package me.henneke.wearauthn.ui

import android.app.Activity
import android.app.KeyguardManager
import android.app.NotificationManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.*
import android.preference.PreferenceManager
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.wear.widget.ConfirmationOverlay
import com.google.android.gms.wearable.CapabilityClient
import com.google.android.gms.wearable.Wearable
import com.google.android.wearable.intent.RemoteIntent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.tasks.asDeferred
import kotlinx.coroutines.withContext
import me.henneke.wearauthn.BuildConfig
import me.henneke.wearauthn.R

fun Context.showToast(message: String, duration: Int = Toast.LENGTH_SHORT) {
    Toast.makeText(this, message, duration).show()
}

val Context.keyguardManager
    get() = ContextCompat.getSystemService(this, KeyguardManager::class.java)
val Context.notificationManager
    get() = ContextCompat.getSystemService(this, NotificationManager::class.java)
val Context.powerManager
    get() = ContextCompat.getSystemService(this, PowerManager::class.java)
val Context.vibrator
    get() = ContextCompat.getSystemService(this, Vibrator::class.java)

val Context.defaultSharedPreferences: SharedPreferences
    get() = PreferenceManager.getDefaultSharedPreferences(this)

fun Context.sharedPreferences(name: String): SharedPreferences =
    getSharedPreferences(name, Context.MODE_PRIVATE)

fun openUrlOnPhone(activity: Activity, url: String) {
    RemoteIntent.startRemoteActivity(
        activity,
        Intent(Intent.ACTION_VIEW)
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .setData(Uri.parse(url)),
        null
    )
    ConfirmationOverlay().setType(ConfirmationOverlay.OPEN_ON_PHONE_ANIMATION)
        .setMessage(activity.getString(R.string.message_continue_on_phone))
        .showOn(activity)
}

fun openPlayStoreListingOnPhone(activity: Activity) {
    RemoteIntent.startRemoteActivity(
        activity,
        Intent(Intent.ACTION_VIEW)
            .setPackage("com.android.vending")
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .setData(Uri.parse("https://play.google.com/store/apps/details?id=${BuildConfig.APPLICATION_ID}")),
        null
    )
    ConfirmationOverlay().setType(ConfirmationOverlay.OPEN_ON_PHONE_ANIMATION)
        .setMessage(activity.getString(R.string.message_continue_on_phone))
        .showOn(activity)
}

suspend fun openPhoneAppOrListing(activity: Activity) {
    val info = Wearable.getCapabilityClient(activity)
        .getCapability("phone-app", CapabilityClient.FILTER_ALL).asDeferred().await()
    if (info.nodes.isEmpty()) {
        withContext(Dispatchers.Main) {
            openPlayStoreListingOnPhone(activity)
        }
    } else {
        val nodeId = info.nodes.first().id
        Wearable.getMessageClient(activity)
            .sendMessage(nodeId, "/launch", Build.MODEL.toByteArray()).asDeferred().await()
        withContext(Dispatchers.Main) {
            ConfirmationOverlay().setType(ConfirmationOverlay.OPEN_ON_PHONE_ANIMATION)
                .setMessage(activity.getString(R.string.message_continue_on_phone))
                .showOn(activity)
        }
    }
}

fun isDoNotDisturbEnabled(context: Context): Boolean {
    val currentInterruptionFilter = context.notificationManager?.currentInterruptionFilter
    return currentInterruptionFilter != NotificationManager.INTERRUPTION_FILTER_ALL
}

private val WINK_VIBRATION_PATTERN = longArrayOf(0, 250, 250, 250)

fun wink(context: Context) {
    if (isDoNotDisturbEnabled(context))
        return
    context.vibrator?.vibrate(VibrationEffect.createWaveform(WINK_VIBRATION_PATTERN, -1))
}
