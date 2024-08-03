package me.henneke.wearauthn.companion.ui.main

import android.app.Activity
import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.map
import androidx.lifecycle.viewModelScope
import com.google.android.gms.wearable.*
import kotlinx.coroutines.cancel
import me.henneke.wearauthn.companion.BillingManager
import me.henneke.wearauthn.companion.BillingManager.WearAuthnInAppProduct
import me.henneke.wearauthn.companion.combineLatestInitialized

class MainViewModel(application: Application) : AndroidViewModel(application),
    MessageClient.OnMessageReceivedListener, CapabilityClient.OnCapabilityChangedListener {

    private val billingManager = BillingManager.getInstance(application)
    private val capabilityClient = Wearable.getCapabilityClient(application.applicationContext)
    private val dataClient = Wearable.getDataClient(application.applicationContext)
    private val messageClient = Wearable.getMessageClient(application.applicationContext)

    init {
        billingManager.connect()
        capabilityClient.addListener(
            this,
            Uri.parse("wear://*/unlock-complication"),
            CapabilityClient.FILTER_LITERAL
        )
        messageClient.addListener(this)
    }

    val isBillingReady
        get() = billingManager.isBillingReady

    val complicationUnlockDetails
        get() = billingManager.productDetailsLiveData[WearAuthnInAppProduct.Complication]
            ?: error("Failed to get details for Complication product")

    private val isWatchAppInstalled = MutableLiveData(false)

    val complicationUnlockStatus
        get() = billingManager.isComplicationUnlockedLiveData.combineLatestInitialized(
            isWatchAppInstalled
        ).map {
            when (it.first) {
                true -> ComplicationUnlockStatus.Purchased
                false -> if (it.second) ComplicationUnlockStatus.Available else ComplicationUnlockStatus.InstallWatchApp
                null -> ComplicationUnlockStatus.Pending
            }
        }

    private val _watchConfirmedUnlock = MutableLiveData<String>()
    val watchConfirmedUnlock: LiveData<String> = _watchConfirmedUnlock

    fun buyComplicationUnlock(activity: Activity) {
        billingManager.launchBillingFlow(activity, WearAuthnInAppProduct.Complication)
    }

    fun unlockComplication() {
        val dataItem = PutDataMapRequest.create("/unlock-complication").run {
            dataMap.putBoolean("complicationUnlockPurchased", true)
            dataMap.putLong("timestamp", System.currentTimeMillis())
            asPutDataRequest()
        }.setUrgent()
        dataClient.putDataItem(dataItem)
    }

    fun update() {
        queryWatchAppInstalled()
        billingManager.updatePurchases()
    }

    private fun queryWatchAppInstalled() {
        capabilityClient.getCapability("unlock-complication", CapabilityClient.FILTER_ALL).apply {
            addOnSuccessListener { info ->
                isWatchAppInstalled.postValue(info.nodes.isNotEmpty())
            }
        }
    }

    override fun onCapabilityChanged(info: CapabilityInfo) {
        queryWatchAppInstalled()
    }

    override fun onMessageReceived(messageEvent: MessageEvent) {
        if (messageEvent.path == "/ack-unlock-complication") {
            val model = String(messageEvent.data)
            _watchConfirmedUnlock.postValue(model)
        }
    }

    override fun onCleared() {
        billingManager.disconnect()
        capabilityClient.removeListener(this)
        messageClient.removeListener(this)
        viewModelScope.coroutineContext.cancel()
    }

    enum class ComplicationUnlockStatus {
        Purchased,
        Pending,
        Available,
        InstallWatchApp
    }
}
