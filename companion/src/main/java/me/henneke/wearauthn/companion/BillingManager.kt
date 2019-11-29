package me.henneke.wearauthn.companion

import android.app.Activity
import android.app.Application
import android.util.Base64
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.android.billingclient.api.*
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

class BillingManager private constructor(private val application: Application) :
    BillingClientStateListener, PurchasesUpdatedListener {

    private lateinit var billingClient: BillingClient

    private val _isComplicationUnlockedLiveData = MutableLiveData<Boolean>(false)
    val isComplicationUnlockedLiveData: LiveData<Boolean?>
        get() = _isComplicationUnlockedLiveData

    private val _skusLiveData = mapOf(
        WearAuthnInAppProduct.Complication to MutableLiveData<SkuDetails>()
    )
    val skusLiveData: Map<WearAuthnInAppProduct, LiveData<SkuDetails>>
        get() = _skusLiveData

    private val _isBillingReady = MutableLiveData<Boolean>(false)
    val isBillingReady: LiveData<Boolean>
        get() = _isBillingReady

    fun connect() {
        billingClient = BillingClient.newBuilder(application.applicationContext).run {
            enablePendingPurchases()
            setListener(this@BillingManager).build()
        }
        if (!billingClient.isReady)
            billingClient.startConnection(this)
    }

    fun disconnect() {
        billingClient.endConnection()
    }

    fun updatePurchases() {
        billingClient.queryPurchases(BillingClient.SkuType.INAPP)?.purchasesList?.forEach {
            process(it)
        }
    }

    fun launchBillingFlow(activity: Activity, product: WearAuthnInAppProduct) {
        if (!billingClient.isReady)
            return

        val skuDetails = skusLiveData[product]?.value
        if (skuDetails == null) {
            Log.e(TAG, "Failed to get SkuDetails for $product")
            return
        }

        val params = BillingFlowParams.newBuilder().run {
            setSkuDetails(skuDetails)
            build()
        }
        billingClient.launchBillingFlow(activity, params)
    }

    private fun updateSkus() {
        if (!billingClient.isReady)
            return

        val params = SkuDetailsParams.newBuilder().run {
            setSkusList(WearAuthnInAppProduct.values().map { it.sku })
            setType(BillingClient.SkuType.INAPP)
            build()
        }
        billingClient.querySkuDetailsAsync(params) { result, skuDetails ->
            when (result.responseCode) {
                BillingClient.BillingResponseCode.OK -> {
                    skuDetails?.forEach { details ->
                        WearAuthnInAppProduct.fromString(details.sku)?.let { product ->
                            _skusLiveData[product]?.value = details
                        }
                    }
                }
            }
        }
    }

    private fun process(purchase: Purchase) {
        when (purchase.purchaseState) {
            Purchase.PurchaseState.PURCHASED -> {
                if (isValid(purchase)) {
                    realizePurchase(purchase)
                    acknowledgePurchase(purchase)
                }
            }
            Purchase.PurchaseState.PENDING -> {
                when (WearAuthnInAppProduct.fromString(purchase.sku)) {
                    WearAuthnInAppProduct.Complication -> {
                        _isComplicationUnlockedLiveData.postValue(null)
                    }
                    null -> {
                        Log.e(
                            TAG,
                            "Purchase pending for ${purchase.sku} which does not match any known SKU"
                        )
                    }
                }
            }
        }
    }

    private fun String.base64(): ByteArray? = try {
        Base64.decode(this, Base64.NO_WRAP)
    } catch (e: IllegalArgumentException) {
        null
    }

    private fun isValid(purchase: Purchase): Boolean {
        if (purchase.signature == null || purchase.originalJson == null)
            return false
        val signature = purchase.signature.base64() ?: return false
        return Signature.getInstance("SHA1withRSA").run {
            initVerify(googlePlayPublicKey)
            update(purchase.originalJson.toByteArray())
            verify(signature)
        }
    }

    private fun realizePurchase(purchase: Purchase) {
        when (WearAuthnInAppProduct.fromString(purchase.sku)) {
            WearAuthnInAppProduct.Complication -> {
                _isComplicationUnlockedLiveData.postValue(true)
            }
            null -> {
                Log.e(TAG, "Purchased ${purchase.sku} which does not match any known SKU")
            }
        }
    }

    private fun acknowledgePurchase(purchase: Purchase) {
        if (purchase.isAcknowledged)
            return

        val params = AcknowledgePurchaseParams.newBuilder().run {
            setPurchaseToken(purchase.purchaseToken)
            build()
        }
        billingClient.acknowledgePurchase(params) { result ->
            if (result.responseCode != BillingClient.BillingResponseCode.OK)
                Log.e(TAG, "Failed to acknowledge purchase: ${result.debugMessage}")
        }
    }

    override fun onBillingServiceDisconnected() {
        Log.i(TAG, "Billing service disconnected")
        _isBillingReady.postValue(false)
        connect()
    }

    override fun onBillingSetupFinished(billingResult: BillingResult) {
        if (billingResult.responseCode == BillingClient.BillingResponseCode.OK) {
            _isBillingReady.postValue(true)
            updateSkus()
            updatePurchases()
        } else {
            Log.w(TAG, "Setting up billing failed: ${billingResult.debugMessage}")
        }
    }

    override fun onPurchasesUpdated(
        billingResult: BillingResult,
        purchases: MutableList<Purchase>?
    ) {
        when (billingResult.responseCode) {
            BillingClient.BillingResponseCode.OK -> purchases?.forEach { process(it) }
            BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED -> updatePurchases()
            BillingClient.BillingResponseCode.SERVICE_DISCONNECTED -> connect()
            else -> Log.i(TAG, billingResult.debugMessage)

        }
    }

    companion object {
        private const val TAG = "BillingManager"

        @Volatile
        private var INSTANCE: BillingManager? = null

        fun getInstance(application: Application): BillingManager =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: BillingManager(application).also { INSTANCE = it }
            }

        private val GOOGLE_PLAY_PUBLIC_KEY = byteArrayOf(
            0x30.toByte(), 0x82.toByte(), 0x01.toByte(), 0x22.toByte(), 0x30.toByte(),
            0x0d.toByte(), 0x06.toByte(), 0x09.toByte(), 0x2a.toByte(), 0x86.toByte(),
            0x48.toByte(), 0x86.toByte(), 0xf7.toByte(), 0x0d.toByte(), 0x01.toByte(),
            0x01.toByte(), 0x01.toByte(), 0x05.toByte(), 0x00.toByte(), 0x03.toByte(),
            0x82.toByte(), 0x01.toByte(), 0x0f.toByte(), 0x00.toByte(), 0x30.toByte(),
            0x82.toByte(), 0x01.toByte(), 0x0a.toByte(), 0x02.toByte(), 0x82.toByte(),
            0x01.toByte(), 0x01.toByte(), 0x00.toByte(), 0xb9.toByte(), 0xa2.toByte(),
            0x26.toByte(), 0x58.toByte(), 0xc3.toByte(), 0x5d.toByte(), 0x4d.toByte(),
            0x73.toByte(), 0x6e.toByte(), 0xe0.toByte(), 0xb5.toByte(), 0xee.toByte(),
            0x77.toByte(), 0x30.toByte(), 0xad.toByte(), 0xf9.toByte(), 0x3b.toByte(),
            0x92.toByte(), 0xc1.toByte(), 0xaa.toByte(), 0xc2.toByte(), 0x5d.toByte(),
            0x7b.toByte(), 0x6f.toByte(), 0x6e.toByte(), 0xcc.toByte(), 0x0d.toByte(),
            0xb1.toByte(), 0xf2.toByte(), 0xd6.toByte(), 0x09.toByte(), 0x47.toByte(),
            0xf5.toByte(), 0xec.toByte(), 0xf0.toByte(), 0x3e.toByte(), 0x42.toByte(),
            0xe7.toByte(), 0xbb.toByte(), 0x31.toByte(), 0x2c.toByte(), 0x5b.toByte(),
            0x10.toByte(), 0x25.toByte(), 0x76.toByte(), 0xe3.toByte(), 0x12.toByte(),
            0x7a.toByte(), 0xeb.toByte(), 0x6c.toByte(), 0xd6.toByte(), 0x16.toByte(),
            0xda.toByte(), 0xa3.toByte(), 0x1a.toByte(), 0x4f.toByte(), 0x1c.toByte(),
            0x0b.toByte(), 0xd7.toByte(), 0x0a.toByte(), 0x7d.toByte(), 0x6d.toByte(),
            0x2e.toByte(), 0x1c.toByte(), 0x3c.toByte(), 0xb5.toByte(), 0xba.toByte(),
            0x88.toByte(), 0x4c.toByte(), 0x38.toByte(), 0x2f.toByte(), 0x7c.toByte(),
            0x8e.toByte(), 0xae.toByte(), 0x65.toByte(), 0x28.toByte(), 0xad.toByte(),
            0xf4.toByte(), 0xfe.toByte(), 0xdd.toByte(), 0xcb.toByte(), 0x71.toByte(),
            0x90.toByte(), 0xd9.toByte(), 0xb6.toByte(), 0x1b.toByte(), 0x82.toByte(),
            0xc0.toByte(), 0x89.toByte(), 0x11.toByte(), 0x4a.toByte(), 0xba.toByte(),
            0x8a.toByte(), 0xc0.toByte(), 0x19.toByte(), 0x9a.toByte(), 0xa2.toByte(),
            0x86.toByte(), 0x5e.toByte(), 0x8e.toByte(), 0xd6.toByte(), 0xbb.toByte(),
            0x31.toByte(), 0xa5.toByte(), 0xb6.toByte(), 0x48.toByte(), 0x4a.toByte(),
            0xbd.toByte(), 0x98.toByte(), 0x72.toByte(), 0x44.toByte(), 0xc9.toByte(),
            0x26.toByte(), 0x3b.toByte(), 0xb3.toByte(), 0xee.toByte(), 0xe2.toByte(),
            0xa8.toByte(), 0xb6.toByte(), 0xc7.toByte(), 0x86.toByte(), 0x0d.toByte(),
            0x6d.toByte(), 0x57.toByte(), 0x16.toByte(), 0x41.toByte(), 0xb3.toByte(),
            0x0e.toByte(), 0x68.toByte(), 0x0a.toByte(), 0x78.toByte(), 0x31.toByte(),
            0x91.toByte(), 0xb3.toByte(), 0xd6.toByte(), 0x83.toByte(), 0x77.toByte(),
            0x5a.toByte(), 0x37.toByte(), 0x89.toByte(), 0x7d.toByte(), 0xc0.toByte(),
            0x10.toByte(), 0x71.toByte(), 0xcb.toByte(), 0xc3.toByte(), 0x97.toByte(),
            0x90.toByte(), 0x98.toByte(), 0x19.toByte(), 0x3c.toByte(), 0x67.toByte(),
            0x97.toByte(), 0x91.toByte(), 0x1d.toByte(), 0xe0.toByte(), 0x11.toByte(),
            0xaa.toByte(), 0xb8.toByte(), 0xe3.toByte(), 0x08.toByte(), 0xed.toByte(),
            0x09.toByte(), 0x8a.toByte(), 0x91.toByte(), 0x7a.toByte(), 0xf3.toByte(),
            0x86.toByte(), 0x36.toByte(), 0x00.toByte(), 0xcc.toByte(), 0x06.toByte(),
            0x8a.toByte(), 0x0e.toByte(), 0x42.toByte(), 0x46.toByte(), 0x3e.toByte(),
            0xb7.toByte(), 0x1f.toByte(), 0xdb.toByte(), 0x7b.toByte(), 0x2a.toByte(),
            0x73.toByte(), 0x63.toByte(), 0xe8.toByte(), 0xf7.toByte(), 0x01.toByte(),
            0xaa.toByte(), 0x9f.toByte(), 0x6f.toByte(), 0xc3.toByte(), 0x54.toByte(),
            0xc2.toByte(), 0x53.toByte(), 0x87.toByte(), 0x4d.toByte(), 0xb4.toByte(),
            0x97.toByte(), 0xe5.toByte(), 0xd1.toByte(), 0x99.toByte(), 0x43.toByte(),
            0x5c.toByte(), 0xa2.toByte(), 0xd7.toByte(), 0x86.toByte(), 0xf1.toByte(),
            0x91.toByte(), 0xe4.toByte(), 0x63.toByte(), 0x20.toByte(), 0xa4.toByte(),
            0x90.toByte(), 0x38.toByte(), 0xb4.toByte(), 0xb4.toByte(), 0x6d.toByte(),
            0x33.toByte(), 0x80.toByte(), 0xd1.toByte(), 0x22.toByte(), 0x02.toByte(),
            0x92.toByte(), 0xcb.toByte(), 0x8c.toByte(), 0x65.toByte(), 0x63.toByte(),
            0x4a.toByte(), 0x42.toByte(), 0x7a.toByte(), 0x9c.toByte(), 0xf9.toByte(),
            0x63.toByte(), 0x27.toByte(), 0x7f.toByte(), 0x01.toByte(), 0xd8.toByte(),
            0xe2.toByte(), 0xa3.toByte(), 0x0c.toByte(), 0x76.toByte(), 0x4c.toByte(),
            0x88.toByte(), 0x05.toByte(), 0xa9.toByte(), 0x3c.toByte(), 0xec.toByte(),
            0x3d.toByte(), 0xe2.toByte(), 0xa9.toByte(), 0x06.toByte(), 0x87.toByte(),
            0xb8.toByte(), 0xb3.toByte(), 0x2b.toByte(), 0xc3.toByte(), 0x02.toByte(),
            0x03.toByte(), 0x01.toByte(), 0x00.toByte(), 0x01.toByte()
        )
        private val googlePlayPublicKey by lazy {
            KeyFactory.getInstance("RSA").run {
                generatePublic(X509EncodedKeySpec(GOOGLE_PLAY_PUBLIC_KEY))
            }
        }
    }

    enum class WearAuthnInAppProduct(val sku: String) {
        Complication("complication");

        companion object {
            private val map = values().associateBy(WearAuthnInAppProduct::sku)
            fun fromString(string: String) = map[string]
        }
    }
}