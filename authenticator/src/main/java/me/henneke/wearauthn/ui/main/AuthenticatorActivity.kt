package me.henneke.wearauthn.ui.main

import android.os.Bundle
import android.support.wearable.preference.WearablePreferenceActivity
import kotlinx.coroutines.*
import me.henneke.wearauthn.fido.context.AuthenticatorContext
import kotlin.coroutines.CoroutineContext


@ExperimentalUnsignedTypes
class AuthenticatorActivity : WearablePreferenceActivity(), CoroutineScope {

    private var hasUpdatedInAmbientMode = false

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + SupervisorJob()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startPreferenceFragment(AuthenticatorMainMenu(), false)
        setAmbientEnabled()
    }

    override fun onResume() {
        super.onResume()
        launch {
            AuthenticatorContext.initAuthenticator(this@AuthenticatorActivity.applicationContext)
            AuthenticatorContext.refreshCachedWebAuthnCredentialIfNecessary(applicationContext)
        }
    }

    override fun onEnterAmbient(ambientDetails: Bundle?) {
        super.onEnterAmbient(ambientDetails)
        hasUpdatedInAmbientMode = false
    }

    override fun onUpdateAmbient() {
        super.onUpdateAmbient()
        if (hasUpdatedInAmbientMode) {
            finish()
        } else {
            hasUpdatedInAmbientMode = true
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        coroutineContext.cancelChildren()
    }
}
