package me.henneke.wearauthn.ui.main

import android.app.Dialog
import android.os.Bundle
import android.support.wearable.activity.WearableActivity
import android.widget.TextView
import kotlinx.android.synthetic.main.activity_about.*
import kotlinx.coroutines.*
import me.henneke.wearauthn.BuildConfig
import me.henneke.wearauthn.R
import me.henneke.wearauthn.fido.context.checkAllKeysInHardware
import me.henneke.wearauthn.ui.openUrlOnPhone
import kotlin.coroutines.CoroutineContext

class AboutActivity : WearableActivity(), CoroutineScope {
    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + SupervisorJob()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_about)
        titleView.setText(applicationInfo.labelRes)
        versionView.text = BuildConfig.VERSION_NAME
        howToUseOpenOnPhoneButton.setOnClickListener {
            openUrlOnPhone(this, getString(R.string.url_usage))
        }
        privacyButtton.setOnClickListener {
            showTextDialog(privacyPolicy)
        }
        licensesButtton.setOnClickListener {
            showTextDialog(licensesText)
        }
    }

    override fun onResume() {
        super.onResume()
        keyStorageView.setText(R.string.message_key_storage_type_unknown)
        launch {
            val messageId =
                if (checkAllKeysInHardware()) R.string.message_key_storage_type_hardware else R.string.message_key_storage_type_software
            withContext(Dispatchers.Main) {
                keyStorageView?.setText(messageId)
            }
        }
    }

    override fun onPause() {
        super.onPause()
        coroutineContext.cancelChildren()
    }

    private val privacyPolicy by lazy {
        resources.openRawResource(R.raw.privacy_policy).bufferedReader().use {
            it.readText()
        }
    }

    private val licensesText by lazy {
        resources.openRawResource(R.raw.licenses_text).bufferedReader().use {
            it.readText()
        }
    }

    private fun showTextDialog(text: String) {
        Dialog(this).run {
            setContentView(R.layout.dialog_text)
            val textView = findViewById<TextView>(R.id.text)
            textView.text = text
            show()
        }
    }

}
