package me.henneke.wearauthn.companion

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.wearable.CapabilityClient
import com.google.android.gms.wearable.Wearable
import kotlinx.android.synthetic.main.main_activity.*
import kotlinx.coroutines.*
import kotlinx.coroutines.tasks.asDeferred
import me.henneke.wearauthn.companion.ui.main.MainFragment

class MainActivity : AppCompatActivity(), CoroutineScope {

    override val coroutineContext = Dispatchers.IO + SupervisorJob()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.main_activity)
        floatingActionButton.setOnClickListener {
            launch {
                val nodeNames = try {
                    val capabilityClient = Wearable.getCapabilityClient(this@MainActivity)
                    withTimeoutOrNull(1000) {
                        val fetchNodeInfoTask = capabilityClient.getCapability(
                            "unlock-complication",
                            CapabilityClient.FILTER_ALL
                        )
                        val nodeInfo = fetchNodeInfoTask.asDeferred().await().nodes
                        // Strip off the identifiable number at the end of the display name
                        nodeInfo.map { it.displayName.take(it.displayName.length - 5) }
                    }
                } catch (e: ApiException) {
                    emptyList<String>()
                }
                val address = arrayOf(getString(R.string.file_bug_email_address))
                val intent = Intent(
                    Intent.ACTION_SENDTO,
                    Uri.fromParts("mailto", address.first(), null)
                )
                intent.putExtra(Intent.EXTRA_EMAIL, address)
                intent.putExtra(Intent.EXTRA_SUBJECT, getString(R.string.file_bug_email_subject))
                intent.putExtra(
                    Intent.EXTRA_TEXT,
                    getString(R.string.file_bug_email_body, nodeNames?.joinToString() ?: "")
                )
                startActivity(Intent.createChooser(intent, "Send bug report via email"))
            }
        }
        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(R.id.container, MainFragment.newInstance())
                .commitNow()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        coroutineContext.cancelChildren()
    }
}
