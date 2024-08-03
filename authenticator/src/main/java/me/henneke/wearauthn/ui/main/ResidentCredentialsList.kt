package me.henneke.wearauthn.ui.main

import android.app.AlertDialog
import android.os.Bundle
import android.preference.PreferenceCategory
import android.preference.PreferenceFragment
import android.support.wearable.preference.WearableDialogPreference
import android.support.wearable.preference.WearablePreferenceActivity
import android.support.wearable.view.AcceptDenyDialog
import me.henneke.wearauthn.R
import me.henneke.wearauthn.fido.context.AuthenticatorContext

@ExperimentalUnsignedTypes
class ResidentCredentialsList : WearablePreferenceActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startPreferenceFragment(ResidentCredentialsPreferenceFragment(), false)
    }
}

@ExperimentalUnsignedTypes
class ResidentCredentialsPreferenceFragment : PreferenceFragment() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        createCredentialList()
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        // Enable rotary wheel scrolling.
        view?.requestFocus()
    }

    private fun createCredentialList() {
        preferenceScreen = preferenceManager.createPreferenceScreen(context)
        val credentialsPerRp = AuthenticatorContext.getAllResidentCredentials(context)
        preferenceScreen.title =
            if (credentialsPerRp.isEmpty()) {
                getString(R.string.credential_management_title_no_credentials)
            } else {
                getString(R.string.credential_management_title)
            }
        for ((rpId, credentials) in credentialsPerRp) {
            if (credentials.isEmpty())
                continue
            val rpCategory = PreferenceCategory(context)
            // PreferenceCategory has to be added to the PreferenceScreen before customizing it
            // https://stackoverflow.com/a/49108303/297261
            preferenceScreen.addPreference(rpCategory)
            rpCategory.apply {
                title = rpId
                for ((index, credential) in credentials.withIndex()) {
                    credential.unlockUserInfoIfNecessary()
                    val credentialTwoLineInfo = credential.getTwoLineInfo(index + 1)
                    val credentialFormattedInfo = credential.getFormattedInfo()
                    addPreference(object : WearableDialogPreference(context) {
                        init {
                            isIconSpaceReserved = false
                            title = credentialTwoLineInfo.first
                            summary = credentialTwoLineInfo.second
                        }

                        override fun onPrepareDialogBuilder(builder: AlertDialog.Builder) {
                            super.onPrepareDialogBuilder(builder)
                            val preference = this
                            builder.apply {
                                setTitle(rpId)
                                setMessage(credentialFormattedInfo)
                                setPositiveButton(R.string.button_delete) { _, _ ->
                                    AcceptDenyDialog(context).run {
                                        setTitle(rpId)
                                        setMessage(
                                            getString(
                                                R.string.prompt_delete_resident_credential_message,
                                                credentialTwoLineInfo.first
                                            )
                                        )
                                        setPositiveButton { _, _ ->
                                            AuthenticatorContext.deleteResidentCredential(
                                                context,
                                                credential
                                            )
                                            rpCategory.removePreference(preference)
                                            if (rpCategory.preferenceCount == 0)
                                                preferenceScreen.removePreference(rpCategory)
                                        }
                                        setNegativeButton { _, _ -> }
                                        show()
                                    }
                                }
                            }
                        }
                    })
                }
            }
        }
    }
}