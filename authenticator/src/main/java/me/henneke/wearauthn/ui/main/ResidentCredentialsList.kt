package me.henneke.wearauthn.ui.main

import android.app.AlertDialog
import android.content.res.ColorStateList
import android.os.Bundle
import android.support.wearable.activity.WearableActivity
import android.support.wearable.view.AcceptDenyDialog
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import me.henneke.wearauthn.R
import me.henneke.wearauthn.databinding.ActivityCredentialListBinding
import me.henneke.wearauthn.databinding.ItemMainRowBinding
import me.henneke.wearauthn.fido.context.AuthenticatorContext

/**
 * Credential manager, laid out with the same Wear Material 3 Expressive list skeleton as the
 * main screen: caption per relying party, full-width pills, one key chip per credential.
 */
@ExperimentalUnsignedTypes
class ResidentCredentialsList : WearableActivity() {

    private lateinit var binding: ActivityCredentialListBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityCredentialListBinding.inflate(layoutInflater)
        setContentView(binding.root)
        render()
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun render() {
        binding.listContainer.removeAllViews()
        val credentialsPerRp = AuthenticatorContext.getAllResidentCredentials(this)

        binding.title.setText(
            if (credentialsPerRp.isEmpty()) R.string.credential_management_title_no_credentials
            else R.string.credential_management_title
        )
        binding.empty.visibility =
            if (credentialsPerRp.isEmpty()) View.VISIBLE else View.GONE

        var groupIndex = 0
        for ((rpId, credentials) in credentialsPerRp) {
            if (credentials.isEmpty()) continue

            val caption = TextView(this).apply {
                text = rpId
                setTextColor(ContextCompat.getColor(context, R.color.m3_on_surface_variant))
                textSize = 13f
                letterSpacing = 0.02f
                setPadding(dp(4), dp(if (groupIndex == 0) 0 else 16), 0, dp(8))
            }
            binding.listContainer.addView(
                caption,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            )

            for ((index, credential) in credentials.withIndex()) {
                credential.unlockUserInfoIfNecessary()
                val twoLineInfo = credential.getTwoLineInfo(index + 1)
                val formattedInfo = credential.getFormattedInfo()

                val chip = Chip.PRIMARY
                val item = ItemMainRowBinding.inflate(layoutInflater, binding.listContainer, false)
                item.rowChip.setBackgroundResource(chip.drawable)
                item.rowChip.setBackgroundTintList(
                    ColorStateList.valueOf(ContextCompat.getColor(this, chip.container))
                )
                item.rowIcon.setImageResource(R.drawable.ic_key)
                item.rowIcon.setColorFilter(ContextCompat.getColor(this, chip.onContainer))
                item.rowTitle.text = twoLineInfo.first
                val subtitle = twoLineInfo.second
                if (subtitle.isNullOrEmpty()) {
                    item.rowSubtitle.visibility = View.GONE
                } else {
                    item.rowSubtitle.visibility = View.VISIBLE
                    item.rowSubtitle.text = subtitle
                }
                item.rowChevron.text = "⋯"
                item.root.setOnClickListener {
                    showCredentialDialog(rpId, formattedInfo, credential, twoLineInfo.first)
                }
                binding.listContainer.addView(
                    item.root,
                    LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply { bottomMargin = dp(4) }
                )
            }
            groupIndex++
        }
    }

    private fun showCredentialDialog(
        rpId: String,
        formattedInfo: String?,
        credential: me.henneke.wearauthn.fido.context.WebAuthnCredential,
        title: String
    ) {
        AlertDialog.Builder(this)
            .setTitle(rpId)
            .setMessage(formattedInfo)
            .setPositiveButton(R.string.button_delete) { _, _ ->
                AcceptDenyDialog(this).run {
                    setTitle(rpId)
                    setMessage(
                        getString(R.string.prompt_delete_resident_credential_message, title)
                    )
                    setPositiveButton { _, _ ->
                        AuthenticatorContext.deleteResidentCredential(this@ResidentCredentialsList, credential)
                        render()
                    }
                    setNegativeButton { _, _ -> }
                    show()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private enum class Chip(val container: Int, val onContainer: Int, val drawable: Int) {
        PRIMARY(R.color.m3_primary_container, R.color.m3_on_primary_container, R.drawable.bg_chip_primary),
        TERTIARY(R.color.m3_tertiary_container, R.color.m3_on_tertiary_container, R.drawable.bg_chip_tertiary)
    }
}
