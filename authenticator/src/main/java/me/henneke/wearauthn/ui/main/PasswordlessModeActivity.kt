package me.henneke.wearauthn.ui.main

import android.app.Activity
import android.content.Intent
import android.content.res.ColorStateList
import android.os.Bundle
import android.os.Handler
import android.os.ResultReceiver
import android.support.wearable.activity.WearableActivity
import android.support.wearable.view.AcceptDenyDialog
import android.text.Html
import androidx.core.content.ContextCompat
import me.henneke.wearauthn.R
import me.henneke.wearauthn.databinding.ActivityPasswordlessBinding
import me.henneke.wearauthn.fido.context.AuthenticatorContext
import me.henneke.wearauthn.fido.context.armUserVerificationFuse
import me.henneke.wearauthn.fido.context.disarmUserVerificationFuse
import me.henneke.wearauthn.fido.context.getUserVerificationState
import me.henneke.wearauthn.ui.ConfirmDeviceCredentialActivity
import me.henneke.wearauthn.ui.EXTRA_CONFIRM_DEVICE_CREDENTIAL_RECEIVER

/**
 * Passwordless mode is a switch, not a one-way door: the fuse can be dropped again and re-armed
 * later, so the screen offers both directions and says what each one costs.
 */
class PasswordlessModeActivity : WearableActivity() {

    private lateinit var binding: ActivityPasswordlessBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPasswordlessBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.root.requestFocus()
        binding.switchRow.setOnClickListener { onSwitchTapped() }
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun tint(id: Int): Int = ContextCompat.getColor(this, id)

    private fun render() {
        val state = getUserVerificationState(this)
        val screenLockEnabled = AuthenticatorContext.isScreenLockEnabled(this)
        val armed = state == true
        val tappable = state != null && (armed || screenLockEnabled)

        binding.switchRow.isEnabled = tappable
        binding.switchRow.isClickable = tappable
        binding.switchRow.alpha = if (tappable) 1f else 0.45f

        binding.switchLabelView.setText(
            when {
                armed -> R.string.passwordless_state_on
                state == false -> R.string.passwordless_state_off
                else -> R.string.passwordless_label_unavailable
            }
        )
        binding.descriptionView.setText(
            when {
                armed -> R.string.passwordless_description_on
                state == false && !screenLockEnabled ->
                    R.string.preference_single_factor_mode_summary_enable_lock
                state == false -> R.string.passwordless_description_off
                else -> R.string.preference_single_factor_mode_summary_disabled
            }
        )

        // The padlock mirrors the state: shut and blue while the mode is off, open and green
        // while it is on. Same geometry, so the two icons read as one control.
        binding.stateIcon.setImageResource(
            if (armed) R.drawable.ic_btn_lock_open else R.drawable.ic_btn_lock
        )
        binding.stateChip.backgroundTintList = ColorStateList.valueOf(
            tint(if (armed) R.color.m3_connected else R.color.m3_primary_container)
        )
        binding.stateIcon.setColorFilter(
            tint(if (armed) R.color.m3_connected_container else R.color.m3_on_primary_container)
        )

        binding.switchTrack.backgroundTintList = ColorStateList.valueOf(
            tint(if (armed) R.color.m3_connected else R.color.m3_surface_container_high)
        )
        binding.switchThumb.backgroundTintList = ColorStateList.valueOf(
            tint(if (armed) R.color.m3_on_primary else R.color.m3_on_surface_variant)
        )
        // Keep the thumb position discrete: a wearable switch reads better as two states than
        // as a sliding thumb, and the travel is known from the track/thumb dimensions.
        placeThumb(armed, animate = false)
    }

    private fun placeThumb(on: Boolean, animate: Boolean) {
        // 50dp track, 22dp thumb, 4dp inset on each side: 20dp of travel.
        val travel = 20 * resources.displayMetrics.density
        val target = if (on) travel else 0f
        if (animate) {
            binding.switchThumb.animate().translationX(target).setDuration(140L).start()
        } else {
            binding.switchThumb.translationX = target
        }
    }

    private fun onSwitchTapped() {
        val state = getUserVerificationState(this)
        if (state == null) return
        if (state == true) {
            showDisableDialog()
        } else if (AuthenticatorContext.isScreenLockEnabled(this)) {
            showEnableDialog()
        }
    }

    private fun showEnableDialog() {
        AcceptDenyDialog(this).run {
            setTitle(R.string.prompt_single_factor_mode_title)
            setMessage(
                Html.fromHtml(
                    getString(R.string.prompt_single_factor_mode_message),
                    Html.FROM_HTML_MODE_LEGACY
                )
            )
            setPositiveButton { _, _ ->
                startActivity(
                    Intent(
                        this@PasswordlessModeActivity,
                        ConfirmDeviceCredentialActivity::class.java
                    ).apply {
                        putExtra(
                            EXTRA_CONFIRM_DEVICE_CREDENTIAL_RECEIVER,
                            object : ResultReceiver(Handler()) {
                                override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                                    if (resultCode == Activity.RESULT_OK) {
                                        armUserVerificationFuse(this@PasswordlessModeActivity)
                                        render()
                                    }
                                }
                            }
                        )
                    }
                )
            }
            setNegativeButton { _, _ -> render() }
            setOnCancelListener { render() }
            show()
        }
    }

    private fun showDisableDialog() {
        AcceptDenyDialog(this).run {
            setTitle(R.string.prompt_passwordless_disable_title)
            setMessage(
                Html.fromHtml(
                    getString(R.string.prompt_passwordless_disable_message),
                    Html.FROM_HTML_MODE_LEGACY
                )
            )
            setPositiveButton { _, _ ->
                disarmUserVerificationFuse(this@PasswordlessModeActivity)
                render()
            }
            setNegativeButton { _, _ -> render() }
            setOnCancelListener { render() }
            show()
        }
    }
}
