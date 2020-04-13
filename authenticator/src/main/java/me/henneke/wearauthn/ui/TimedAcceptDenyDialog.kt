/* Modified by Fabian Henneke, original taken from the Android PackageInstaller
 * and licensed under the following terms:
 *
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package me.henneke.wearauthn.ui

import android.app.Dialog
import android.content.Context
import android.content.DialogInterface
import android.os.PowerManager
import android.os.PowerManager.ACQUIRE_CAUSES_WAKEUP
import android.os.PowerManager.FULL_WAKE_LOCK
import android.view.View
import android.view.ViewTreeObserver
import kotlinx.android.synthetic.main.timed_accept_deny_dialog.*
import me.henneke.wearauthn.R

private const val TAG = "TimedAcceptDenyDialog"

private const val DEFAULT_TIMEOUT = 5_000L


class TimedAcceptDenyDialog(context: Context) : Dialog(context) {

    var messageLineBreaks: List<Int>? = null
        private set

    private var wakeOnShow = false
    private var vibrateOnShow = false
    private var positiveButtonListener: DialogInterface.OnClickListener? = null
    private var negativeButtonListener: DialogInterface.OnClickListener? = null
    private var timeoutListener: DialogInterface.OnCancelListener? = null

    private var wakeLock: PowerManager.WakeLock? = null

    private val actionHandler: (View) -> Unit = { v: View ->
        when {
            v == positiveButton -> {
                positiveButtonListener?.let {
                    it.onClick(this, DialogInterface.BUTTON_POSITIVE)
                    dismiss()
                }
            }
            v == negativeButton || (v == negativeTimeout && timeoutListener == null) -> {
                negativeButtonListener?.let {
                    it.onClick(this, DialogInterface.BUTTON_NEGATIVE)
                    dismiss()
                }
            }
            v == negativeTimeout -> {
                timeoutListener?.let {
                    it.onCancel(this)
                    dismiss()
                }
            }
        }
    }

    init {
        setContentView(R.layout.timed_accept_deny_dialog)
        setCancelable(false)
        setTimeout(DEFAULT_TIMEOUT)
        negativeButton.setOnClickListener(actionHandler)
        negativeTimeout.setOnTimerFinishedListener(actionHandler)
        positiveButton.setOnClickListener(actionHandler)
        // The txAuthSimple extension requires us to record the line breaks inserted into the
        // message by the text rendering engine. This information can only be extracted reliably
        // right before a draw. Since we do not expect the message to change after the dialog is
        // shown, we remove the listener after the text layout has been obtained once.
        messageView.viewTreeObserver.addOnPreDrawListener(object : ViewTreeObserver.OnPreDrawListener {
            override fun onPreDraw(): Boolean {
                if (messageView.layout != null) {
                    computeMessageLineBreaks()
                    messageView.viewTreeObserver.removeOnPreDrawListener(this)
                }
                return true
            }
        })
    }

    override fun onStart() {
        super.onStart()
        if (negativeButtonListener != null) {
            negativeTimeout.startTimer()
        }
        if (vibrateOnShow) {
            wink(context)
        }
        if (wakeOnShow) {
            wakeLock = context.powerManager?.newWakeLock(
                FULL_WAKE_LOCK or ACQUIRE_CAUSES_WAKEUP, "WearAuthn:WakeForDialog"
            )?.apply { acquire(negativeTimeout.totalTime) }
        }
    }

    override fun onStop() {
        super.onStop()
        if (negativeTimeout.isTimerRunning) {
            negativeTimeout.stopTimer()
        }
        wakeLock?.release()
    }

    private fun setButton(whichButton: Int, listener: DialogInterface.OnClickListener) {
        when (whichButton) {
            DialogInterface.BUTTON_POSITIVE -> positiveButtonListener = listener
            DialogInterface.BUTTON_NEGATIVE -> negativeButtonListener = listener
            else -> return
        }

        spacer.visibility = if (positiveButtonListener == null || negativeButtonListener == null)
            View.GONE
        else
            View.INVISIBLE
        positiveButton.visibility = if (positiveButtonListener == null) View.GONE else View.VISIBLE
        negativeTimeout.visibility = if (negativeButtonListener == null) View.GONE else View.VISIBLE
        buttonPanel.visibility =
            if (positiveButtonListener == null && negativeButtonListener == null)
                View.GONE
            else
                View.VISIBLE
    }

    fun setIcon(resId: Int) {
        iconView.run {
            visibility = if (resId == 0) View.GONE else View.VISIBLE
            setImageResource(resId)
        }
    }

    fun setMessage(message: CharSequence?) {
        messageView.run {
            text = message
            visibility = if (message == null) View.GONE else View.VISIBLE
        }
    }

    fun setNegativeButton(listener: DialogInterface.OnClickListener) {
        setButton(DialogInterface.BUTTON_NEGATIVE, listener)
    }

    fun setPositiveButton(listener: DialogInterface.OnClickListener) {
        setButton(DialogInterface.BUTTON_POSITIVE, listener)
    }

    fun setTimeoutListener(listener: DialogInterface.OnCancelListener) {
        timeoutListener = listener
    }

    fun setTimeout(timeout: Long) {
        negativeTimeout.totalTime = timeout
    }

    override fun setTitle(title: CharSequence?) {
        titleView.run {
            text = title
            visibility = if (title == null) View.GONE else View.VISIBLE
        }
    }

    override fun setTitle(resId: Int) {
        titleView.run {
            visibility = if (resId == 0) View.GONE else View.VISIBLE
            setText(resId)
        }
    }

    fun setVibrateOnShow(vibrateOnShow: Boolean) {
        this.vibrateOnShow = vibrateOnShow
    }

    fun setWakeOnShow(wakeOnShow: Boolean) {
        this.wakeOnShow = wakeOnShow
    }

    private fun computeMessageLineBreaks() {
        val layout = messageView.layout
        if (layout != null)
            messageLineBreaks = (0 until layout.lineCount - 1).map { layout.getLineEnd(it) }
    }
}