package me.henneke.wearauthn.ui.main

/**
 * Which screen can actually consume the HID session right now.
 *
 * The link is deliberately kept alive when the user leaves the "attached" screen for the main
 * list, because the main list installs its own TransactionManager. It must not be kept alive when
 * nobody is looking: sitting on the watch face with a live HID link drains the battery and leaves
 * an open session behind.
 */
internal object HidScreenState {
    @Volatile
    var mainVisible: Boolean = false

    @Volatile
    var attachedVisible: Boolean = false

    val someoneCanHandleRequests: Boolean
        get() = mainVisible || attachedVisible
}
