package me.henneke.wearauthn

import android.content.Context
import android.provider.Settings
import android.util.Log
import me.henneke.wearauthn.ui.defaultSharedPreferences

val Context.isDeveloperModeEnabled
    get() = Settings.Global.getInt(
        contentResolver,
        Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
        0
    ) != 0

enum class LogLevel(val priority: Int) {
    // Raw input/output which will usually contain PII (but never any key material)
    Verbose(Log.VERBOSE),

    // Truncated input/output which may in rare cases contain (statistics about) PII
    Debug(Log.DEBUG),

    // Invoked commands and intermediate steps
    Info(Log.INFO),

    // Errors that can be encountered in normal operation
    Warn(Log.WARN),

    // Unexpected errors that hint at logic bugs in WearAuthn or hardware incompatibilities
    Error(Log.ERROR),

    // No logging (default level; all other levels require developer options to be unlocked)
    Disabled(Int.MAX_VALUE);

    companion object {
        fun safeValueOf(value: String) = try {
            valueOf(value)
        } catch (_: Exception) {
            Disabled
        }
    }
}

interface Logging {
    @Suppress("PropertyName")
    val TAG: String

    companion object {
        fun init(context: Context, value: String? = null) {
            minimumLogLevel = if (context.isDeveloperModeEnabled)
                LogLevel.safeValueOf(
                    value ?: context.defaultSharedPreferences.getString(
                        context.getString(R.string.preference_log_level_key),
                        LogLevel.Disabled.name
                    )!!
                )
            else
                LogLevel.Disabled
        }

        inline fun v(tag: String, tr: Throwable? = null, crossinline message: () -> String) {
            runIfLoggedLevel(LogLevel.Verbose) { log(LogLevel.Verbose, tag, tr, message()) }
        }

        inline fun d(tag: String, tr: Throwable? = null, crossinline message: () -> String) {
            runIfLoggedLevel(LogLevel.Debug) { log(LogLevel.Debug, tag, tr, message()) }
        }

        inline fun i(tag: String, tr: Throwable? = null, crossinline message: () -> String) {
            runIfLoggedLevel(LogLevel.Info) { log(LogLevel.Info, tag, tr, message()) }
        }

        inline fun w(tag: String, tr: Throwable? = null, crossinline message: () -> String) {
            runIfLoggedLevel(LogLevel.Warn) { log(LogLevel.Warn, tag, tr, message()) }
        }

        inline fun e(tag: String, tr: Throwable? = null, crossinline message: () -> String) {
            runIfLoggedLevel(LogLevel.Error) { log(LogLevel.Error, tag, tr, message()) }
        }

        fun log(
            level: LogLevel,
            tag: String,
            tr: Throwable? = null,
            message: String = ""
        ) {
            val logMessage = when {
                tr != null && message.isNotEmpty() -> "$message\n${Log.getStackTraceString(tr)}"
                tr != null -> Log.getStackTraceString(tr)
                message.isNotEmpty() -> message
                else -> return
            }
            logMessage.split('\n')
                .flatMap { line -> line.chunked(MAX_LOG_LINE_LENGTH) }
                .forEach { line -> Log.println(level.priority, tag, line) }
        }

        fun runIfLoggedLevel(level: LogLevel, block: () -> Unit) {
            if (level >= minimumLogLevel)
                block()
        }

        private const val MAX_LOG_LINE_LENGTH = 4_000

        private lateinit var minimumLogLevel: LogLevel
    }
}

inline fun <T : Logging> T.v(tr: Throwable? = null, crossinline message: () -> String) =
    Logging.v(TAG, tr, message)

inline fun <T : Logging> T.d(tr: Throwable? = null, crossinline message: () -> String) =
    Logging.d(TAG, tr, message)

inline fun <T : Logging> T.i(tr: Throwable? = null, crossinline message: () -> String) =
    Logging.i(TAG, tr, message)

inline fun <T : Logging> T.w(tr: Throwable? = null, crossinline message: () -> String) =
    Logging.w(TAG, tr, message)

inline fun <T : Logging> T.e(tr: Throwable? = null, crossinline message: () -> String) =
    Logging.e(TAG, tr, message)
