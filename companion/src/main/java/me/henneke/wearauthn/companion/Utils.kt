package me.henneke.wearauthn.companion

import android.content.Intent
import android.net.Uri
import androidx.lifecycle.LiveData
import androidx.lifecycle.MediatorLiveData

fun <S, T> LiveData<S>.combineLatestInitialized(that: LiveData<T>): LiveData<Pair<S, T>> {
    return MediatorLiveData<Pair<S, T>>().also {
        var currentS: S? = null
        var initializedS = false

        var currentT: T? = null
        var initializedT = false

        fun emit() {
            @Suppress("UNCHECKED_CAST")
            if (initializedS && initializedT)
                it.value = Pair(currentS as S, currentT as T)
        }

        it.addSource(this) { newS: S ->
            currentS = newS
            initializedS = true
            emit()
        }
        it.addSource(that) { newT: T ->
            currentT = newT
            initializedT = true
            emit()
        }
    }
}

fun composeEmail(to: String, subject: String, body: String): Intent {
    return Intent(Intent.ACTION_SENDTO).apply {
        data = Uri.parse("mailto:")
        putExtra(Intent.EXTRA_EMAIL, arrayOf(to))
        putExtra(Intent.EXTRA_SUBJECT, subject)
        putExtra(Intent.EXTRA_TEXT, body)
    }
}
