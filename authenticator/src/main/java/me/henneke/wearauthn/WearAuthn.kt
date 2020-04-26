package me.henneke.wearauthn

import android.app.Application

class WearAuthn: Application() {

    override fun onCreate() {
        super.onCreate()
        Logging.init(applicationContext)
    }
}