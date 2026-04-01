package com.vlessvpn

import android.app.Application
import com.vlessvpn.util.ConfigManager

class VlessVpnApp : Application() {
    override fun onCreate() {
        super.onCreate()
        ConfigManager.init(this)
    }
}
