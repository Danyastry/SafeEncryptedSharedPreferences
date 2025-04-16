package com.dvstry.safeencryptedsharedpreferences

import android.app.Application
import com.dvstry.safeencryptedsharedpreferences.safe.EncryptionFactory

class EncryptionApp : Application() {

    override fun onCreate() {
        super.onCreate()
        EncryptionFactory.initialize(this)
    }
}