package com.dvstry.safeencryptedsharedpreferences.safe

import android.content.Context


object EncryptionFactory {

    private var secureStorage: SecureStorage? = null
    private var encryption: Encryption? = null
    private var aesKey: ByteArray? = null

    fun initialize(context: Context) {
        if (secureStorage == null) {
            secureStorage = SecureStorage(context.applicationContext)
        }

        if (encryption == null) {
            encryption = Encryption(context.applicationContext)
        }

        if (aesKey == null) {
            aesKey = getEncryption().generateAesKey()
        }
    }

    fun getSecureStorage(): SecureStorage {
        return secureStorage
            ?: throw IllegalStateException("EncryptionFactory не инициализирован. Сначала вызовите initialize(context)")
    }

    fun getEncryption(): Encryption {
        return encryption
            ?: throw IllegalStateException("EncryptionFactory не инициализирован. Сначала вызовите initialize(context)")
    }

    fun getAesKey(): ByteArray {
        return aesKey
            ?: throw IllegalStateException("EncryptionFactory не инициализирован. Сначала вызовите initialize(context)")
    }

    fun createSafeEncryptedSharedPreferences(
        context: Context,
        fileName: String
    ): SafeEncryptedSharedPreferences {
        return SafeEncryptedSharedPreferences(context.applicationContext, fileName)
    }

    fun quickEncrypt(data: String): String {
        return getEncryption().encryptWithKeystore(data)
    }

    fun quickDecrypt(encryptedData: String): String {
        return getEncryption().decryptWithKeystore(encryptedData)
    }

    fun reset() {
        secureStorage = null
        encryption = null
        aesKey = null
    }
}