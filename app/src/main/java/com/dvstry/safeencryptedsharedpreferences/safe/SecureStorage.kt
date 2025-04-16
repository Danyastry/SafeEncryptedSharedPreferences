package com.dvstry.safeencryptedsharedpreferences.safe

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.crypto.SecretKey

class SecureStorage(private val context: Context) {

    private val prefs: SafeEncryptedSharedPreferences by lazy {
        SafeEncryptedSharedPreferences(context, SECURE_PREFS_NAME)
    }

    private val secretKey: SecretKey by lazy {
        EncryptedPreferencesHelper.getSecretKey(context)
    }

    fun saveSecureString(key: String, value: String) {
        prefs.edit().putString(key, value).apply()
    }

    fun getSecureString(key: String, defaultValue: String = ""): String {
        return prefs.getString(key, defaultValue) ?: defaultValue
    }

    fun saveSecureInt(key: String, value: Int) {
        prefs.edit().putInt(key, value).apply()
    }

    fun getSecureInt(key: String, defaultValue: Int = 0): Int {
        return prefs.getInt(key, defaultValue)
    }

    fun saveSecureBoolean(key: String, value: Boolean) {
        prefs.edit().putBoolean(key, value).apply()
    }

    fun getSecureBoolean(key: String, defaultValue: Boolean = false): Boolean {
        return prefs.getBoolean(key, defaultValue)
    }

    fun saveSecureFloat(key: String, value: Float) {
        prefs.edit().putFloat(key, value).apply()
    }

    fun getSecureFloat(key: String, defaultValue: Float = 0f): Float {
        return prefs.getFloat(key, defaultValue)
    }

    fun saveSecureLong(key: String, value: Long) {
        prefs.edit().putLong(key, value).apply()
    }

    fun getSecureLong(key: String, defaultValue: Long = 0L): Long {
        return prefs.getLong(key, defaultValue)
    }

    fun saveSecureStringSet(key: String, values: Set<String>) {
        prefs.edit().putStringSet(key, values.toMutableSet()).apply()
    }

    fun getSecureStringSet(key: String, defaultValues: Set<String> = emptySet()): Set<String> {
        return prefs.getStringSet(key, defaultValues.toMutableSet()) ?: defaultValues
    }

    fun encryptData(data: String): String {
        return EncryptedPreferencesHelper.encrypt(data, secretKey)
    }

    fun decryptData(encryptedData: String): String {
        return EncryptedPreferencesHelper.decrypt(encryptedData, secretKey)
    }

    fun remove(key: String) {
        prefs.edit().remove(key).apply()
    }

    fun clearAll() {
        prefs.edit().clear().apply()
    }

    fun contains(key: String): Boolean {
        return prefs.contains(key)
    }

    suspend fun saveSecureDataAsync(key: String, data: String) = withContext(Dispatchers.IO) {
        saveSecureString(key, data)
    }

    suspend fun getSecureDataAsync(key: String, defaultValue: String = "") = withContext(Dispatchers.IO) {
        getSecureString(key, defaultValue)
    }

    companion object {
        private const val SECURE_PREFS_NAME = "secure_storage_prefs"
    }
}