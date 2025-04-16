package com.dvstry.safeencryptedsharedpreferences.safe

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class Encryption(private val context: Context) {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION_AES_GCM = "AES/GCM/NoPadding"
        private const val TRANSFORMATION_AES_CBC = "AES/CBC/PKCS7Padding"
        private const val KEY_ALIAS = "encryption_key"
        private const val AES_KEY_SIZE = 256
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12
        private const val CBC_IV_LENGTH = 16
    }


    fun encryptWithKeystore(data: String): String {
        val key = getOrCreateKeystoreKey()

        val iv = ByteArray(GCM_IV_LENGTH)
        SecureRandom().nextBytes(iv)

        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

        val cipher = Cipher.getInstance(TRANSFORMATION_AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)

        val encryptedData = cipher.doFinal(data.toByteArray(Charsets.UTF_8))

        val combined = ByteArray(iv.size + encryptedData.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encryptedData, 0, combined, iv.size, encryptedData.size)

        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    fun decryptWithKeystore(encryptedData: String): String {
        val key = getOrCreateKeystoreKey()

        val combined = Base64.decode(encryptedData, Base64.DEFAULT)

        val iv = ByteArray(GCM_IV_LENGTH)
        System.arraycopy(combined, 0, iv, 0, iv.size)

        val encrypted = ByteArray(combined.size - iv.size)
        System.arraycopy(combined, iv.size, encrypted, 0, encrypted.size)

        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

        val cipher = Cipher.getInstance(TRANSFORMATION_AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)

        val decryptedBytes = cipher.doFinal(encrypted)

        return String(decryptedBytes, Charsets.UTF_8)
    }

    fun encrypt(data: String, secretKeyBytes: ByteArray): String {
        val secretKey = SecretKeySpec(secretKeyBytes, "AES")

        val iv = ByteArray(CBC_IV_LENGTH)
        SecureRandom().nextBytes(iv)
        val ivSpec = IvParameterSpec(iv)

        val cipher = Cipher.getInstance(TRANSFORMATION_AES_CBC)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)

        val encryptedData = cipher.doFinal(data.toByteArray(Charsets.UTF_8))

        val combined = ByteArray(iv.size + encryptedData.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encryptedData, 0, combined, iv.size, encryptedData.size)

        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    fun decrypt(encryptedData: String, secretKeyBytes: ByteArray): String {
        val secretKey = SecretKeySpec(secretKeyBytes, "AES")

        val combined = Base64.decode(encryptedData, Base64.DEFAULT)

        val iv = ByteArray(CBC_IV_LENGTH)
        System.arraycopy(combined, 0, iv, 0, iv.size)
        val ivSpec = IvParameterSpec(iv)

        val encrypted = ByteArray(combined.size - iv.size)
        System.arraycopy(combined, iv.size, encrypted, 0, encrypted.size)

        val cipher = Cipher.getInstance(TRANSFORMATION_AES_CBC)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

        val decryptedBytes = cipher.doFinal(encrypted)

        return String(decryptedBytes, Charsets.UTF_8)
    }

    fun generateAesKey(keySize: Int = AES_KEY_SIZE): ByteArray {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(keySize)
        return keyGenerator.generateKey().encoded
    }

    private fun getOrCreateKeystoreKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        if (keyStore.containsAlias(KEY_ALIAS)) {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry
            return entry.secretKey
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(AES_KEY_SIZE)
            .setUserAuthenticationRequired(false)
            .build()

        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }
}