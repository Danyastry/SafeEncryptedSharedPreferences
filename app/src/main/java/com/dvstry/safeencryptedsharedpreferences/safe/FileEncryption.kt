package com.dvstry.safeencryptedsharedpreferences.safe

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec


class FileEncryption(private val context: Context) {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION_AES_GCM = "AES/GCM/NoPadding"
        private const val KEY_ALIAS = "file_encryption_key"
        private const val AES_KEY_SIZE = 256
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12
        private const val BUFFER_SIZE = 8192
    }

    fun encryptFile(inputFile: File, outputFile: File): Boolean {
        return try {
            val key = getOrCreateKey()

            val cipher = Cipher.getInstance(TRANSFORMATION_AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, key)

            val iv = cipher.iv

            FileInputStream(inputFile).use { inputStream ->
                FileOutputStream(outputFile).use { outputStream ->
                    outputStream.write(GCM_IV_LENGTH)
                    outputStream.write(iv)

                    val buffer = ByteArray(BUFFER_SIZE)
                    var bytesRead: Int
                    val outputBuffer = ByteArray(BUFFER_SIZE + 16)

                    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                        val encryptedBytes = if (bytesRead < BUFFER_SIZE) {
                            cipher.doFinal(buffer, 0, bytesRead)
                        } else {
                            cipher.update(buffer, 0, bytesRead)
                        }

                        outputStream.write(encryptedBytes)
                    }

                    if (bytesRead == BUFFER_SIZE) {
                        val finalBlock = cipher.doFinal()
                        if (finalBlock.isNotEmpty()) {
                            outputStream.write(finalBlock)
                        }
                    }

                    outputStream.flush()
                }
            }
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    fun decryptFile(inputFile: File, outputFile: File): Boolean {
        return try {
            val key = getOrCreateKey()

            FileInputStream(inputFile).use { inputStream ->
                FileOutputStream(outputFile).use { outputStream ->
                    val ivLength = inputStream.read()
                    if (ivLength <= 0) {
                        throw IllegalStateException("Некорректный формат зашифрованного файла")
                    }

                    val iv = ByteArray(ivLength)
                    inputStream.read(iv)

                    val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

                    val cipher = Cipher.getInstance(TRANSFORMATION_AES_GCM)
                    cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)

                    val buffer = ByteArray(BUFFER_SIZE)
                    var bytesRead: Int

                    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                        val decryptedBytes = if (bytesRead < BUFFER_SIZE) {
                            cipher.doFinal(buffer, 0, bytesRead)
                        } else {
                            cipher.update(buffer, 0, bytesRead)
                        }

                        outputStream.write(decryptedBytes)
                    }

                    if (bytesRead == BUFFER_SIZE) {
                        val finalBlock = cipher.doFinal()
                        if (finalBlock.isNotEmpty()) {
                            outputStream.write(finalBlock)
                        }
                    }

                    outputStream.flush()
                }
            }
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }


    fun encryptStringToFile(data: String, outputFile: File): Boolean {
        val tempFile = File.createTempFile("temp_encryption", null, context.cacheDir)
        try {
            FileOutputStream(tempFile).use { outputStream ->
                outputStream.write(data.toByteArray(Charsets.UTF_8))
                outputStream.flush()
            }

            val result = encryptFile(tempFile, outputFile)

            tempFile.delete()

            return result
        } catch (e: Exception) {
            e.printStackTrace()
            tempFile.delete()
            return false
        }
    }

    fun decryptFileToString(inputFile: File): String? {
        val tempFile = File.createTempFile("temp_decryption", null, context.cacheDir)
        try {
            if (!decryptFile(inputFile, tempFile)) {
                tempFile.delete()
                return null
            }

            FileInputStream(tempFile).use { inputStream ->
                val bytes = inputStream.readBytes()
                tempFile.delete()
                return String(bytes, Charsets.UTF_8)
            }
        } catch (e: Exception) {
            e.printStackTrace()
            tempFile.delete()
            return null
        }
    }


    private fun getOrCreateKey(): SecretKey {
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