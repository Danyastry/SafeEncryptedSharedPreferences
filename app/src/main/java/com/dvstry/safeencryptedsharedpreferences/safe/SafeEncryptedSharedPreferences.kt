package com.dvstry.safeencryptedsharedpreferences.safe

import android.content.Context
import android.content.Context.MODE_PRIVATE
import android.content.SharedPreferences
import java.util.concurrent.atomic.AtomicBoolean

class SafeEncryptedSharedPreferences(
    context: Context,
    fileName: String
) : SharedPreferences {
    private val encrypted: SharedPreferences by lazy {
        EncryptedPreferencesHelper.createEncrypted(
            context,
            fileName,
            plain
        )
    }
    private val plain: SharedPreferences by lazy {
        context.getSharedPreferences("plain_$fileName", MODE_PRIVATE)
    }

    override fun contains(key: String?): Boolean {
        return encrypted.safeContains(key) || plain.contains(key)
    }

    override fun getBoolean(key: String?, defValue: Boolean): Boolean {
        return get(key, defValue, SharedPreferences::getBoolean)
    }

    override fun getInt(key: String?, defValue: Int): Int {
        return get(key, defValue, SharedPreferences::getInt)
    }

    override fun getLong(key: String?, defValue: Long): Long {
        return get(key, defValue, SharedPreferences::getLong)
    }

    override fun getFloat(key: String?, defValue: Float): Float {
        return get(key, defValue, SharedPreferences::getFloat)
    }

    override fun getString(key: String?, defValue: String?): String? {
        return get(key, defValue, SharedPreferences::getString)
    }

    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? {
        return get(key, defValues, SharedPreferences::getStringSet)
    }

    override fun getAll(): MutableMap<String, *> {
        val allEncrypted = encrypted.safeAll()
        val allPlain = plain.all
        val all = HashMap<String, Any?>(allEncrypted.size + allEncrypted.size)
        all.putAll(allPlain)
        all.putAll(allEncrypted)
        return all
    }

    override fun edit(): SharedPreferences.Editor {
        return Editor(encrypted.edit(), plain.edit())
    }

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) {
        encrypted.registerOnSharedPreferenceChangeListener(listener)
        plain.registerOnSharedPreferenceChangeListener(listener)
    }

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) {
        encrypted.unregisterOnSharedPreferenceChangeListener(listener)
        plain.unregisterOnSharedPreferenceChangeListener(listener)
    }

    private inline fun <T> get(
        key: String?,
        defValue: T,
        getter: SharedPreferences.(key: String?, defValue: T) -> T
    ): T {
        return if (encrypted.safeContains(key)) {
            try {
                encrypted.getter(key, defValue)
            } catch (e: Exception) {
                plain.getter(key, defValue)
            }
        } else {
            plain.getter(key, defValue)
        }
    }

    private class Editor(
        private val encryptedEditor: SharedPreferences.Editor,
        private val plainEditor: SharedPreferences.Editor
    ) : SharedPreferences.Editor {

        private val clearRequested = AtomicBoolean(false)

        override fun remove(key: String?) = apply {
            encryptedEditor.safeRemove(key)
            plainEditor.remove(key)
        }

        override fun clear() = apply {
            clearRequested.set(true)
            encryptedEditor.safeClear()
            plainEditor.clear()
        }

        override fun putLong(key: String?, value: Long) = apply {
            put(key, value, SharedPreferences.Editor::putLong)
        }

        override fun putInt(key: String?, value: Int) = apply {
            put(key, value, SharedPreferences.Editor::putInt)
        }

        override fun putBoolean(key: String?, value: Boolean) = apply {
            put(key, value, SharedPreferences.Editor::putBoolean)
        }

        override fun putStringSet(key: String?, values: MutableSet<String>?) = apply {
            put(key, values, SharedPreferences.Editor::putStringSet)
        }

        override fun putFloat(key: String?, value: Float) = apply {
            put(key, value, SharedPreferences.Editor::putFloat)
        }

        override fun putString(key: String?, value: String?) = apply {
            put(key, value, SharedPreferences.Editor::putString)
        }

        override fun commit(): Boolean {
            return encryptedEditor.safeCommit() && plainEditor.commit()
        }

        override fun apply() {
            if (clearRequested.getAndSet(false)) {
                encryptedEditor.safeCommit()
            } else {
                encryptedEditor.safeApply()
            }
            plainEditor.apply()
        }

        private inline fun <T> put(
            key: String?,
            value: T,
            putter: SharedPreferences.Editor.(key: String?, value: T) -> Any
        ) = apply {
            try {
                encryptedEditor.putter(key, value)
            } catch (e: Exception) {
                plainEditor.putter(key, value)
            }
        }
    }

    companion object {
        fun SharedPreferences.safeContains(key: String?): Boolean {
            return try {
                contains(key)
            } catch (e: Exception) {
                false
            }
        }

        fun SharedPreferences.safeAll(): Map<String, *> {
            return try {
                all
            } catch (e: Exception) {
                emptyMap<String, Any?>()
            }
        }

        fun SharedPreferences.Editor.safeRemove(key: String?): SharedPreferences.Editor {
            return try {
                remove(key)
            } catch (e: Exception) {
                this
            }
        }

        fun SharedPreferences.Editor.safeClear(): SharedPreferences.Editor {
            return try {
                clear()
            } catch (e: Exception) {
                this
            }
        }

        fun SharedPreferences.Editor.safeCommit(): Boolean {
            return try {
                commit()
            } catch (e: Exception) {
                return false
            }
        }

        fun SharedPreferences.Editor.safeApply() {
            return try {
                apply()
            } catch (ignored: Exception) {
            }
        }
    }
}