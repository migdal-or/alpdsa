package com.raopheefah.alpdsa

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.core.content.edit
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

object KeyManager {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val PREFS_NAME = "alpdsa_prefs"
    private const val PREF_ACTIVE_KEY = "active_key_alias"
    private const val PREF_KEY_LIST = "key_alias_list"
    private const val PREF_PORT = "server_port"
    private const val PREF_AUTH_COUNT = "auth_count"

    private fun keystore(): KeyStore {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER)
        ks.load(null)
        return ks
    }

    fun listKeyAliases(context: Context): List<String> {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val stored = prefs.getStringSet(PREF_KEY_LIST, emptySet()) ?: emptySet()
        return stored.sorted()
    }

    fun createKey(context: Context, alias: String) {
        val ks = keystore()
        if (ks.containsAlias(alias)) return

        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER
        )
        val spec = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()
        kpg.initialize(spec)
        kpg.generateKeyPair()

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val current = prefs.getStringSet(PREF_KEY_LIST, mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        current.add(alias)
        prefs.edit { putStringSet(PREF_KEY_LIST, current) }

        if (getActiveAlias(context) == null) {
            setActiveAlias(context, alias)
        }
    }

    fun deleteKey(context: Context, alias: String) {
        val ks = keystore()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val current = prefs.getStringSet(PREF_KEY_LIST, mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        current.remove(alias)
        prefs.edit { putStringSet(PREF_KEY_LIST, current) }

        if (getActiveAlias(context) == alias) {
            prefs.edit { remove(PREF_ACTIVE_KEY) }
        }
    }

    fun getActiveAlias(context: Context): String? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(PREF_ACTIVE_KEY, null)
    }

    fun setActiveAlias(context: Context, alias: String) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit { putString(PREF_ACTIVE_KEY, alias) }
    }

    fun getPublicKeyBytes(alias: String): ByteArray {
        val ks = keystore()
        val cert = ks.getCertificate(alias)
        return cert.publicKey.encoded
    }

    fun sign(alias: String, nonce: ByteArray): ByteArray {
        val ks = keystore()
        val privateKey = ks.getKey(alias, null) as java.security.PrivateKey

        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(nonce)
        return signature.sign()
    }

    fun getPort(context: Context): Int {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getInt(PREF_PORT, 7654)
    }

    fun setPort(context: Context, port: Int) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit { putInt(PREF_PORT, port) }
    }

    // Counts only successful AUTH signatures served (not raw connection attempts).
    @Synchronized
    fun incrementAuthCount(context: Context): Int {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val newCount = prefs.getInt(PREF_AUTH_COUNT, 0) + 1
        prefs.edit { putInt(PREF_AUTH_COUNT, newCount) }
        return newCount
    }

    fun getAuthCount(context: Context): Int {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getInt(PREF_AUTH_COUNT, 0)
    }
}