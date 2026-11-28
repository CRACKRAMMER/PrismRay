// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed AndroidKeyStore AES-256-GCM biometric key wrapper.
 * Stores only the encrypted KEK ciphertext + IV in MODE_PRIVATE SharedPreferences;
 * decryption strictly requires OS BiometricPrompt.CryptoObject authentication.
 */
object AndroidBiometricCrypto {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "prismray_biometric_master_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val PREFS_NAME = "prismray_biometric_hw"
    private const val PREF_IV = "kek_iv"
    private const val PREF_CT = "kek_ct"
    private const val GCM_TAG_BITS = 128

    private fun loadKeyStore(): KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    private fun createFreshSecretKey(): SecretKey {
        val ks = loadKeyStore()
        if (ks.containsAlias(KEY_ALIAS)) {
            ks.deleteEntry(KEY_ALIAS)
        }
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        val specBuilder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        keyGen.init(specBuilder.build())
        return keyGen.generateKey()
    }

    private fun getExistingSecretKey(): SecretKey? {
        val ks = loadKeyStore()
        return ks.getKey(KEY_ALIAS, null) as? SecretKey
    }

    fun prepareEncryptCipher(): Cipher {
        val key = createFreshSecretKey()
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, key)
        }
    }

    fun persistEncryptedKek(context: Context, cipher: Cipher, kekBase64: String) {
        val plain = kekBase64.toByteArray(Charsets.UTF_8)
        val ct = cipher.doFinal(plain)
        plain.fill(0)
        val iv = cipher.iv
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(PREF_CT, Base64.encodeToString(ct, Base64.NO_WRAP))
            .apply()
    }

    fun hasStoredKek(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val iv = prefs.getString(PREF_IV, null)
        val ct = prefs.getString(PREF_CT, null)
        return !iv.isNullOrBlank() && !ct.isNullOrBlank() && getExistingSecretKey() != null
    }

    fun prepareDecryptCipher(context: Context): Cipher {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val ivB64 = prefs.getString(PREF_IV, null)
            ?: throw IllegalStateException("未找到硬件生物解锁密钥，请使用主密码登录并在设置中重新开启")
        val iv = Base64.decode(ivB64, Base64.NO_WRAP)
        val key = getExistingSecretKey()
            ?: throw IllegalStateException("Android Keystore 生物密钥不存在，请使用主密码重新开启")
        return try {
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            }
        } catch (err: KeyPermanentlyInvalidatedException) {
            clear(context)
            throw IllegalStateException("系统生物信息已变更，硬件密钥已失效，请用主密码登录并重新开启", err)
        }
    }

    fun decryptStoredKek(context: Context, cipher: Cipher): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val ctB64 = prefs.getString(PREF_CT, null)
            ?: throw IllegalStateException("缺少加密的生物解锁凭据")
        val ct = Base64.decode(ctB64, Base64.NO_WRAP)
        val plain = cipher.doFinal(ct)
        return try {
            String(plain, Charsets.UTF_8)
        } finally {
            plain.fill(0)
        }
    }

    fun clear(context: Context) {
        try {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().clear().apply()
        } catch (_: Throwable) {
        }
        try {
            val ks = loadKeyStore()
            if (ks.containsAlias(KEY_ALIAS)) {
                ks.deleteEntry(KEY_ALIAS)
            }
        } catch (_: Throwable) {
        }
    }
}
