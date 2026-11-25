// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package net.rcbj.oidccaep

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

/** Where a Keystore key lives: StrongBox (a separate secure chip), the TEE, or software. */
public enum class KeySecurityLevel(public val description: String) {
    STRONGBOX("StrongBox (a separate secure element)"),
    TRUSTED_ENVIRONMENT("the Trusted Execution Environment (TEE)"),
    SOFTWARE("software (no secure hardware on this device)"),
    UNKNOWN("the Android Keystore"),
}

private fun securityLevelOf(key: java.security.Key): KeySecurityLevel = try {
    val info = when (key) {
        is PrivateKey -> KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        is SecretKey -> SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        else -> null
    }
    when {
        info == null -> KeySecurityLevel.UNKNOWN
        Build.VERSION.SDK_INT >= 31 -> when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeySecurityLevel.STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeySecurityLevel.TRUSTED_ENVIRONMENT
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeySecurityLevel.SOFTWARE
            else -> KeySecurityLevel.UNKNOWN
        }
        @Suppress("DEPRECATION") info.isInsideSecureHardware -> KeySecurityLevel.TRUSTED_ENVIRONMENT
        else -> KeySecurityLevel.SOFTWARE
    }
} catch (e: Exception) {
    KeySecurityLevel.UNKNOWN
}

private fun androidKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

/**
 * A DPoP key generated in the Android Keystore (ES256 only), in StrongBox when the device has one, else in the TEE.
 * The private key never leaves the secure hardware: the app can ask it to sign, but nothing (not the app, not malware
 * running as the app) can read it out, so stolen access and refresh tokens are useless on any other device. This is
 * the Android counterpart of the Secure Enclave on Apple platforms.
 */
public class AndroidKeystoreKeyStore(
    /** The Keystore alias of the key. */
    public val alias: String = "oidc-caep-dpop",
    /** Try StrongBox first (when the device has it). */
    public val preferStrongBox: Boolean = true,
    private val context: Context? = null,
) : DPoPKeyStore {
    override val supportedAlgorithms: List<String> get() = listOf("ES256")
    override val isExtractable: Boolean get() = false

    /** Where the key currently held lives, or null when there is none. */
    public suspend fun securityLevel(): KeySecurityLevel? = withContext(Dispatchers.IO) {
        (androidKeyStore().getKey(alias, null) as? PrivateKey)?.let(::securityLevelOf)
    }

    override suspend fun load(alg: String): JWSSigner? = withContext(Dispatchers.IO) {
        if (alg != "ES256") return@withContext null
        val ks = androidKeyStore()
        val key = ks.getKey(alias, null) as? PrivateKey ?: return@withContext null
        val pub = ks.getCertificate(alias)?.publicKey as? ECPublicKey ?: return@withContext null
        KeystoreSigner(key, pub)
    }

    override suspend fun create(alg: String): JWSSigner = withContext(Dispatchers.IO) {
        if (alg != "ES256") throw OIDCError.usage("The Android Keystore key store holds P-256 keys only (ES256), not $alg")
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val hasStrongBox = context?.packageManager?.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) ?: true
        val pair = try {
            if (preferStrongBox && hasStrongBox) {
                try {
                    generator.initialize(spec(true))
                    generator.generateKeyPair()
                } catch (e: StrongBoxUnavailableException) {
                    generator.initialize(spec(false))
                    generator.generateKeyPair()
                }
            } else {
                generator.initialize(spec(false))
                generator.generateKeyPair()
            }
        } catch (e: Exception) {
            throw OIDCError(OIDCError.Kind.GENERAL, "The Android Keystore could not create a key: ${e.message}", code = "keystore_unavailable", cause = e)
        }
        KeystoreSigner(pair.private, pair.public as ECPublicKey)
    }

    override suspend fun delete(): Unit = withContext(Dispatchers.IO) {
        androidKeyStore().deleteEntry(alias)
    }
}

private class KeystoreSigner(private val key: PrivateKey, publicKey: ECPublicKey) : JWSSigner {
    override val alg: String = "ES256"
    override val publicJWK: JsonObject = ecPublicJWK(publicKey, "P-256", 32)
    override fun sign(data: ByteArray): ByteArray {
        val der = Signature.getInstance("SHA256withECDSA").run { initSign(key); update(data); sign() }
        return derToRaw(der, 32)
    }
}

/** The best place for a DPoP key on this device: the Android Keystore (StrongBox when present, else the TEE). */
public fun preferredDPoPKeyStore(context: Context, alias: String = "${context.packageName}.oidc-dpop"): AndroidKeystoreKeyStore =
    AndroidKeystoreKeyStore(alias, preferStrongBox = true, context = context)

/**
 * Tokens (and an [AccountManager]'s account list) in the app's private storage, each value encrypted with AES-256-GCM
 * under a key held in the Android Keystore (the key never leaves it), with the item's name as associated data. They
 * survive relaunches, so every signed-in account stays signed in.
 *
 * Pair it with DPoP ([AndroidKeystoreKeyStore]): a DPoP-bound refresh token is useless without the key it is bound to.
 * Exclude the preferences file from backups (the demo turns backups off): the encryption key cannot be restored on
 * another device, so a restored file would be unreadable anyway.
 */
public class KeystoreTokenStore(
    context: Context,
    /** The SharedPreferences file the encrypted values are kept in. */
    public val fileName: String = "${context.packageName}.oidc-tokens",
    /** The Keystore alias of the encryption key. */
    public val keyAlias: String = "${context.packageName}.oidc-tokens-key",
) : TokenStore {
    private val prefs: SharedPreferences = context.applicationContext.getSharedPreferences(fileName, Context.MODE_PRIVATE)

    /** Where the encryption key lives. */
    public suspend fun securityLevel(): KeySecurityLevel = withContext(Dispatchers.IO) { securityLevelOf(secretKey()) }

    private fun secretKey(): SecretKey {
        val ks = androidKeyStore()
        (ks.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build())
        return generator.generateKey()
    }

    override suspend fun get(key: String): ByteArray? = withContext(Dispatchers.IO) {
        val stored = prefs.getString(key, null) ?: return@withContext null
        val blob = Base64URL.decode(stored) ?: return@withContext null
        if (blob.size < 13) return@withContext null
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
            cipher.updateAAD(key.encodeToByteArray())
            cipher.doFinal(blob.copyOfRange(12, blob.size))
        } catch (e: Exception) {
            OIDCLog.log(OIDCLog.Level.WARNING, "KeystoreTokenStore: could not decrypt $key; it is ignored")
            null
        }
    }

    override suspend fun set(key: String, value: ByteArray): Unit = withContext(Dispatchers.IO) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        cipher.updateAAD(key.encodeToByteArray())
        val sealed = cipher.iv + cipher.doFinal(value)
        if (!prefs.edit().putString(key, Base64URL.encode(sealed)).commit()) {
            throw OIDCError(OIDCError.Kind.GENERAL, "Could not write $key to the token store", code = "store_error")
        }
    }

    override suspend fun delete(key: String): Unit = withContext(Dispatchers.IO) {
        prefs.edit().remove(key).commit()
        Unit
    }

    override val isPersistent: Boolean get() = true
}
