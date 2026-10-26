package app.gogogadget

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import org.bouncycastle.asn1.x509.X509Name
import org.bouncycastle.x509.X509V3CertificateGenerator
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** True only when the stored key can never be read again; any other failure may be transient. */
fun isKeyGone(e: Throwable): Boolean = generateSequence(e) { it.cause }.take(8).any {
    it is AEADBadTagException || it is KeyPermanentlyInvalidatedException
}

class AdbIdentity(val privateKey: PrivateKey, val certificate: Certificate)

/** A fresh RSA-2048 identity with a self-signed certificate (the format ADB pairing expects). */
@Suppress("DEPRECATION") // BouncyCastle's X509V3CertificateGenerator is the only generator in bcprov.
fun generateAdbIdentity(subject: String = "CN=GoGo Gadget"): AdbIdentity {
    val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    val name = X509Name(subject)
    val now = System.currentTimeMillis()
    val cert = X509V3CertificateGenerator().apply {
        setSerialNumber(BigInteger(63, SecureRandom()).add(BigInteger.ONE))
        setIssuerDN(name)
        setSubjectDN(name)
        setNotBefore(Date(now - 86_400_000L))
        setNotAfter(Date(now + 25L * 365 * 86_400_000L))
        setPublicKey(pair.public)
        setSignatureAlgorithm("SHA256withRSA")
    }.generate(pair.private)
    return AdbIdentity(pair.private, cert)
}

/**
 * Stores the ADB identity. The library signs with raw RSA, which Android Keystore RSA keys cannot do,
 * so the private key lives in the app's private storage encrypted with an AES-GCM key that never leaves
 * the Keystore. If that key is gone (for example after a lock-screen reset) a new identity is made and
 * the device has to be paired again. Any other failure (a Keystore or IO error) is rethrown: the existing
 * identity is kept so a transient fault does not silently invalidate every pairing.
 */
class AdbKeyStore(context: Context) {
    private val dir = context.filesDir
    private val keyFile get() = File(dir, "adb_key.enc")
    private val certFile get() = File(dir, "adb_cert.der")

    fun loadOrCreate(): AdbIdentity {
        load()?.let { return it }
        val identity = generateAdbIdentity()
        certFile.writeBytes(identity.certificate.encoded)
        val pkcs8 = identity.privateKey.encoded
        try {
            val cipher = Cipher.getInstance(Transformation).apply { init(Cipher.ENCRYPT_MODE, wrapKey()) }
            keyFile.writeBytes(cipher.iv + cipher.doFinal(pkcs8))
        } finally {
            pkcs8.fill(0)
        }
        return identity
    }

    private fun load(): AdbIdentity? {
        if (!keyFile.exists() || !certFile.exists()) return null
        var pkcs8: ByteArray? = null
        return try {
            val blob = keyFile.readBytes()
            val cipher = Cipher.getInstance(Transformation).apply {
                init(Cipher.DECRYPT_MODE, wrapKey(), GCMParameterSpec(128, blob, 0, IvSize))
            }
            pkcs8 = cipher.doFinal(blob, IvSize, blob.size - IvSize)
            val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            val cert = certFile.inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) }
            AdbIdentity(key, cert)
        } catch (e: Exception) {
            if (isKeyGone(e)) null else throw IllegalStateException("Cannot read the ADB key", e)
        } finally {
            pkcs8?.fill(0)
        }
    }

    private fun wrapKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(Alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(Alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
        }.generateKey()
    }

    private companion object {
        const val Alias = "gogo_adb_wrap"
        const val Transformation = "AES/GCM/NoPadding"
        const val IvSize = 12
    }
}
