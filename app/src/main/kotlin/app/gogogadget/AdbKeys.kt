package app.gogogadget

import java.io.ByteArrayInputStream

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import org.bouncycastle.asn1.x509.X509Name
import org.bouncycastle.x509.X509V3CertificateGenerator
import java.io.File
import java.io.IOException
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateException
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

/**
 * Which ADB key a connection uses. Android remembers a pairing by the app's public key, so deleting a key makes the
 * devices that trusted it ask again. [Local] is this phone's own key; every saved network device has a key of its own
 * ([Network]); [Shared] is the single network key of 0.9.22 to 0.9.24, still used by the devices saved back then.
 * [Everything] is not a key but a sweep marker: [Local], [Shared] and every per-device key.
 */
sealed class IdentityName(val id: String) {
    object Local : IdentityName("local")
    object Shared : IdentityName("network")
    data class Network(val deviceId: String) : IdentityName("${IdentityName.DeviceIdPrefix}$deviceId") {
        init {
            require(isValidDeviceId(deviceId)) { "Invalid device id" }
        }
    }
    object Everything : IdentityName("all")

    companion object {
        const val DeviceIdPrefix = "dev_"
    }
}

/** Ids end up in file names and Keystore aliases, so only plain letters and digits are accepted. */
fun isValidDeviceId(id: String) = id.length in 1..64 && id.all { it in '0'..'9' || it in 'a'..'z' || it in 'A'..'Z' }

/** A random, stable id for a newly saved network device. */
fun newDeviceId(): String = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }

/**
 * This phone's own addresses use the local identity. Any other host uses the key of its saved device ([deviceId]); an
 * entry saved by 0.9.24 or earlier has none and keeps the shared key.
 */
fun identityFor(host: String, ownAddresses: Collection<String>, deviceId: String? = null): IdentityName = when {
    isLocalHost(host, ownAddresses) -> IdentityName.Local
    deviceId != null -> IdentityName.Network(deviceId)
    else -> IdentityName.Shared
}

private fun concrete(name: IdentityName): IdentityName =
    if (name === IdentityName.Everything) throw IllegalArgumentException("Everything has no key of its own") else name

fun identityKeyFileName(name: IdentityName) = "adb_key_${concrete(name).id}.enc"

fun identityCertFileName(name: IdentityName) = "adb_cert_${concrete(name).id}.der"

/** The shared identity keeps the original Keystore alias, so the key migrated from 0.9.21 and earlier still opens. */
fun identityAlias(name: IdentityName) = if (concrete(name) === IdentityName.Shared) "gogo_adb_wrap" else "gogo_adb_wrap_${name.id}"

/** The single key of earlier versions becomes the shared identity, once, and never over an existing one. */
fun legacyMigration(existsOld: Boolean, existsNew: Boolean): Boolean = existsOld && !existsNew

/** The identities marked for deletion, kept in the preferences so a deletion the app was killed in is finished later. */
fun encodeIdentities(identities: Set<IdentityName>): String = identities.map { it.id }.sorted().joinToString(",")

fun identityFromId(id: String): IdentityName? = when {
    id == IdentityName.Local.id -> IdentityName.Local
    id == IdentityName.Shared.id -> IdentityName.Shared
    id == IdentityName.Everything.id -> IdentityName.Everything
    id.startsWith(IdentityName.DeviceIdPrefix) ->
        id.removePrefix(IdentityName.DeviceIdPrefix).takeIf(::isValidDeviceId)?.let { IdentityName.Network(it) }
    else -> null
}

fun decodeIdentities(text: String?): Set<IdentityName> =
    text.orEmpty().split(',').mapNotNull { identityFromId(it.trim()) }.toSet()

private val DeviceKeyFile = Regex("^adb_(?:key|cert)_dev_([0-9A-Za-z]{1,64})\\.(?:enc|der)(?:\\.tmp)?$")
private val DeviceAlias = Regex("^gogo_adb_wrap_dev_([0-9A-Za-z]{1,64})$")

/** The per-device identities that have a key file or a Keystore alias, found by their names. */
fun deviceIdentitiesIn(fileNames: Collection<String>, aliases: Collection<String>): Set<IdentityName> =
    (fileNames.mapNotNull { DeviceKeyFile.matchEntire(it)?.groupValues?.get(1) } +
        aliases.mapNotNull { DeviceAlias.matchEntire(it)?.groupValues?.get(1) })
        .map { IdentityName.Network(it) }.toSet()

/** Replaces [IdentityName.Everything] by this phone's key, the shared key and every per-device key found. */
fun expandIdentities(
    doomed: Set<IdentityName>,
    fileNames: Collection<String>,
    aliases: Collection<String>,
): Set<IdentityName> {
    if (IdentityName.Everything !in doomed) return doomed
    return doomed - IdentityName.Everything + IdentityName.Local + IdentityName.Shared + deviceIdentitiesIn(fileNames, aliases)
}

/** [expandIdentities] for the files and Keystore aliases of this app. A Keystore failure is thrown: the caller retries. */
fun expandIdentities(context: Context, doomed: Set<IdentityName>): Set<IdentityName> {
    if (IdentityName.Everything !in doomed) return doomed
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    return expandIdentities(doomed, context.filesDir.list().orEmpty().toList(), store.aliases().toList())
}

/**
 * The identities to delete after the user forgot a device: this phone's key when this phone was forgotten, the own key
 * of a network device that has one, and every key when no saved device is left (a first open). A device on the shared
 * key deletes nothing: other devices still use that key.
 */
fun identitiesToDelete(forgotten: IdentityName, noDeviceLeft: Boolean): Set<IdentityName> = when {
    noDeviceLeft -> setOf(IdentityName.Everything)
    forgotten === IdentityName.Local -> setOf(IdentityName.Local)
    forgotten is IdentityName.Network -> setOf(forgotten)
    else -> emptySet()
}

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
    // BouncyCastle's certificate object finds its public key through provider classes that R8 strips, so in a
    // release build getPublicKey() returns null and pairing fails. Re-read the bytes with the platform parser.
    val platform = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(cert.encoded))
    checkNotNull(platform.publicKey) { "The new ADB certificate has no public key" }
    return AdbIdentity(pair.private, platform)
}

/**
 * Stores the ADB identity. The library signs with raw RSA, which Android Keystore RSA keys cannot do,
 * so the private key lives in the app's private storage encrypted with an AES-GCM key that never leaves
 * the Keystore. If that key is gone (for example after a lock-screen reset) a new identity is made and
 * the device has to be paired again. Any other failure (a Keystore or IO error) is rethrown: the existing
 * identity is kept so a transient fault does not silently invalidate every pairing.
 */
class AdbKeyStore(context: Context, private val name: IdentityName) {
    private val dir = context.filesDir
    private val keyFile get() = File(dir, identityKeyFileName(name))
    private val certFile get() = File(dir, identityCertFileName(name))
    private val alias get() = identityAlias(name)

    private fun tempFile(file: File) = File(dir, file.name + ".tmp")

    /** The shared identity also owns the single key of earlier versions, until it is moved to its new name. */
    private fun ownFiles(): List<File> {
        val own = listOf(keyFile, certFile, tempFile(keyFile), tempFile(certFile))
        return if (name === IdentityName.Shared) own + File(dir, "adb_key.enc") + File(dir, "adb_cert.der") else own
    }

    /**
     * Removes the key files and the Keystore wrap key. The next [loadOrCreate] makes a brand new identity. Throws if a
     * key file is still there afterwards: a "forgotten" key that can be loaded again must not go unnoticed.
     */
    fun delete() {
        ownFiles().forEach { it.delete() }
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (store.containsAlias(alias)) store.deleteEntry(alias)
        val left = ownFiles().filter { it.exists() }
        if (left.isNotEmpty()) throw IOException("Could not delete ${left.joinToString { it.name }}")
    }

    private fun migrateLegacy() {
        if (name !== IdentityName.Shared) return
        val oldKey = File(dir, "adb_key.enc")
        val oldCert = File(dir, "adb_cert.der")
        if (!legacyMigration(oldKey.exists() && oldCert.exists(), keyFile.exists() || certFile.exists())) return
        if (!oldCert.renameTo(certFile)) return
        if (!oldKey.renameTo(keyFile)) oldCert.renameTo(File(dir, "adb_cert.der"))
    }

    /**
     * Loads the identity or makes a new one. Any failure on the way (Keystore, files, key generation) is an
     * [AdbKeyException], so callers can tell "the key" from every other problem.
     */
    fun loadOrCreate(): AdbIdentity = try {
        loadOrCreateRaw()
    } catch (e: AdbKeyException) {
        throw e
    } catch (e: Exception) {
        throw AdbKeyException(e)
    }

    private fun loadOrCreateRaw(): AdbIdentity {
        migrateLegacy()
        load()?.let { return it }
        val identity = generateAdbIdentity()
        val pkcs8 = identity.privateKey.encoded
        try {
            val cipher = Cipher.getInstance(Transformation).apply { init(Cipher.ENCRYPT_MODE, wrapKey()) }
            val sealed = cipher.iv + cipher.doFinal(pkcs8)
            // The encryption (the step that can fail on a Keystore) comes first and each file is replaced whole, so a
            // failure never leaves a certificate without its key, or half a file.
            try {
                writeAtomically(keyFile, sealed)
                writeAtomically(certFile, identity.certificate.encoded)
            } catch (e: Exception) {
                keyFile.delete()
                certFile.delete()
                throw e
            }
        } finally {
            pkcs8.fill(0)
        }
        return identity
    }

    private fun writeAtomically(file: File, bytes: ByteArray) {
        val temp = tempFile(file)
        temp.writeBytes(bytes)
        if (!temp.renameTo(file)) {
            temp.delete()
            throw IOException("Cannot write ${file.name}")
        }
    }

    private fun load(): AdbIdentity? {
        if (!keyFile.exists() || !certFile.exists()) return null
        var pkcs8: ByteArray? = null
        return try {
            val blob = keyFile.readBytes()
            // A file cut short (the app was killed while an older version wrote it) can never be decrypted.
            if (blob.size < IvSize + TagBytes) return null
            val cipher = Cipher.getInstance(Transformation).apply {
                init(Cipher.DECRYPT_MODE, wrapKey(), GCMParameterSpec(128, blob, 0, IvSize))
            }
            pkcs8 = cipher.doFinal(blob, IvSize, blob.size - IvSize)
            val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            val cert = certFile.inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) }
            AdbIdentity(key, cert)
        } catch (e: CertificateException) {
            // A certificate that does not parse is a damaged file, not a transient fault: make a new identity.
            null
        } catch (e: Exception) {
            if (isKeyGone(e)) null else throw IllegalStateException("Cannot read the ADB key", e)
        } finally {
            pkcs8?.fill(0)
        }
    }

    private fun wrapKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
        }.generateKey()
    }

    private companion object {
        const val Transformation = "AES/GCM/NoPadding"
        const val IvSize = 12
        const val TagBytes = 16
    }
}
