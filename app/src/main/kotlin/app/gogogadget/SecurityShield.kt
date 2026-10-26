package app.gogogadget

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.CancellationException
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

// Phase 4: Antivirus shield — streaming SHA-256, offline signature & manifest analysis,
// VirusTotal v3 hash lookup, verdict evaluation, and Keystore-encrypted shield settings.

private const val HashBufferBytes = 64 * 1024
private const val MaxManifestBytes = 4 * 1024 * 1024
private const val MaxCertEntryBytes = 512 * 1024
private const val MaxVtResponseBytes = 256 * 1024
const val MaxDeepScanBytes = 32L * 1024L * 1024L

/** High-risk manifest permissions scanned offline in `AndroidManifest.xml`. */
val HighRiskPermissions: List<String> = listOf(
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW",
    "READ_SMS",
    "RECEIVE_SMS",
    "SEND_SMS",
)

/** Well-known public AOSP testkey / platform / shared / media / debug certificate SHA-256 digests (lowercase hex). */
val KnownTestKeySha256s: Set<String> = setOf(
    // AOSP build/target/product/security/testkey.x509.pem
    "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc",
    // AOSP build/target/product/security/platform.x509.pem
    "27196e386b875e76adf700e7ea84e4c6eee33dfa8906c22283e97c3114461f2d",
    // AOSP build/target/product/security/shared.x509.pem
    "5b368cff2da2686996bc95eac190eaa4f5630f5f2050d07139c47f8c3190339f",
    // AOSP build/target/product/security/media.x509.pem
    "b79df4a82e90b57526525e2a39f21f90f5c41023f6760d92c07a0f964e2b0d84",
)

private val KnownDebugOrTestDnTokens: List<String> = listOf(
    "CN=Android Debug",
    "EmailAddress=android@android.com",
    "OU=Android",
    "CN=Android",
    "O=Android",
    "CN=Unknown",
    "CN=Test",
    "O=APKTool",
    "CN=APK Easy Tool",
    "CN=MT Manager",
    "OU=MT Manager",
    "CN=NP Manager",
    "CN=Lucky Patcher",
)

// All Regex patterns escape literal `{`, `}`, `[`, and `]` outside character classes for Android ICU compatibility.
private val VtStatsBlockRegex = Regex(""""last_analysis_stats"\s*:\s*\{([^{}]*)\}""")
private val VtMaliciousRegex = Regex(""""malicious"\s*:\s*(\d+)""")
private val VtSuspiciousRegex = Regex(""""suspicious"\s*:\s*(\d+)""")
private val VtHarmlessRegex = Regex(""""harmless"\s*:\s*(\d+)""")
private val VtUndetectedRegex = Regex(""""undetected"\s*:\s*(\d+)""")
private val VersionCodeXmlRegex = Regex("""(?i)versionCode\s*=\s*"?(\d+)"?""")
private val VersionCodeJsonRegex = Regex("""(?i)"(?:version_code|versioncode)"\s*:\s*"?(\d+)"?""")
private val DumpsysVersionCodeRegex = Regex("""\bversionCode=(\d+)""")
private val DumpsysCertSha256Regex = Regex("""(?i)(?:sha-?256|cert-sha256)\s*[:=]\s*([0-9a-f]{2}(?::[0-9a-f]{2}){31}|[0-9a-f]{64})""")
private val ColonRegex = Regex(":")

private val HexChars = "0123456789abcdef".toCharArray()

/** Computes the lowercase 64-character SHA-256 hex digest of [file] using a 64 KiB streaming buffer. */
fun sha256Hex(file: File): String =
    file.inputStream().use { sha256Hex(it) }

/** Computes the lowercase 64-character SHA-256 hex digest of [input] using a 64 KiB streaming buffer. */
fun sha256Hex(input: InputStream): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(HashBufferBytes)
    while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        if (read > 0) digest.update(buffer, 0, read)
    }
    return bytesToHex(digest.digest())
}

internal fun bytesToHex(bytes: ByteArray): String {
    val out = CharArray(bytes.size * 2)
    for (i in bytes.indices) {
        val v = bytes[i].toInt() and 0xFF
        out[i * 2] = HexChars[v ushr 4]
        out[i * 2 + 1] = HexChars[v and 0x0F]
    }
    return String(out)
}

/** Formats a 64-char SHA-256 hex string as `abcd1234…ef90` for compact display. */
fun truncateSha256(sha256: String): String {
    val clean = sha256.trim().lowercase(Locale.US)
    return if (clean.length >= 16) "${clean.take(8)}\u2026${clean.takeLast(4)}" else clean
}

// ---- Shield warning reasons, offline report, VirusTotal lookup, and verdict ----

enum class ShieldWarningReason {
    MalwareDetected,
    UnsignedPackage,
    DebugOrTestCertificate,
    SignatureMismatch,
    VersionDowngrade,
}

data class OfflineScanReport(
    val signed: Boolean,
    val debugOrTestSigned: Boolean,
    val signerSha256: String?,
    val versionCode: Long?,
    val highRiskPermissions: Set<String>,
    val versionDowngrade: Boolean,
    val signatureMismatch: Boolean,
    val reasons: List<ShieldWarningReason>,
    val allPermissions: List<String> = emptyList(),
    val certSubject: String? = null,
)

sealed interface VtLookupResult {
    data class Found(val malicious: Int, val suspicious: Int, val total: Int) : VtLookupResult
    data object UnknownHash : VtLookupResult
    data object InvalidKey : VtLookupResult
    data object RateLimited : VtLookupResult
    data object Unavailable : VtLookupResult
}

enum class ShieldStatusKind { VerifiedWithVt, OfflineNoKey, OfflineVtIssue }

fun shieldStatusKind(vtSummary: String?): ShieldStatusKind = when {
    vtSummary == null -> ShieldStatusKind.OfflineNoKey
    vtSummary.contains('/') -> ShieldStatusKind.VerifiedWithVt
    else -> ShieldStatusKind.OfflineVtIssue
}

sealed interface ShieldVerdict {
    val offline: OfflineScanReport?

    data class Clean(
        val sha256: String,
        val vtSummary: String?,
        override val offline: OfflineScanReport? = null,
    ) : ShieldVerdict

    data class Warning(
        val sha256: String,
        val reasons: List<ShieldWarningReason>,
        val vtMalicious: Int,
        val vtTotal: Int,
        override val offline: OfflineScanReport? = null,
    ) : ShieldVerdict
}

/** Evaluates the final [ShieldVerdict] from the package [sha256], [offline] scan report, and optional [vt] result. */
fun evaluateShieldVerdict(
    sha256: String,
    offline: OfflineScanReport,
    vt: VtLookupResult? = null,
    deepScanEnabled: Boolean = false,
    fileSizeBytes: Long = 0L,
): ShieldVerdict {
    val reasons = mutableListOf<ShieldWarningReason>()
    var vtMalicious = 0
    var vtTotal = 0
    var vtSummary: String? = null

    when (vt) {
        is VtLookupResult.Found -> {
            vtMalicious = vt.malicious + vt.suspicious
            vtTotal = vt.total
            vtSummary = "$vtMalicious/${vt.total}"
            if (vt.malicious > 0 || vt.suspicious > 0) {
                reasons += ShieldWarningReason.MalwareDetected
            }
        }
        VtLookupResult.UnknownHash -> {
            vtSummary = if (deepScanEnabled && fileSizeBytes in 1L..MaxDeepScanBytes) {
                "unknown (deep scan eligible)"
            } else {
                "unknown"
            }
        }
        VtLookupResult.InvalidKey -> vtSummary = "invalid key"
        VtLookupResult.RateLimited -> vtSummary = "rate limited"
        VtLookupResult.Unavailable -> vtSummary = "unavailable"
        null -> vtSummary = null
    }

    for (reason in offline.reasons) {
        if (reason !in reasons) reasons += reason
    }

    return if (reasons.isEmpty()) {
        ShieldVerdict.Clean(sha256 = sha256, vtSummary = vtSummary, offline = offline)
    } else {
        ShieldVerdict.Warning(
            sha256 = sha256,
            reasons = reasons,
            vtMalicious = vtMalicious,
            vtTotal = vtTotal,
            offline = offline,
        )
    }
}

// ---- Offline APK & Bundle analysis ----

/**
 * Inspects a single APK ([sourceFile]) or all extracted split `.apk` files in [bundle] offline:
 * - Checks whether every APK has a V1 (`META-INF/` `.RSA`/`.DSA`/`.EC`) or V2/V3 (`APK Sig Block 42`) signature.
 * - Checks whether any signer certificate matches public AOSP/SDK testkeys or common debug/mod subjects.
 * - Scans `AndroidManifest.xml` string tables (UTF-8 and UTF-16LE) for all requested and high-risk permissions.
 * - Compares candidate version code and signer SHA-256 against the currently installed package on the target device.
 */
fun analyzePackageOffline(
    sourceFile: File,
    bundle: ExtractedBundle,
    installedSigSha256: String? = null,
    installedVersionCode: Long? = null,
    candidateSigSha256: String? = null,
    candidateVersionCode: Long? = null,
    candidateDebugOrTest: Boolean = false,
    candidateCertSubject: String? = null,
): OfflineScanReport {
    var allSigned = true
    var anyDebugOrTest = candidateDebugOrTest
    var primarySignerSha256: String? = candidateSigSha256?.normalizeHexSha256()
    var primaryCertSubject: String? = candidateCertSubject?.takeIf { it.isNotBlank() }
    var detectedVersionCode: Long? = candidateVersionCode
    val riskPermissions = LinkedHashSet<String>()
    val allPermissions = LinkedHashSet<String>()

    try {
        if (bundle.format == PackageFormat.SingleApk || bundle.apks.isEmpty()) {
            if (!sourceFile.exists() || sourceFile.length() <= 0L) {
                allSigned = false
            } else {
                val apkInspection = inspectSingleApkFile(sourceFile)
                allSigned = apkInspection.signed || primarySignerSha256 != null
                if (apkInspection.debugOrTestSigned) anyDebugOrTest = true
                if (primarySignerSha256 == null) primarySignerSha256 = apkInspection.signerSha256
                if (primaryCertSubject == null) primaryCertSubject = apkInspection.certSubject
                if (detectedVersionCode == null) detectedVersionCode = apkInspection.versionCode
                riskPermissions += apkInspection.highRiskPermissions
                allPermissions += apkInspection.allPermissions
            }
        } else {
            val baseApk = bundle.findBaseApk()
            for (split in bundle.apks) {
                val apkInspection = inspectExtractedApk(split)
                if (!apkInspection.signed) allSigned = false
                if (apkInspection.debugOrTestSigned) anyDebugOrTest = true
                riskPermissions += apkInspection.highRiskPermissions
                allPermissions += apkInspection.allPermissions
                val isBase = baseApk != null && split.entryPath == baseApk.entryPath
                if (primarySignerSha256 == null || (isBase && apkInspection.signerSha256 != null && candidateSigSha256 == null)) {
                    apkInspection.signerSha256?.let { primarySignerSha256 = it }
                }
                if (primaryCertSubject == null || (isBase && apkInspection.certSubject != null && candidateCertSubject == null)) {
                    apkInspection.certSubject?.let { primaryCertSubject = it }
                }
                if (detectedVersionCode == null || (isBase && apkInspection.versionCode != null && candidateVersionCode == null)) {
                    apkInspection.versionCode?.let { detectedVersionCode = it }
                }
            }
            if (detectedVersionCode == null && sourceFile.exists() && sourceFile.length() > 0L) {
                detectedVersionCode = extractBundleJsonVersionCode(sourceFile)
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (t: Throwable) {
        allSigned = false
    }

    if (primarySignerSha256 != null && primarySignerSha256 in KnownTestKeySha256s) {
        anyDebugOrTest = true
    }
    if (primaryCertSubject != null && isDebugOrTestCertificateDn(primaryCertSubject)) {
        anyDebugOrTest = true
    }

    val normalizedInstalledSig = installedSigSha256?.normalizeHexSha256()
    val sigMismatch = normalizedInstalledSig != null &&
        primarySignerSha256 != null &&
        !normalizedInstalledSig.equals(primarySignerSha256, ignoreCase = true)

    val isDowngrade = installedVersionCode != null &&
        detectedVersionCode != null &&
        detectedVersionCode < installedVersionCode

    val reasons = mutableListOf<ShieldWarningReason>()
    if (!allSigned) reasons += ShieldWarningReason.UnsignedPackage
    if (allSigned && anyDebugOrTest) reasons += ShieldWarningReason.DebugOrTestCertificate
    if (sigMismatch) reasons += ShieldWarningReason.SignatureMismatch
    if (isDowngrade) reasons += ShieldWarningReason.VersionDowngrade

    return OfflineScanReport(
        signed = allSigned,
        debugOrTestSigned = anyDebugOrTest,
        signerSha256 = primarySignerSha256,
        versionCode = detectedVersionCode,
        highRiskPermissions = riskPermissions,
        versionDowngrade = isDowngrade,
        signatureMismatch = sigMismatch,
        reasons = reasons,
        allPermissions = allPermissions.sorted(),
        certSubject = primaryCertSubject,
    )
}

private fun String.normalizeHexSha256(): String? {
    val clean = trim().replace(ColonRegex, "").lowercase(Locale.US)
    return clean.takeIf { it.length == 64 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } }
}

private data class SingleApkInspection(
    val signed: Boolean,
    val debugOrTestSigned: Boolean,
    val signerSha256: String?,
    val certSubject: String?,
    val versionCode: Long?,
    val highRiskPermissions: Set<String>,
    val allPermissions: List<String>,
)

private fun inspectExtractedApk(extracted: ExtractedFile): SingleApkInspection {
    val existingFile = extracted.file
    if (existingFile != null && existingFile.exists()) {
        return inspectSingleApkFile(existingFile)
    }
    val temp = File.createTempFile("shield_split_", ".apk")
    return try {
        extracted.openStream().use { input ->
            temp.outputStream().use { output -> input.copyTo(output, HashBufferBytes) }
        }
        inspectSingleApkFile(temp)
    } finally {
        runCatching { temp.delete() }
    }
}

private fun inspectSingleApkFile(apkFile: File): SingleApkInspection {
    var hasV1Sig = false
    var debugOrTest = false
    var signerSha256: String? = null
    var certSubject: String? = null
    var versionCode: Long? = null
    val riskPerms = LinkedHashSet<String>()
    val allPerms = LinkedHashSet<String>()

    ZipFile(apkFile).use { zip ->
        val entries = zip.entries()
        val sigEntries = mutableListOf<ZipEntry>()
        var manifestEntry: ZipEntry? = null

        while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            if (entry.isDirectory) continue
            val name = entry.name.replace('\\', '/').trimStart('/')
            if (name == "AndroidManifest.xml") {
                manifestEntry = entry
            } else if (isV1SignatureBlockEntry(name)) {
                sigEntries += entry
            }
        }

        if (manifestEntry != null) {
            val manifestBytes = zip.getInputStream(manifestEntry).use { readBoundedBytes(it, MaxManifestBytes) }
            val scannedAll = scanManifestPermissions(manifestBytes)
            allPerms += scannedAll
            riskPerms += scanManifestRiskPermissions(manifestBytes)
            for (perm in scannedAll) {
                if (perm in HighRiskPermissions) riskPerms += perm
            }
            versionCode = extractManifestVersionCode(manifestBytes)
        }

        for (sigEntry in sigEntries) {
            val certBytes = zip.getInputStream(sigEntry).use { readBoundedBytes(it, MaxCertEntryBytes) }
            val parsed = parseCertificateBytes(certBytes)
            if (parsed != null) {
                hasV1Sig = true
                if (signerSha256 == null) signerSha256 = parsed.sha256
                if (certSubject == null) certSubject = parsed.subject
                if (parsed.debugOrTest) debugOrTest = true
            }
        }
    }

    val v2v3 = inspectApkSigningBlock(apkFile)
    val hasV2V3Sig = v2v3.present
    if (v2v3.signerSha256 != null && signerSha256 == null) {
        signerSha256 = v2v3.signerSha256
    }
    if (v2v3.certSubject != null && certSubject == null) {
        certSubject = v2v3.certSubject
    }
    if (v2v3.debugOrTest) {
        debugOrTest = true
    }

    return SingleApkInspection(
        signed = hasV1Sig || hasV2V3Sig,
        debugOrTestSigned = debugOrTest,
        signerSha256 = signerSha256,
        certSubject = certSubject,
        versionCode = versionCode,
        highRiskPermissions = riskPerms,
        allPermissions = allPerms.sorted(),
    )
}

private fun isV1SignatureBlockEntry(normalizedPath: String): Boolean {
    if (!normalizedPath.startsWith("META-INF/", ignoreCase = true)) return false
    val fileName = normalizedPath.substringAfterLast('/')
    if ('/' in normalizedPath.substringAfter("META-INF/")) return false
    return fileName.endsWith(".RSA", ignoreCase = true) ||
        fileName.endsWith(".DSA", ignoreCase = true) ||
        fileName.endsWith(".EC", ignoreCase = true)
}

internal data class ParsedCertInfo(
    val sha256: String,
    val debugOrTest: Boolean,
    val subject: String? = null,
)

private fun containsDnToken(dn: String, token: String): Boolean {
    var startIndex = 0
    while (true) {
        val idx = dn.indexOf(token, startIndex, ignoreCase = true)
        if (idx < 0) return false
        val endIdx = idx + token.length
        val afterOk = endIdx >= dn.length || !dn[endIdx].isLetterOrDigit()
        if (afterOk) return true
        startIndex = idx + 1
    }
}

internal fun isDebugOrTestCertificateDn(dn: String): Boolean {
    val normalized = dn.replace("\"", "")
    return KnownDebugOrTestDnTokens.any { token -> containsDnToken(normalized, token) }
}

internal fun parseCertificateBytes(rawBytes: ByteArray): ParsedCertInfo? {
    if (rawBytes.isEmpty()) return null
    return try {
        val cf = CertificateFactory.getInstance("X.509")
        val certs = runCatching { cf.generateCertificates(ByteArrayInputStream(rawBytes)) }.getOrNull()
        val first = certs?.firstOrNull() ?: extractEmbeddedDerCert(cf, rawBytes) ?: return null
        val sha256 = sha256Hex(ByteArrayInputStream(first.encoded))
        val sha1 = bytesToHex(MessageDigest.getInstance("SHA-1").digest(first.encoded))
        val x509 = first as? X509Certificate
        val subjectPrincipal = x509?.subjectX500Principal?.name?.trim()?.takeIf { it.isNotEmpty() }
            ?: x509?.subjectDN?.name?.trim()?.takeIf { it.isNotEmpty() }
        val combinedDn = buildString {
            append(x509?.subjectX500Principal?.name.orEmpty())
            append(' ')
            append(x509?.subjectDN?.name.orEmpty())
            append(' ')
            append(x509?.issuerX500Principal?.name.orEmpty())
            append(' ')
            append(x509?.issuerDN?.name.orEmpty())
        }
        val isDebugCn = isDebugOrTestCertificateDn(combinedDn)
        ParsedCertInfo(
            sha256 = sha256,
            debugOrTest = isDebugCn || sha256 in KnownTestKeySha256s || sha1 == "61ed377e85d386a8dfee6b864bd85b0bfaa5af81",
            subject = subjectPrincipal,
        )
    } catch (_: Throwable) {
        null
    }
}

private fun extractEmbeddedDerCert(cf: CertificateFactory, rawBytes: ByteArray): java.security.cert.Certificate? {
    for (i in 0 until rawBytes.size - 8) {
        if (rawBytes[i] == 0x30.toByte() &&
            rawBytes[i + 1] == 0x82.toByte() &&
            rawBytes[i + 4] == 0x30.toByte() &&
            (rawBytes[i + 5] == 0x82.toByte() || rawBytes[i + 5] == 0x81.toByte())
        ) {
            val bodyLen = ((rawBytes[i + 2].toInt() and 0xFF) shl 8) or (rawBytes[i + 3].toInt() and 0xFF)
            val totalLen = 4 + bodyLen
            if (bodyLen >= 128 && i + totalLen <= rawBytes.size) {
                val parsed = runCatching {
                    cf.generateCertificate(ByteArrayInputStream(rawBytes, i, totalLen))
                }.getOrNull()
                if (parsed != null) return parsed
            }
        }
    }
    return null
}

private data class ApkSigningBlockInfo(
    val present: Boolean,
    val signerSha256: String? = null,
    val certSubject: String? = null,
    val debugOrTest: Boolean = false,
)

private data class V2V3PairsExtraction(
    val hasSchemeId: Boolean,
    val certInfo: ParsedCertInfo?,
)

private val ApkSigBlockMagic = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
private const val ApkSigSchemeV2Id = 0x7109871a
private const val ApkSigSchemeV3Id = -0xfac9740 // 0xf05368c0
private const val ApkSigSchemeV31Id = 0x1b93ad61

private fun inspectApkSigningBlock(apkFile: File): ApkSigningBlockInfo {
    return try {
        RandomAccessFile(apkFile, "r").use { raf ->
            val fileLen = raf.length()
            if (fileLen < 22L) return ApkSigningBlockInfo(false)

            // Locate ZIP End of Central Directory (EOCD) in the last 65 KiB.
            val searchSize = minOf(fileLen, 65_557L).toInt()
            val tail = ByteArray(searchSize)
            raf.seek(fileLen - searchSize)
            raf.readFully(tail)

            var eocdOffsetInTail = -1
            for (i in searchSize - 22 downTo 0) {
                if (tail[i] == 0x50.toByte() &&
                    tail[i + 1] == 0x4B.toByte() &&
                    tail[i + 2] == 0x05.toByte() &&
                    tail[i + 3] == 0x06.toByte()
                ) {
                    eocdOffsetInTail = i
                    break
                }
            }

            if (eocdOffsetInTail >= 0) {
                val cdOffset = readUInt32Le(tail, eocdOffsetInTail + 16)
                if (cdOffset >= 24L && cdOffset <= fileLen) {
                    val footer = ByteArray(24)
                    raf.seek(cdOffset - 24L)
                    raf.readFully(footer)
                    val magicMatches = (0 until 16).all { footer[8 + it] == ApkSigBlockMagic[it] }
                    if (magicMatches) {
                        val sizeOfBlock = ByteBuffer.wrap(footer, 0, 8).order(ByteOrder.LITTLE_ENDIAN).long
                        val blockStart = cdOffset - 8L - sizeOfBlock
                        if (sizeOfBlock in 24L..(16L * 1024L * 1024L) && blockStart >= 0L) {
                            val pairsLen = (sizeOfBlock - 16L).toInt()
                            val pairsBytes = ByteArray(pairsLen)
                            raf.seek(blockStart + 8L)
                            raf.readFully(pairsBytes)
                            val extracted = extractV2V3CertFromPairs(pairsBytes)
                            return ApkSigningBlockInfo(
                                present = extracted.hasSchemeId,
                                signerSha256 = extracted.certInfo?.sha256,
                                debugOrTest = extracted.certInfo?.debugOrTest == true,
                            )
                        }
                    }
                }
            }
            ApkSigningBlockInfo(false)
        }
    } catch (_: Throwable) {
        ApkSigningBlockInfo(false)
    }
}

private fun extractV2V3CertFromPairs(pairsBytes: ByteArray): V2V3PairsExtraction {
    val buf = ByteBuffer.wrap(pairsBytes).order(ByteOrder.LITTLE_ENDIAN)
    var hasSchemeId = false
    while (buf.remaining() >= 12) {
        val pairLen = buf.long
        if (pairLen < 4L || pairLen > buf.remaining()) break
        val nextPairPos = buf.position() + pairLen.toInt()
        val id = buf.int
        if (id == ApkSigSchemeV2Id || id == ApkSigSchemeV3Id || id == ApkSigSchemeV31Id) {
            hasSchemeId = true
            val valueBytes = ByteArray(pairLen.toInt() - 4)
            buf.get(valueBytes)
            extractFirstX509FromSchemeBlock(valueBytes)?.let {
                return V2V3PairsExtraction(hasSchemeId = true, certInfo = it)
            }
        }
        buf.position(nextPairPos)
    }
    return V2V3PairsExtraction(hasSchemeId = hasSchemeId, certInfo = null)
}

private fun extractFirstX509FromSchemeBlock(blockBytes: ByteArray): ParsedCertInfo? {
    return try {
        val buf = ByteBuffer.wrap(blockBytes).order(ByteOrder.LITTLE_ENDIAN)
        val signersLen = buf.int
        if (signersLen <= 0 || signersLen > buf.remaining()) return null
        val firstSignerLen = buf.int
        if (firstSignerLen <= 0 || firstSignerLen > buf.remaining()) return null
        val signedDataLen = buf.int
        if (signedDataLen <= 0 || signedDataLen > buf.remaining()) return null
        val digestsLen = buf.int
        if (digestsLen < 0 || digestsLen > buf.remaining()) return null
        buf.position(buf.position() + digestsLen)
        val certsLen = buf.int
        if (certsLen <= 4 || certsLen > buf.remaining()) return null
        val firstCertLen = buf.int
        if (firstCertLen <= 0 || firstCertLen > buf.remaining()) return null
        val certBytes = ByteArray(firstCertLen)
        buf.get(certBytes)
        parseCertificateBytes(certBytes)
    } catch (_: Throwable) {
        null
    }
}

/**
 * Scans [manifestBytes] (either compiled binary AXML with UTF-8/UTF-16LE string pools or plain XML) for
 * all `android.permission.*` permissions and returns their sorted short names (e.g. `INTERNET`, `READ_SMS`).
 */
fun scanManifestPermissions(manifestBytes: ByteArray): List<String> {
    if (manifestBytes.isEmpty()) return emptyList()
    val found = LinkedHashSet<String>()
    val prefixAscii = "android.permission.".toByteArray(Charsets.US_ASCII)
    // 1. Scan ASCII / UTF-8 occurrences of `android.permission.<NAME>`
    var i = 0
    while (i <= manifestBytes.size - prefixAscii.size) {
        var match = true
        for (j in prefixAscii.indices) {
            if (manifestBytes[i + j] != prefixAscii[j]) {
                match = false
                break
            }
        }
        if (match) {
            val start = i + prefixAscii.size
            var end = start
            while (end < manifestBytes.size) {
                val c = manifestBytes[end].toInt() and 0xFF
                val isPermChar = (c in 'A'.code..'Z'.code) || (c in '0'.code..'9'.code) || c == '_'.code
                if (!isPermChar) break
                end++
            }
            if (end > start) {
                found += String(manifestBytes, start, end - start, Charsets.US_ASCII)
            }
            i = end
        } else {
            i++
        }
    }
    // 2. Scan UTF-16LE occurrences of `android.permission.<NAME>`
    val prefixUtf16 = "android.permission.".toByteArray(Charsets.UTF_16LE)
    var k = 0
    while (k <= manifestBytes.size - prefixUtf16.size) {
        var match = true
        for (j in prefixUtf16.indices) {
            if (manifestBytes[k + j] != prefixUtf16[j]) {
                match = false
                break
            }
        }
        if (match) {
            val start = k + prefixUtf16.size
            var pos = start
            val sb = StringBuilder()
            while (pos + 1 < manifestBytes.size) {
                val lo = manifestBytes[pos].toInt() and 0xFF
                val hi = manifestBytes[pos + 1].toInt() and 0xFF
                val isPermChar = hi == 0 && ((lo in 'A'.code..'Z'.code) || (lo in '0'.code..'9'.code) || lo == '_'.code)
                if (!isPermChar) break
                sb.append(lo.toChar())
                pos += 2
            }
            if (sb.isNotEmpty()) {
                found += sb.toString()
            }
            k = pos
        } else {
            k++
        }
    }
    for (perm in HighRiskPermissions) {
        val utf8 = perm.toByteArray(Charsets.UTF_8)
        val utf16le = perm.toByteArray(Charsets.UTF_16LE)
        if (containsSubarray(manifestBytes, utf8) || containsSubarray(manifestBytes, utf16le)) {
            found += perm
        }
    }
    return found.sorted()
}

/**
 * Scans [manifestBytes] (either compiled binary AXML with UTF-8/UTF-16LE string pools or plain XML) for
 * [HighRiskPermissions] without any external library.
 */
fun scanManifestRiskPermissions(manifestBytes: ByteArray): Set<String> {
    if (manifestBytes.isEmpty()) return emptySet()
    val found = LinkedHashSet<String>()
    for (perm in HighRiskPermissions) {
        val utf8 = perm.toByteArray(Charsets.UTF_8)
        val utf16le = perm.toByteArray(Charsets.UTF_16LE)
        if (containsSubarray(manifestBytes, utf8) || containsSubarray(manifestBytes, utf16le)) {
            found += perm
        }
    }
    return found
}

/**
 * Extracts `android:versionCode` from [manifestBytes], supporting both binary AXML (`0x0101021b` / `0x0101021c`)
 * and plain-text XML (`versionCode="..."`).
 */
fun extractManifestVersionCode(manifestBytes: ByteArray): Long? {
    if (manifestBytes.size >= 8) {
        parseBinaryAxmlVersionCode(manifestBytes)?.let { return it }
    }
    return try {
        val text = manifestBytes.toString(Charsets.UTF_8)
        VersionCodeXmlRegex.find(text)?.groupValues?.get(1)?.toLongOrNull()
    } catch (_: Throwable) {
        null
    }
}

private const val ResXmlType = 0x0003
private const val ResXmlResourceMapType = 0x0180
private const val ResXmlStartElementType = 0x0102
private const val AttrVersionCodeResId = 0x0101021b
private const val AttrVersionCodeMajorResId = 0x0101021c

private fun parseBinaryAxmlVersionCode(bytes: ByteArray): Long? {
    return try {
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val fileType = buf.getShort(0).toInt() and 0xFFFF
        val fileHeaderSize = buf.getShort(2).toInt() and 0xFFFF
        if (fileType != ResXmlType || fileHeaderSize < 8) return null

        var offset = fileHeaderSize
        var versionCodeResIndex = -1
        var versionCodeMajorResIndex = -1

        while (offset + 8 <= bytes.size) {
            val chunkType = buf.getShort(offset).toInt() and 0xFFFF
            val headerSize = buf.getShort(offset + 2).toInt() and 0xFFFF
            val chunkSize = buf.getInt(offset + 4)
            if (chunkSize < 8 || offset + chunkSize > bytes.size) break

            when (chunkType) {
                ResXmlResourceMapType -> {
                    val count = (chunkSize - headerSize) / 4
                    for (i in 0 until count) {
                        val resId = buf.getInt(offset + headerSize + i * 4)
                        if (resId == AttrVersionCodeResId) versionCodeResIndex = i
                        if (resId == AttrVersionCodeMajorResId) versionCodeMajorResIndex = i
                    }
                }
                ResXmlStartElementType -> {
                    if (offset + 36 <= bytes.size && versionCodeResIndex >= 0) {
                        val attrStart = buf.getShort(offset + 16 + 12).toInt() and 0xFFFF
                        val attrSize = buf.getShort(offset + 16 + 14).toInt() and 0xFFFF
                        val attrCount = buf.getShort(offset + 16 + 16).toInt() and 0xFFFF
                        val step = if (attrSize >= 20) attrSize else 20
                        var attrPos = offset + 16 + attrStart
                        var low: Long? = null
                        var high = 0L
                        for (i in 0 until attrCount) {
                            if (attrPos + 20 > offset + chunkSize) break
                            val nameIdx = buf.getInt(attrPos + 4)
                            val dataType = bytes[attrPos + 15].toInt() and 0xFF
                            val data = buf.getInt(attrPos + 16)
                            if (dataType in 0x10..0x1F) {
                                if (nameIdx == versionCodeResIndex) low = data.toLong() and 0xFFFFFFFFL
                                if (nameIdx == versionCodeMajorResIndex) high = data.toLong() and 0xFFFFFFFFL
                            }
                            attrPos += step
                        }
                        if (low != null) {
                            return (high shl 32) or low
                        }
                    }
                }
            }
            offset += chunkSize
        }
        null
    } catch (_: Throwable) {
        null
    }
}

private fun extractBundleJsonVersionCode(archiveFile: File): Long? = try {
    ZipFile(archiveFile).use { zip ->
        val entries = zip.entries()
        while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            if (entry.isDirectory) continue
            val name = entry.name.replace('\\', '/').trimStart('/')
            if (name.equals("manifest.json", ignoreCase = true) || name.equals("info.json", ignoreCase = true)) {
                val json = zip.getInputStream(entry).use { readBoundedBytes(it, 64 * 1024).toString(Charsets.UTF_8) }
                VersionCodeJsonRegex.find(json)?.groupValues?.get(1)?.toLongOrNull()?.let { return it }
            }
        }
        null
    }
} catch (_: Throwable) {
    null
}

internal fun containsSubarray(haystack: ByteArray, needle: ByteArray): Boolean {
    if (needle.isEmpty()) return true
    if (haystack.size < needle.size) return false
    val first = needle[0]
    val limit = haystack.size - needle.size
    outer@ for (i in 0..limit) {
        if (haystack[i] != first) continue
        for (j in 1 until needle.size) {
            if (haystack[i + j] != needle[j]) continue@outer
        }
        return true
    }
    return false
}

private fun readUInt32Le(bytes: ByteArray, offset: Int): Long =
    (bytes[offset].toLong() and 0xFFL) or
        ((bytes[offset + 1].toLong() and 0xFFL) shl 8) or
        ((bytes[offset + 2].toLong() and 0xFFL) shl 16) or
        ((bytes[offset + 3].toLong() and 0xFFL) shl 24)

private fun readBoundedBytes(input: InputStream, maxBytes: Int): ByteArray {
    val out = ByteArrayOutputStream()
    val buf = ByteArray(8192)
    var remaining = maxBytes
    while (remaining > 0) {
        val n = input.read(buf, 0, minOf(buf.size, remaining))
        if (n < 0) break
        if (n > 0) {
            out.write(buf, 0, n)
            remaining -= n
        }
    }
    return out.toByteArray()
}

// ---- Installed package info from ADB `dumpsys package <pkg>` & local PackageManager ----

data class InstalledAppInfo(
    val versionCode: Long?,
    val sigSha256: String?,
    val debugOrTestSigned: Boolean = false,
    val certSubject: String? = null,
)

/** Parses `dumpsys package <pkg>` output for `versionCode` and optional signer SHA-256. */
fun parseDumpsysInstalledApp(dumpsysOutput: String): InstalledAppInfo {
    val versionCode = DumpsysVersionCodeRegex.find(dumpsysOutput)?.groupValues?.get(1)?.toLongOrNull()
    val sigSha256 = DumpsysCertSha256Regex.find(dumpsysOutput)?.groupValues?.get(1)?.normalizeHexSha256()
    return InstalledAppInfo(versionCode = versionCode, sigSha256 = sigSha256)
}

/**
 * Queries the currently installed package info for [packageName] on the connected target device over [adb]
 * (`dumpsys package <pkg>`), and when [localContext] is provided (local device), supplements with [PackageManager]
 * signing certificate SHA-256 and `longVersionCode`.
 */
fun queryInstalledAppInfo(
    adb: AdbClient,
    packageName: String,
    localContext: Context? = null,
): InstalledAppInfo {
    val safePkg = sanitizePackageName(packageName)
    val dumpsys = runCatching { adb.shell("dumpsys package $safePkg") }.getOrDefault("")
    val parsed = parseDumpsysInstalledApp(dumpsys)

    var versionCode = parsed.versionCode
    var sigSha256 = parsed.sigSha256

    if (localContext != null) {
        try {
            val info = localContext.packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNING_CERTIFICATES,
            )
            if (versionCode == null) versionCode = info.longVersionCode
            if (sigSha256 == null) {
                val signer = info.signingInfo?.let { si ->
                    if (si.hasMultipleSigners()) si.apkContentsSigners?.firstOrNull()
                    else si.signingCertificateHistory?.firstOrNull()
                }
                if (signer != null) {
                    sigSha256 = sha256Hex(ByteArrayInputStream(signer.toByteArray()))
                }
            }
        } catch (_: Throwable) {
            // Package is not installed locally or could not be queried.
        }
    }
    return InstalledAppInfo(versionCode = versionCode, sigSha256 = sigSha256)
}

/** Extracts the signing certificate SHA-256 and `longVersionCode` from an APK file via Android [PackageManager]. */
fun queryArchiveAppInfo(context: Context, apkFile: File): InstalledAppInfo {
    return try {
        val info = context.packageManager.getPackageArchiveInfo(
            apkFile.path,
            PackageManager.GET_SIGNING_CERTIFICATES,
        ) ?: return InstalledAppInfo(null, null)
        val signer = info.signingInfo?.let { si ->
            if (si.hasMultipleSigners()) si.apkContentsSigners?.firstOrNull()
            else si.signingCertificateHistory?.firstOrNull()
        }
        val signerBytes = signer?.toByteArray()
        val parsedCert = signerBytes?.let(::parseCertificateBytes)
        val sigSha256 = parsedCert?.sha256 ?: signerBytes?.let { sha256Hex(ByteArrayInputStream(it)) }
        InstalledAppInfo(
            versionCode = info.longVersionCode,
            sigSha256 = sigSha256,
            debugOrTestSigned = parsedCert?.debugOrTest == true,
            certSubject = parsedCert?.subject,
        )
    } catch (_: Throwable) {
        InstalledAppInfo(null, null)
    }
}

// ---- VirusTotal API v3 hash lookup & response parser ----

/**
 * Pure JSON parser for VirusTotal v3 `GET /api/v3/files/{sha256}` responses:
 * - `200`: extracts `last_analysis_stats` (`malicious`, `suspicious`, `harmless`, `undetected`) -> [VtLookupResult.Found]
 * - `404`: [VtLookupResult.UnknownHash]
 * - `401` / `403`: [VtLookupResult.InvalidKey]
 * - `429`: [VtLookupResult.RateLimited]
 * - Any other status or malformed JSON: [VtLookupResult.Unavailable]
 */
fun parseVirusTotalResponse(httpCode: Int, body: String): VtLookupResult = when (httpCode) {
    200 -> {
        val statsSection = VtStatsBlockRegex.find(body)?.groupValues?.get(1) ?: body
        val malicious = VtMaliciousRegex.find(statsSection)?.groupValues?.get(1)?.toIntOrNull()
        val suspicious = VtSuspiciousRegex.find(statsSection)?.groupValues?.get(1)?.toIntOrNull()
        val harmless = VtHarmlessRegex.find(statsSection)?.groupValues?.get(1)?.toIntOrNull()
        val undetected = VtUndetectedRegex.find(statsSection)?.groupValues?.get(1)?.toIntOrNull()
        if (malicious == null && suspicious == null && harmless == null && undetected == null) {
            VtLookupResult.Unavailable
        } else {
            val m = malicious ?: 0
            val s = suspicious ?: 0
            val h = harmless ?: 0
            val u = undetected ?: 0
            VtLookupResult.Found(malicious = m, suspicious = s, total = m + s + h + u)
        }
    }
    404 -> VtLookupResult.UnknownHash
    401, 403 -> VtLookupResult.InvalidKey
    429 -> VtLookupResult.RateLimited
    else -> VtLookupResult.Unavailable
}

/**
 * Queries VirusTotal v3 (`GET https://www.virustotal.com/api/v3/files/$sha256`) with header `x-apikey: $apiKey`.
 * Never throws: any network or I/O error returns [VtLookupResult.Unavailable] so offline shield is never blocked.
 */
fun checkVirusTotalHash(sha256: String, apiKey: String, timeoutMs: Int = 10_000): VtLookupResult {
    val cleanHash = sha256.normalizeHexSha256() ?: return VtLookupResult.Unavailable
    val cleanKey = apiKey.trim().takeIf { it.isNotEmpty() } ?: return VtLookupResult.InvalidKey
    var conn: HttpURLConnection? = null
    return try {
        conn = (URL("https://www.virustotal.com/api/v3/files/$cleanHash").openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            useCaches = false
            setRequestProperty("Accept", "application/json")
            setRequestProperty("x-apikey", cleanKey)
        }
        val code = conn.responseCode
        val stream = (if (code in 200..299) conn.inputStream else conn.errorStream)
        val body = stream?.use { readBoundedBytes(it, MaxVtResponseBytes).toString(Charsets.UTF_8) }.orEmpty()
        parseVirusTotalResponse(code, body)
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        VtLookupResult.Unavailable
    } finally {
        runCatching { conn?.disconnect() }
    }
}

// ---- Keystore AES-GCM Encrypted Shield Settings ----

private const val ShieldPrefsName = "shield_settings"
private const val KeyShieldEnabled = "shield_enabled"
private const val KeyDeepScanEnabled = "deep_scan_enabled"
private const val KeyVtApiKeyCiphertext = "vt_api_key_enc"
private const val VtKeyStoreAlias = "gogo_vt_key_aes"
private const val AesGcmTransformation = "AES/GCM/NoPadding"
private const val GcmIvBytes = 12
private const val GcmTagBits = 128

/** Encrypts [plainKey] with [secretKey] using `AES/GCM/NoPadding` and encodes `IV + ciphertext` as Base64. */
internal fun encryptApiKeyWithSecretKey(plainKey: String, secretKey: SecretKey): String {
    val cipher = Cipher.getInstance(AesGcmTransformation)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    val iv = cipher.iv
    val plaintextBytes = plainKey.trim().toByteArray(Charsets.UTF_8)
    val ciphertext = try {
        cipher.doFinal(plaintextBytes)
    } finally {
        plaintextBytes.fill(0)
    }
    val combined = ByteArray(iv.size + ciphertext.size)
    System.arraycopy(iv, 0, combined, 0, iv.size)
    System.arraycopy(ciphertext, 0, combined, iv.size, ciphertext.size)
    return Base64.getEncoder().encodeToString(combined)
}

/** Decrypts a Base64 `IV + ciphertext` [encoded] string using [secretKey] (`AES/GCM/NoPadding`). */
internal fun decryptApiKeyWithSecretKey(encoded: String, secretKey: SecretKey): String? {
    if (encoded.isBlank()) return null
    val combined = Base64.getDecoder().decode(encoded.trim())
    if (combined.size <= GcmIvBytes) return null
    val cipher = Cipher.getInstance(AesGcmTransformation)
    cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GcmTagBits, combined, 0, GcmIvBytes))
    val decrypted = cipher.doFinal(combined, GcmIvBytes, combined.size - GcmIvBytes)
    return try {
        String(decrypted, Charsets.UTF_8).trim().takeIf { it.isNotEmpty() }
    } finally {
        decrypted.fill(0)
    }
}

/**
 * Persists Antivirus Shield settings in [SharedPreferences], encrypting the user's VirusTotal API key at rest
 * with an Android Keystore `AES/GCM/NoPadding` secret key (`alias = "gogo_vt_key_aes"`).
 */
class ShieldSettingsStore(
    private val prefs: SharedPreferences,
    private val keyProvider: () -> SecretKey = ::getOrCreateAndroidKeystoreAesKey,
) {
    constructor(context: Context) : this(
        context.applicationContext.getSharedPreferences(ShieldPrefsName, Context.MODE_PRIVATE),
    )

    var shieldEnabled: Boolean
        get() = runCatching { prefs.getBoolean(KeyShieldEnabled, true) }.getOrDefault(true)
        set(value) {
            runCatching { prefs.edit().putBoolean(KeyShieldEnabled, value).apply() }
        }

    var deepScanEnabled: Boolean
        get() = runCatching { prefs.getBoolean(KeyDeepScanEnabled, false) }.getOrDefault(false)
        set(value) {
            runCatching { prefs.edit().putBoolean(KeyDeepScanEnabled, value).apply() }
        }

    fun hasVirusTotalApiKey(): Boolean =
        runCatching { !prefs.getString(KeyVtApiKeyCiphertext, null).isNullOrBlank() }.getOrDefault(false)

    fun loadVirusTotalApiKey(): String? {
        val encoded = runCatching { prefs.getString(KeyVtApiKeyCiphertext, null) }.getOrNull()
            ?.takeIf { it.isNotBlank() } ?: return null
        return try {
            decryptApiKeyWithSecretKey(encoded, keyProvider())
        } catch (e: CancellationException) {
            throw e
        } catch (t: Throwable) {
            if (isKeyGone(t)) {
                runCatching { prefs.edit().remove(KeyVtApiKeyCiphertext).apply() }
            }
            null
        }
    }

    fun saveVirusTotalApiKey(rawKey: String?): Boolean {
        val clean = rawKey?.trim().orEmpty()
        if (clean.isEmpty()) {
            clearVirusTotalApiKey()
            return true
        }
        return try {
            val encrypted = encryptApiKeyWithSecretKey(clean, keyProvider())
            prefs.edit().putString(KeyVtApiKeyCiphertext, encrypted).apply()
            true
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            false
        }
    }

    fun clearVirusTotalApiKey() {
        runCatching {
            prefs.edit()
                .remove(KeyVtApiKeyCiphertext)
                .putBoolean(KeyDeepScanEnabled, false)
                .apply()
        }
    }
}

private fun getOrCreateAndroidKeystoreAesKey(): SecretKey {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (store.getKey(VtKeyStoreAlias, null) as? SecretKey)?.let { return it }
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
        init(
            KeyGenParameterSpec.Builder(
                VtKeyStoreAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
    }.generateKey()
}
