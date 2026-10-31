package app.gogogadget

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.CancellationException
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.RandomAccessFile
import java.net.HttpURLConnection
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
// VirusTotal v3 hash lookup (upload and analysis are in VirusTotal.kt), verdict evaluation, and Keystore-encrypted shield settings.

private const val HashBufferBytes = 64 * 1024
private const val MaxManifestBytes = 4 * 1024 * 1024
private const val MaxCertEntryBytes = 512 * 1024
/** A VirusTotal file report with every engine's result can be several hundred KiB; a longer body is never parsed. */
internal const val MaxVtResponseBytes = 2 * 1024 * 1024

/** A file with fewer analysing engines than this is not trusted, even when none of them flags it. */
const val MinVtEngines = 20

/** The largest file that is offered for upload to VirusTotal (its API limit for the large-file upload URL). */
const val MaxVtUploadBytes = 650L * 1024L * 1024L

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

/**
 * Certificates whose private key is public AND that mark a build as a system component: an APK signed with one can claim
 * the platform's privileges (shared UID `android.uid.system`). Match is a hard block. The digests are the AOSP platform,
 * shared and media keys listed above (the `.x509.pem` files in `build/target/product/security`, public in the AOSP tree). The AOSP
 * `testkey` is NOT here: modders sign with it all the time, so it stays a Yellow "test key" warning.
 *
 * OEM platform certificates that leaked (reported by Google's Android Partner Vulnerability Initiative in 2022:
 * Samsung, LG, MediaTek, Revoview, Szroco) are NOT embedded: no digest could be cited from a source at hand, and one is
 * never guessed. See the TODO list in the 0.9.28 section of the planning progress file.
 */
val CompromisedPlatformKeySha256s: Set<String> = setOf(
    // AOSP build/target/product/security/platform.x509.pem
    "27196e386b875e76adf700e7ea84e4c6eee33dfa8906c22283e97c3114461f2d",
    // AOSP build/target/product/security/shared.x509.pem
    "5b368cff2da2686996bc95eac190eaa4f5630f5f2050d07139c47f8c3190339f",
    // AOSP build/target/product/security/media.x509.pem
    "b79df4a82e90b57526525e2a39f21f90f5c41023f6760d92c07a0f964e2b0d84",
)

/**
 * Subject tokens of the public modding tools (Lucky Patcher, MT Manager, APKTool...): an APK signed by one of them was
 * repackaged. The Android debug certificate is matched by its complete DN ([isAndroidDebugDn]) and the AOSP keys by their
 * SHA-256 ([KnownTestKeySha256s]); generic names such as `CN=Unknown`, `CN=Test` or `OU=Android` are NOT here, because
 * `keytool` writes "Unknown" when a developer presses Enter on every question and real teams use "Android" as a unit name.
 */
private val ModToolDnTokens: List<String> = listOf(
    "O=APKTool",
    "CN=APK Easy Tool",
    "CN=MT Manager",
    "OU=MT Manager",
    "CN=NP Manager",
    "CN=Lucky Patcher",
)

// All Regex patterns escape literal `{`, `}`, `[`, and `]` outside character classes for Android ICU compatibility.
private val VersionCodeXmlRegex = Regex("""(?i)versionCode\s*=\s*"?(\d+)"?""")
private val VersionCodeJsonRegex = Regex("""(?i)"(?:version_code|versioncode)"\s*:\s*"?(\d+)"?""")
private val DumpsysVersionCodeRegex = Regex("""\bversionCode=(\d+)""")
private val DumpsysVersionNameRegex = Regex("""\bversionName=([^\s]+)""")
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

/**
 * Why a package is not Green. The order is the order of gravity: Red reasons first, then Yellow, and the UI lists them
 * that way ([orderedByGravity]).
 */
enum class ShieldWarningReason {
    MalwareDetected,
    CompromisedKey,
    SignatureMismatch,
    PackageMismatch,
    MalformedArchive,
    UnsignedPackage,
    LegacySignatureOnly,
    AdwareDetected,
    AbusivePermissions,
    VersionDowngrade,

    /** 1 to 3 engines flag the file and none of them is serious: the user decides. */
    EnginesFlagged,
    DropperDetected,
    DebugOrTestCertificate,
    SuspiciousNativeCode,
    InvalidNativeLibrary,
    RiskyPermissionCombo,

    /** Part of the package could not be inspected, so it is not proven clean. */
    ScanIncomplete,
    NotKnownToVirusTotal,

    /** No online source could be reached (no connection, timeout, service error). */
    VirusTotalUnreachable,
    OnlineRateLimited,
    OnlineKeyRejected,
    TooFewEngines,
    StaleAnalysis,
    VirusTotalKeyMissing,
    SelfUpdaterPermission,
}

enum class SecurityTier { Green, Yellow, Red }

enum class SecuritySeverity { Red, Yellow }

/**
 * Categorizes security verdict reasons into 3-Color Security Tiers:
 * - YELLOW (Caution / User Decision): everything that is not proof of harm. The user can accept it: EnginesFlagged,
 *   DropperDetected, DebugOrTestCertificate, SuspiciousNativeCode, InvalidNativeLibrary, RiskyPermissionCombo,
 *   ScanIncomplete, NotKnownToVirusTotal, VirusTotalUnreachable, OnlineRateLimited, OnlineKeyRejected, TooFewEngines,
 *   StaleAnalysis, VirusTotalKeyMissing, SelfUpdaterPermission. A missing proof is never Red.
 * - RED (Critical / Hard Block, no override): proof of harm or of a forged package: MalwareDetected, CompromisedKey,
 *   SignatureMismatch, PackageMismatch, MalformedArchive, UnsignedPackage, LegacySignatureOnly, AdwareDetected,
 *   AbusivePermissions, VersionDowngrade.
 */
fun ShieldWarningReason.severity(): SecuritySeverity = when (this) {
    ShieldWarningReason.EnginesFlagged,
    ShieldWarningReason.DropperDetected,
    ShieldWarningReason.DebugOrTestCertificate,
    ShieldWarningReason.SuspiciousNativeCode,
    ShieldWarningReason.InvalidNativeLibrary,
    ShieldWarningReason.RiskyPermissionCombo,
    ShieldWarningReason.ScanIncomplete,
    ShieldWarningReason.NotKnownToVirusTotal,
    ShieldWarningReason.VirusTotalUnreachable,
    ShieldWarningReason.OnlineRateLimited,
    ShieldWarningReason.OnlineKeyRejected,
    ShieldWarningReason.TooFewEngines,
    ShieldWarningReason.StaleAnalysis,
    ShieldWarningReason.VirusTotalKeyMissing,
    ShieldWarningReason.SelfUpdaterPermission -> SecuritySeverity.Yellow
    else -> SecuritySeverity.Red
}

/**
 * Returns the overall security tier of a [ShieldVerdict]:
 * - Green: proven clean
 * - Yellow: all warning reasons are Yellow severity
 * - Red: at least one reason is Red severity (fail-closed)
 */
fun securityTierOf(verdict: ShieldVerdict): SecurityTier = when (verdict) {
    is ShieldVerdict.Clean -> SecurityTier.Green
    is ShieldVerdict.NeedsUpload -> SecurityTier.Yellow
    is ShieldVerdict.Warning -> {
        if (verdict.reasons.any { it.severity() == SecuritySeverity.Red }) {
            SecurityTier.Red
        } else {
            SecurityTier.Yellow
        }
    }
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
    val issueDetail: String? = null,
    /** Known tracker SDKs found by the deep scan (informational only). */
    val trackers: List<String> = emptyList(),
    /** SHA-256 of every certificate in the APK's signing-certificate lineage (v3 rotation), oldest first; empty without rotation. */
    val signerLineageSha256: Set<String> = emptySet(),
    /** Every deep-scan finding with its code and parameters, so the screen can say it in the user's language. */
    val issues: List<StaticAnalysisIssue> = emptyList(),
    /**
     * Capabilities the app ships but does not request, such as `BIND_ACCESSIBILITY_SERVICE` when it declares an accessibility
     * service. They take part in the permission rules and are not counted as requested permissions.
     */
    val capabilities: Set<String> = emptySet(),
)

sealed interface VtLookupResult {
    /**
     * [lastAnalysisDate] is epoch seconds, null when the service did not say. [detections] are the engines that flagged the
     * file (category malicious or suspicious) with the name each gave; empty when the service gave only counts.
     */
    data class Found(
        val malicious: Int,
        val suspicious: Int,
        val total: Int,
        val lastAnalysisDate: Long? = null,
        val detections: List<EngineFlag> = emptyList(),
    ) : VtLookupResult
    data object UnknownHash : VtLookupResult
    data object InvalidKey : VtLookupResult
    data object RateLimited : VtLookupResult
    data object Unavailable : VtLookupResult
}

enum class ShieldStatusKind { VerifiedWithVt, TrustedUpdate }

fun shieldStatusKind(verdict: ShieldVerdict.Clean): ShieldStatusKind =
    if (verdict.trustedUpdate) ShieldStatusKind.TrustedUpdate else ShieldStatusKind.VerifiedWithVt

/**
 * What the online sources said about one APK of the package (a bundle has one entry per split). [vt] and [md] are null
 * when that source was not asked (no key); a source that was asked and failed is one of the failure results.
 */
data class ShieldFileEvidence(
    val name: String,
    val sizeBytes: Long,
    val sha256: String,
    val vt: VtLookupResult? = null,
    /** False for a resource-only split: it is not looked up online (it still went through the offline checks). */
    val lookedUp: Boolean = true,
    val md: VtLookupResult? = null,
    val vtInfo: SourceInfo = SourceInfo(),
    val mdInfo: SourceInfo = SourceInfo(),
)

/** A file VirusTotal does not know yet, which the user may choose to upload. */
data class UploadCandidate(val name: String, val sizeBytes: Long, val sha256: String)

sealed interface ShieldVerdict {
    val offline: OfflineScanReport?

    /** GoGo's own report of what the online sources said; null when nothing was looked up. */
    val report: ShieldReport?

    /** No engine flags the package ([vtSummary] like `VirusTotal 0/62`, null when a trusted update was not looked up). */
    data class Clean(
        val sha256: String,
        val vtSummary: String?,
        override val offline: OfflineScanReport? = null,
        val trustedUpdate: Boolean = false,
        override val report: ShieldReport? = null,
    ) : ShieldVerdict

    /** [vtMalicious] and [vtTotal] are the flagging engines and the engines asked, for the worst file. */
    data class Warning(
        val sha256: String,
        val reasons: List<ShieldWarningReason>,
        val vtMalicious: Int,
        val vtTotal: Int,
        override val offline: OfflineScanReport? = null,
        override val report: ShieldReport? = null,
    ) : ShieldVerdict

    /** Safety is not proven yet: these files can be sent to VirusTotal, after the user agrees. */
    data class NeedsUpload(
        val sha256: String,
        val files: List<UploadCandidate>,
        override val offline: OfflineScanReport? = null,
        override val report: ShieldReport? = null,
    ) : ShieldVerdict
}

/**
 * An update of the installed app: it is signed with the same certificate as the installed one, its version is not
 * older, and the offline scan found nothing wrong. A lone self-updater permission is information, not a finding.
 */
fun isTrustedUpdate(offline: OfflineScanReport, installed: InstalledAppInfo?): Boolean {
    val installedSig = installed?.sigSha256?.normalizeHexSha256() ?: return false
    val installedVersion = installed.versionCode ?: return false
    val candidateSig = offline.signerSha256?.normalizeHexSha256() ?: return false
    val candidateVersion = offline.versionCode ?: return false
    // A key rotation counts: the installed certificate is an ancestor of the new signer in the APK's lineage.
    val sameSigner = candidateSig == installedSig || installedSig in offline.signerLineageSha256
    return offline.reasons.all { it == ShieldWarningReason.SelfUpdaterPermission } && sameSigner && candidateVersion >= installedVersion
}

/** True when the newest dated analysis of [answered] is older than [StaleAnalysisDays]; undated sources never make it fresh. */
internal fun isStaleAnalysis(answered: List<SourceReport>, nowEpochSeconds: Long): Boolean {
    val dated = answered.mapNotNull { it.analysisDate }
    if (dated.isEmpty()) return false
    return dated.all { (nowEpochSeconds - it) / 86_400L > StaleAnalysisDays }
}

/** What is missing from the online proof of each looked-up file; fills [reasons] and the files nobody knows into [unknown]. */
private fun collectOnlineGaps(
    checked: List<ReportFile>,
    nowEpochSeconds: Long,
    reasons: MutableSet<ShieldWarningReason>,
    unknown: MutableList<ReportFile>,
) {
    if (checked.isEmpty()) {
        reasons += ShieldWarningReason.VirusTotalUnreachable
        return
    }
    for (file in checked) {
        val queried = file.sources.filter { it.status != SourceStatus.NotQueried }
        val answered = queried.filter { it.status == SourceStatus.Answered }
        when {
            answered.isNotEmpty() -> {
                if (answered.maxOf { it.total } < MinVtEngines) reasons += ShieldWarningReason.TooFewEngines
                if (isStaleAnalysis(answered, nowEpochSeconds)) reasons += ShieldWarningReason.StaleAnalysis
            }
            queried.isEmpty() -> reasons += ShieldWarningReason.VirusTotalUnreachable
            queried.all { it.status == SourceStatus.UnknownHash } -> unknown += file
            else -> {
                // One source did not know the file and another failed: the file is not "unknown", it is not checked.
                if (queried.any { it.status == SourceStatus.RateLimited }) reasons += ShieldWarningReason.OnlineRateLimited
                if (queried.any { it.status == SourceStatus.InvalidKey }) reasons += ShieldWarningReason.OnlineKeyRejected
                if (queried.any { it.status == SourceStatus.Unavailable }) reasons += ShieldWarningReason.VirusTotalUnreachable
            }
        }
    }
}

/**
 * Decides what the package is, from BOTH the on-device findings and the online evidence; the result is the worst of the
 * two, so an on-device warning never hides what the online engines said. Rules:
 * - engines: 4 or more distinct flagging engines, or any serious detection name, is Red ([ShieldWarningReason.MalwareDetected]);
 *   1 to 3 light detections is Yellow ([ShieldWarningReason.EnginesFlagged]);
 * - no key at all: Yellow, never Green; a source that failed (no network, quota, rejected key, timeout) is Yellow with its own
 *   reason, and a source's failure never hides the other source's answer;
 * - a file every asked source does not know is Yellow, with an optional upload when [canUpload] and no Red reason exists;
 *   it is only "unknown" when no asked source failed;
 * - fewer than [MinVtEngines] engines, or an analysis older than [StaleAnalysisDays], is Yellow;
 * - a trusted update (same signer, not older) is Green when no engine flags it and the on-device scan found nothing.
 * Resource-only splits ([ShieldFileEvidence.lookedUp] false) are ignored for the online rules.
 */
fun evaluateShieldVerdict(
    sha256: String,
    offline: OfflineScanReport,
    hasKey: Boolean,
    trustedUpdate: Boolean,
    files: List<ShieldFileEvidence>,
    canUpload: Boolean = true,
    displayName: String? = null,
    nowEpochSeconds: Long = System.currentTimeMillis() / 1000L,
): ShieldVerdict {
    val report = buildShieldReport(displayName ?: files.firstOrNull()?.name.orEmpty(), sha256, files)
    val reasons = LinkedHashSet<ShieldWarningReason>(offline.reasons)
    val unknown = mutableListOf<ReportFile>()

    when (report.level) {
        EngineLevel.Severe -> reasons += ShieldWarningReason.MalwareDetected
        EngineLevel.Light -> reasons += ShieldWarningReason.EnginesFlagged
        EngineLevel.Clean -> Unit
    }
    if (report.level != EngineLevel.Severe && !trustedUpdate) {
        if (!hasKey) reasons += ShieldWarningReason.VirusTotalKeyMissing
        else collectOnlineGaps(report.files.filter { it.lookedUp }, nowEpochSeconds, reasons, unknown)
    }
    if (unknown.isNotEmpty()) {
        val hasRed = reasons.any { it.severity() == SecuritySeverity.Red }
        // The upload is not offered while a service is failing for another file: the answer would not be trusted either.
        val serviceFailing = reasons.any {
            it == ShieldWarningReason.VirusTotalUnreachable || it == ShieldWarningReason.OnlineRateLimited ||
                it == ShieldWarningReason.OnlineKeyRejected
        }
        if (!hasRed && !serviceFailing && canUpload && unknown.none { it.sizeBytes > MaxVtUploadBytes }) {
            return ShieldVerdict.NeedsUpload(sha256, unknown.map { UploadCandidate(it.name, it.sizeBytes, it.sha256) }, offline, report)
        }
        reasons += ShieldWarningReason.NotKnownToVirusTotal
    }
    // A lone self-updater permission is how every self-updating app works: information, not a warning.
    if (reasons.size == 1 && ShieldWarningReason.SelfUpdaterPermission in reasons) reasons.clear()
    if (reasons.isEmpty()) {
        return ShieldVerdict.Clean(sha256, report.summary, offline, trustedUpdate = trustedUpdate, report = report)
    }
    return ShieldVerdict.Warning(sha256, orderedByGravity(reasons), report.flaggedEngines, report.totalEngines, offline, report)
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
    candidateMinSdk: Int? = null,
    candidateTargetSdk: Int? = null,
    candidateLineageSha256: Collection<String> = emptyList(),
): OfflineScanReport {
    var allSigned = true
    var anyCompromised = false
    var anyV1Only = false
    var anyV2Plus = false
    var structureProblem: String? = null
    var anyDebugOrTest = candidateDebugOrTest
    var primarySignerSha256: String? = candidateSigSha256?.normalizeHexSha256()
    var primaryCertSubject: String? = candidateCertSubject?.takeIf { it.isNotBlank() }
    var detectedVersionCode: Long? = candidateVersionCode
    val riskPermissions = LinkedHashSet<String>()
    val allPermissions = LinkedHashSet<String>()
    val capabilities = LinkedHashSet<String>()

    try {
        if (bundle.format == PackageFormat.SingleApk || bundle.apks.isEmpty()) {
            if (!sourceFile.exists() || sourceFile.length() <= 0L) {
                allSigned = false
            } else {
                val apkInspection = inspectSingleApkFile(sourceFile)
                allSigned = apkInspection.signed || primarySignerSha256 != null
                if (apkInspection.debugOrTestSigned) anyDebugOrTest = true
                if (apkInspection.compromised) anyCompromised = true
                if (apkInspection.v1Only) anyV1Only = true
                if (apkInspection.hasV2Plus) anyV2Plus = true
                structureProblem = structureProblem ?: apkInspection.structureProblem
                if (primarySignerSha256 == null) primarySignerSha256 = apkInspection.signerSha256
                if (primaryCertSubject == null) primaryCertSubject = apkInspection.certSubject
                if (detectedVersionCode == null) detectedVersionCode = apkInspection.versionCode
                riskPermissions += apkInspection.highRiskPermissions
                allPermissions += apkInspection.allPermissions
                capabilities += apkInspection.capabilities
            }
        } else {
            val baseApk = bundle.findBaseApk()
            for (split in bundle.apks) {
                val apkInspection = inspectExtractedApk(split)
                if (!apkInspection.signed) allSigned = false
                if (apkInspection.debugOrTestSigned) anyDebugOrTest = true
                if (apkInspection.compromised) anyCompromised = true
                if (apkInspection.v1Only) anyV1Only = true
                if (apkInspection.hasV2Plus) anyV2Plus = true
                structureProblem = structureProblem ?: apkInspection.structureProblem
                riskPermissions += apkInspection.highRiskPermissions
                allPermissions += apkInspection.allPermissions
                capabilities += apkInspection.capabilities
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

    // Nothing here verifies a signature (pm does), but a package whose signer certificate cannot be read at all is not trusted.
    if (primarySignerSha256 == null) allSigned = false

    if (primarySignerSha256 != null && primarySignerSha256 in KnownTestKeySha256s) {
        anyDebugOrTest = true
    }
    if (primarySignerSha256 != null && primarySignerSha256 in CompromisedPlatformKeySha256s) {
        anyCompromised = true
    }
    if (primaryCertSubject != null && isDebugOrTestCertificateDn(primaryCertSubject)) {
        anyDebugOrTest = true
    }

    val normalizedInstalledSig = installedSigSha256?.normalizeHexSha256()
    val lineage = candidateLineageSha256.mapNotNull { it.normalizeHexSha256() }.toSet()
    // A new signer is accepted when the installed certificate is an ancestor of it in the APK's v3 rotation lineage.
    val sigMismatch = normalizedInstalledSig != null &&
        primarySignerSha256 != null &&
        !normalizedInstalledSig.equals(primarySignerSha256, ignoreCase = true) &&
        normalizedInstalledSig !in lineage

    val isDowngrade = installedVersionCode != null &&
        detectedVersionCode != null &&
        detectedVersionCode < installedVersionCode

    val reasons = mutableListOf<ShieldWarningReason>()
    if (structureProblem != null) reasons += ShieldWarningReason.MalformedArchive
    if (anyV1Only && !anyV2Plus && isV1OnlyRejected(true, false, candidateMinSdk, candidateTargetSdk)) {
        reasons += ShieldWarningReason.LegacySignatureOnly
    }
    if (anyCompromised) reasons += ShieldWarningReason.CompromisedKey
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
        issueDetail = structureProblem,
        signerLineageSha256 = lineage,
        capabilities = capabilities,
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
    val capabilities: Set<String> = emptySet(),
    val compromised: Boolean = false,
    /** Signed with a v1 (JAR) signature and no v2/v3 block. */
    val v1Only: Boolean = false,
    val hasV2Plus: Boolean = false,
    /** What is inconsistent in the archive structure (BadPack, Janus polyglot), or null. */
    val structureProblem: String? = null,
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
    val v1Certs = mutableListOf<ParsedCertInfo>()
    var versionCode: Long? = null
    val riskPerms = LinkedHashSet<String>()
    val allPerms = LinkedHashSet<String>()
    val capabilities = LinkedHashSet<String>()

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
            // The permissions the manifest declares with <uses-permission>; the string scan is only the fallback for a
            // manifest that is neither binary nor plain XML.
            val declared = declaredManifestPermissions(manifestBytes)
            if (declared != null) {
                allPerms += declared
                for (perm in declared) {
                    if (perm in HighRiskPermissions) riskPerms += perm
                }
            } else {
                val scannedAll = scanManifestPermissions(manifestBytes)
                allPerms += scannedAll
                riskPerms += scanManifestRiskPermissions(manifestBytes)
                for (perm in scannedAll) {
                    if (perm in HighRiskPermissions) riskPerms += perm
                }
            }
            versionCode = extractManifestVersionCode(manifestBytes)
            if (declaredServiceGuards(manifestBytes)?.contains("BIND_ACCESSIBILITY_SERVICE") == true) {
                capabilities += "BIND_ACCESSIBILITY_SERVICE"
                riskPerms += "BIND_ACCESSIBILITY_SERVICE"
            }
        }

        for (sigEntry in sigEntries) {
            val certBytes = zip.getInputStream(sigEntry).use { readBoundedBytes(it, MaxCertEntryBytes) }
            val parsed = parseCertificateBytes(certBytes)
            if (parsed != null) v1Certs += parsed
        }
    }

    val v2v3 = inspectApkSigningBlock(apkFile)
    val facts = mergeSignerFacts(v1Certs, v2v3.certs)
    val structure = if (isJanusPolyglot(apkFile)) "a DEX file is glued in front of the APK (Janus)" else zipStructureProblem(apkFile)

    return SingleApkInspection(
        signed = v1Certs.isNotEmpty() || v2v3.present,
        compromised = facts.compromised,
        v1Only = v1Certs.isNotEmpty() && !v2v3.present,
        hasV2Plus = v2v3.present,
        structureProblem = structure,
        debugOrTestSigned = facts.debugOrTest,
        signerSha256 = facts.signerSha256,
        certSubject = facts.certSubject,
        versionCode = versionCode,
        highRiskPermissions = riskPerms,
        allPermissions = allPerms.sorted(),
        capabilities = capabilities,
    )
}

internal data class SignerFacts(
    val signerSha256: String?,
    val certSubject: String?,
    val debugOrTest: Boolean,
    val compromised: Boolean = false,
)

/** The v2/v3 signer wins over a v1 certificate (the platform checks v2/v3 first); a test key among ANY certificate flags the package. */
internal fun mergeSignerFacts(v1: List<ParsedCertInfo>, v2v3: List<ParsedCertInfo>): SignerFacts {
    val primary = v2v3.firstOrNull() ?: v1.firstOrNull()
    return SignerFacts(primary?.sha256, primary?.subject, (v1 + v2v3).any { it.debugOrTest }, (v1 + v2v3).any { it.compromised })
}

/** True when ANY of the DER [certs] is a public test/debug key. */
internal fun anyCertDebugOrTest(certs: List<ByteArray>): Boolean = certs.any { parseCertificateBytes(it)?.debugOrTest == true }

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
    val compromised: Boolean = false,
)

private fun containsDnToken(dn: String, token: String): Boolean {
    var startIndex = 0
    while (true) {
        val idx = dn.indexOf(token, startIndex, ignoreCase = true)
        if (idx < 0) return false
        val endIdx = idx + token.length
        val beforeOk = idx == 0 || !dn[idx - 1].isLetterOrDigit()
        val afterOk = endIdx >= dn.length || !dn[endIdx].isLetterOrDigit()
        if (beforeOk && afterOk) return true
        startIndex = idx + 1
    }
}

/** The relative names of a distinguished name as lower-case `key=value` pairs, separated by commas, `/` or `+`. */
private fun dnParts(dn: String): List<String> =
    dn.replace("\"", "").split(',', '/', '+').map { it.trim().lowercase(Locale.ROOT).replace(" =", "=").replace("= ", "=") }.filter { it.isNotEmpty() }

/**
 * True when [dn] is exactly the Android SDK debug certificate: `CN=Android Debug, O=Android, C=US` (three names, in any
 * order). Nothing less specific counts as a debug certificate.
 */
internal fun isAndroidDebugDn(dn: String): Boolean =
    dnParts(dn).toSet() == setOf("cn=android debug", "o=android", "c=us")

/** True for the exact Android SDK debug DN or for the DN of a public modding tool. [dn] is ONE name: subject or issuer, never both joined. */
internal fun isDebugOrTestCertificateDn(dn: String): Boolean {
    val normalized = dn.replace("\"", "")
    return isAndroidDebugDn(normalized) || ModToolDnTokens.any { token -> containsDnToken(normalized, token) }
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
        // Each name on its own: joined together they would turn two unrelated names into one match.
        val names = listOf(
            x509?.subjectX500Principal?.name,
            x509?.subjectDN?.name,
            x509?.issuerX500Principal?.name,
            x509?.issuerDN?.name,
        ).filterNotNull()
        val isDebugCn = names.any { isDebugOrTestCertificateDn(it) }
        ParsedCertInfo(
            sha256 = sha256,
            debugOrTest = isDebugCn || sha256 in KnownTestKeySha256s || sha1 == "61ed377e85d386a8dfee6b864bd85b0bfaa5af81",
            subject = subjectPrincipal,
            compromised = sha256 in CompromisedPlatformKeySha256s,
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
    val certs: List<ParsedCertInfo> = emptyList(),
)

private data class V2V3PairsExtraction(
    val hasSchemeId: Boolean,
    val certs: List<ParsedCertInfo>,
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
                                certs = extracted.certs,
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
    val certs = mutableListOf<ParsedCertInfo>()
    while (buf.remaining() >= 12) {
        val pairLen = buf.long
        if (pairLen < 4L || pairLen > buf.remaining()) break
        val nextPairPos = buf.position() + pairLen.toInt()
        val id = buf.int
        if (id == ApkSigSchemeV2Id || id == ApkSigSchemeV3Id || id == ApkSigSchemeV31Id) {
            hasSchemeId = true
            val valueBytes = ByteArray(pairLen.toInt() - 4)
            buf.get(valueBytes)
            certs += extractX509sFromSchemeBlock(valueBytes)
        }
        buf.position(nextPairPos)
    }
    return V2V3PairsExtraction(hasSchemeId = hasSchemeId, certs = certs)
}

/** Every certificate of every signer in a v2/v3 scheme block, in file order; whatever was readable before a malformed part. */
private fun extractX509sFromSchemeBlock(blockBytes: ByteArray): List<ParsedCertInfo> {
    val found = mutableListOf<ParsedCertInfo>()
    try {
        val buf = ByteBuffer.wrap(blockBytes).order(ByteOrder.LITTLE_ENDIAN)
        val signersLen = buf.int
        if (signersLen <= 0 || signersLen > buf.remaining()) return found
        val signersEnd = buf.position() + signersLen
        while (buf.position() + 4 <= signersEnd) {
            val signerLen = buf.int
            if (signerLen <= 0 || signerLen > signersEnd - buf.position()) break
            val signerEnd = buf.position() + signerLen
            val signedDataLen = buf.int
            if (signedDataLen <= 0 || signedDataLen > signerEnd - buf.position()) break
            val signedDataEnd = buf.position() + signedDataLen
            val digestsLen = buf.int
            if (digestsLen < 0 || digestsLen > signedDataEnd - buf.position()) break
            buf.position(buf.position() + digestsLen)
            val certsLen = buf.int
            if (certsLen < 0 || certsLen > signedDataEnd - buf.position()) break
            val certsEnd = buf.position() + certsLen
            while (buf.position() + 4 <= certsEnd) {
                val certLen = buf.int
                if (certLen <= 0 || certLen > certsEnd - buf.position()) break
                val certBytes = ByteArray(certLen)
                buf.get(certBytes)
                parseCertificateBytes(certBytes)?.let { found += it }
            }
            buf.position(signerEnd)
        }
    } catch (_: Throwable) {
        // Keep what was read.
    }
    return found
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
        axmlVersionCode(manifestBytes)?.let { return it }
    }
    return try {
        val text = manifestBytes.toString(Charsets.UTF_8)
        VersionCodeXmlRegex.find(text)?.groupValues?.get(1)?.toLongOrNull()
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

internal fun readBoundedBytes(input: InputStream, maxBytes: Int): ByteArray {
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

/** The response body as text, or null when it is longer than [MaxVtResponseBytes]: a cut body is never parsed. */
internal fun readVtBody(input: InputStream): String? {
    val bytes = readBoundedBytes(input, MaxVtResponseBytes + 1)
    return if (bytes.size > MaxVtResponseBytes) null else bytes.toString(Charsets.UTF_8)
}

// ---- Installed package info from ADB `dumpsys package <pkg>` & local PackageManager ----

data class InstalledAppInfo(
    val versionCode: Long?,
    val sigSha256: String?,
    val debugOrTestSigned: Boolean = false,
    val certSubject: String? = null,
    val appName: String? = null,
    val versionName: String? = null,
    val minSdk: Int? = null,
    val targetSdk: Int? = null,
    /** SHA-256 of the certificates in the APK's signing lineage (v3 rotation), oldest first; empty without rotation. */
    val lineageSha256: List<String> = emptyList(),
    /** The device could not be asked (the shell call failed): the installed version is unknown, not "not installed". */
    val queryFailed: Boolean = false,
)

/** Parses `dumpsys package <pkg>` output for `versionCode` and optional signer SHA-256. */
fun parseDumpsysInstalledApp(dumpsysOutput: String): InstalledAppInfo {
    val versionCode = DumpsysVersionCodeRegex.find(dumpsysOutput)?.groupValues?.get(1)?.toLongOrNull()
    val sigSha256 = DumpsysCertSha256Regex.find(dumpsysOutput)?.groupValues?.get(1)?.normalizeHexSha256()
    val versionName = DumpsysVersionNameRegex.find(dumpsysOutput)?.groupValues?.get(1)
    return InstalledAppInfo(versionCode = versionCode, sigSha256 = sigSha256, versionName = versionName)
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
    val dumpsysResult = runCatching { adb.shell("dumpsys package $safePkg") }
    val dumpsys = dumpsysResult.getOrDefault("")
    val parsed = parseDumpsysInstalledApp(dumpsys)

    var versionCode = parsed.versionCode
    var sigSha256 = parsed.sigSha256
    var versionName = parsed.versionName
    var appName: String? = null

    if (localContext != null) {
        try {
            val info = localContext.packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNING_CERTIFICATES,
            )
            if (versionCode == null) versionCode = info.longVersionCode
            if (versionName == null) versionName = info.versionName
            appName = runCatching { info.applicationInfo?.loadLabel(localContext.packageManager)?.toString() }.getOrNull()
            if (sigSha256 == null) {
                // apkContentsSigners holds the current signer even after a key rotation; the history starts with the oldest.
                val signer = info.signingInfo?.let { si ->
                    si.apkContentsSigners?.firstOrNull() ?: si.signingCertificateHistory?.lastOrNull()
                }
                if (signer != null) {
                    sigSha256 = sha256Hex(ByteArrayInputStream(signer.toByteArray()))
                }
            }
        } catch (_: Throwable) {
            // Package is not installed locally or could not be queried.
        }
    }
    return InstalledAppInfo(
        versionCode = versionCode,
        sigSha256 = sigSha256,
        appName = appName,
        versionName = versionName,
        queryFailed = dumpsysResult.isFailure,
    )
}

/** Extracts the signing certificate SHA-256 and `longVersionCode` from an APK file via Android [PackageManager]. */
fun queryArchiveAppInfo(context: Context, apkFile: File): InstalledAppInfo {
    return try {
        val info = context.packageManager.getPackageArchiveInfo(
            apkFile.path,
            PackageManager.GET_SIGNING_CERTIFICATES,
        ) ?: return InstalledAppInfo(null, null)
        val signer = info.signingInfo?.let { si ->
            si.apkContentsSigners?.firstOrNull() ?: si.signingCertificateHistory?.lastOrNull()
        }
        val signerBytes = signer?.toByteArray()
        val parsedCert = signerBytes?.let(::parseCertificateBytes)
        val sigSha256 = parsedCert?.sha256 ?: signerBytes?.let { sha256Hex(ByteArrayInputStream(it)) }
        val allSigners = info.signingInfo?.apkContentsSigners.orEmpty().map { it.toByteArray() }
        // The lineage is only trusted when the platform itself parsed a proof of rotation out of the APK.
        val lineage = info.signingInfo?.takeIf { it.hasPastSigningCertificates() && !it.hasMultipleSigners() }
            ?.signingCertificateHistory.orEmpty().map { sha256Hex(ByteArrayInputStream(it.toByteArray())) }
        InstalledAppInfo(
            versionCode = info.longVersionCode,
            sigSha256 = sigSha256,
            debugOrTestSigned = parsedCert?.debugOrTest == true || anyCertDebugOrTest(allSigners),
            certSubject = parsedCert?.subject,
            minSdk = info.applicationInfo?.minSdkVersion,
            targetSdk = info.applicationInfo?.targetSdkVersion,
            lineageSha256 = lineage,
        )
    } catch (_: Throwable) {
        InstalledAppInfo(null, null)
    }
}

// ---- VirusTotal API v3 hash lookup & response parser ----

/**
 * Reads the engine counts (`malicious`, `suspicious`, `harmless`, `undetected`) out of a stats object; null when none is
 * there or one is not a non-negative number.
 */
internal fun vtStatsToFound(stats: JSONObject, lastAnalysisDate: Long? = null): VtLookupResult.Found? {
    val counts = listOf("malicious", "suspicious", "harmless", "undetected").map { key ->
        if (!stats.has(key)) {
            null
        } else {
            stats.optInt(key, -1).takeIf { it >= 0 } ?: return null
        }
    }
    if (counts.all { it == null }) return null
    return VtLookupResult.Found(
        malicious = counts[0] ?: 0,
        suspicious = counts[1] ?: 0,
        total = counts.sumOf { it ?: 0 },
        lastAnalysisDate = lastAnalysisDate,
    )
}

/**
 * Pure JSON parser for VirusTotal v3 `GET /api/v3/files/{sha256}` responses:
 * - `200`: needs `data.id` equal to [sha256], `data.attributes.last_analysis_stats` and `data.attributes.last_analysis_date`;
 *   the counters come only from `last_analysis_stats` -> [VtLookupResult.Found]
 * - `404`: [VtLookupResult.UnknownHash]
 * - `401` / `403`: [VtLookupResult.InvalidKey]
 * - `429`: [VtLookupResult.RateLimited]
 * - Any other status (redirects included), a mismatch, or malformed JSON: [VtLookupResult.Unavailable]
 */
fun parseVirusTotalResponse(httpCode: Int, body: String, sha256: String): VtLookupResult = when (httpCode) {
    200 -> parseVirusTotalFile(body, sha256)
    404 -> VtLookupResult.UnknownHash
    401, 403 -> VtLookupResult.InvalidKey
    429 -> VtLookupResult.RateLimited
    else -> VtLookupResult.Unavailable
}

private fun parseVirusTotalFile(body: String, sha256: String): VtLookupResult = try {
    val data = JSONObject(body).getJSONObject("data")
    val attributes = data.getJSONObject("attributes")
    val stats = attributes.getJSONObject("last_analysis_stats")
    val date = attributes.optLong("last_analysis_date", -1L).takeIf { it > 0L }
    if (!data.optString("id").equals(sha256, ignoreCase = true) || date == null) VtLookupResult.Unavailable
    else vtStatsToFound(stats, date)?.copy(detections = parseVirusTotalDetections(attributes.optJSONObject("last_analysis_results")))
        ?: VtLookupResult.Unavailable
} catch (_: JSONException) {
    VtLookupResult.Unavailable
}

private const val MaxEngineFlags = 200

/**
 * The engines that flagged the file in `last_analysis_results` (`{"<engine>": {"category": "malicious", "result": "Trojan.X"}}`):
 * those with category `malicious` or `suspicious`. Missing or malformed results give an empty list; the counters always
 * come from `last_analysis_stats`.
 */
internal fun parseVirusTotalDetections(results: JSONObject?): List<EngineFlag> {
    if (results == null) return emptyList()
    val flags = mutableListOf<EngineFlag>()
    val names = results.keys()
    while (names.hasNext() && flags.size < MaxEngineFlags) {
        val engine = names.next()
        val item = results.optJSONObject(engine) ?: continue
        val category = item.optString("category").lowercase(Locale.ROOT)
        if (category != "malicious" && category != "suspicious") continue
        val label = if (item.isNull("result")) "" else item.optString("result").trim()
        flags += EngineFlag(engine, label, category)
    }
    return flags.sortedBy { it.engine.lowercase(Locale.ROOT) }
}

/** `analysed 3 days ago` for the terminal log. The decision uses [isStaleAnalysis]. */
internal fun analysisAgeText(lastAnalysisDate: Long?, nowEpochSeconds: Long): String {
    if (lastAnalysisDate == null) return "analysis date unknown"
    val days = ((nowEpochSeconds - lastAnalysisDate) / 86_400L).coerceAtLeast(0L)
    return when (days) {
        0L -> "analysed today"
        1L -> "analysed 1 day ago"
        else -> "analysed $days days ago"
    }
}

/**
 * Queries VirusTotal v3 (`GET https://www.virustotal.com/api/v3/files/$sha256`) with header `x-apikey: $apiKey`.
 * Never throws: any network or I/O error returns [VtLookupResult.Unavailable] (the Shield then says "not checked online").
 */
fun checkVirusTotalHash(sha256: String, apiKey: String, timeoutMs: Int = 10_000): VtLookupResult {
    val cleanHash = sha256.normalizeHexSha256() ?: return VtLookupResult.Unavailable
    val cleanKey = apiKey.trim().takeIf { it.isNotEmpty() } ?: return VtLookupResult.InvalidKey
    var conn: HttpURLConnection? = null
    return try {
        conn = openVt("$VtBase/files/$cleanHash", "GET", cleanKey, timeoutMs, timeoutMs)
        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)?.use { readVtBody(it) }.orEmpty()
        parseVirusTotalResponse(code, body, cleanHash)
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
private const val KeyMdApiKeyCiphertext = "md_api_key_enc"
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
 * Persists Antivirus Shield settings in [SharedPreferences], encrypting the user's VirusTotal and MetaDefender API keys at rest
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
        get() = runCatching { prefs.getBoolean(KeyDeepScanEnabled, true) }.getOrDefault(true)
        set(value) {
            runCatching { prefs.edit().putBoolean(KeyDeepScanEnabled, value).apply() }
        }

    fun hasVirusTotalApiKey(): Boolean = hasKey(KeyVtApiKeyCiphertext)

    fun loadVirusTotalApiKey(): String? = loadKey(KeyVtApiKeyCiphertext)

    fun saveVirusTotalApiKey(rawKey: String?): Boolean = saveKey(KeyVtApiKeyCiphertext, rawKey)

    fun clearVirusTotalApiKey() = clearKey(KeyVtApiKeyCiphertext)

    fun hasMetaDefenderApiKey(): Boolean = false

    fun loadMetaDefenderApiKey(): String? = null

    fun saveMetaDefenderApiKey(rawKey: String?): Boolean = false

    fun clearMetaDefenderApiKey() = clearKey(KeyMdApiKeyCiphertext)

    /** True when VirusTotal has a key: without it, the Shield runs in limited (on-device only) mode. */
    fun hasAnyApiKey(): Boolean = hasVirusTotalApiKey()

    private fun hasKey(slot: String): Boolean =
        runCatching { !prefs.getString(slot, null).isNullOrBlank() }.getOrDefault(false)

    private fun loadKey(slot: String): String? {
        val encoded = runCatching { prefs.getString(slot, null) }.getOrNull()
            ?.takeIf { it.isNotBlank() } ?: return null
        return try {
            decryptApiKeyWithSecretKey(encoded, keyProvider())
        } catch (e: CancellationException) {
            throw e
        } catch (t: Throwable) {
            // Only a key that can never decrypt again is forgotten. A temporary Keystore failure (boot, locked screen)
            // must not cost the user their API key: the key stays and the next call tries again.
            if (isPermanentKeyFailure(t)) runCatching { prefs.edit().remove(slot).apply() }
            null
        }
    }

    private fun saveKey(slot: String, rawKey: String?): Boolean {
        val clean = rawKey?.trim().orEmpty()
        if (clean.isEmpty()) {
            clearKey(slot)
            return true
        }
        return try {
            val encrypted = encryptApiKeyWithSecretKey(clean, keyProvider())
            prefs.edit().putString(slot, encrypted).apply()
            true
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            try {
                val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                runCatching { store.deleteEntry(VtKeyStoreAlias) }
                val encrypted = encryptApiKeyWithSecretKey(clean, keyProvider())
                prefs.edit().putString(slot, encrypted).apply()
                true
            } catch (_: Throwable) {
                false
            }
        }
    }

    private fun clearKey(slot: String) {
        runCatching { prefs.edit().remove(slot).apply() }
    }
}

/**
 * True when [t] means the stored ciphertext can never be decrypted again: the Keystore key was replaced (the GCM tag no
 * longer matches), permanently invalidated or unrecoverable, or the stored text is not valid Base64. Anything else is
 * treated as temporary.
 */
internal fun isPermanentKeyFailure(t: Throwable): Boolean =
    t is javax.crypto.AEADBadTagException ||
        t is java.security.UnrecoverableKeyException ||
        t is android.security.keystore.KeyPermanentlyInvalidatedException ||
        t is IllegalArgumentException

private fun getOrCreateAndroidKeystoreAesKey(): SecretKey {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    try {
        (store.getKey(VtKeyStoreAlias, null) as? SecretKey)?.let { return it }
    } catch (t: Throwable) {
        // A temporary failure must not delete the key: every stored API key would be lost with it.
        if (!isPermanentKeyFailure(t)) throw t
        runCatching { store.deleteEntry(VtKeyStoreAlias) }
    }
    return try {
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
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
    } catch (t: Throwable) {
        runCatching { store.deleteEntry(VtKeyStoreAlias) }
        throw t
    }
}

// ---- Re-check before streaming ----

/** A file as the shield saw it: its size and SHA-256 when it was scanned and looked up. */
data class ScannedFile(val file: File, val sizeBytes: Long, val sha256: String)

/**
 * True only when every file in [streamed] was scanned and still has the scanned size and SHA-256. A file that is
 * missing, changed, or was never scanned makes it false (fail closed).
 */
internal fun filesUnchangedSinceScan(scanned: List<ScannedFile>, streamed: List<File?>): Boolean =
    streamed.all { file ->
        file != null && scanned.any { it.file == file && file.isFile && file.length() == it.sizeBytes && sha256Hex(file) == it.sha256 }
    }
