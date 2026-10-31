package app.gogogadget

import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.util.Locale
import java.util.zip.ZipFile

// Phase 4c: Local static code analysis / Deep Scan — zero-dependency pure Kotlin DEX bytecode & asset inspector.
// Inspects DEX string tables directly from header offsets and assets/resources for hidden droppers, aggressive adware,
// and abusive permissions.

internal const val MaxDexSizeBytes: Int = 32 * 1024 * 1024 // 32 MiB
internal const val MaxDexStringsCount: Int = 100_000
internal const val MaxStringBytes: Int = 4096
internal const val MaxAssetHeaderBytes: Int = 1024
private const val HashBufferBytesNested: Int = 64 * 1024
internal const val MaxNestedZipBytes: Int = 64 * 1024 * 1024
internal const val MaxNativeScanBytes: Int = 16 * 1024 * 1024

internal val DexMagic = byteArrayOf(0x64, 0x65, 0x78, 0x0A) // "dex\n"
internal val ZipMagic = byteArrayOf(0x50, 0x4B, 0x03, 0x04) // "PK\x03\x04"

// All Regex patterns escape literal `{`, `}`, `[`, and `]` outside character classes for Android ICU compatibility.
private val DexEntryRegex = Regex("""(?i)^classes\d*\.dex$""")

/** High-confidence aggressive adware / malvertising SDK package prefixes. */
val KnownAdwareSdkPrefixes: List<String> = listOf(
    "com.airpush",
    "com.leadbolt",
    "com.kuguo",
    "com.adwhirl",
    "com.appflood",
    "com.revmob",
    "com.senddroid",
    "com.tapcontext",
    "com.mobclix",
    "com.waps",
    "com.youmi",
)

enum class IssueCode {
    HiddenDex,
    HiddenApk,
    HiddenNative,
    HiddenInArchive,
    EncryptedBlob,
    LoaderWithPath,
    AdwareSdk,
    AbusiveCombo,
    InstallOverlay,
    InstallSms,
    SmsOverlay,
    SelfUpdater,
    NativeNotElf,
    NativeBadHeader,
    NativeAbiMismatch,
    NativePacker,
    NativeMarker,
    DexUnreadable,
    DexTooBig,
    DexStringsCut,
    NestedTooBig,
    NestedUnreadable,
    ArchiveUnreadable,
    ApkMissing,
    InstalledQueryFailed,
    Generic,
}

data class StaticAnalysisIssue(
    val reason: ShieldWarningReason,
    val detail: String,
    val code: IssueCode = IssueCode.Generic,
    val param: String? = null,
    val param2: String? = null,
    val apk: String? = null,
)

data class StaticAnalysisResult(
    val dexCount: Int,
    val dexInspected: Int = dexCount,
    val issues: List<StaticAnalysisIssue>,
    /** Known tracker SDKs found in the bytecode (informational), sorted. */
    val trackers: List<String> = emptyList(),
    val notes: List<String> = emptyList(),
)

/** Calculates Shannon entropy in bits per byte (0.0 for uniform/empty, near 8.0 for random/encrypted bytes). */
fun shannonEntropy(bytes: ByteArray): Double {
    if (bytes.isEmpty()) return 0.0
    val counts = IntArray(256)
    for (b in bytes) counts[b.toInt() and 0xFF]++
    val total = bytes.size.toDouble()
    var entropy = 0.0
    val log2 = Math.log(2.0)
    for (c in counts) {
        if (c > 0) {
            val p = c / total
            entropy -= p * (Math.log(p) / log2)
        }
    }
    return entropy
}

/** True if a full DEX header magic (`dex\n0\d\d\0`) starts at [offset] in [bytes]. */
fun hasFullDexHeaderAt(bytes: ByteArray, offset: Int): Boolean {
    if (offset < 0 || offset + 8 > bytes.size) return false
    return bytes[offset] == 0x64.toByte() &&
        bytes[offset + 1] == 0x65.toByte() &&
        bytes[offset + 2] == 0x78.toByte() &&
        bytes[offset + 3] == 0x0A.toByte() &&
        bytes[offset + 4] == '0'.code.toByte() &&
        bytes[offset + 5].toInt().toChar() in '0'..'9' &&
        bytes[offset + 6].toInt().toChar() in '0'..'9' &&
        bytes[offset + 7] == 0.toByte()
}

object StaticAnalyzer {

    data class DexParse(
        val strings: Set<String>,
        val unreadable: Boolean = false,
        val cut: Boolean = false,
    )

    /**
     * Parses the string table of a DEX file directly from byte offsets in its header:
     * - Magic `dex\n035\0` through `dex\n039\0`
     * - `string_ids_size` (uint32 at 0x38) and `string_ids_off` (uint32 at 0x3C)
     * - Bounded string reading using unsigned LEB128 lengths and null-terminated UTF-8.
     * Memory-safe and bounded to prevent out-of-memory or allocation bombs.
     */
    fun parseDex(bytes: ByteArray): DexParse {
        if (bytes.size < 0x70) return DexParse(emptySet(), unreadable = true)
        if (!hasFullDexHeaderAt(bytes, 0)) return DexParse(emptySet(), unreadable = true)

        val fileSize = readUInt32Le(bytes, 0x20)
        if (fileSize < 0x70L || fileSize > bytes.size) return DexParse(emptySet(), unreadable = true)

        val stringIdsSize = readUInt32Le(bytes, 0x38).toInt()
        val stringIdsOff = readUInt32Le(bytes, 0x3C).toInt()
        if (stringIdsSize < 0 || stringIdsOff < 0x70) return DexParse(emptySet(), unreadable = true)
        if (stringIdsSize == 0) return DexParse(emptySet(), unreadable = false)

        if (stringIdsOff.toLong() + (stringIdsSize.toLong() * 4L) > bytes.size.toLong()) {
            return DexParse(emptySet(), unreadable = true)
        }

        val maxCount = minOf(stringIdsSize, MaxDexStringsCount)
        val cut = stringIdsSize > MaxDexStringsCount
        val strings = LinkedHashSet<String>()

        for (i in 0 until maxCount) {
            val entryOff = stringIdsOff + i * 4
            val dataOff = readUInt32Le(bytes, entryOff).toInt()
            if (dataOff < 0 || dataOff >= bytes.size) return DexParse(strings, unreadable = true)

            var cur = dataOff
            var shift = 0
            while (cur < bytes.size && shift < 32) {
                val b = bytes[cur++].toInt() and 0xFF
                if ((b and 0x80) == 0) break
                shift += 7
            }
            val strStart = cur
            while (cur < bytes.size && bytes[cur] != 0.toByte()) {
                if (cur - strStart >= MaxStringBytes) break
                cur++
            }
            if (cur >= bytes.size && (cur - strStart < MaxStringBytes)) {
                return DexParse(strings, unreadable = true)
            }
            val len = cur - strStart
            if (len > 0) {
                try {
                    strings += String(bytes, strStart, len, Charsets.UTF_8)
                } catch (_: Throwable) {
                }
            }
        }
        return DexParse(strings, unreadable = false, cut = cut)
    }

    fun parseDexStrings(bytes: ByteArray): Set<String> = parseDex(bytes).strings

    /** Parses DEX strings from an [InputStream] bounded by [MaxDexSizeBytes]. */
    fun parseDexStrings(input: InputStream): Set<String> {
        val bytes = readBoundedBytes(input, MaxDexSizeBytes)
        return parseDexStrings(bytes)
    }

    /**
     * Inspects [strings] extracted from [dexName] for:
     * 1. Droppers & dynamic code loading: loader paired with suspicious dynamic code path.
     * 2. Aggressive adware SDKs matching [KnownAdwareSdkPrefixes].
     */
    fun inspectDexStrings(strings: Iterable<String>, dexName: String): List<StaticAnalysisIssue> {
        val issues = mutableListOf<StaticAnalysisIssue>()
        var loaderType: String? = null
        var hasSuspiciousDynamicPath = false

        for (str in strings) {
            if (str.contains("dalvik.system.DexClassLoader") || str == "DexClassLoader" || str.contains("Ldalvik/system/DexClassLoader;")) {
                loaderType = loaderType ?: "DexClassLoader"
            } else if (str.contains("dalvik.system.InMemoryDexClassLoader") || str == "InMemoryDexClassLoader" || str.contains("Ldalvik/system/InMemoryDexClassLoader;")) {
                loaderType = loaderType ?: "InMemoryDexClassLoader"
            } else if (str.contains("dalvik.system.PathClassLoader") || str == "PathClassLoader" || str.contains("Ldalvik/system/PathClassLoader;")) {
                loaderType = loaderType ?: "PathClassLoader"
            }

            val adwareSdk = matchAdwareSdk(str)
            if (adwareSdk != null) {
                issues += StaticAnalysisIssue(
                    ShieldWarningReason.AdwareDetected,
                    "Aggressive adware SDK ($adwareSdk) found in $dexName",
                    IssueCode.AdwareSdk,
                    adwareSdk,
                )
            }

            if (!hasSuspiciousDynamicPath && isSuspiciousDynamicPath(str)) {
                hasSuspiciousDynamicPath = true
            }
        }

        if (loaderType != null && hasSuspiciousDynamicPath) {
            issues += StaticAnalysisIssue(
                ShieldWarningReason.DropperDetected,
                "Dynamic class loader ($loaderType) combined with dynamic loading path found in $dexName",
                IssueCode.LoaderWithPath,
                loaderType,
            )
        }

        return issues.distinctBy { listOf(it.reason, it.detail, it.code, it.param) }
    }

    /**
     * Checks whether an entry in an APK disguises or contains an executable payload (DEX, ELF, ZIP, or high-entropy blob).
     * Does NOT flag animation or data files such as `.lottie` as hidden payloads.
     */
    fun checkAssetPayload(
        entryName: String,
        headerBytes: ByteArray,
        assetStream: InputStream? = null,
    ): StaticAnalysisIssue? {
        val lower = entryName.lowercase(Locale.US)
        val simpleName = entryName.substringAfterLast('/').lowercase(Locale.US)

        // 1. Do NOT flag animation or data files such as .lottie as hidden payloads.
        if (lower.endsWith(".lottie")) {
            return null
        }

        // 2. Direct executable extensions in assets/resources
        if (lower.endsWith(".dex")) {
            return StaticAnalysisIssue(
                ShieldWarningReason.DropperDetected,
                "Hidden DEX file ($entryName) found in assets or resources",
                IssueCode.HiddenDex,
                entryName,
            )
        }
        if (lower.endsWith(".apk") || lower.endsWith(".jar")) {
            return StaticAnalysisIssue(
                ShieldWarningReason.DropperDetected,
                "Hidden APK or JAR package ($entryName) found in assets or resources",
                IssueCode.HiddenApk,
                entryName,
            )
        }

        // 3. Full DEX magic header anywhere in headerBytes
        for (i in 0..headerBytes.size - 8) {
            if (hasFullDexHeaderAt(headerBytes, i)) {
                return StaticAnalysisIssue(
                    ShieldWarningReason.DropperDetected,
                    "Hidden DEX file ($entryName) found in assets or resources",
                    IssueCode.HiddenDex,
                    entryName,
                )
            }
        }

        // 4. ELF header check (outside lib/)
        if (!lower.startsWith("lib/") && headerBytes.size >= 4 &&
            headerBytes[0] == 0x7F.toByte() && headerBytes[1] == 'E'.code.toByte() &&
            headerBytes[2] == 'L'.code.toByte() && headerBytes[3] == 'F'.code.toByte()
        ) {
            return StaticAnalysisIssue(
                ShieldWarningReason.DropperDetected,
                "Native library ($entryName) hidden outside the library folder",
                IssueCode.HiddenNative,
                entryName,
            )
        }

        // 5. ZIP payload check: only flag if it actually contains classes*.dex or .so file.
        val isZip = (headerBytes.size >= 4 &&
            headerBytes[0] == 0x50.toByte() && headerBytes[1] == 0x4B.toByte() &&
            headerBytes[2] == 0x03.toByte() && headerBytes[3] == 0x04.toByte()) ||
            lower.endsWith(".zip")

        if (isZip) {
            val stream = assetStream ?: ByteArrayInputStream(headerBytes)
            val temp = try {
                File.createTempFile("shield_nested_", ".zip")
            } catch (_: Throwable) {
                return StaticAnalysisIssue(
                    ShieldWarningReason.ScanIncomplete,
                    "The compressed file $entryName could not be read",
                    IssueCode.NestedUnreadable,
                    entryName,
                )
            }
            try {
                var totalRead = 0L
                temp.outputStream().use { out ->
                    val buffer = ByteArray(HashBufferBytesNested)
                    while (true) {
                        val read = stream.read(buffer)
                        if (read < 0) break
                        totalRead += read
                        if (totalRead > MaxNestedZipBytes) {
                            return StaticAnalysisIssue(
                                ShieldWarningReason.ScanIncomplete,
                                "The compressed file $entryName is too big to inspect",
                                IssueCode.NestedTooBig,
                                entryName,
                            )
                        }
                        out.write(buffer, 0, read)
                    }
                }
                val execName = ZipFile(temp).use { zip ->
                    zip.entries().asSequence().map { it.name }.firstOrNull { entry ->
                        val name = entry.substringAfterLast('/').lowercase(Locale.US)
                        isDexEntry(name) || name.endsWith(".so")
                    }
                }
                if (execName != null) {
                    return StaticAnalysisIssue(
                        ShieldWarningReason.DropperDetected,
                        "Executable code ($execName) inside the compressed file $entryName",
                        IssueCode.HiddenInArchive,
                        execName,
                        entryName,
                    )
                }
            } catch (_: Throwable) {
                return StaticAnalysisIssue(
                    ShieldWarningReason.ScanIncomplete,
                    "The compressed file $entryName could not be read",
                    IssueCode.NestedUnreadable,
                    entryName,
                )
            } finally {
                runCatching { temp.delete() }
            }
        }

        // 6. High entropy encrypted blob check in assets/, res/raw/, or root
        val isEligibleLocation = lower.startsWith("assets/") || lower.startsWith("res/raw/") || !entryName.contains('/')
        val nonBlobExtensions = setOf(
            ".tflite", ".mp3", ".ogg", ".pak", ".db", ".ttf", ".webp",
            ".png", ".jpg", ".jpeg", ".gif", ".wav", ".mp4", ".zip", ".so",
        )
        val hasNonBlobExtension = nonBlobExtensions.any { lower.endsWith(it) }
        val isGenericBlobName = lower.endsWith(".bin") || lower.endsWith(".dat") || lower.endsWith(".tmp") ||
            lower.endsWith(".blob") || !simpleName.contains('.')
        if (isEligibleLocation && !hasNonBlobExtension && isGenericBlobName && headerBytes.size >= 4096) {
            if (shannonEntropy(headerBytes) > 7.5) {
                return StaticAnalysisIssue(
                    ShieldWarningReason.DropperDetected,
                    "A file with encrypted-looking content and a generic name: $entryName",
                    IssueCode.EncryptedBlob,
                    entryName,
                )
            }
        }

        return null
    }

    /**
     * Flags abusive permissions:
     * - Banking trojan combo: overlay + accessibility + install or SMS (Red)
     * - Overlay + install (Red)
     * - Overlay + SMS (Red)
     * - Install + SMS (Yellow)
     * - Lone install in non-store application (Yellow)
     */
    fun checkAbusivePermissions(
        permissions: Collection<String>,
        packageName: String? = null,
        manifestStrings: Collection<String>? = null,
    ): StaticAnalysisIssue? {
        val norm = permissions.map { it.removePrefix("android.permission.") }.toSet()
        val hasOverlay = "SYSTEM_ALERT_WINDOW" in norm
        val hasInstall = "REQUEST_INSTALL_PACKAGES" in norm
        val hasAccessibility = "BIND_ACCESSIBILITY_SERVICE" in norm

        val smsPerms = listOf("READ_SMS", "RECEIVE_SMS", "SEND_SMS")
        val matchedSms = smsPerms.filter { it in norm }
        val hasSms = matchedSms.isNotEmpty()
        val isSmsApp = packageName?.lowercase(Locale.US)?.let {
            it.contains("sms") || it.contains("mms") || it.contains("messaging")
        } ?: false

        // 1. Banking trojan combo: overlay + accessibility + (install or SMS) -> Red (AbusivePermissions)
        if (hasOverlay && hasAccessibility && (hasInstall || (hasSms && !isSmsApp))) {
            return StaticAnalysisIssue(
                ShieldWarningReason.AbusivePermissions,
                "Permissions typical of banking trojans: overlay, accessibility service and installing apps or SMS",
                IssueCode.AbusiveCombo,
            )
        }

        // 2. Install + Overlay -> Red (AbusivePermissions)
        if (hasInstall && hasOverlay) {
            return StaticAnalysisIssue(
                ShieldWarningReason.AbusivePermissions,
                "REQUEST_INSTALL_PACKAGES paired with SYSTEM_ALERT_WINDOW overlay capability",
                IssueCode.InstallOverlay,
            )
        }

        // 3. SMS + Overlay -> Red (AbusivePermissions)
        if (hasSms && !isSmsApp && hasOverlay) {
            val joined = matchedSms.joinToString(", ")
            return StaticAnalysisIssue(
                ShieldWarningReason.AbusivePermissions,
                "SMS access ($joined) paired with SYSTEM_ALERT_WINDOW overlay capability",
                IssueCode.SmsOverlay,
                joined,
            )
        }

        // 4. Install + SMS in non-SMS app -> Yellow (RiskyPermissionCombo)
        if (hasInstall && hasSms && !isSmsApp) {
            val joined = matchedSms.joinToString(", ")
            return StaticAnalysisIssue(
                ShieldWarningReason.RiskyPermissionCombo,
                "REQUEST_INSTALL_PACKAGES paired with SMS access ($joined) in non-SMS app",
                IssueCode.InstallSms,
                joined,
            )
        }

        // 5. Lone REQUEST_INSTALL_PACKAGES in non-store app -> Yellow (SelfUpdaterPermission)
        if (hasInstall && !isAppStoreOrPackageManager(packageName, manifestStrings)) {
            val pkg = packageName ?: "unknown"
            return StaticAnalysisIssue(
                ShieldWarningReason.SelfUpdaterPermission,
                "REQUEST_INSTALL_PACKAGES requested by non-store application ($pkg)",
                IssueCode.SelfUpdater,
                pkg,
            )
        }

        return null
    }

    /** Inspects a single APK file on disk, scanning its DEX files, native libraries and assets/resources. */
    fun analyzeApkFile(
        apkFile: File,
        permissions: Collection<String> = emptyList(),
        packageName: String? = null,
    ): StaticAnalysisResult {
        val issues = mutableListOf<StaticAnalysisIssue>()
        val trackers = sortedSetOf<String>()
        val notes = mutableListOf<String>()
        var dexCount = 0
        var dexInspected = 0

        val permIssue = checkAbusivePermissions(permissions, packageName)
        if (permIssue != null) {
            issues += permIssue
        }

        if (!apkFile.exists() || apkFile.length() <= 0L) {
            return StaticAnalysisResult(
                dexCount = 0,
                dexInspected = 0,
                issues = listOf(StaticAnalysisIssue(ShieldWarningReason.ScanIncomplete, "The file ${apkFile.name} is missing", IssueCode.ApkMissing, apkFile.name)),
            )
        }

        val zip = try {
            ZipFile(apkFile)
        } catch (_: Throwable) {
            return StaticAnalysisResult(
                dexCount = 0,
                dexInspected = 0,
                issues = listOf(StaticAnalysisIssue(ShieldWarningReason.ScanIncomplete, "${apkFile.name} could not be read", IssueCode.ArchiveUnreadable, apkFile.name)),
            )
        }

        try {
            zip.use {
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory) continue
                    val name = entry.name.replace('\\', '/').trimStart('/')

                    if (isDexEntry(name)) {
                        dexCount++
                        if (entry.size > MaxDexSizeBytes) {
                            issues += StaticAnalysisIssue(
                                ShieldWarningReason.ScanIncomplete,
                                "$name is too big to inspect",
                                IssueCode.DexTooBig,
                                name,
                            )
                            continue
                        }
                        val dexBytes = zip.getInputStream(entry).use { readBoundedBytes(it, MaxDexSizeBytes + 1) }
                        if (dexBytes.size > MaxDexSizeBytes) {
                            issues += StaticAnalysisIssue(
                                ShieldWarningReason.ScanIncomplete,
                                "$name is too big to inspect",
                                IssueCode.DexTooBig,
                                name,
                            )
                            continue
                        }
                        val parsed = parseDex(dexBytes)
                        if (parsed.unreadable) {
                            issues += StaticAnalysisIssue(
                                ShieldWarningReason.ScanIncomplete,
                                "$name could not be read completely",
                                IssueCode.DexUnreadable,
                                name,
                            )
                            continue
                        }
                        if (parsed.cut) {
                            issues += StaticAnalysisIssue(
                                ShieldWarningReason.ScanIncomplete,
                                "$name has too much data and part of it was not inspected",
                                IssueCode.DexStringsCut,
                                name,
                            )
                        }
                        dexInspected++
                        issues += inspectDexStrings(parsed.strings, name)
                        trackers += findTrackers(parsed.strings)
                    } else if (name.startsWith("lib/") && name.endsWith(".so")) {
                        val finding = zip.getInputStream(entry).use { inspectNativeLibraryStream(name, it) }
                        when (finding.verdict) {
                            NativeVerdict.InvalidElf -> issues += StaticAnalysisIssue(
                                ShieldWarningReason.InvalidNativeLibrary,
                                finding.detail,
                                finding.code,
                                finding.param,
                                finding.param2,
                            )
                            NativeVerdict.Suspicious -> issues += StaticAnalysisIssue(
                                ShieldWarningReason.SuspiciousNativeCode,
                                finding.detail,
                                finding.code,
                                finding.param,
                                finding.param2,
                            )
                            NativeVerdict.Valid -> Unit
                        }
                    } else if (isPayloadScanEntry(name)) {
                        val headerBytes = zip.getInputStream(entry).use { readBoundedBytes(it, 8192) }
                        val payloadIssue = zip.getInputStream(entry).use { stream ->
                            checkAssetPayload(name, headerBytes, stream)
                        }
                        if (payloadIssue != null) {
                            issues += payloadIssue
                        }
                    }
                }
            }
        } catch (_: Throwable) {
            issues += StaticAnalysisIssue(
                ShieldWarningReason.ScanIncomplete,
                "${apkFile.name} could not be read completely",
                IssueCode.ArchiveUnreadable,
                apkFile.name,
            )
        }

        return StaticAnalysisResult(
            dexCount = dexCount,
            dexInspected = dexInspected,
            issues = issues.distinctBy { listOf(it.reason, it.detail, it.code, it.param, it.param2) },
            trackers = trackers.toList(),
            notes = notes,
        )
    }

    /**
     * Inspects a single APK or bundle offline, scanning all candidate `.apk` splits, their DEX bytecodes,
     * embedded assets, native libraries, and requested permissions.
     */
    fun analyzeApkOrBundle(
        sourceFile: File,
        bundle: ExtractedBundle,
        permissions: Collection<String> = emptyList(),
        packageName: String? = null,
    ): StaticAnalysisResult {
        val issues = mutableListOf<StaticAnalysisIssue>()
        var totalDexCount = 0
        var totalDexInspected = 0
        val trackers = sortedSetOf<String>()
        val notes = mutableListOf<String>()

        val permIssue = checkAbusivePermissions(permissions, packageName)
        if (permIssue != null) {
            issues += permIssue
        }

        val isSingle = bundle.format == PackageFormat.SingleApk || bundle.apks.isEmpty()
        if (isSingle) {
            val result = analyzeApkFile(sourceFile, emptyList(), packageName)
            totalDexCount += result.dexCount
            totalDexInspected += result.dexInspected
            issues += result.issues
            trackers += result.trackers
            notes += result.notes
        } else {
            for (split in bundle.apks) {
                val file = split.file
                if (file == null || !file.exists() || file.length() <= 0L) {
                    issues += StaticAnalysisIssue(
                        ShieldWarningReason.ScanIncomplete,
                        "The file ${split.name} is missing",
                        IssueCode.ApkMissing,
                        split.name,
                        apk = split.name,
                    )
                    continue
                }
                val result = analyzeApkFile(file, emptyList(), packageName)
                totalDexCount += result.dexCount
                totalDexInspected += result.dexInspected
                for (issue in result.issues) {
                    issues += issue.copy(apk = split.name)
                }
                trackers += result.trackers
                notes += result.notes
            }
        }

        return StaticAnalysisResult(
            dexCount = totalDexCount,
            dexInspected = totalDexInspected,
            issues = issues.distinctBy { listOf(it.reason, it.detail, it.code, it.param, it.param2, it.apk) },
            trackers = trackers.toList(),
            notes = notes,
        )
    }

    internal fun isDexEntry(name: String): Boolean {
        val simpleName = name.substringAfterLast('/')
        return DexEntryRegex.matches(simpleName)
    }

    internal fun isPayloadScanEntry(name: String): Boolean {
        if (name.endsWith('/')) return false
        val lower = name.lowercase(Locale.US)
        if (lower == "androidmanifest.xml" || lower.endsWith("/androidmanifest.xml")) return false
        if (lower == "resources.arsc" || lower.endsWith("/resources.arsc")) return false
        if (lower.startsWith("meta-inf/")) return false
        if (lower.startsWith("lib/")) return false
        if (lower.startsWith("kotlin/")) return false
        if (DexEntryRegex.matches(name.substringAfterLast('/'))) return false
        return true
    }

    internal fun isAssetOrRawEntry(name: String): Boolean {
        val lower = name.lowercase(Locale.US)
        return lower.startsWith("assets/") || lower.startsWith("res/raw/")
    }

    internal fun matchAdwareSdk(str: String): String? {
        val trimmed = str.trimStart('[')
        if (!trimmed.startsWith('L') || !trimmed.endsWith(';')) return null
        val path = trimmed.substring(1, trimmed.length - 1)
        for (prefix in KnownAdwareSdkPrefixes) {
            val slashPrefix = prefix.replace('.', '/')
            if (path == slashPrefix || path.startsWith("$slashPrefix/")) {
                return prefix
            }
        }
        return null
    }

    internal fun isSuspiciousDynamicPath(str: String): Boolean {
        if (str.startsWith("/system/") || str.startsWith("/vendor/")) return false
        val lower = str.lowercase(Locale.US)
        val hasExecutableExt = lower.endsWith(".dex") || lower.endsWith(".jar") || lower.endsWith(".apk") || lower.endsWith(".so")
        val isAppDex = lower.contains("app_dex") || lower.contains("/code_cache/")
        val isAppData = lower.contains("/data/data/") || lower.contains("/data/user/")
        return (isAppData && (hasExecutableExt || isAppDex)) || (isAppDex && hasExecutableExt) ||
            ((lower.contains("/sdcard/") || lower.contains("/storage/")) && hasExecutableExt)
    }

    internal fun isAppStoreOrPackageManager(packageName: String?, manifestStrings: Collection<String>?): Boolean {
        val pkg = packageName?.lowercase(Locale.US).orEmpty()
        if (pkg.contains("store") || pkg.contains("market") || pkg.contains("installer") ||
            pkg.contains("packagemanager") || pkg.contains("fdroid") || pkg.contains("vending") ||
            pkg.contains("gogogadget") || pkg.contains("apkpure") || pkg.contains("apkmirror")) {
            return true
        }
        if (manifestStrings?.any { it.contains("android.intent.category.APP_MARKET") || it.contains("package-archive") } == true) {
            return true
        }
        return false
    }

    private fun readUInt32Le(bytes: ByteArray, offset: Int): Long =
        (bytes[offset].toLong() and 0xFFL) or
            ((bytes[offset + 1].toLong() and 0xFFL) shl 8) or
            ((bytes[offset + 2].toLong() and 0xFFL) shl 16) or
            ((bytes[offset + 3].toLong() and 0xFFL) shl 24)
}
