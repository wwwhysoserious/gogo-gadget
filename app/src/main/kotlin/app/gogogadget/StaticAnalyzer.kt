package app.gogogadget

import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.util.Locale
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

// Phase 4c: Local static code analysis / Deep Scan — zero-dependency pure Kotlin DEX bytecode & asset inspector.
// Inspects DEX string tables directly from header offsets and assets/resources for hidden droppers, aggressive adware,
// and abusive permissions.

internal const val MaxDexSizeBytes: Int = 32 * 1024 * 1024 // 32 MiB
internal const val MaxDexStringsCount: Int = 100_000
internal const val MaxStringBytes: Int = 4096
internal const val MaxAssetHeaderBytes: Int = 1024

internal val DexMagic = byteArrayOf(0x64, 0x65, 0x78, 0x0A) // "dex\n"
internal val ZipMagic = byteArrayOf(0x50, 0x4B, 0x03, 0x04) // "PK\x03\x04"

// All Regex patterns escape literal `{`, `}`, `[`, and `]` outside character classes for Android ICU compatibility.
private val DexEntryRegex = Regex("""(?i)^classes\d*\.dex$""")

/** High-confidence aggressive adware / malvertising / intrusive telemetry SDK package prefixes. */
val KnownAdwareSdkPrefixes: List<String> = listOf(
    "com.airpush",
    "com.leadbolt",
    "com.kuguo",
    "com.startapp.android.publish",
    "com.startapp.sdk",
    "com.secneo",
    "com.adwhirl",
    "com.appflood",
    "com.revmob",
    "com.senddroid",
    "com.tapcontext",
    "com.mobclix",
    "com.waps",
    "com.youmi",
)

data class StaticAnalysisIssue(
    val reason: ShieldWarningReason,
    val detail: String,
)

data class StaticAnalysisResult(
    val dexCount: Int,
    val issues: List<StaticAnalysisIssue>,
)

object StaticAnalyzer {

    /**
     * Parses the string table of a DEX file directly from byte offsets in its header:
     * - Magic `dex\n035` through `dex\n039`
     * - `string_ids_size` (uint32 at 0x38) and `string_ids_off` (uint32 at 0x3C)
     * - Bounded string reading using unsigned LEB128 lengths and null-terminated UTF-8.
     * Memory-safe and bounded to prevent out-of-memory or allocation bombs.
     */
    fun parseDexStrings(bytes: ByteArray): Set<String> {
        if (bytes.size < 0x70) return emptySet()
        // Header magic: dex\n
        if (bytes[0] != 0x64.toByte() || bytes[1] != 0x65.toByte() ||
            bytes[2] != 0x78.toByte() || bytes[3] != 0x0A.toByte()) {
            return emptySet()
        }

        val fileSize = readUInt32Le(bytes, 0x20)
        if (fileSize < 0x70L) return emptySet()

        val stringIdsSize = readUInt32Le(bytes, 0x38).toInt()
        val stringIdsOff = readUInt32Le(bytes, 0x3C).toInt()
        if (stringIdsSize <= 0 || stringIdsOff < 0x70) return emptySet()

        val maxCount = minOf(stringIdsSize, MaxDexStringsCount)
        if (stringIdsOff.toLong() + (maxCount.toLong() * 4L) > bytes.size.toLong()) return emptySet()

        val strings = LinkedHashSet<String>()
        for (i in 0 until maxCount) {
            val entryOff = stringIdsOff + i * 4
            val dataOff = readUInt32Le(bytes, entryOff).toInt()
            if (dataOff < 0 || dataOff >= bytes.size) continue

            // Read unsigned LEB128 utf16 character length
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
            val len = cur - strStart
            if (len > 0) {
                try {
                    strings += String(bytes, strStart, len, Charsets.UTF_8)
                } catch (_: Throwable) {
                }
            }
        }
        return strings
    }

    /** Parses DEX strings from an [InputStream] bounded by [MaxDexSizeBytes]. */
    fun parseDexStrings(input: InputStream): Set<String> {
        val bytes = readBoundedBytes(input, MaxDexSizeBytes)
        return parseDexStrings(bytes)
    }

    /**
     * Inspects [strings] extracted from [dexName] for:
     * 1. Droppers & dynamic code loading: `DexClassLoader`, `InMemoryDexClassLoader`, or `PathClassLoader` paired with dynamic paths.
     * 2. Aggressive adware SDKs matching [KnownAdwareSdkPrefixes].
     */
    fun inspectDexStrings(strings: Iterable<String>, dexName: String): List<StaticAnalysisIssue> {
        val issues = mutableListOf<StaticAnalysisIssue>()
        var hasPathClassLoader = false
        var hasSuspiciousDynamicPath = false

        for (str in strings) {
            // 1. Dynamic class loaders (Dropper signature)
            if (str.contains("dalvik.system.DexClassLoader") || str == "DexClassLoader" || str.contains("Ldalvik/system/DexClassLoader;")) {
                issues += StaticAnalysisIssue(
                    ShieldWarningReason.DropperDetected,
                    "Dynamic class loader (DexClassLoader) found in $dexName",
                )
            } else if (str.contains("dalvik.system.InMemoryDexClassLoader") || str == "InMemoryDexClassLoader" || str.contains("Ldalvik/system/InMemoryDexClassLoader;")) {
                issues += StaticAnalysisIssue(
                    ShieldWarningReason.DropperDetected,
                    "Dynamic class loader (InMemoryDexClassLoader) found in $dexName",
                )
            } else if (str.contains("dalvik.system.PathClassLoader") || str == "PathClassLoader" || str.contains("Ldalvik/system/PathClassLoader;")) {
                hasPathClassLoader = true
            }

            // 2. Known aggressive adware SDKs
            val adwareSdk = matchAdwareSdk(str)
            if (adwareSdk != null) {
                issues += StaticAnalysisIssue(
                    ShieldWarningReason.AdwareDetected,
                    "Aggressive adware SDK ($adwareSdk) found in $dexName",
                )
            }

            // 3. Dynamic loading path candidate
            if (!hasSuspiciousDynamicPath && isSuspiciousDynamicPath(str)) {
                hasSuspiciousDynamicPath = true
            }
        }

        if (hasPathClassLoader && hasSuspiciousDynamicPath) {
            issues += StaticAnalysisIssue(
                ShieldWarningReason.DropperDetected,
                "PathClassLoader combined with dynamic loading path found in $dexName",
            )
        }

        return issues.distinctBy { it.reason to it.detail }
    }

    /**
     * Checks whether an asset or raw resource entry in an APK disguises or contains an executable payload (DEX or ZIP/APK/JAR).
     * Does NOT flag animation or data files such as `.lottie` as hidden payloads. Lottie animations are ZIP archives
     * (`PK\x03\x04`) containing JSON, NOT executable code.
     * Only flags as Dropper if the asset entry is explicitly `.dex`, `.apk`, `.jar`, OR if it starts with DEX magic
     * `dex\n`, OR if it is a ZIP that actually contains a `classes*.dex` or `.so` file. Does not flag generic ZIP
     * headers or `.lottie` files.
     */
    fun checkAssetPayload(
        entryName: String,
        headerBytes: ByteArray,
        assetStream: InputStream? = null,
    ): StaticAnalysisIssue? {
        val lower = entryName.lowercase(Locale.US)

        // 1. Do NOT flag animation or data files such as .lottie as hidden payloads.
        if (lower.endsWith(".lottie")) {
            return null
        }

        // 2. Direct executable extensions in assets/resources
        if (lower.endsWith(".dex")) {
            return StaticAnalysisIssue(
                ShieldWarningReason.DropperDetected,
                "Hidden DEX file ($entryName) found in assets or resources",
            )
        }
        if (lower.endsWith(".apk") || lower.endsWith(".jar")) {
            return StaticAnalysisIssue(
                ShieldWarningReason.DropperDetected,
                "Hidden APK/JAR payload ($entryName) found in assets or resources",
            )
        }

        // 3. Starts with DEX magic `dex\n`
        if (headerBytes.size >= 4 &&
            headerBytes[0] == 0x64.toByte() && headerBytes[1] == 0x65.toByte() &&
            headerBytes[2] == 0x78.toByte() && headerBytes[3] == 0x0A.toByte()) {
            return StaticAnalysisIssue(
                ShieldWarningReason.DropperDetected,
                "Hidden DEX executable payload ($entryName) found in assets or resources",
            )
        }

        // 4. Embedded DEX payload signature check
        if (containsSubarray(headerBytes, DexMagic)) {
            return StaticAnalysisIssue(
                ShieldWarningReason.DropperDetected,
                "Embedded DEX payload signature detected in $entryName",
            )
        }

        // 5. ZIP payload check: only flag if it actually contains `classes*.dex` or `.so` file.
        // Do NOT flag generic ZIP headers or .lottie files.
        val isZip = (headerBytes.size >= 4 &&
            headerBytes[0] == 0x50.toByte() && headerBytes[1] == 0x4B.toByte() &&
            headerBytes[2] == 0x03.toByte() && headerBytes[3] == 0x04.toByte()) ||
            lower.endsWith(".zip")

        if (isZip) {
            val stream = assetStream ?: ByteArrayInputStream(headerBytes)
            val execName = findExecutableInZip(stream)
            if (execName != null) {
                return StaticAnalysisIssue(
                    ShieldWarningReason.DropperDetected,
                    "Hidden executable payload ($execName) found in archive $entryName",
                )
            }
        }

        return null
    }

    private fun findExecutableInZip(input: InputStream): String? {
        return try {
            ZipInputStream(input).use { zis ->
                var entry = zis.nextEntry
                while (entry != null) {
                    val name = entry.name.substringAfterLast('/').lowercase(Locale.US)
                    if (isDexEntry(name) || name.endsWith(".so")) {
                        return entry.name
                    }
                    entry = zis.nextEntry
                }
                null
            }
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * Flags abusive dropper permissions:
     * - `REQUEST_INSTALL_PACKAGES` paired with `SYSTEM_ALERT_WINDOW` (overlay / clickjacking attack)
     * - `REQUEST_INSTALL_PACKAGES` paired with SMS access in a non-SMS app
     * - `REQUEST_INSTALL_PACKAGES` requested by non-store application
     */
    fun checkAbusivePermissions(
        permissions: Collection<String>,
        packageName: String? = null,
        manifestStrings: Collection<String>? = null,
    ): StaticAnalysisIssue? {
        val norm = permissions.map { it.removePrefix("android.permission.") }.toSet()
        if ("REQUEST_INSTALL_PACKAGES" !in norm) return null

        if ("SYSTEM_ALERT_WINDOW" in norm) {
            return StaticAnalysisIssue(
                ShieldWarningReason.AbusivePermissions,
                "REQUEST_INSTALL_PACKAGES paired with SYSTEM_ALERT_WINDOW overlay capability",
            )
        }

        val smsPerms = listOf("READ_SMS", "RECEIVE_SMS", "SEND_SMS")
        val matchedSms = smsPerms.filter { it in norm }
        val isSmsApp = packageName?.lowercase(Locale.US)?.let {
            it.contains("sms") || it.contains("mms") || it.contains("messaging")
        } ?: false
        if (matchedSms.isNotEmpty() && !isSmsApp) {
            return StaticAnalysisIssue(
                ShieldWarningReason.AbusivePermissions,
                "REQUEST_INSTALL_PACKAGES paired with SMS access (${matchedSms.joinToString(", ")}) in non-SMS app",
            )
        }

        if (!isAppStoreOrPackageManager(packageName, manifestStrings)) {
            // Alone, this is how self-updating apps work: Yellow (user decides), not a hard block.
            return StaticAnalysisIssue(
                ShieldWarningReason.SelfUpdaterPermission,
                "REQUEST_INSTALL_PACKAGES requested by non-store application (${packageName ?: "unknown"})",
            )
        }

        return null
    }

    /** Inspects a single APK file on disk, scanning its DEX files and assets/resources. */
    fun analyzeApkFile(
        apkFile: File,
        permissions: Collection<String> = emptyList(),
        packageName: String? = null,
    ): StaticAnalysisResult {
        val issues = mutableListOf<StaticAnalysisIssue>()
        var dexCount = 0

        val permIssue = checkAbusivePermissions(permissions, packageName)
        if (permIssue != null) {
            issues += permIssue
        }

        if (!apkFile.exists() || apkFile.length() <= 0L) {
            return StaticAnalysisResult(0, issues)
        }

        try {
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory) continue
                    val name = entry.name.replace('\\', '/').trimStart('/')

                    if (isDexEntry(name)) {
                        dexCount++
                        val dexBytes = zip.getInputStream(entry).use { readBoundedBytes(it, MaxDexSizeBytes) }
                        val dexStrings = parseDexStrings(dexBytes)
                        issues += inspectDexStrings(dexStrings, name)
                    } else if (isAssetOrRawEntry(name)) {
                        val headerBytes = zip.getInputStream(entry).use { readBoundedBytes(it, MaxAssetHeaderBytes) }
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
        }

        return StaticAnalysisResult(dexCount, issues.distinctBy { it.reason to it.detail })
    }

    /**
     * Inspects a single APK or bundle offline, scanning all candidate `.apk` splits, their DEX bytecodes,
     * embedded assets, and requested permissions.
     */
    fun analyzeApkOrBundle(
        sourceFile: File,
        bundle: ExtractedBundle,
        permissions: Collection<String> = emptyList(),
        packageName: String? = null,
    ): StaticAnalysisResult {
        val issues = mutableListOf<StaticAnalysisIssue>()
        var totalDexCount = 0

        val permIssue = checkAbusivePermissions(permissions, packageName)
        if (permIssue != null) {
            issues += permIssue
        }

        val apkFiles = if (bundle.format == PackageFormat.SingleApk || bundle.apks.isEmpty()) {
            listOf(sourceFile)
        } else {
            bundle.apks.mapNotNull { it.file }
        }

        for (file in apkFiles) {
            if (!file.exists() || file.length() <= 0L) continue
            val result = analyzeApkFile(file, emptyList(), packageName)
            totalDexCount += result.dexCount
            issues += result.issues
        }

        return StaticAnalysisResult(totalDexCount, issues.distinctBy { it.reason to it.detail })
    }

    internal fun isDexEntry(name: String): Boolean {
        val simpleName = name.substringAfterLast('/')
        return DexEntryRegex.matches(simpleName)
    }

    internal fun isAssetOrRawEntry(name: String): Boolean {
        val lower = name.lowercase(Locale.US)
        return lower.startsWith("assets/") || lower.startsWith("res/raw/")
    }

    internal fun matchAdwareSdk(str: String): String? {
        for (prefix in KnownAdwareSdkPrefixes) {
            if (str.startsWith(prefix) || str == prefix) return prefix
            val slashPrefix = "L" + prefix.replace('.', '/')
            if (str.startsWith(slashPrefix)) return prefix
        }
        return null
    }

    internal fun isSuspiciousDynamicPath(str: String): Boolean {
        if (str.startsWith("/system/") || str.startsWith("/vendor/")) return false
        return str.contains("/data/data/") || str.contains("/data/user/") ||
            str.contains("/sdcard/") || str.contains("/storage/") ||
            str.contains("app_dex") || str.contains("/code_cache/")
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
