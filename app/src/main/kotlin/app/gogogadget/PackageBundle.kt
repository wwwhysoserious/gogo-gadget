package app.gogogadget

import kotlinx.coroutines.CancellationException
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import kotlin.math.abs

// Content-based package format detection, safe ZIP extraction, smart split filtering, and multi-APK ADB sessions.

/** Package container formats recognised from archive contents (never from the file extension). */
enum class PackageFormat {
    SingleApk,
    Xapk,
    Apkm,
    Apks,
}

/** Standard ZIP local file header magic (`PK\x03\x04`). */
fun hasZipMagic(bytes: ByteArray, length: Int = bytes.size): Boolean =
    length >= 4 &&
        bytes[0] == 0x50.toByte() &&
        bytes[1] == 0x4B.toByte() &&
        bytes[2] == 0x03.toByte() &&
        bytes[3] == 0x04.toByte()

/**
 * Resolves [entryName] under [destDir] and checks via [File.getCanonicalPath] that the target stays strictly within
 * [destDir], guarding against Zip-Slip path traversal.
 */
fun resolveSafeZipEntry(destDir: File, entryName: String): File {
    val clean = entryName.replace('\\', '/').trimStart('/')
    if (clean.isEmpty() || clean.split('/').any { it == ".." }) {
        throw SecurityException("Unsafe zip entry path: $entryName")
    }
    val baseCanonical = destDir.canonicalPath
    val target = File(destDir, clean)
    val targetCanonical = target.canonicalPath
    if (targetCanonical != baseCanonical && !targetCanonical.startsWith(baseCanonical + File.separator)) {
        throw SecurityException("Zip entry outside target directory: $entryName")
    }
    return target
}

/** An extracted `.apk` split or `.obb` expansion file from a package bundle. */
data class ExtractedFile(
    val entryPath: String,
    val name: String,
    val size: Long,
    val file: File? = null,
    val obbPackageName: String? = null,
    /** Other package names this OBB points at (its `install_path` in the bundle metadata); all must be the base APK's. */
    val otherPackageClaims: List<String> = emptyList(),
    private val bytes: ByteArray? = null,
) {
    fun openStream(): InputStream = when {
        bytes != null -> ByteArrayInputStream(bytes)
        file != null -> file.inputStream()
        else -> throw IOException("No stream available for $name")
    }
}

/** Inspects and extracts a package archive. */
sealed interface PackageInspectResult {
    data class Valid(val bundle: ExtractedBundle) : PackageInspectResult
    data class Invalid(val reasonRes: Int) : PackageInspectResult
}

data class ExtractedBundle(
    val format: PackageFormat,
    val packageName: String?,
    val baseApkName: String?,
    val apks: List<ExtractedFile>,
    val obbs: List<ExtractedFile>,
) {
    fun findBaseApk(): ExtractedFile? = selectBaseApk(apks, baseApkName, packageName)
}

private const val MaxMetadataBytes = 1 shl 20
private const val CopyBufferBytes = 64 * 1024

/** A package with more entries, or more uncompressed bytes (by its central directory), than this is not checked. */
internal const val MaxZipEntries = 5000
internal const val MaxZipUncompressedBytes = 8L * 1024L * 1024L * 1024L

internal fun zipWithinLimits(entryCount: Int, totalUncompressedBytes: Long): Boolean =
    entryCount in 0..MaxZipEntries && totalUncompressedBytes in 0..MaxZipUncompressedBytes

/** The staging volume needs the bytes to extract plus 5%. */
internal fun hasRoomToExtract(freeBytes: Long, extractBytes: Long): Boolean = freeBytes >= extractBytes + extractBytes / 20

private fun freeSpaceOf(dir: File): Long =
    generateSequence(dir) { it.parentFile }.firstOrNull { it.exists() }?.usableSpace ?: 0L

/** Copies at most [limit] bytes (the size the central directory promised); a longer entry is an error. */
private fun copyBounded(input: InputStream, output: OutputStream, limit: Long): Long {
    val buffer = ByteArray(CopyBufferBytes)
    var total = 0L
    while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        total += read
        if (total > limit) throw IOException("Zip entry is larger than its central directory says")
        output.write(buffer, 0, read)
    }
    return total
}

enum class BundlePackageProblem { Mismatch, Unreadable }

/** The package name of a bundle, read from its APK files, and what is wrong with it (null when nothing). */
data class BundlePackageCheck(val packageName: String?, val problem: BundlePackageProblem?)

/**
 * The package name comes from the base APK file itself ([basePackage], read by the platform). Metadata in the bundle
 * ([claimed], from manifest.json / info.json) may only agree with it, and every split must carry the same name.
 */
internal fun checkBundlePackage(basePackage: String?, splitPackages: List<String?>, claimed: String?): BundlePackageCheck {
    if (basePackage == null) return BundlePackageCheck(null, BundlePackageProblem.Unreadable)
    val readableSplits = splitPackages.filterNotNull()
    val consistent = readableSplits.all { it == basePackage } && (claimed == null || claimed == basePackage)
    return BundlePackageCheck(basePackage, if (consistent) null else BundlePackageProblem.Mismatch)
}

/** True when everything this OBB says about its own package (path, file name, metadata) is [packageName]. */
internal fun obbBelongsTo(obb: ExtractedFile, packageName: String): Boolean =
    (listOfNotNull(obb.obbPackageName, extractObbPackageFromPath(obb.name, obb.name)) + obb.otherPackageClaims)
        .all { it == packageName }

/**
 * Inspects [archiveFile] by content (magic bytes and ZIP central directory) and, when it is a bundle, extracts `.apk`
 * and `.obb` entries into [destDir] (or keeps them in memory when [destDir] is null, e.g. in unit tests).
 * For a single APK (`AndroidManifest.xml` at root and no `.apk` entries), returns immediately after scanning the
 * central directory without decompressing or copying any entry.
 */
fun inspectAndExtractPackage(archiveFile: File, destDir: File? = null): PackageInspectResult {
    if (!archiveFile.exists() || archiveFile.length() <= 0L) {
        return PackageInspectResult.Invalid(R.string.err_read_file)
    }
    val magic = ByteArray(4)
    val magicRead = try {
        archiveFile.inputStream().use { input ->
            var total = 0
            while (total < 4) {
                val n = input.read(magic, total, 4 - total)
                if (n < 0) break
                total += n
            }
            total
        }
    } catch (e: IOException) {
        return PackageInspectResult.Invalid(R.string.err_read_file)
    }
    if (magicRead == 0) return PackageInspectResult.Invalid(R.string.err_read_file)
    if (!hasZipMagic(magic, magicRead)) {
        return PackageInspectResult.Invalid(R.string.reason_not_zip_or_proprietary)
    }

    return try {
        ZipFile(archiveFile).use { zip ->
            var entryCount = 0
            var totalUncompressed = 0L
            var hasRootAndroidManifest = false
            var manifestEntry: ZipEntry? = null
            var infoEntry: ZipEntry? = null
            val apkEntries = mutableListOf<Pair<String, ZipEntry>>()
            val obbEntries = mutableListOf<Pair<String, ZipEntry>>()

            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                entryCount++
                totalUncompressed += entry.size.let { if (it < 0L) Long.MAX_VALUE / 2 else it }
                if (!zipWithinLimits(entryCount, totalUncompressed)) return PackageInspectResult.Invalid(R.string.reason_too_complex)
                val normalizedPath = entry.name.replace('\\', '/').trimStart('/')
                if (normalizedPath.isEmpty()) continue
                if (normalizedPath.split('/').any { it == ".." }) {
                    return PackageInspectResult.Invalid(R.string.reason_parse)
                }
                if (destDir != null) {
                    resolveSafeZipEntry(destDir, normalizedPath)
                }
                if (entry.isDirectory) continue

                val fileName = normalizedPath.substringAfterLast('/')
                when {
                    normalizedPath == "AndroidManifest.xml" -> {
                        hasRootAndroidManifest = true
                    }
                    normalizedPath.equals("manifest.json", ignoreCase = true) ||
                        (manifestEntry == null && normalizedPath.endsWith("/manifest.json", ignoreCase = true)) -> {
                        manifestEntry = entry
                    }
                    normalizedPath.equals("info.json", ignoreCase = true) ||
                        (infoEntry == null && normalizedPath.endsWith("/info.json", ignoreCase = true)) -> {
                        infoEntry = entry
                    }
                    fileName.endsWith(".apk", ignoreCase = true) -> {
                        apkEntries += normalizedPath to entry
                    }
                    fileName.endsWith(".obb", ignoreCase = true) -> {
                        obbEntries += normalizedPath to entry
                    }
                }
            }

            if (entryCount == 0) return PackageInspectResult.Invalid(R.string.reason_parse)

            // A manifest at the root makes it ONE app; an .apk inside it (assets/stub.apk) is data, which the deep scan reads.
            if (hasRootAndroidManifest) {
                return PackageInspectResult.Valid(
                    ExtractedBundle(
                        format = PackageFormat.SingleApk,
                        packageName = null,
                        baseApkName = null,
                        apks = emptyList(),
                        obbs = emptyList(),
                    ),
                )
            }

            if (apkEntries.isEmpty()) {
                return PackageInspectResult.Invalid(R.string.reason_parse)
            }
            if (destDir != null) {
                val extractBytes = (apkEntries + obbEntries).sumOf { it.second.size }
                if (!hasRoomToExtract(freeSpaceOf(destDir), extractBytes)) {
                    return PackageInspectResult.Invalid(R.string.reason_too_complex)
                }
            }

            val manifestJson = manifestEntry?.let { entry ->
                zip.getInputStream(entry).use { readBoundedText(it, MaxMetadataBytes) }
            }
            val infoJson = infoEntry?.let { entry ->
                zip.getInputStream(entry).use { readBoundedText(it, MaxMetadataBytes) }
            }
            val format = when {
                manifestJson != null -> PackageFormat.Xapk
                infoJson != null -> PackageFormat.Apkm
                else -> PackageFormat.Apks
            }

            val apks = mutableListOf<ExtractedFile>()
            val obbs = mutableListOf<ExtractedFile>()

            for ((normalizedPath, entry) in apkEntries) {
                val fileName = normalizedPath.substringAfterLast('/')
                if (destDir != null) {
                    val out = resolveSafeZipEntry(destDir, normalizedPath)
                    out.parentFile?.mkdirs()
                    val written = zip.getInputStream(entry).use { input ->
                        out.outputStream().use { output -> copyBounded(input, output, entry.size) }
                    }
                    apks += ExtractedFile(entryPath = normalizedPath, name = fileName, size = written, file = out)
                } else {
                    val data = zip.getInputStream(entry).use { it.readBytes() }
                    apks += ExtractedFile(
                        entryPath = normalizedPath,
                        name = fileName,
                        size = data.size.toLong(),
                        bytes = data,
                    )
                }
            }

            for ((normalizedPath, entry) in obbEntries) {
                val fileName = normalizedPath.substringAfterLast('/')
                val obbPkg = extractObbPackageFromPath(normalizedPath, fileName)
                if (destDir != null) {
                    val out = resolveSafeZipEntry(destDir, normalizedPath)
                    out.parentFile?.mkdirs()
                    val written = zip.getInputStream(entry).use { input ->
                        out.outputStream().use { output -> copyBounded(input, output, entry.size) }
                    }
                    obbs += ExtractedFile(
                        entryPath = normalizedPath,
                        name = fileName,
                        size = written,
                        file = out,
                        obbPackageName = obbPkg,
                    )
                } else {
                    val data = zip.getInputStream(entry).use { it.readBytes() }
                    obbs += ExtractedFile(
                        entryPath = normalizedPath,
                        name = fileName,
                        size = data.size.toLong(),
                        obbPackageName = obbPkg,
                        bytes = data,
                    )
                }
            }

            val meta = parseBundleMetadata(manifestJson, infoJson)
            val pkg = meta.packageName ?: obbs.firstNotNullOfOrNull { it.obbPackageName }
            val resolvedObbs = obbs.map { obb ->
                val mappedInstallPath = meta.obbInstallPaths[obb.entryPath] ?: meta.obbInstallPaths[obb.name]
                val mappedPkg = mappedInstallPath?.let { extractObbPackageFromPath(it, obb.name) }
                val mappedName = mappedInstallPath?.substringAfterLast('/')
                    ?.takeIf { it.endsWith(".obb", ignoreCase = true) }
                obb.copy(
                    name = mappedName ?: obb.name,
                    obbPackageName = obb.obbPackageName ?: mappedPkg ?: pkg,
                    otherPackageClaims = listOfNotNull(mappedPkg),
                )
            }

            PackageInspectResult.Valid(
                ExtractedBundle(
                    format = format,
                    packageName = pkg,
                    baseApkName = meta.baseApkFile,
                    apks = apks,
                    obbs = resolvedObbs,
                ),
            )
        }
    } catch (e: CancellationException) {
        throw e
    } catch (t: Throwable) {
        PackageInspectResult.Invalid(R.string.reason_parse)
    }
}

/**
 * Inspects [input] by copying it to a temporary file and delegating to [inspectAndExtractPackage] on [File].
 */
fun inspectAndExtractPackage(input: InputStream, destDir: File? = null): PackageInspectResult {
    val tempFile = try {
        File.createTempFile("inspect_", ".pkg", destDir?.also { it.mkdirs() })
    } catch (t: Throwable) {
        return PackageInspectResult.Invalid(R.string.err_read_file)
    }
    return try {
        try {
            tempFile.outputStream().use { out -> input.copyTo(out, CopyBufferBytes) }
        } catch (e: IOException) {
            return PackageInspectResult.Invalid(R.string.err_read_file)
        }
        inspectAndExtractPackage(tempFile, destDir)
    } catch (e: CancellationException) {
        throw e
    } catch (t: Throwable) {
        PackageInspectResult.Invalid(R.string.reason_parse)
    } finally {
        runCatching { tempFile.delete() }
    }
}

private fun readBoundedText(input: InputStream, maxBytes: Int): String {
    val out = ByteArrayOutputStream()
    val buf = ByteArray(4096)
    var left = maxBytes
    while (left > 0) {
        val n = input.read(buf, 0, minOf(buf.size, left))
        if (n < 0) break
        out.write(buf, 0, n)
        left -= n
    }
    return out.toString(Charsets.UTF_8.name())
}

// ---- Metadata parsing (pure Kotlin, no org.json dependency) ----

private val ValidPackageRegex = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")
private val JsonPackageNameRegex = Regex(""""(?:package_name|pname)"\s*:\s*"([^"]+)"""")
private val JsonObjectRegex = Regex("""\{[^{}]*\}""")
private val JsonIdRegex = Regex(""""id"\s*:\s*"([^"]+)"""")
private val JsonFileRegex = Regex(""""file"\s*:\s*"([^"]+)"""")
private val JsonInstallPathRegex = Regex(""""install_path"\s*:\s*"([^"]+)"""")
private val ObbDirPackageRegex = Regex("""(?i)(?:^|/)Android/obb/([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+)/[^/]+\.obb$""")
private val ObbNamePackageRegex = Regex("""(?i)^(?:main|patch)\.\d+\.([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+)\.obb$""")

internal data class BundleMetadata(
    val packageName: String?,
    val baseApkFile: String?,
    val obbInstallPaths: Map<String, String>,
)

internal fun parseBundleMetadata(manifestJson: String?, infoJson: String?): BundleMetadata {
    val pkgFromManifest = manifestJson?.let { JsonPackageNameRegex.find(it)?.groupValues?.get(1)?.trim() }
        ?.takeIf { ValidPackageRegex.matches(it) }
    val pkgFromInfo = infoJson?.let { JsonPackageNameRegex.find(it)?.groupValues?.get(1)?.trim() }
        ?.takeIf { ValidPackageRegex.matches(it) }

    var baseApkFile: String? = null
    val obbInstallPaths = mutableMapOf<String, String>()
    if (manifestJson != null) {
        for (objMatch in JsonObjectRegex.findAll(manifestJson)) {
            val obj = objMatch.value
            val id = JsonIdRegex.find(obj)?.groupValues?.get(1)
            val file = JsonFileRegex.find(obj)?.groupValues?.get(1)?.replace('\\', '/')?.trimStart('/')
            val installPath = JsonInstallPathRegex.find(obj)?.groupValues?.get(1)?.replace('\\', '/')?.trimStart('/')
            if (id == "base" && file != null && file.endsWith(".apk", ignoreCase = true)) {
                baseApkFile = file
            }
            if (file != null && installPath != null &&
                (file.endsWith(".obb", ignoreCase = true) || installPath.endsWith(".obb", ignoreCase = true))
            ) {
                obbInstallPaths[file] = installPath
                obbInstallPaths[file.substringAfterLast('/')] = installPath
            }
        }
    }
    return BundleMetadata(
        packageName = pkgFromManifest ?: pkgFromInfo,
        baseApkFile = baseApkFile,
        obbInstallPaths = obbInstallPaths,
    )
}

internal fun extractObbPackageFromPath(entryPath: String, fileName: String): String? {
    val cleanPath = entryPath.replace('\\', '/').trimStart('/')
    return ObbDirPackageRegex.find(cleanPath)?.groupValues?.get(1)
        ?: ObbNamePackageRegex.find(fileName)?.groupValues?.get(1)
}

/** Picks the base `.apk` entry from a bundle's `.apk` list. */
fun selectBaseApk(apks: List<ExtractedFile>, baseApkName: String? = null, packageName: String? = null): ExtractedFile? {
    if (apks.isEmpty()) return null
    if (baseApkName != null) {
        val baseSimple = baseApkName.substringAfterLast('/')
        apks.firstOrNull { it.entryPath.equals(baseApkName, ignoreCase = true) || it.name.equals(baseSimple, ignoreCase = true) }
            ?.let { return it }
    }
    apks.firstOrNull { it.name.equals("base.apk", ignoreCase = true) || it.name.equals("base-master.apk", ignoreCase = true) }
        ?.let { return it }
    if (packageName != null) {
        apks.firstOrNull { it.name.equals("$packageName.apk", ignoreCase = true) }
            ?.let { return it }
    }
    val nonConfig = apks.filter { classifySplit(it.name, baseApkName, packageName) == SplitKind.BaseOrFeature }
    if (nonConfig.isNotEmpty()) {
        val nonSplitPrefix = nonConfig.filterNot {
            val n = it.name.lowercase()
            n.startsWith("split_") || n.startsWith("config.")
        }
        return (nonSplitPrefix.ifEmpty { nonConfig }).maxByOrNull { it.size }
    }
    return apks.maxByOrNull { it.size }
}

// ---- Target device properties & smart split filtering ----

data class DeviceSpec(
    val abis: List<String>,
    val densityDpi: Int?,
    val languages: Set<String>,
)

fun normalizeAbi(abi: String): String {
    val clean = abi.trim().lowercase().replace('_', '-')
    return when (clean) {
        "x86-64" -> "x86_64"
        else -> clean
    }
}

fun parseAbis(propOutput: String, fallback: List<String> = emptyList()): List<String> {
    val parsed = propOutput.lineSequence()
        .firstOrNull { it.isNotBlank() }
        .orEmpty()
        .split(',')
        .map { normalizeAbi(it) }
        .filter { it.isNotEmpty() }
        .distinct()
    if (parsed.isNotEmpty()) return parsed
    return fallback.map { normalizeAbi(it) }.filter { it.isNotEmpty() }.distinct()
}

private val OverrideDensityRegex = Regex("""(?i)Override density:\s*(\d+)""")
private val PhysicalDensityRegex = Regex("""(?i)Physical density:\s*(\d+)""")
private val AnyDensityRegex = Regex("""\b(\d{2,4})\b""")

fun parseDensityDpi(lcdDensityOutput: String, wmDensityOutput: String = "", fallbackDpi: Int? = null): Int? {
    lcdDensityOutput.trim().toIntOrNull()?.takeIf { it > 0 }?.let { return it }
    OverrideDensityRegex.find(wmDensityOutput)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it > 0 }?.let { return it }
    PhysicalDensityRegex.find(wmDensityOutput)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it > 0 }?.let { return it }
    AnyDensityRegex.find(wmDensityOutput)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it > 0 }?.let { return it }
    return fallbackDpi?.takeIf { it > 0 }
}

fun parseLanguages(
    persistLocaleOutput: String,
    productLocaleOutput: String = "",
    fallbackLanguage: String? = null,
): Set<String> {
    val langs = LinkedHashSet<String>()
    fun addFrom(raw: String?) {
        if (raw.isNullOrBlank()) return
        for (token in raw.split(',', ';', ' ', '\n', '\r', '\t')) {
            val primary = token.trim().substringBefore('-').substringBefore('_').lowercase()
            if (primary.length == 2 && primary.all { it in 'a'..'z' }) {
                langs += primary
            }
        }
    }
    addFrom(persistLocaleOutput)
    addFrom(productLocaleOutput)
    addFrom(fallbackLanguage)
    langs += "en"
    return langs
}

/** Queries the connected device's ABI list, screen density DPI, and locale over [adb], with safe local fallbacks. */
fun queryDeviceSpec(
    adb: AdbClient,
    fallbackAbis: List<String> = emptyList(),
    fallbackDpi: Int? = null,
    fallbackLanguage: String? = null,
): DeviceSpec {
    val abisProp = runCatching { adb.shell("getprop ro.product.cpu.abilist") }.getOrDefault("")
    val lcdProp = runCatching { adb.shell("getprop ro.sf.lcd_density") }.getOrDefault("")
    val wmOut = if (lcdProp.trim().toIntOrNull() == null) {
        runCatching { adb.shell("wm density") }.getOrDefault("")
    } else {
        ""
    }
    val persistLocale = runCatching { adb.shell("getprop persist.sys.locale") }.getOrDefault("")
    val productLocale = if (persistLocale.isBlank()) {
        runCatching { adb.shell("getprop ro.product.locale") }.getOrDefault("")
    } else {
        ""
    }
    return DeviceSpec(
        abis = parseAbis(abisProp, fallbackAbis),
        densityDpi = parseDensityDpi(lcdProp, wmOut, fallbackDpi),
        languages = parseLanguages(persistLocale, productLocale, fallbackLanguage),
    )
}

enum class DensityBucket(val token: String, val dpi: Int) {
    Ldpi("ldpi", 120),
    Mdpi("mdpi", 160),
    Tvdpi("tvdpi", 213),
    Hdpi("hdpi", 240),
    Xhdpi("xhdpi", 320),
    Xxhdpi("xxhdpi", 480),
    Xxxhdpi("xxxhdpi", 640),
    Anydpi("anydpi", -1),
}

sealed interface SplitKind {
    data object BaseOrFeature : SplitKind
    data class Abi(val abi: String) : SplitKind
    data class Density(val bucket: DensityBucket) : SplitKind
    data class Language(val lang: String) : SplitKind
}

private val AbiTokenMatchers: List<Pair<String, Regex>> = listOf(
    "arm64-v8a" to Regex("(?i)(?:^|[._-])arm64[_-]v8a(?:[._-]|$)"),
    "armeabi-v7a" to Regex("(?i)(?:^|[._-])armeabi[_-]v7a(?:[._-]|$)"),
    "armeabi" to Regex("(?i)(?:^|[._-])armeabi(?![_-]v7a)(?:[._-]|$)"),
    "x86_64" to Regex("(?i)(?:^|[._-])x86[_-]64(?:[._-]|$)"),
    "x86" to Regex("(?i)(?:^|[._-])x86(?![_-]64)(?:[._-]|$)"),
)

private val DensityTokenRegex = Regex("(?i)(?:^|[._-])(xxxhdpi|xxhdpi|xhdpi|tvdpi|hdpi|mdpi|ldpi|anydpi)(?:[._-]|$)")
private val ConfigLangRegex = Regex("(?i)(?:^|[._-])(?:split_)?config[._-]([a-z]{2})(?:[_-]r?[a-z]{2,4})?$")
private val BaseLangRegex = Regex("(?i)^base-([a-z]{2})(?:[_-]r?[a-z]{2,4})?$")
private val ApkSuffixRegex = Regex("(?i)\\.apk$")

/** Classifies a split `.apk` filename into Base/Feature, ABI, Density, or Language. */
fun classifySplit(fileName: String, baseApkName: String? = null, packageName: String? = null): SplitKind {
    val cleanName = fileName.substringAfterLast('/')
    if (cleanName.equals("base.apk", ignoreCase = true) ||
        cleanName.equals("base-master.apk", ignoreCase = true) ||
        (baseApkName != null && cleanName.equals(baseApkName.substringAfterLast('/'), ignoreCase = true)) ||
        (packageName != null && cleanName.equals("$packageName.apk", ignoreCase = true))
    ) {
        return SplitKind.BaseOrFeature
    }
    val stem = cleanName.replace(ApkSuffixRegex, "")
    for ((canonicalAbi, regex) in AbiTokenMatchers) {
        if (regex.containsMatchIn(stem)) return SplitKind.Abi(canonicalAbi)
    }
    DensityTokenRegex.find(stem)?.groupValues?.get(1)?.lowercase()?.let { token ->
        DensityBucket.entries.firstOrNull { it.token == token }?.let { return SplitKind.Density(it) }
    }
    val lang = ConfigLangRegex.find(stem)?.groupValues?.get(1)?.lowercase()
        ?: BaseLangRegex.find(stem)?.groupValues?.get(1)?.lowercase()
    if (lang != null) {
        return SplitKind.Language(lang)
    }
    return SplitKind.BaseOrFeature
}

sealed interface SplitFilterResult {
    data class Selected(val splits: List<ExtractedFile>) : SplitFilterResult
    data class IncompatibleAbi(val reasonRes: Int = R.string.reason_abis) : SplitFilterResult
}

/**
 * Selects the splits to install on [device]:
 * - Base APK and feature splits are always included.
 * - ABI splits: picks only the split(s) matching the first supported ABI of [device] present in the bundle; if the
 *   bundle contains ABI splits and none match [device], returns [SplitFilterResult.IncompatibleAbi].
 * - Density splits: picks the closest density bucket for [device.densityDpi] (plus `anydpi` if present).
 * - Language splits: picks splits matching [device.languages] + English (`en`), or all if none match.
 */
fun filterSplits(
    apks: List<ExtractedFile>,
    device: DeviceSpec,
    baseApkName: String? = null,
    packageName: String? = null,
): SplitFilterResult {
    val classified = apks.map { it to classifySplit(it.name, baseApkName, packageName) }

    // 1. ABI splits
    val abiSplits = classified.mapNotNull { (apk, kind) -> (kind as? SplitKind.Abi)?.let { apk to it.abi } }
    val selectedAbiSplits = if (abiSplits.isNotEmpty()) {
        val availableAbis = abiSplits.map { it.second }.toSet()
        val deviceAbis = device.abis.map { normalizeAbi(it) }
        val winningAbi = deviceAbis.firstOrNull { it in availableAbis }
            ?: return SplitFilterResult.IncompatibleAbi(R.string.reason_abis)
        abiSplits.filter { it.second == winningAbi }.map { it.first }
    } else {
        emptyList()
    }

    // 2. Density splits
    val densitySplits = classified.mapNotNull { (apk, kind) -> (kind as? SplitKind.Density)?.let { apk to it.bucket } }
    val selectedDensitySplits = if (densitySplits.isNotEmpty()) {
        val numericBuckets = densitySplits.map { it.second }.filter { it.dpi > 0 }.distinct()
        val dpi = device.densityDpi
        if (numericBuckets.size <= 1 || dpi == null || dpi <= 0) {
            densitySplits.map { it.first }
        } else {
            val closest = numericBuckets.minWith(
                compareBy<DensityBucket> { abs(it.dpi - dpi) }.thenByDescending { it.dpi },
            )
            densitySplits.filter { it.second == closest || it.second == DensityBucket.Anydpi }.map { it.first }
        }
    } else {
        emptyList()
    }

    // 3. Language splits
    val langSplits = classified.mapNotNull { (apk, kind) -> (kind as? SplitKind.Language)?.let { apk to it.lang } }
    val selectedLangSplits = if (langSplits.isNotEmpty()) {
        val wantedLangs = device.languages.map { it.take(2).lowercase() }.toSet() + "en"
        val matched = langSplits.filter { it.second in wantedLangs }.map { it.first }
        matched.ifEmpty { langSplits.map { it.first } }
    } else {
        emptyList()
    }

    // 4. Base and feature splits (always included, with base APK ordered first)
    val baseAndFeatures = classified.filter { it.second == SplitKind.BaseOrFeature }.map { it.first }
    val baseApk = selectBaseApk(apks, baseApkName, packageName)
    val orderedBaseAndFeatures = if (baseApk != null && baseApk in baseAndFeatures) {
        listOf(baseApk) + baseAndFeatures.filterNot { it == baseApk }
    } else {
        baseAndFeatures
    }

    val allSelected = (orderedBaseAndFeatures + selectedAbiSplits + selectedDensitySplits + selectedLangSplits).distinct()
    return SplitFilterResult.Selected(allSelected)
}

// ---- Multi-APK ADB Session & OBB Commands ----

/** pm-style failure code of an OBB that names another app; [pmFailure] maps it to a plain sentence. */
const val ObbOtherAppCode = "INSTALL_GOGO_OBB_PACKAGE_MISMATCH"

private val SessionIdRegex = Regex("""Success:.*\[(\d+)\]""")
private val UnsafeSplitCharRegex = Regex("[^A-Za-z0-9._-]")
private val UnsafePackageCharRegex = Regex("[^A-Za-z0-9._]")

const val DisableAdbVerifyCommand = "settings put global verifier_verify_adb_installs 0"
const val DisableVerifierCommand = "settings put global package_verifier_user_consent -1"
const val ReadAdbVerifyCommand = "settings get global verifier_verify_adb_installs"
const val ReadVerifierCommand = "settings get global package_verifier_user_consent"
private const val AdbVerifyKey = "verifier_verify_adb_installs"
private const val VerifierConsentKey = "package_verifier_user_consent"
private val WholeNumberRegex = Regex("^-?[0-9]{1,10}$")

/**
 * What a global setting held before the install turned it off. [known] is false when the device's answer was not understood:
 * such a setting is left as the install set it rather than guessed. A [value] of null with [known] true means "not set".
 */
data class SavedSetting(val key: String, val value: String?, val known: Boolean)

/** Reads the answer of `settings get global <key>`: `null` is "not set", a whole number is its value, anything else is unknown. */
fun parseSavedSetting(key: String, output: String): SavedSetting {
    val text = output.trim()
    return when {
        text.equals("null", ignoreCase = true) -> SavedSetting(key, null, true)
        WholeNumberRegex.matches(text) -> SavedSetting(key, text, true)
        else -> SavedSetting(key, null, false)
    }
}

/** The command that puts [saved] back, or null when its previous value is not known. */
fun restoreSettingCommand(saved: SavedSetting): String? = when {
    !saved.known -> null
    saved.value == null -> "settings delete global ${saved.key}"
    else -> "settings put global ${saved.key} ${saved.value}"
}

/** The two Play Protect settings as they are now, read before the install changes them. Never throws. */
fun readVerifierSettings(adb: AdbClient): List<SavedSetting> = listOf(
    parseSavedSetting(AdbVerifyKey, runCatching { adb.shell(ReadAdbVerifyCommand) }.getOrDefault("")),
    parseSavedSetting(VerifierConsentKey, runCatching { adb.shell(ReadVerifierCommand) }.getOrDefault("")),
)

/** Puts the settings of [saved] back as they were. Best effort: a lost connection must not turn a finished install into an error. */
fun restoreVerifierSettings(adb: AdbClient, saved: List<SavedSetting>, onLog: (String) -> Unit = {}) {
    for (setting in saved) {
        val command = restoreSettingCommand(setting) ?: continue
        onLog("> adb: $command (Play Protect setting put back as it was)")
        runCatching { adb.shell(command) }
    }
}

fun createSessionCommand(bypass: Boolean = true, userInstall: Boolean = false, testOnly: Boolean = false): String =
    "pm install-create -r -d${if (testOnly) " -t" else ""}${if (bypass) " --bypass-low-target-sdk-block" else ""}" +
        if (userInstall) " --install-reason $InstallReasonUser" else ""

fun parseSessionId(output: String): Long? =
    output.replace("\r", "")
        .lineSequence()
        .map { it.trim() }
        .firstOrNull { it.startsWith("Success") }
        ?.let { SessionIdRegex.find(it)?.groupValues?.get(1)?.toLongOrNull() }

fun sanitizeSplitName(name: String): String =
    name.substringAfterLast('/')
        .replace(UnsafeSplitCharRegex, "_")
        .trimStart('-', '.')
        .ifEmpty { "split.apk" }

fun sanitizePackageName(packageName: String): String =
    packageName.trim()
        .replace(UnsafePackageCharRegex, "")
        .trim('.')
        .ifEmpty { "unknown.package" }

fun installWriteCommand(sessionId: Long, splitName: String, size: Long): String =
    "cmd package install-write -S $size $sessionId ${sanitizeSplitName(splitName)} -"

fun installCommitCommand(sessionId: Long): String =
    "pm install-commit $sessionId"

fun installAbandonCommand(sessionId: Long): String =
    "pm install-abandon $sessionId"

fun obbMkdirCommand(packageName: String): String =
    "mkdir -p '/sdcard/Android/obb/${sanitizePackageName(packageName)}'"

fun obbWriteCommand(packageName: String, obbName: String, size: Long): String =
    "head -c $size > '/sdcard/Android/obb/${sanitizePackageName(packageName)}/${sanitizeSplitName(obbName)}'"

/**
 * Installs a multi-APK bundle (and optional `.obb` expansion files) via an ADB package installer session.
 * Aggregates byte progress smoothly across all selected splits and OBB files via [onProgress].
 * The OBB files always belong to [packageName] (the package of the base APK): an OBB that names another app fails the
 * install before anything is written, and OBB files are written only after `pm install-commit` succeeded. If that
 * write fails, the result is still a success with [PmResult.obbFailure] set.
 * If any step after session creation and before commit fails or throws, abandons the session in `finally`.
 */
fun installBundleSession(
    adb: AdbClient,
    splits: List<ExtractedFile>,
    obbs: List<ExtractedFile> = emptyList(),
    packageName: String? = null,
    onProgress: (sent: Long, total: Long) -> Unit = { _, _ -> },
    onLog: (String) -> Unit = {},
    userInstall: Boolean = false,
    testOnly: Boolean = false,
): PmResult {
    val obbPackage = packageName?.takeIf { it.isNotBlank() }
    if (obbs.isNotEmpty() && (obbPackage == null || obbs.any { !obbBelongsTo(it, obbPackage) })) {
        onLog("> obb: refused, an OBB file belongs to another app (nothing was written)")
        return PmResult(false, "Failure [$ObbOtherAppCode]")
    }
    // The install turns Play Protect's ADB check off; whatever the outcome, the previous settings are put back.
    val saved = readVerifierSettings(adb)
    try {
        return runBundleSession(adb, splits, obbs, obbPackage, onProgress, onLog, userInstall, testOnly)
    } finally {
        restoreVerifierSettings(adb, saved, onLog)
    }
}

private fun runBundleSession(
    adb: AdbClient,
    splits: List<ExtractedFile>,
    obbs: List<ExtractedFile>,
    obbPackage: String?,
    onProgress: (sent: Long, total: Long) -> Unit,
    onLog: (String) -> Unit,
    userInstall: Boolean,
    testOnly: Boolean,
): PmResult {
    val totalBytes = splits.sumOf { it.size.coerceAtLeast(0L) } + obbs.sumOf { it.size.coerceAtLeast(0L) }
    onProgress(0L, totalBytes)

    // Keep Google Play Protect out of ADB installs: the package verifier skips them when this setting is 0.
    onLog("> adb: $DisableAdbVerifyCommand")
    adb.shell(DisableAdbVerifyCommand)
    adb.shell(DisableVerifierCommand)
    val createCmd = createSessionCommand(bypass = true, userInstall = userInstall, testOnly = testOnly)
    onLog("> adb: $createCmd (none granted by GoGo)")
    var createOut = adb.shell(createCmd)
    if (shouldRetryWithoutBypass(createOut)) {
        val fallbackCmd = createSessionCommand(bypass = false, userInstall = userInstall, testOnly = testOnly)
        onLog("> adb: retrying $fallbackCmd")
        createOut = adb.shell(fallbackCmd)
    }
    val sessionId = parseSessionId(createOut)
        ?: return PmResult(false, parsePmOutput(createOut).line)
    onLog("> session: created [$sessionId] for ${splits.size} split(s)")

    var committed = false
    try {
        var completedBytes = 0L
        val usedNames = mutableSetOf<String>()
        for ((index, split) in splits.withIndex()) {
            val baseSafe = sanitizeSplitName(split.name)
            val safeName = if (usedNames.add(baseSafe)) baseSafe else "${index}_$baseSafe"
            val cmd = installWriteCommand(sessionId, safeName, split.size)
            onLog("> adb: install-write [${index + 1}/${splits.size}] $safeName (${split.size} B)")
            val writeOut = split.openStream().use { stream ->
                adb.writeStream(cmd, split.size, stream) { sent ->
                    onProgress((completedBytes + sent).coerceAtMost(totalBytes), totalBytes)
                }
            }
            val writeResult = parsePmOutput(writeOut)
            if (!writeResult.success) {
                return writeResult
            }
            completedBytes += split.size
            onProgress(completedBytes, totalBytes)
        }

        committed = true
        val commitCmd = installCommitCommand(sessionId)
        onLog("> adb: $commitCmd")
        val commit = parsePmOutput(adb.shell(commitCmd))
        if (!commit.success || obbs.isEmpty() || obbPackage == null) return commit

        // The app is installed now; only now may its data files be written.
        fun obbFailed(why: String): PmResult {
            onLog("> obb: write failed ($why), the app is installed but its data files were not copied")
            return PmResult(true, commit.line, obbFailure = why)
        }
        try {
            adb.shell(obbMkdirCommand(obbPackage))
            for (obb in obbs) {
                val cmd = obbWriteCommand(obbPackage, obb.name, obb.size)
                onLog("> adb: streaming OBB ${obb.name} (${obb.size} B)")
                val obbOut = obb.openStream().use { stream ->
                    adb.writeStream(cmd, obb.size, stream) { sent ->
                        onProgress((completedBytes + sent).coerceAtMost(totalBytes), totalBytes)
                    }
                }
                if (obbOut.isNotBlank() && !parsePmOutput(obbOut).success) {
                    return obbFailed(obbOut.lineSequence().firstOrNull { it.isNotBlank() } ?: "Failure [OBB_WRITE_FAILED]")
                }
                completedBytes += obb.size
                onProgress(completedBytes, totalBytes)
            }
        } catch (e: IOException) {
            return obbFailed(e.message ?: "I/O error")
        }
        return commit
    } finally {
        if (!committed) {
            runCatching { adb.shell(installAbandonCommand(sessionId)) }
        }
    }
}
