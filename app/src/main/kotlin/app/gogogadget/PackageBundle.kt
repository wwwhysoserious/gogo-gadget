package app.gogogadget

import kotlinx.coroutines.CancellationException
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
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
            var hasRootAndroidManifest = false
            var manifestEntry: ZipEntry? = null
            var infoEntry: ZipEntry? = null
            val apkEntries = mutableListOf<Pair<String, ZipEntry>>()
            val obbEntries = mutableListOf<Pair<String, ZipEntry>>()

            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                entryCount++
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

            if (hasRootAndroidManifest && apkEntries.isEmpty()) {
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

            if (hasRootAndroidManifest || apkEntries.isEmpty()) {
                return PackageInspectResult.Invalid(R.string.reason_parse)
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
                        out.outputStream().use { output -> input.copyTo(output, CopyBufferBytes) }
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
                        out.outputStream().use { output -> input.copyTo(output, CopyBufferBytes) }
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

private val SessionIdRegex = Regex("""Success:.*\[(\d+)\]""")
private val UnsafeSplitCharRegex = Regex("[^A-Za-z0-9._-]")
private val UnsafePackageCharRegex = Regex("[^A-Za-z0-9._]")

fun createSessionCommand(bypass: Boolean = true): String =
    "pm install-create -r -d${if (bypass) " --bypass-low-target-sdk-block" else ""}"

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
 * If any step after session creation and before commit fails or throws, abandons the session in `finally`.
 */
fun installBundleSession(
    adb: AdbClient,
    splits: List<ExtractedFile>,
    obbs: List<ExtractedFile> = emptyList(),
    packageName: String? = null,
    onProgress: (sent: Long, total: Long) -> Unit = { _, _ -> },
): PmResult {
    val totalBytes = splits.sumOf { it.size.coerceAtLeast(0L) } + obbs.sumOf { it.size.coerceAtLeast(0L) }
    onProgress(0L, totalBytes)

    var createOut = adb.shell(createSessionCommand(bypass = true))
    if (shouldRetryWithoutBypass(createOut)) {
        createOut = adb.shell(createSessionCommand(bypass = false))
    }
    val sessionId = parseSessionId(createOut)
        ?: return PmResult(false, parsePmOutput(createOut).line)

    var committed = false
    try {
        var completedBytes = 0L
        val usedNames = mutableSetOf<String>()
        for ((index, split) in splits.withIndex()) {
            val baseSafe = sanitizeSplitName(split.name)
            val safeName = if (usedNames.add(baseSafe)) baseSafe else "${index}_$baseSafe"
            val cmd = installWriteCommand(sessionId, safeName, split.size)
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

        if (obbs.isNotEmpty()) {
            val defaultPkg = packageName?.takeIf { it.isNotBlank() }
                ?: obbs.firstNotNullOfOrNull { it.obbPackageName }
                ?: return PmResult(false, "Failure [INSTALL_PARSE_FAILED_MANIFEST_MALFORMED: Missing package name for OBB]")
            val createdDirs = mutableSetOf<String>()
            for (obb in obbs) {
                val targetPkg = sanitizePackageName(obb.obbPackageName ?: defaultPkg)
                if (createdDirs.add(targetPkg)) {
                    adb.shell(obbMkdirCommand(targetPkg))
                }
                val cmd = obbWriteCommand(targetPkg, obb.name, obb.size)
                val obbOut = obb.openStream().use { stream ->
                    adb.writeStream(cmd, obb.size, stream) { sent ->
                        onProgress((completedBytes + sent).coerceAtMost(totalBytes), totalBytes)
                    }
                }
                if (obbOut.isNotBlank() && !parsePmOutput(obbOut).success) {
                    return PmResult(false, obbOut.lineSequence().firstOrNull { it.isNotBlank() } ?: "Failure [OBB_WRITE_FAILED]")
                }
                completedBytes += obb.size
                onProgress(completedBytes, totalBytes)
            }
        }

        committed = true
        val commitOut = adb.shell(installCommitCommand(sessionId))
        return parsePmOutput(commitOut)
    } finally {
        if (!committed) {
            runCatching { adb.shell(installAbandonCommand(sessionId)) }
        }
    }
}
