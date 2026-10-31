package app.gogogadget

import java.io.File
import java.util.zip.ZipFile

/** A package handed to GoGo from outside ("Open with" or Share): a private copy in the cache, and the name to show. */
data class IncomingFile(val name: String, val file: File)

/** The waiting file starts only with a connected device and no install running; otherwise it waits (or queues). */
fun pendingFileReady(connected: Boolean, installing: Boolean): Boolean = connected && !installing

/** The name another app gave the file, reduced to a plain display name: no path, no control characters. */
fun incomingDisplayName(raw: String?): String =
    raw.orEmpty().substringAfterLast('/').filterNot { it.isISOControl() }.trim().take(MaxIncomingNameLength).ifEmpty { "package" }

/**
 * True when [file] is an APK (`AndroidManifest.xml` at the root) or a bundle with APK entries (XAPK, APKM, APKS, ZIP).
 * Only the central directory is read; the real inspection happens when the install starts.
 */
fun looksInstallable(file: File): Boolean {
    val magic = ByteArray(4)
    val read = runCatching { file.inputStream().use { it.read(magic) } }.getOrDefault(-1)
    if (read < 0 || !hasZipMagic(magic, read)) return false
    return runCatching {
        ZipFile(file).use { zip ->
            var count = 0
            var total = 0L
            var hasManifest = false
            var hasApk = false
            for (entry in zip.entries()) {
                count++
                total += entry.size.let { if (it < 0L) Long.MAX_VALUE / 2 else it }
                if (!zipWithinLimits(count, total)) return@use false
                val path = entry.name.replace('\\', '/').trimStart('/')
                if (entry.isDirectory) continue
                if (path == "AndroidManifest.xml") hasManifest = true
                else if (path.endsWith(".apk", ignoreCase = true)) hasApk = true
            }
            // Same rule as the installer: a root manifest means a single APK (an .apk inside it is data); without one, the
            // archive must carry split APKs.
            hasManifest || hasApk
        }
    }.getOrDefault(false)
}

private const val MaxIncomingNameLength = 100
