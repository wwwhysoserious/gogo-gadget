package app.gogogadget

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.util.Locale

// Format hardening from the antivirus study: Janus (CVE-2017-13156) and BadPack. An APK is read through its central
// directory only (java.util.zip.ZipFile); this file additionally checks that the central directory and the local file
// headers tell the same story, because a scanner and the platform that disagree about an archive can be tricked.

private const val EocdSignature = 0x06054b50
private const val CentralSignature = 0x02014b50
private const val LocalSignature = 0x04034b50
private const val EocdMinBytes = 22
private const val CentralFixedBytes = 46
private const val LocalFixedBytes = 30
private const val MaxCentralDirectoryBytes = 16 * 1024 * 1024
private const val DataDescriptorFlag = 0x0008

/** The first API level with the v2 APK signature scheme (Android 7.0). */
const val ApkV2MinSdk = 24

/** Android 11 refuses to install apps that target API 30 or higher with only a v1 signature. */
const val ApkV2RequiredTargetSdk = 30

/**
 * A v1-only (JAR) signature is rejected when the app does not need to run on a platform without v2: its minSdk is 24
 * or higher, or it targets API 30 or higher. A v1-only APK is the one the Janus attack can prepend a DEX to. Unknown
 * SDK levels (null) are not judged.
 */
fun isV1OnlyRejected(hasV1: Boolean, hasV2Plus: Boolean, minSdk: Int?, targetSdk: Int?): Boolean =
    hasV1 && !hasV2Plus && ((minSdk ?: 0) >= ApkV2MinSdk || (targetSdk ?: 0) >= ApkV2RequiredTargetSdk)

/** True when the file starts with the DEX magic yet opens as a ZIP: the Janus polyglot (a DEX glued in front of an APK). */
fun isJanusPolyglot(file: File): Boolean = try {
    file.inputStream().use { input ->
        val head = ByteArray(4)
        input.read(head) == 4 && head.contentEquals(DexMagic)
    }
} catch (_: IOException) {
    false
}

private fun u16(b: ByteArray, o: Int): Int = (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

private fun u32(b: ByteArray, o: Int): Long = u16(b, o).toLong() or (u16(b, o + 2).toLong() shl 16)

/**
 * Null when the archive is consistent, otherwise a short English detail. Checks: one end-of-central-directory record
 * at the very end, a central directory that holds exactly the announced entries, no duplicate names, only the stored
 * and deflate methods, and for every entry a local header at the stated offset that agrees on name, method and (when
 * no data descriptor is used) sizes, with its data ending before the central directory. ZIP64 archives are not judged.
 */
fun zipStructureProblem(file: File): String? = try {
    RandomAccessFile(file, "r").use { checkZip(it) }
} catch (_: IOException) {
    "archive cannot be read"
}

private fun checkZip(raf: RandomAccessFile): String? {
    val length = raf.length()
    if (length < EocdMinBytes) return "archive too short"
    val tailSize = minOf(length, 65_557L).toInt()
    val tail = ByteArray(tailSize)
    raf.seek(length - tailSize)
    raf.readFully(tail)
    var eocd = -1
    var sawSignature = false
    for (i in tailSize - EocdMinBytes downTo 0) {
        if (u32(tail, i) != EocdSignature.toLong()) continue
        sawSignature = true
        if (i + EocdMinBytes + u16(tail, i + 20) == tailSize) {
            eocd = i
            break
        }
    }
    if (eocd < 0) return if (sawSignature) "end of central directory is not at the end of the file" else "no central directory"
    val count = u16(tail, eocd + 10)
    val cdSize = u32(tail, eocd + 12)
    val cdOffset = u32(tail, eocd + 16)
    if (count == 0xFFFF || cdOffset == 0xFFFFFFFFL || cdSize == 0xFFFFFFFFL) return null
    val eocdPosition = length - tailSize + eocd
    if (cdSize > MaxCentralDirectoryBytes || cdOffset + cdSize > eocdPosition) return "central directory out of bounds"
    val cd = ByteArray(cdSize.toInt())
    raf.seek(cdOffset)
    raf.readFully(cd)

    val names = HashSet<String>()
    val local = ByteArray(LocalFixedBytes)
    var pos = 0
    var seen = 0
    while (pos < cd.size) {
        if (pos + CentralFixedBytes > cd.size || u32(cd, pos) != CentralSignature.toLong()) return "malformed central directory entry"
        val flags = u16(cd, pos + 8)
        val method = u16(cd, pos + 10)
        val csize = u32(cd, pos + 20)
        val usize = u32(cd, pos + 24)
        val nameLen = u16(cd, pos + 28)
        val extraLen = u16(cd, pos + 30)
        val commentLen = u16(cd, pos + 32)
        val offset = u32(cd, pos + 42)
        val next = pos + CentralFixedBytes + nameLen + extraLen + commentLen
        if (next > cd.size) return "central directory entry overruns the directory"
        val name = cd.copyOfRange(pos + CentralFixedBytes, pos + CentralFixedBytes + nameLen)
        if (!names.add(String(name, Charsets.ISO_8859_1))) return "duplicate entry name"
        if (method != 0 && method != 8) return "unsupported compression method $method"
        if (method == 0 && csize != usize) return "stored entry with different sizes"
        if (offset + LocalFixedBytes > cdOffset) return "local header offset out of bounds"
        raf.seek(offset)
        raf.readFully(local)
        if (u32(local, 0) != LocalSignature.toLong()) return "missing local file header"
        if (u16(local, 8) != method) return "compression method differs between central directory and local header"
        val localNameLen = u16(local, 26)
        val localExtraLen = u16(local, 28)
        if (localNameLen != nameLen) return "entry name length differs between central directory and local header"
        val localName = ByteArray(nameLen)
        raf.readFully(localName)
        if (!localName.contentEquals(name)) return "entry name differs between central directory and local header"
        if ((flags and DataDescriptorFlag) == 0 && (u32(local, 18) != csize || u32(local, 22) != usize)) {
            return "entry sizes differ between central directory and local header"
        }
        if (offset + LocalFixedBytes + localNameLen + localExtraLen + csize > cdOffset) return "entry data runs into the central directory"
        pos = next
        seen++
    }
    return if (seen != count) "central directory entry count differs from the end record" else null
}

/** True for a name inside an APK that holds executable code: a classes DEX file or a native `.so` library under `lib`. */
fun isCodeEntryName(name: String): Boolean {
    val clean = name.replace('\\', '/').trimStart('/').lowercase(Locale.US)
    val simple = clean.substringAfterLast('/')
    return StaticAnalyzer.isDexEntry(clean) ||
        (clean.startsWith("lib/") && simple.endsWith(".so"))
}

/**
 * Whether an APK of a package is looked up online: the base APK always, any other split only when it holds code
 * (a classes DEX file or a `.so` library under `lib`). Resource-only splits (languages, screen densities) carry no code, so they are not
 * sent anywhere; they still go through the signature and format checks.
 */
fun needsReputationLookup(isBase: Boolean, entryNames: Iterable<String>): Boolean =
    isBase || entryNames.any(::isCodeEntryName)

/** The entry names of an APK read from its central directory, or null when it cannot be read (then it is looked up). */
fun apkEntryNames(file: File): List<String>? = try {
    java.util.zip.ZipFile(file).use { zip -> zip.entries().toList().map { it.name } }
} catch (_: Exception) {
    null
}
