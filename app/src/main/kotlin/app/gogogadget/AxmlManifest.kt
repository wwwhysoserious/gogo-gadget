package app.gogogadget

import java.nio.ByteBuffer
import java.nio.ByteOrder

// A small reader for the compiled (binary) AndroidManifest.xml of an APK. It walks the real XML elements, so the Shield
// sees the permissions the app DECLARES with <uses-permission>, not every string that happens to contain a permission
// name (a service guard such as android:permission="...SEND_SMS" is a declaration of protection, not a request).

private const val AxmlFileType = 0x0003
private const val AxmlStringPoolType = 0x0001
private const val AxmlResourceMapType = 0x0180
private const val AxmlStartElementType = 0x0102
private const val AxmlUtf8Flag = 0x100
private const val MaxAxmlStrings = 200_000

/** `android:name`, `android:versionCode` and `android:versionCodeMajor` attribute resource ids. */
private const val AttrNameResId = 0x01010003
private const val AttrPermissionResId = 0x01010006
private const val AttrVersionCodeResId = 0x0101021b
private const val AttrVersionCodeMajorResId = 0x0101021c
private const val AxmlTypeString = 0x03

internal data class AxmlAttribute(
    val name: String,
    val resId: Int,
    /** The text of a string attribute, null for numbers and references. */
    val stringValue: String?,
    val dataType: Int,
    val data: Int,
)

internal data class AxmlElement(val name: String, val attributes: List<AxmlAttribute>)

private fun readAxmlStringPool(buf: ByteBuffer, bytes: ByteArray, chunkStart: Int): List<String> {
    val headerSize = buf.getShort(chunkStart + 2).toInt() and 0xFFFF
    val count = buf.getInt(chunkStart + 8)
    val flags = buf.getInt(chunkStart + 16)
    val stringsStart = buf.getInt(chunkStart + 20)
    require(count in 0..MaxAxmlStrings)
    val utf8 = (flags and AxmlUtf8Flag) != 0
    val out = ArrayList<String>(count)
    for (i in 0 until count) {
        val relative = buf.getInt(chunkStart + headerSize + i * 4)
        var p = chunkStart + stringsStart + relative
        if (utf8) {
            // Two lengths follow: characters, then bytes; each is one byte, or two when its high bit is set.
            p += if ((bytes[p].toInt() and 0x80) != 0) 2 else 1
            var byteLength = bytes[p].toInt() and 0xFF
            p += 1
            if ((byteLength and 0x80) != 0) {
                byteLength = ((byteLength and 0x7F) shl 8) or (bytes[p].toInt() and 0xFF)
                p += 1
            }
            out += String(bytes, p, byteLength, Charsets.UTF_8)
        } else {
            var length = buf.getShort(p).toInt() and 0xFFFF
            p += 2
            if ((length and 0x8000) != 0) {
                length = ((length and 0x7FFF) shl 16) or (buf.getShort(p).toInt() and 0xFFFF)
                p += 2
            }
            out += String(bytes, p, length * 2, Charsets.UTF_16LE)
        }
    }
    return out
}

/** Every start element of a compiled manifest with its attributes; null when [bytes] is not binary AXML or is cut off. */
internal fun parseAxmlElements(bytes: ByteArray): List<AxmlElement>? {
    if (bytes.size < 8) return null
    return try {
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        if ((buf.getShort(0).toInt() and 0xFFFF) != AxmlFileType) return null
        val fileHeader = buf.getShort(2).toInt() and 0xFFFF
        if (fileHeader < 8) return null
        var strings: List<String> = emptyList()
        var resIds = IntArray(0)
        val elements = ArrayList<AxmlElement>()
        var offset = fileHeader
        while (offset + 8 <= bytes.size) {
            val type = buf.getShort(offset).toInt() and 0xFFFF
            val headerSize = buf.getShort(offset + 2).toInt() and 0xFFFF
            val size = buf.getInt(offset + 4)
            if (size < 8 || size > bytes.size - offset) break
            when (type) {
                AxmlStringPoolType -> strings = readAxmlStringPool(buf, bytes, offset)
                AxmlResourceMapType -> {
                    val count = (size - headerSize) / 4
                    resIds = IntArray(count) { buf.getInt(offset + headerSize + it * 4) }
                }
                AxmlStartElementType -> {
                    val ext = offset + 16
                    val nameIndex = buf.getInt(ext + 4)
                    val attrStart = buf.getShort(ext + 8).toInt() and 0xFFFF
                    val attrSize = buf.getShort(ext + 10).toInt() and 0xFFFF
                    val attrCount = buf.getShort(ext + 12).toInt() and 0xFFFF
                    val step = if (attrSize >= 20) attrSize else 20
                    val attributes = ArrayList<AxmlAttribute>(attrCount)
                    var pos = ext + attrStart
                    for (i in 0 until attrCount) {
                        if (pos + 20 > offset + size) break
                        val attrName = buf.getInt(pos + 4)
                        val rawIndex = buf.getInt(pos + 8)
                        val dataType = bytes[pos + 15].toInt() and 0xFF
                        val data = buf.getInt(pos + 16)
                        val text = when {
                            rawIndex >= 0 -> strings.getOrNull(rawIndex)
                            dataType == AxmlTypeString -> strings.getOrNull(data)
                            else -> null
                        }
                        attributes += AxmlAttribute(
                            name = strings.getOrNull(attrName).orEmpty(),
                            resId = resIds.getOrElse(attrName) { 0 },
                            stringValue = text,
                            dataType = dataType,
                            data = data,
                        )
                        pos += step
                    }
                    elements += AxmlElement(strings.getOrNull(nameIndex).orEmpty(), attributes)
                }
            }
            offset += size
        }
        elements
    } catch (_: Throwable) {
        null
    }
}

private val UsesPermissionXmlRegex = Regex("""<uses-permission(?:-sdk-23)?\s[^>]*?android:name\s*=\s*["']([^"']+)["']""")

/**
 * The permissions the manifest declares with `<uses-permission>` (and `uses-permission-sdk-23`), sorted. A name in the
 * `android.permission.` namespace is returned short (`SEND_SMS`); any other name is returned complete, so
 * `com.example.permission.READ_SMS` is never mistaken for the platform's `READ_SMS`. Null when [bytes] is neither a
 * binary manifest nor plain XML, so the caller can fall back.
 */
internal fun declaredManifestPermissions(bytes: ByteArray): List<String>? {
    val names = parseAxmlElements(bytes)?.let { elements ->
        elements
            .filter { it.name == "uses-permission" || it.name == "uses-permission-sdk-23" }
            .mapNotNull { element ->
                element.attributes.firstOrNull { it.resId == AttrNameResId || it.name == "name" }?.stringValue
            }
    } ?: run {
        val text = runCatching { bytes.toString(Charsets.UTF_8).trimStart('﻿', ' ', '\n', '\r', '\t') }.getOrNull()
        if (text == null || !text.startsWith("<")) return null
        UsesPermissionXmlRegex.findAll(text).map { it.groupValues[1] }.toList()
    }
    return names
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .map { if (it.startsWith("android.permission.")) it.removePrefix("android.permission.") else it }
        .distinct()
        .sorted()
}

/** `android:versionCode` (with `versionCodeMajor` in the high 32 bits) of a binary manifest, or null. */
internal fun axmlVersionCode(bytes: ByteArray): Long? {
    val manifest = parseAxmlElements(bytes)?.firstOrNull { it.name == "manifest" } ?: return null
    fun number(resId: Int, name: String): Long? = manifest.attributes
        .firstOrNull { (it.resId == resId || it.name == name) && it.dataType in 0x10..0x1F }
        ?.let { it.data.toLong() and 0xFFFFFFFFL }
    val low = number(AttrVersionCodeResId, "versionCode") ?: return null
    val high = number(AttrVersionCodeMajorResId, "versionCodeMajor") ?: 0L
    return (high shl 32) or low
}

/**
 * The permissions that components of the app REQUIRE from their callers (`android:permission` on `<service>`), as short
 * names. `BIND_ACCESSIBILITY_SERVICE` here means the app ships an accessibility service; it is a capability of the app, not a
 * permission it requests. Null when [bytes] is not a binary manifest.
 */
internal fun declaredServiceGuards(bytes: ByteArray): Set<String>? {
    val elements = parseAxmlElements(bytes) ?: return null
    return elements
        .filter { it.name == "service" }
        .mapNotNull { service -> service.attributes.firstOrNull { it.resId == AttrPermissionResId || it.name == "permission" }?.stringValue }
        .map { it.trim().removePrefix("android.permission.") }
        .toSet()
}
