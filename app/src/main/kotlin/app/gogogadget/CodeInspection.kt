package app.gogogadget

import java.util.Locale

// Offline inspection of what an APK carries besides its Java code: known tracker SDKs (informational) and the native
// libraries (the .so files under lib/<abi>): a valid ELF for the folder it sits in, and a few markers of instrumentation or packers.

/**
 * An offline subset of the Exodus Privacy tracker database (https://reports.exodus-privacy.eu.org/api/trackers):
 * tracker name to the code signature package prefixes it uses. The full database has 400+ entries; this is the part
 * that shows up most often. Informational only: a tracker never blocks an install.
 */
val KnownTrackerSignatures: Map<String, List<String>> = mapOf(
    "Google Firebase Analytics" to listOf("com.google.firebase.analytics", "com.google.android.gms.measurement"),
    "Google Analytics" to listOf("com.google.android.gms.analytics", "com.google.analytics"),
    "Google AdMob" to listOf("com.google.android.gms.ads"),
    "Google CrashLytics" to listOf("com.crashlytics", "com.google.firebase.crashlytics"),
    "Facebook Ads" to listOf("com.facebook.ads"),
    "Facebook Analytics" to listOf("com.facebook.appevents"),
    "Facebook Login" to listOf("com.facebook.login"),
    "AppsFlyer" to listOf("com.appsflyer"),
    "Adjust" to listOf("com.adjust.sdk"),
    "Branch" to listOf("io.branch"),
    "Mixpanel" to listOf("com.mixpanel"),
    "Flurry" to listOf("com.flurry"),
    "Segment" to listOf("com.segment.analytics"),
    "Amplitude" to listOf("com.amplitude"),
    "OneSignal" to listOf("com.onesignal"),
    "Braze (Appboy)" to listOf("com.appboy", "com.braze"),
    "Unity3d Ads" to listOf("com.unity3d.ads"),
    "AppLovin" to listOf("com.applovin"),
    "ironSource" to listOf("com.ironsource"),
    "Vungle" to listOf("com.vungle"),
    "Chartboost" to listOf("com.chartboost"),
    "InMobi" to listOf("com.inmobi"),
    "MoPub" to listOf("com.mopub"),
    "Tapjoy" to listOf("com.tapjoy"),
    "Kochava" to listOf("com.kochava"),
    "Singular" to listOf("com.singular.sdk"),
    "Yandex AppMetrica" to listOf("com.yandex.metrica"),
    "Microsoft Visual Studio App Center" to listOf("com.microsoft.appcenter"),
    "Bugsnag" to listOf("com.bugsnag"),
    "New Relic" to listOf("com.newrelic"),
    "Countly" to listOf("ly.count.android"),
    "Localytics" to listOf("com.localytics"),
    "Adobe Experience Cloud" to listOf("com.adobe.mobile"),
    "comScore" to listOf("com.comscore"),
    "StartApp" to listOf("com.startapp"),
)

/** The name of the tracker whose package prefix starts [str] (a dotted name or a `Lcom/x/Y;` DEX type descriptor), else null. */
fun matchTracker(str: String): String? {
    val first = str.firstOrNull() ?: return null
    if (first != 'L' && first !in 'a'..'z') return null
    val dotted = if (first == 'L' && str.indexOf('/') > 0) str.substring(1).replace('/', '.') else str
    for ((name, prefixes) in KnownTrackerSignatures) {
        if (prefixes.any { dotted == it || dotted.startsWith("$it.") }) return name
    }
    return null
}

/** The distinct tracker names found in [strings], sorted. */
fun findTrackers(strings: Iterable<String>): Set<String> {
    val found = sortedSetOf<String>()
    for (s in strings) matchTracker(s)?.let { found += it }
    return found
}

// ---- Native libraries ----

private const val ElfClass32 = 1
private const val ElfClass64 = 2
private const val ElfLittleEndian = 1

/** ELF `e_machine` and `EI_CLASS` expected for an Android ABI folder; null for an ABI this does not know. */
private fun expectedElf(abi: String): Pair<Int, Int>? = when (abi) {
    "arm64-v8a" -> 183 to ElfClass64
    "armeabi-v7a", "armeabi" -> 40 to ElfClass32
    "x86" -> 3 to ElfClass32
    "x86_64" -> 62 to ElfClass64
    "riscv64" -> 243 to ElfClass64
    else -> null
}

/** Strings that instrumentation and repackaging frameworks leave in a native library (Frida, LSPatch, Xposed). */
val SuspiciousNativeMarkers: List<String> = listOf("frida-agent", "frida-gadget", "lspatch", "XposedBridge")

/** File names of commercial packers that hide the real code (Qihoo 360 Jiagu, Bangcle/SecNeo, Tencent Legu, Ijiami). */
val PackerLibraryNames: List<String> = listOf("libjiagu", "libsecexe", "libsecmain", "libdexhelper", "libshella", "libshellx", "libexecmain", "libijiami")

enum class NativeVerdict { Valid, InvalidElf, Suspicious }

/** [detail] is the English line for the terminal; [code], [param] and [param2] let the screen say it in the user's language. */
data class NativeFinding(
    val verdict: NativeVerdict,
    val detail: String,
    val exportsJniOnLoad: Boolean = false,
    val code: IssueCode = IssueCode.Generic,
    val param: String? = null,
    val param2: String? = null,
)

/**
 * Judges one native library. [entryPath] is `lib/<abi>/<name>.so`; [bytes] is the file (or its first part). Not an ELF
 * file, the wrong class or the wrong machine for its folder: [NativeVerdict.InvalidElf] (a disguised payload).
 * A valid ELF that carries a marker of instrumentation, or whose name is a known packer: [NativeVerdict.Suspicious].
 * `JNI_OnLoad` alone is normal and only noted.
 */
fun inspectNativeLibrary(entryPath: String, bytes: ByteArray): NativeFinding {
    val parts = entryPath.replace('\\', '/').trimStart('/').split('/')
    val abi = parts.getOrNull(1).orEmpty()
    val name = parts.last()
    if (bytes.size < 20 || bytes[0] != 0x7F.toByte() || bytes[1] != 'E'.code.toByte() ||
        bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
    ) {
        return NativeFinding(NativeVerdict.InvalidElf, "$name is not an ELF file", code = IssueCode.NativeNotElf, param = name)
    }
    val elfClass = bytes[4].toInt()
    val data = bytes[5].toInt()
    val machine = (bytes[18].toInt() and 0xFF) or ((bytes[19].toInt() and 0xFF) shl 8)
    if (elfClass != ElfClass32 && elfClass != ElfClass64 || data != ElfLittleEndian) {
        return NativeFinding(NativeVerdict.InvalidElf, "$name has an invalid ELF header", code = IssueCode.NativeBadHeader, param = name)
    }
    expectedElf(abi)?.let { (expectedMachine, expectedClass) ->
        if (machine != expectedMachine || elfClass != expectedClass) {
            return NativeFinding(NativeVerdict.InvalidElf, "$name does not match its $abi folder", code = IssueCode.NativeAbiMismatch, param = name, param2 = abi)
        }
    }
    val jni = containsSubarray(bytes, "JNI_OnLoad".toByteArray(Charsets.US_ASCII))
    val lower = name.lowercase(Locale.US)
    PackerLibraryNames.firstOrNull { lower.startsWith(it) }?.let {
        return NativeFinding(NativeVerdict.Suspicious, "$name looks like a packer library", jni, IssueCode.NativePacker, name)
    }
    SuspiciousNativeMarkers.firstOrNull { containsSubarray(bytes, it.toByteArray(Charsets.US_ASCII)) }?.let {
        return NativeFinding(NativeVerdict.Suspicious, "$name contains the marker \"$it\"", jni, IssueCode.NativeMarker, name, it)
    }
    return NativeFinding(NativeVerdict.Valid, name, jni)
}

private const val NativeHeadBytes = 64 * 1024
private const val NativeChunkBytes = 256 * 1024

/** Libraries are read to the end; past this many bytes the rest is not searched (a library that large is not a hook agent). */
private const val MaxNativeStreamBytes = 1024L * 1024L * 1024L

/**
 * Like [inspectNativeLibrary] but reads the WHOLE library from [input] in chunks, so a marker after the first 16 MiB (large
 * Unity or game libraries) is still found without holding the library in memory. The ELF header checks use the first 64 KiB.
 */
fun inspectNativeLibraryStream(entryPath: String, input: java.io.InputStream): NativeFinding {
    val head = readBoundedBytes(input, NativeHeadBytes)
    val first = inspectNativeLibrary(entryPath, head)
    if (first.verdict != NativeVerdict.Valid) return first
    val name = entryPath.replace('\\', '/').substringAfterLast('/')
    val markers = SuspiciousNativeMarkers.map { it to it.toByteArray(Charsets.US_ASCII) }
    val keep = markers.maxOf { it.second.size } - 1
    var tail = head.copyOfRange(maxOf(0, head.size - keep), head.size)
    val buffer = ByteArray(NativeChunkBytes)
    var scanned = head.size.toLong()
    while (scanned < MaxNativeStreamBytes) {
        val read = input.read(buffer)
        if (read < 0) break
        if (read == 0) continue
        scanned += read
        val window = tail + buffer.copyOf(read)
        markers.firstOrNull { containsSubarray(window, it.second) }?.let {
            return NativeFinding(NativeVerdict.Suspicious, "$name contains the marker \"${it.first}\"", first.exportsJniOnLoad, IssueCode.NativeMarker, name, it.first)
        }
        tail = window.copyOfRange(maxOf(0, window.size - keep), window.size)
    }
    return first
}
