package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Random
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** 0.9.50: payload candidates, entropy, incomplete scans, bundles, adware boundaries, native libraries. */
class ShieldScanTest {
    private fun dex(strings: List<String>): ByteArray {
        val count = strings.size
        val offsets = mutableListOf<Int>()
        val data = ByteArrayOutputStream()
        for (str in strings) {
            offsets += 0x70 + count * 4 + data.size()
            data.write(str.length)
            data.write(str.toByteArray(Charsets.UTF_8))
            data.write(0)
        }
        val total = 0x70 + count * 4 + data.size()
        val out = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
        out.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII))
        out.putInt(0)
        out.put(ByteArray(20))
        out.putInt(total)
        out.putInt(0x70)
        out.putInt(0x12345678)
        out.putInt(0); out.putInt(0); out.putInt(0)
        out.putInt(count)
        out.putInt(0x70)
        while (out.position() < 0x70) out.put(0.toByte())
        for (o in offsets) out.putInt(o)
        out.put(data.toByteArray())
        return out.array()
    }

    private fun apk(entries: Map<String, ByteArray>): File {
        val file = File.createTempFile("shield_scan_", ".apk")
        file.deleteOnExit()
        ZipOutputStream(FileOutputStream(file)).use { zip ->
            for ((name, bytes) in entries) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return file
    }

    private fun random(size: Int, seed: Long = 7L): ByteArray = ByteArray(size).also { Random(seed).nextBytes(it) }

    private fun elf(machine: Int, elfClass: Int, tail: ByteArray = ByteArray(0)): ByteArray {
        val head = ByteArray(64)
        head[0] = 0x7F; head[1] = 'E'.code.toByte(); head[2] = 'L'.code.toByte(); head[3] = 'F'.code.toByte()
        head[4] = elfClass.toByte(); head[5] = 1; head[6] = 1
        head[18] = (machine and 0xFF).toByte(); head[19] = (machine shr 8).toByte()
        return head + tail
    }

    private val cleanDex = dex(listOf("com.example.app", "kotlin.jvm.internal.Intrinsics"))

    // ---- Entropy ----

    @Test fun entropyIsZeroForConstantDataAndNearEightForRandomData() {
        assertEquals(0.0, shannonEntropy(ByteArray(4096)), 0.0001)
        assertEquals(8.0, shannonEntropy(ByteArray(4096) { it.toByte() }), 0.0001)
        assertTrue(shannonEntropy(random(4096)) > 7.5)
        val text = "home\nindex\nsettings\nabout\n".repeat(200).toByteArray()
        assertTrue(shannonEntropy(text) < 4.5)
        assertEquals(0.0, shannonEntropy(ByteArray(0)), 0.0)
    }

    // ---- Payload candidates: false negatives that used to pass (audit F18) ----

    @Test fun anEncryptedBlobWithAGenericNameIsFlaggedInAssetsRawAndTheRoot() {
        for (name in listOf("assets/data.bin", "assets/blob", "res/raw/payload.dat", "a.dat", "assets/sub/x.tmp")) {
            val issue = StaticAnalyzer.checkAssetPayload(name, random(4096))
            assertNotNull(name, issue)
            assertEquals(name, ShieldWarningReason.DropperDetected, issue?.reason)
            assertEquals(name, IssueCode.EncryptedBlob, issue?.code)
            assertEquals(name, name, issue?.param)
        }
    }

    @Test fun highEntropyDataThatIsNotAGenericBlobIsNotFlagged() {
        // Models, media, fonts, databases and archives are high-entropy by nature.
        for (name in listOf("assets/model.tflite", "assets/song.mp3", "assets/voice.ogg", "assets/pack.pak", "assets/app.db", "assets/font.ttf", "assets/img.webp")) {
            assertNull(name, StaticAnalyzer.checkAssetPayload(name, random(4096)))
        }
        // A blob in a place where payloads are not hidden.
        assertNull(StaticAnalyzer.checkAssetPayload("res/drawable/x.bin", random(4096)))
        assertNull(StaticAnalyzer.checkAssetPayload("lib/arm64-v8a/data.bin", random(4096)))
        // Low entropy and short files are not blobs.
        assertNull(StaticAnalyzer.checkAssetPayload("assets/data.bin", ByteArray(4096)))
        assertNull(StaticAnalyzer.checkAssetPayload("assets/data.bin", "plain text ".repeat(400).toByteArray().copyOf(4096)))
        assertNull(StaticAnalyzer.checkAssetPayload("assets/data.bin", random(3000)))
    }

    @Test fun aDexOrElfHiddenInAResourceOrTheRootIsFlagged() {
        val hidden = dex(listOf("com.hidden.payload"))
        for (name in listOf("res/drawable/x.png", "res/xml/y.xml", "assets/z.jpg", "kept.png")) {
            val issue = StaticAnalyzer.checkAssetPayload(name, hidden)
            assertEquals(name, IssueCode.HiddenDex, issue?.code)
        }
        val native = StaticAnalyzer.checkAssetPayload("res/drawable/x.png", elf(183, 2))
        assertEquals(IssueCode.HiddenNative, native?.code)
        // An ordinary PNG header is fine, and so is an ELF under lib/.
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) + ByteArray(100)
        assertNull(StaticAnalyzer.checkAssetPayload("res/drawable/x.png", png))
        assertNull(StaticAnalyzer.checkAssetPayload("lib/arm64-v8a/libx.so", elf(183, 2)))
    }

    @Test fun everyEntryWherePayloadsHideIsInspectedAndTheManifestIsNot() {
        assertTrue(StaticAnalyzer.isPayloadScanEntry("assets/a.bin"))
        assertTrue(StaticAnalyzer.isPayloadScanEntry("res/drawable/a.png"))
        assertTrue(StaticAnalyzer.isPayloadScanEntry("a.dat"))
        assertFalse(StaticAnalyzer.isPayloadScanEntry("AndroidManifest.xml"))
        assertFalse(StaticAnalyzer.isPayloadScanEntry("resources.arsc"))
        assertFalse(StaticAnalyzer.isPayloadScanEntry("META-INF/CERT.RSA"))
        assertFalse(StaticAnalyzer.isPayloadScanEntry("lib/arm64-v8a/libx.so"))
        assertFalse(StaticAnalyzer.isPayloadScanEntry("kotlin/kotlin.kotlin_builtins"))
    }

    @Test fun anApkScanFindsABlobInAnyPlaceAndTheSameBlobAsAModelIsFine() {
        val file = apk(mapOf("classes.dex" to cleanDex, "assets/data.bin" to random(8192)))
        try {
            val result = StaticAnalyzer.analyzeApkFile(file)
            assertEquals(listOf(IssueCode.EncryptedBlob), result.issues.map { it.code })
        } finally {
            file.delete()
        }
        val model = apk(mapOf("classes.dex" to cleanDex, "assets/model.tflite" to random(8192)))
        try {
            assertTrue(StaticAnalyzer.analyzeApkFile(model).issues.isEmpty())
        } finally {
            model.delete()
        }
    }

    // ---- "index" is not a DEX (audit F17) ----

    @Test fun aTextFileWhoseLineEndsInDexIsNotADexPayload() {
        val text = "home\nindex\nYandex\ncodex\nRolodex\n".toByteArray()
        assertNull(StaticAnalyzer.checkAssetPayload("assets/words.txt", text))
        assertNull(StaticAnalyzer.checkAssetPayload("res/raw/names.txt", "dex\n".toByteArray()))
        // The complete header still counts, at the start and with leading junk.
        assertEquals(IssueCode.HiddenDex, StaticAnalyzer.checkAssetPayload("assets/p", dex(listOf("a")))?.code)
        assertEquals(IssueCode.HiddenDex, StaticAnalyzer.checkAssetPayload("assets/p", ByteArray(100) + dex(listOf("a")))?.code)
        assertTrue(hasFullDexHeaderAt(dex(listOf("a")), 0))
        assertFalse(hasFullDexHeaderAt("dex\nabc\u0000".toByteArray(Charsets.US_ASCII), 0))
        assertFalse(hasFullDexHeaderAt("dex\n035x".toByteArray(Charsets.US_ASCII), 0))
    }

    // ---- Nested archives: never clean when they cannot be read (audit F18, decision 8) ----

    private class PatternStream(private val size: Long, private val head: ByteArray) : InputStream() {
        private var pos = 0L

        override fun read(): Int {
            if (pos >= size) return -1
            val value = if (pos < head.size) head[pos.toInt()].toInt() and 0xFF else 0
            pos++
            return value
        }

        override fun read(buffer: ByteArray, off: Int, len: Int): Int {
            if (pos >= size) return -1
            val count = minOf(len.toLong(), size - pos).toInt()
            for (i in 0 until count) buffer[off + i] = if (pos + i < head.size) head[(pos + i).toInt()] else 0
            pos += count
            return count
        }
    }

    @Test fun aNestedArchiveBiggerThanTheLimitIsAnIncompleteScanNotClean() {
        val big = PatternStream(MaxNestedZipBytes + 1L, ZipMagic)
        val issue = StaticAnalyzer.checkAssetPayload("assets/big.zip", ZipMagic, big)
        assertEquals(ShieldWarningReason.ScanIncomplete, issue?.reason)
        assertEquals(IssueCode.NestedTooBig, issue?.code)
        assertEquals("assets/big.zip", issue?.param)
    }

    @Test fun aNestedArchiveThatCannotBeReadIsAnIncompleteScan() {
        val garbage = ZipMagic + ByteArray(50) { 9 }
        val issue = StaticAnalyzer.checkAssetPayload("assets/broken.zip", garbage, garbage.inputStream())
        assertEquals(ShieldWarningReason.ScanIncomplete, issue?.reason)
        assertEquals(IssueCode.NestedUnreadable, issue?.code)
    }

    @Test fun aReadableNestedArchiveWithoutCodeIsStillClean() {
        val inner = ByteArrayOutputStream().also { out ->
            ZipOutputStream(out).use { zip ->
                zip.putNextEntry(ZipEntry("config.json"))
                zip.write("{}".toByteArray())
                zip.closeEntry()
            }
        }.toByteArray()
        assertNull(StaticAnalyzer.checkAssetPayload("assets/data.zip", inner, inner.inputStream()))
    }

    // ---- Incomplete scans (audit F19, F20, decision 8) ----

    @Test fun aTruncatedDexInTheApkIsAnIncompleteScan() {
        val whole = dex((1..30).map { "com.example.Class$it" })
        val file = apk(mapOf("classes.dex" to whole.copyOf(whole.size / 2)))
        try {
            val result = StaticAnalyzer.analyzeApkFile(file)
            assertEquals(1, result.dexCount)
            assertEquals(0, result.dexInspected)
            val issue = result.issues.single()
            assertEquals(ShieldWarningReason.ScanIncomplete, issue.reason)
            assertEquals(IssueCode.DexUnreadable, issue.code)
            assertEquals("classes.dex", issue.param)
        } finally {
            file.delete()
        }
    }

    @Test fun aDexBiggerThanTheLimitIsAnIncompleteScan() {
        val file = apk(mapOf("classes.dex" to ByteArray(MaxDexSizeBytes + 10)))
        try {
            val issue = StaticAnalyzer.analyzeApkFile(file).issues.single()
            assertEquals(IssueCode.DexTooBig, issue.code)
            assertEquals(ShieldWarningReason.ScanIncomplete, issue.reason)
        } finally {
            file.delete()
        }
    }

    @Test fun anArchiveThatIsNotAZipOrIsMissingIsAnIncompleteScan() {
        val notZip = File.createTempFile("not_zip_", ".apk").apply { writeBytes(ByteArray(300) { 5 }); deleteOnExit() }
        assertEquals(IssueCode.ArchiveUnreadable, StaticAnalyzer.analyzeApkFile(notZip).issues.single().code)
        val missing = File(notZip.parentFile, "does_not_exist_${System.nanoTime()}.apk")
        val result = StaticAnalyzer.analyzeApkFile(missing)
        assertEquals(IssueCode.ApkMissing, result.issues.single().code)
        assertEquals(0, result.dexInspected)
    }

    @Test fun aCompleteCleanApkReportsEveryDexInspected() {
        val file = apk(mapOf("classes.dex" to cleanDex, "classes2.dex" to cleanDex))
        try {
            val result = StaticAnalyzer.analyzeApkFile(file)
            assertEquals(2, result.dexCount)
            assertEquals(2, result.dexInspected)
            assertTrue(result.issues.isEmpty())
        } finally {
            file.delete()
        }
    }

    // ---- Bundles: which APK did it (decision 7) ----

    @Test fun inABundleEachFindingNamesTheApkAndAMissingFileIsIncomplete() {
        val base = apk(mapOf("classes.dex" to cleanDex))
        val split = apk(mapOf("classes.dex" to cleanDex, "assets/data.bin" to random(8192)))
        try {
            val bundle = ExtractedBundle(
                format = PackageFormat.Apks,
                packageName = "com.example.app",
                baseApkName = "base.apk",
                apks = listOf(
                    ExtractedFile("base.apk", "base.apk", base.length(), base),
                    ExtractedFile("split_x.apk", "split_x.apk", split.length(), split),
                    ExtractedFile("gone.apk", "gone.apk", 10L, null),
                ),
                obbs = emptyList(),
            )
            val result = StaticAnalyzer.analyzeApkOrBundle(File("unused"), bundle, emptyList(), "com.example.app")
            val blob = result.issues.single { it.code == IssueCode.EncryptedBlob }
            assertEquals("split_x.apk", blob.apk)
            val missing = result.issues.single { it.code == IssueCode.ApkMissing }
            assertEquals("gone.apk", missing.apk)
            assertEquals(ShieldWarningReason.ScanIncomplete, missing.reason)
            assertEquals(2, result.dexCount)
            // A single APK has no inner name.
            assertNull(StaticAnalyzer.analyzeApkFile(split).issues.single().apk)
        } finally {
            base.delete()
            split.delete()
        }
    }

    // ---- Adware (audit F16) ----

    @Test fun adwareIsMatchedOnTypesAtAPackageBoundaryOnly() {
        assertEquals("com.waps", StaticAnalyzer.matchAdwareSdk("Lcom/waps/Foo;"))
        assertEquals("com.waps", StaticAnalyzer.matchAdwareSdk("[Lcom/waps/Foo;"))
        assertEquals("com.youmi", StaticAnalyzer.matchAdwareSdk("Lcom/youmi/Ads;"))
        // A different package that starts with the same letters.
        assertNull(StaticAnalyzer.matchAdwareSdk("Lcom/wapsomething/Foo;"))
        assertNull(StaticAnalyzer.matchAdwareSdk("Lcom/youmixyz/Ads;"))
        // A plain string, such as a tracker list in an ad blocker, is not a type.
        assertNull(StaticAnalyzer.matchAdwareSdk("com.airpush.sdk"))
        assertNull(StaticAnalyzer.matchAdwareSdk("blocked: Lcom/airpush/Foo; and others"))
        assertNull(StaticAnalyzer.matchAdwareSdk(""))
        assertNull(StaticAnalyzer.matchAdwareSdk("L;"))
    }

    @Test fun currentAdNetworksAreTrackersNotAdware() {
        assertNull(StaticAnalyzer.matchAdwareSdk("Lcom/startapp/sdk/Ads;"))
        assertNull(StaticAnalyzer.matchAdwareSdk("Lcom/startapp/android/publish/Ads;"))
        assertNull(StaticAnalyzer.matchAdwareSdk("Lcom/secneo/apkwrapper/Foo;"))
        assertEquals("StartApp", matchTracker("Lcom/startapp/sdk/Ads;"))
        assertTrue(KnownAdwareSdkPrefixes.none { it.startsWith("com.startapp") || it == "com.secneo" })
    }

    @Test fun aListOfTrackerNamesAsTextIsNotAdware() {
        val file = apk(mapOf("classes.dex" to dex(listOf("com.airpush", "com.waps.Ad", "Exodus tracker list: com.leadbolt"))))
        try {
            assertTrue(StaticAnalyzer.analyzeApkFile(file).issues.isEmpty())
        } finally {
            file.delete()
        }
    }

    // ---- Native libraries (audit F22) ----

    @Test fun anEmptyOrFillerLibraryIsYellowNotRed() {
        val file = apk(mapOf("classes.dex" to cleanDex, "lib/arm64-v8a/libdummy.so" to ByteArray(0)))
        try {
            val issue = StaticAnalyzer.analyzeApkFile(file).issues.single()
            assertEquals(ShieldWarningReason.InvalidNativeLibrary, issue.reason)
            assertEquals(SecuritySeverity.Yellow, issue.reason.severity())
            assertEquals(IssueCode.NativeNotElf, issue.code)
            assertEquals("libdummy.so", issue.param)
        } finally {
            file.delete()
        }
    }

    @Test fun aMarkerAfterTheFirstSixteenMegabytesOfALibraryIsStillFound() {
        val padding = ByteArray(17 * 1024 * 1024)
        val library = elf(183, 2, padding + "xx frida-gadget xx".toByteArray() + ByteArray(10))
        val finding = inspectNativeLibraryStream("lib/arm64-v8a/libbig.so", library.inputStream())
        assertEquals(NativeVerdict.Suspicious, finding.verdict)
        assertEquals(IssueCode.NativeMarker, finding.code)
        assertEquals("frida-gadget", finding.param2)
        // A marker split across two read chunks is found too.
        val splitAt = 256 * 1024 + 64 * 1024 - 5
        val split = elf(183, 2, ByteArray(splitAt - 64) + "XposedBridge".toByteArray() + ByteArray(1000))
        assertEquals(NativeVerdict.Suspicious, inspectNativeLibraryStream("lib/arm64-v8a/libsplit.so", split.inputStream()).verdict)
        // A clean library of the same size stays valid.
        assertEquals(NativeVerdict.Valid, inspectNativeLibraryStream("lib/arm64-v8a/libok.so", elf(183, 2, padding).inputStream()).verdict)
    }

    @Test fun nativeFindingsCarryACodeForTheScreen() {
        assertEquals(IssueCode.NativeAbiMismatch, inspectNativeLibrary("lib/arm64-v8a/libx.so", elf(40, 1)).code)
        assertEquals("arm64-v8a", inspectNativeLibrary("lib/arm64-v8a/libx.so", elf(40, 1)).param2)
        assertEquals(IssueCode.NativePacker, inspectNativeLibrary("lib/arm64-v8a/libjiagu_64.so", elf(183, 2)).code)
        assertEquals(IssueCode.NativeMarker, inspectNativeLibrary("lib/arm64-v8a/libhook.so", elf(183, 2, "lspatch".toByteArray())).code)
    }
}
