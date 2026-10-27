package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Unit tests for [StaticAnalyzer] (Phase 4c: Local static code analysis / Deep Scan). */
class StaticAnalyzerTest {

    private fun buildTestDex(strings: List<String>): ByteArray {
        val stringIdsCount = strings.size
        val stringIdsOff = 0x70 // 112 bytes standard header
        val stringDataOffsets = mutableListOf<Int>()

        val dataStream = ByteArrayOutputStream()
        for (str in strings) {
            val currentOffset = stringIdsOff + (stringIdsCount * 4) + dataStream.size()
            stringDataOffsets += currentOffset
            // Write uleb128 of length
            var len = str.length
            while (true) {
                val byte = len and 0x7F
                len = len ushr 7
                if (len == 0) {
                    dataStream.write(byte)
                    break
                } else {
                    dataStream.write(byte or 0x80)
                }
            }
            dataStream.write(str.toByteArray(Charsets.UTF_8))
            dataStream.write(0) // null terminator
        }

        val totalSize = stringIdsOff + (stringIdsCount * 4) + dataStream.size()
        val out = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)

        // Magic "dex\n035\0"
        out.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII))
        // Checksum at 0x08
        out.putInt(0)
        // SHA-1 signature 20 bytes at 0x0C
        out.put(ByteArray(20))
        // file_size at 0x20
        out.putInt(totalSize)
        // header_size at 0x24
        out.putInt(0x70)
        // endian_tag at 0x28
        out.putInt(0x12345678)
        // link_size & link_off (0x2C, 0x30)
        out.putInt(0); out.putInt(0)
        // map_off at 0x34
        out.putInt(0)
        // string_ids_size at 0x38
        out.putInt(stringIdsCount)
        // string_ids_off at 0x3C
        out.putInt(stringIdsOff)

        // Pad rest of header to 0x70 bytes
        while (out.position() < 0x70) {
            out.put(0.toByte())
        }

        // String IDs offset table
        for (offset in stringDataOffsets) {
            out.putInt(offset)
        }

        // String data items
        out.put(dataStream.toByteArray())
        return out.array()
    }

    private fun createTestApk(entries: Map<String, ByteArray>): File {
        val temp = File.createTempFile("test_static_scan_", ".apk")
        temp.deleteOnExit()
        ZipOutputStream(FileOutputStream(temp)).use { zos ->
            for ((name, bytes) in entries) {
                val entry = ZipEntry(name)
                zos.putNextEntry(entry)
                zos.write(bytes)
                zos.closeEntry()
            }
        }
        return temp
    }

    // 1. Clean DEX passes inspection
    @Test
    fun cleanDexPassesInspection() {
        val cleanStrings = listOf(
            "app.gogogadget",
            "androidx.compose.runtime.Composable",
            "com.google.android.gms.ads.AdView",
            "kotlin.jvm.internal.Intrinsics",
        )
        val dex = buildTestDex(cleanStrings)
        val parsed = StaticAnalyzer.parseDexStrings(dex)
        for (str in cleanStrings) {
            assertTrue("Expected string '$str' in parsed DEX strings", parsed.contains(str))
        }
        val issues = StaticAnalyzer.inspectDexStrings(parsed, "classes.dex")
        assertTrue("Clean DEX must pass inspection with 0 issues, but found: $issues", issues.isEmpty())
    }

    // 2. DEX containing DexClassLoader triggers DropperDetected
    @Test
    fun dexContainingDexClassLoaderTriggersDropperDetected() {
        val dex = buildTestDex(listOf("com.modded.app", "dalvik.system.DexClassLoader"))
        val strings = StaticAnalyzer.parseDexStrings(dex)
        val issues = StaticAnalyzer.inspectDexStrings(strings, "classes.dex")
        assertEquals(1, issues.size)
        assertEquals(ShieldWarningReason.DropperDetected, issues[0].reason)
        assertTrue(issues[0].detail.contains("DexClassLoader"))
    }

    @Test
    fun dexContainingInMemoryDexClassLoaderTriggersDropperDetected() {
        val dex = buildTestDex(listOf("com.modded.app", "dalvik.system.InMemoryDexClassLoader"))
        val strings = StaticAnalyzer.parseDexStrings(dex)
        val issues = StaticAnalyzer.inspectDexStrings(strings, "classes.dex")
        assertEquals(1, issues.size)
        assertEquals(ShieldWarningReason.DropperDetected, issues[0].reason)
        assertTrue(issues[0].detail.contains("InMemoryDexClassLoader"))
    }

    @Test
    fun dexContainingPathClassLoaderWithDynamicPathTriggersDropperDetected() {
        val dex = buildTestDex(listOf(
            "com.modded.app",
            "dalvik.system.PathClassLoader",
            "/data/data/com.modded.app/files/payload.dex",
        ))
        val strings = StaticAnalyzer.parseDexStrings(dex)
        val issues = StaticAnalyzer.inspectDexStrings(strings, "classes.dex")
        assertEquals(1, issues.size)
        assertEquals(ShieldWarningReason.DropperDetected, issues[0].reason)
        assertTrue(issues[0].detail.contains("PathClassLoader"))
    }

    // 3. APK containing hidden executable payload in assets triggers DropperDetected
    @Test
    fun apkContainingHiddenDexPayloadInAssetsTriggersDropperDetected() {
        val cleanDex = buildTestDex(listOf("com.example.app"))
        val hiddenDex = buildTestDex(listOf("com.hidden.payload"))
        val apk = createTestApk(mapOf(
            "classes.dex" to cleanDex,
            "assets/payload.bin" to hiddenDex,
        ))
        try {
            val result = StaticAnalyzer.analyzeApkFile(apk)
            assertEquals(1, result.dexCount)
            val dropperIssue = result.issues.firstOrNull { it.reason == ShieldWarningReason.DropperDetected }
            assertNotNull("Expected DropperDetected issue for hidden payload in assets", dropperIssue)
            assertTrue(dropperIssue?.detail?.contains("assets/payload.bin") == true)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun apkContainingHiddenZipPayloadInRawTriggersDropperDetected() {
        val cleanDex = buildTestDex(listOf("com.example.app"))
        val zipWithPayload = ByteArrayOutputStream().apply {
            ZipOutputStream(this).use { zos ->
                zos.putNextEntry(ZipEntry("classes.dex"))
                zos.write(buildTestDex(listOf("com.hidden.in.zip")))
                zos.closeEntry()
            }
        }.toByteArray()
        val apk = createTestApk(mapOf(
            "classes.dex" to cleanDex,
            "res/raw/extra.dat" to zipWithPayload,
        ))
        try {
            val result = StaticAnalyzer.analyzeApkFile(apk)
            val dropperIssue = result.issues.firstOrNull { it.reason == ShieldWarningReason.DropperDetected }
            assertNotNull("Expected DropperDetected issue for hidden ZIP with classes.dex in res/raw", dropperIssue)
            assertTrue(dropperIssue?.detail?.contains("res/raw/extra.dat") == true)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun lottieAnimationAssetDoesNotTriggerDropperDetected() {
        val cleanDex = buildTestDex(listOf("com.example.app"))
        // Create a real ZIP archive representing a .lottie animation containing data.json
        val lottieZip = ByteArrayOutputStream().apply {
            ZipOutputStream(this).use { zos ->
                zos.putNextEntry(ZipEntry("data.json"))
                zos.write("{\"v\":\"5.5.2\",\"fr\":60,\"ip\":0,\"op\":60,\"w\":500,\"h\":500}".toByteArray(Charsets.UTF_8))
                zos.closeEntry()
            }
        }.toByteArray()

        val apk = createTestApk(mapOf(
            "classes.dex" to cleanDex,
            "assets/animations/loading.lottie" to lottieZip,
            "res/raw/animation.lottie" to lottieZip,
        ))
        try {
            val result = StaticAnalyzer.analyzeApkFile(apk)
            val dropperIssues = result.issues.filter { it.reason == ShieldWarningReason.DropperDetected }
            assertTrue(
                "Lottie animation assets must not trigger DropperDetected, but found: $dropperIssues",
                dropperIssues.isEmpty(),
            )
        } finally {
            apk.delete()
        }
    }

    @Test
    fun genericZipDataAssetWithoutExecutableDoesNotTriggerDropperDetected() {
        val cleanDex = buildTestDex(listOf("com.example.app"))
        val dataZip = ByteArrayOutputStream().apply {
            ZipOutputStream(this).use { zos ->
                zos.putNextEntry(ZipEntry("config.json"))
                zos.write("{\"key\":\"value\"}".toByteArray(Charsets.UTF_8))
                zos.closeEntry()
            }
        }.toByteArray()

        val apk = createTestApk(mapOf(
            "classes.dex" to cleanDex,
            "assets/data/bundle.zip" to dataZip,
        ))
        try {
            val result = StaticAnalyzer.analyzeApkFile(apk)
            val dropperIssues = result.issues.filter { it.reason == ShieldWarningReason.DropperDetected }
            assertTrue("Generic data ZIP must not trigger DropperDetected, but found: $dropperIssues", dropperIssues.isEmpty())
        } finally {
            apk.delete()
        }
    }

    @Test
    fun apkContainingDirectDexFileInAssetsTriggersDropperDetected() {
        val cleanDex = buildTestDex(listOf("com.example.app"))
        val apk = createTestApk(mapOf(
            "classes.dex" to cleanDex,
            "assets/sub/hidden.dex" to byteArrayOf(1, 2, 3),
        ))
        try {
            val result = StaticAnalyzer.analyzeApkFile(apk)
            val dropperIssue = result.issues.firstOrNull { it.reason == ShieldWarningReason.DropperDetected }
            assertNotNull("Expected DropperDetected issue for .dex in assets", dropperIssue)
        } finally {
            apk.delete()
        }
    }

    // 4. DEX containing known adware SDK string triggers AdwareDetected
    @Test
    fun dexContainingKnownAdwareSdkStringTriggersAdwareDetected() {
        val dex = buildTestDex(listOf("com.example.app", "com.airpush.android.Airpush"))
        val strings = StaticAnalyzer.parseDexStrings(dex)
        val issues = StaticAnalyzer.inspectDexStrings(strings, "classes.dex")
        assertEquals(1, issues.size)
        assertEquals(ShieldWarningReason.AdwareDetected, issues[0].reason)
        assertTrue(issues[0].detail.contains("com.airpush"))
    }

    @Test
    fun dexContainingMultipleKnownAdwareSdksTriggersAdwareDetected() {
        val sdks = listOf(
            "com.leadbolt.AdController",
            "com.kuguo.push.Main",
            "com.startapp.android.publish.Ads",
            "com.secneo.apkwrapper",
            "com.adwhirl.AdWhirlLayout",
        )
        for (sdk in sdks) {
            val dex = buildTestDex(listOf("com.example.app", sdk))
            val strings = StaticAnalyzer.parseDexStrings(dex)
            val issues = StaticAnalyzer.inspectDexStrings(strings, "classes.dex")
            assertTrue("Expected AdwareDetected for $sdk", issues.any { it.reason == ShieldWarningReason.AdwareDetected })
        }
    }

    @Test
    fun dexWithSlashDescriptorFormatMatchesAdwareSdk() {
        val dex = buildTestDex(listOf("Lcom/airpush/android/AdView;"))
        val strings = StaticAnalyzer.parseDexStrings(dex)
        val issues = StaticAnalyzer.inspectDexStrings(strings, "classes.dex")
        assertTrue(issues.any { it.reason == ShieldWarningReason.AdwareDetected })
    }

    // 5. Dangerous permission combination triggers AbusivePermissions
    @Test
    fun dangerousPermissionCombinationTriggersAbusivePermissions() {
        // Overlay + REQUEST_INSTALL_PACKAGES
        val overlayIssue = StaticAnalyzer.checkAbusivePermissions(
            permissions = listOf("REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW"),
            packageName = "com.utility.calculator",
        )
        assertNotNull(overlayIssue)
        assertEquals(ShieldWarningReason.AbusivePermissions, overlayIssue?.reason)
        assertTrue(overlayIssue?.detail?.contains("SYSTEM_ALERT_WINDOW") == true)

        // SMS + REQUEST_INSTALL_PACKAGES in non-SMS app
        val smsIssue = StaticAnalyzer.checkAbusivePermissions(
            permissions = listOf("android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.RECEIVE_SMS"),
            packageName = "com.puzzle.game",
        )
        assertNotNull(smsIssue)
        assertEquals(ShieldWarningReason.AbusivePermissions, smsIssue?.reason)
        assertTrue(smsIssue?.detail?.contains("SMS") == true)

        // REQUEST_INSTALL_PACKAGES requested by non-store application
        val nonStoreIssue = StaticAnalyzer.checkAbusivePermissions(
            permissions = listOf("REQUEST_INSTALL_PACKAGES"),
            packageName = "com.cool.flashlight",
        )
        assertNotNull(nonStoreIssue)
        assertEquals(ShieldWarningReason.SelfUpdaterPermission, nonStoreIssue?.reason)
        assertTrue(nonStoreIssue?.detail?.contains("com.cool.flashlight") == true)

        // App store requesting REQUEST_INSTALL_PACKAGES passes clean
        val storeResult = StaticAnalyzer.checkAbusivePermissions(
            permissions = listOf("REQUEST_INSTALL_PACKAGES"),
            packageName = "org.fdroid.fdroid",
        )
        assertNull("Package manager / app store should not trigger AbusivePermissions without overlay/SMS", storeResult)

        // Normal app with standard permissions passes clean
        val cleanResult = StaticAnalyzer.checkAbusivePermissions(
            permissions = listOf("INTERNET", "ACCESS_NETWORK_STATE", "WAKE_LOCK"),
            packageName = "com.clean.mod",
        )
        assertNull(cleanResult)
    }

    // 6. Clean mod APK passes inspection
    @Test
    fun cleanModApkPassesInspection() {
        val cleanDex1 = buildTestDex(listOf("com.modded.music", "androidx.compose.ui.Modifier", "com.google.android.gms.ads.AdView"))
        val cleanDex2 = buildTestDex(listOf("kotlinx.coroutines.Dispatchers", "okhttp3.OkHttpClient"))
        val apk = createTestApk(mapOf(
            "classes.dex" to cleanDex1,
            "classes2.dex" to cleanDex2,
            "assets/fonts/Roboto.ttf" to byteArrayOf(0, 1, 0, 0),
            "assets/config.json" to "{\"premium\": true}".toByteArray(Charsets.UTF_8),
        ))
        try {
            val result = StaticAnalyzer.analyzeApkFile(
                apkFile = apk,
                permissions = listOf("INTERNET", "ACCESS_NETWORK_STATE", "POST_NOTIFICATIONS"),
                packageName = "com.modded.music",
            )
            assertEquals(2, result.dexCount)
            assertTrue("Clean mod APK with multiple DEX files should have 0 issues, but had: ${result.issues}", result.issues.isEmpty())
        } finally {
            apk.delete()
        }
    }

    // 7. Robustness against corrupt or truncated DEX
    @Test
    fun corruptOrTruncatedDexDoesNotCrash() {
        val truncated = byteArrayOf(0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00)
        val strings = StaticAnalyzer.parseDexStrings(truncated)
        assertTrue(strings.isEmpty())

        val invalidMagic = ByteArray(200) { 0xAA.toByte() }
        val strings2 = StaticAnalyzer.parseDexStrings(invalidMagic)
        assertTrue(strings2.isEmpty())
    }
}
