package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipException
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class PackageBundleTest {
    private fun makeZip(vararg entries: Pair<String, ByteArray>): ByteArray {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            for ((name, data) in entries) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(data)
                zos.closeEntry()
            }
        }
        return baos.toByteArray()
    }

    private fun inspectBytes(bytes: ByteArray, destDir: File? = null): PackageInspectResult =
        inspectAndExtractPackage(ByteArrayInputStream(bytes), destDir)

    // ---- Format detection & extraction ----

    @Test fun detectsSingleApkByRootAndroidManifest() {
        val zip = makeZip(
            "AndroidManifest.xml" to ByteArray(64) { 1 },
            "classes.dex" to ByteArray(128) { 2 },
            "resources.arsc" to ByteArray(32) { 3 },
        )
        val res = inspectBytes(zip)
        assertTrue(res is PackageInspectResult.Valid)
        val bundle = (res as PackageInspectResult.Valid).bundle
        assertEquals(PackageFormat.SingleApk, bundle.format)
        assertTrue(bundle.apks.isEmpty())
        assertTrue(bundle.obbs.isEmpty())
    }

    @Test fun handlesStoredZipEntryWithDataDescriptorAndSingleApkWithoutExtracting() {
        val arscBytes = ByteArray(128) { 0x42 }
        val manifestBytes = ByteArray(64) { 0x11 }
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            val storedEntry = ZipEntry("resources.arsc").apply {
                method = ZipEntry.STORED
                size = arscBytes.size.toLong()
                compressedSize = arscBytes.size.toLong()
                crc = CRC32().apply { update(arscBytes) }.value
            }
            zos.putNextEntry(storedEntry)
            zos.write(arscBytes)
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zos.write(manifestBytes)
            zos.closeEntry()
        }
        val zipBytes = baos.toByteArray()
        // Set general purpose bit 3 (0x08 data descriptor) on the STORED Local File Header (offset 6),
        // reproducing real Android zipflinger APKs that make ZipInputStream throw ZipException.
        zipBytes[6] = (zipBytes[6].toInt() or 0x08).toByte()

        var zisFailed = false
        try {
            ZipInputStream(ByteArrayInputStream(zipBytes)).use { it.nextEntry }
        } catch (e: ZipException) {
            zisFailed = true
        }
        assertTrue(zisFailed)

        val tempDir = Files.createTempDirectory("single_apk_stored").toFile()
        try {
            val sourceFile = File(tempDir, "source.pkg")
            sourceFile.writeBytes(zipBytes)
            val res = inspectAndExtractPackage(sourceFile, tempDir)
            assertTrue(res is PackageInspectResult.Valid)
            val bundle = (res as PackageInspectResult.Valid).bundle
            assertEquals(PackageFormat.SingleApk, bundle.format)
            assertTrue(bundle.apks.isEmpty())
            assertTrue(bundle.obbs.isEmpty())
            assertEquals(listOf("source.pkg"), tempDir.list()?.toList().orEmpty())
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test fun detectsXapkWithManifestJsonAndObb() {
        val manifest = """
            {
              "xapk_version": 2,
              "package_name": "com.example.game",
              "name": "Example Game",
              "split_apks": [
                { "file": "com.example.game.apk", "id": "base" },
                { "file": "config.arm64_v8a.apk", "id": "config.arm64_v8a" }
              ],
              "expansions": [
                {
                  "file": "Android/obb/com.example.game/main.12.com.example.game.obb",
                  "install_location": "EXTERNAL_STORAGE",
                  "install_path": "Android/obb/com.example.game/main.12.com.example.game.obb"
                }
              ]
            }
        """.trimIndent().toByteArray()
        val zip = makeZip(
            "manifest.json" to manifest,
            "com.example.game.apk" to ByteArray(200) { 0x11 },
            "config.arm64_v8a.apk" to ByteArray(100) { 0x22 },
            "Android/obb/com.example.game/main.12.com.example.game.obb" to ByteArray(300) { 0x33 },
        )
        val res = inspectBytes(zip)
        assertTrue(res is PackageInspectResult.Valid)
        val bundle = (res as PackageInspectResult.Valid).bundle
        assertEquals(PackageFormat.Xapk, bundle.format)
        assertEquals("com.example.game", bundle.packageName)
        assertEquals("com.example.game.apk", bundle.findBaseApk()?.name)
        assertEquals(2, bundle.apks.size)
        assertEquals(1, bundle.obbs.size)
        assertEquals("main.12.com.example.game.obb", bundle.obbs.single().name)
        assertEquals("com.example.game", bundle.obbs.single().obbPackageName)
        assertEquals(300L, bundle.obbs.single().size)
    }

    @Test fun detectsApkmWithInfoJson() {
        val info = """{"pname": "org.mozilla.firefox", "versioncode": "20159"}""".toByteArray()
        val zip = makeZip(
            "info.json" to info,
            "base.apk" to ByteArray(150),
            "split_config.arm64_v8a.apk" to ByteArray(80),
            "split_config.xxhdpi.apk" to ByteArray(40),
        )
        val res = inspectBytes(zip)
        assertTrue(res is PackageInspectResult.Valid)
        val bundle = (res as PackageInspectResult.Valid).bundle
        assertEquals(PackageFormat.Apkm, bundle.format)
        assertEquals("org.mozilla.firefox", bundle.packageName)
        assertEquals(3, bundle.apks.size)
        assertEquals("base.apk", bundle.findBaseApk()?.name)
    }

    @Test fun detectsApksAndSplitZipWithoutJsonMetadata() {
        val zip = makeZip(
            "splits/base-master.apk" to ByteArray(500),
            "splits/base-arm64_v8a.apk" to ByteArray(250),
            "splits/base-xxhdpi.apk" to ByteArray(100),
        )
        val res = inspectBytes(zip)
        assertTrue(res is PackageInspectResult.Valid)
        val bundle = (res as PackageInspectResult.Valid).bundle
        assertEquals(PackageFormat.Apks, bundle.format)
        assertNull(bundle.packageName)
        assertEquals(3, bundle.apks.size)
        assertEquals("base-master.apk", bundle.findBaseApk()?.name)
    }

    @Test fun rejectsNonZipOrProprietaryEncryptedBytes() {
        for (raw in listOf(
            "APKM\u0000\u0001encrypted".toByteArray(),
            "not a zip file at all".toByteArray(),
            byteArrayOf(0x01, 0x02),
        )) {
            val res = inspectBytes(raw)
            assertEquals(PackageInspectResult.Invalid(R.string.reason_not_zip_or_proprietary), res)
        }
    }

    @Test fun rejectsEmptyStreamWithReadFileError() {
        assertEquals(PackageInspectResult.Invalid(R.string.err_read_file), inspectBytes(ByteArray(0)))
    }

    @Test fun rejectsPlainZipWithoutManifestOrApks() {
        val zip = makeZip(
            "readme.txt" to "hello world".toByteArray(),
            "images/logo.png" to ByteArray(20),
        )
        assertEquals(PackageInspectResult.Invalid(R.string.reason_parse), inspectBytes(zip))
    }

    @Test fun guardsAgainstZipSlipPathTraversal() {
        val tempDir = Files.createTempDirectory("bundle_test").toFile()
        try {
            val malicious = makeZip(
                "../../evil.apk" to ByteArray(32),
            )
            assertEquals(PackageInspectResult.Invalid(R.string.reason_parse), inspectBytes(malicious, tempDir))
            var threw = false
            try {
                resolveSafeZipEntry(tempDir, "../outside.apk")
            } catch (e: SecurityException) {
                threw = true
            }
            assertTrue(threw)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test fun extractsBundleFilesToTempDirectory() {
        val tempDir = Files.createTempDirectory("bundle_extract").toFile()
        try {
            val zip = makeZip(
                "base.apk" to byteArrayOf(1, 2, 3, 4, 5),
                "config.arm64_v8a.apk" to byteArrayOf(6, 7, 8),
                "Android/obb/com.test.app/main.1.com.test.app.obb" to byteArrayOf(9, 10),
            )
            val res = inspectBytes(zip, tempDir)
            assertTrue(res is PackageInspectResult.Valid)
            val bundle = (res as PackageInspectResult.Valid).bundle
            assertEquals(2, bundle.apks.size)
            assertEquals(1, bundle.obbs.size)
            assertTrue(bundle.apks.all { it.file?.exists() == true })
            assertTrue(bundle.obbs.single().file?.exists() == true)
            assertEquals(5L, bundle.apks.first { it.name == "base.apk" }.file?.length())
            assertEquals("com.test.app", bundle.packageName)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    // ---- Smart split filtering ----

    private fun fakeApk(name: String, size: Long = 100L) =
        ExtractedFile(entryPath = name, name = name, size = size, bytes = ByteArray(size.toInt()))

    @Test fun filtersAbiSplitsPickingFirstSupportedDeviceAbi() {
        val apks = listOf(
            fakeApk("base.apk", 500),
            fakeApk("split_feature_camera.apk", 200),
            fakeApk("split_config.armeabi_v7a.apk", 100),
            fakeApk("split_config.arm64_v8a.apk", 120),
            fakeApk("split_config.x86_64.apk", 130),
        )
        val arm64Device = DeviceSpec(
            abis = listOf("arm64-v8a", "armeabi-v7a", "armeabi"),
            densityDpi = 480,
            languages = setOf("en"),
        )
        val res = filterSplits(apks, arm64Device)
        assertTrue(res is SplitFilterResult.Selected)
        val names = (res as SplitFilterResult.Selected).splits.map { it.name }
        assertEquals(listOf("base.apk", "split_feature_camera.apk", "split_config.arm64_v8a.apk"), names)
    }

    @Test fun fallsBackToSecondSupportedDeviceAbiWhenFirstIsAbsent() {
        val apks = listOf(
            fakeApk("base.apk"),
            fakeApk("config.armeabi-v7a.apk"),
            fakeApk("config.x86.apk"),
        )
        val device = DeviceSpec(
            abis = listOf("arm64-v8a", "armeabi-v7a"),
            densityDpi = 320,
            languages = setOf("en"),
        )
        val res = filterSplits(apks, device)
        assertTrue(res is SplitFilterResult.Selected)
        val names = (res as SplitFilterResult.Selected).splits.map { it.name }
        assertEquals(listOf("base.apk", "config.armeabi-v7a.apk"), names)
    }

    @Test fun rejectsBundleWhenNoAbiSplitMatchesTargetDevice() {
        val apks = listOf(
            fakeApk("base.apk"),
            fakeApk("split_config.arm64_v8a.apk"),
        )
        val armv7OnlyDevice = DeviceSpec(
            abis = listOf("armeabi-v7a", "armeabi"),
            densityDpi = 320,
            languages = setOf("en"),
        )
        val res = filterSplits(apks, armv7OnlyDevice)
        assertEquals(SplitFilterResult.IncompatibleAbi(R.string.reason_abis), res)
    }

    @Test fun selectsClosestDensityBucketPlusAnydpi() {
        val apks = listOf(
            fakeApk("base.apk"),
            fakeApk("split_config.mdpi.apk"),
            fakeApk("split_config.hdpi.apk"),
            fakeApk("split_config.xhdpi.apk"),
            fakeApk("split_config.xxhdpi.apk"),
            fakeApk("split_config.xxxhdpi.apk"),
            fakeApk("split_config.anydpi.apk"),
        )
        val device440 = DeviceSpec(abis = listOf("arm64-v8a"), densityDpi = 440, languages = setOf("en"))
        val res = filterSplits(apks, device440)
        assertTrue(res is SplitFilterResult.Selected)
        val names = (res as SplitFilterResult.Selected).splits.map { it.name }
        assertEquals(listOf("base.apk", "split_config.xxhdpi.apk", "split_config.anydpi.apk"), names)
    }

    @Test fun selectsMatchingLanguageSplitsPlusEnglishFallback() {
        val apks = listOf(
            fakeApk("base.apk"),
            fakeApk("split_config.en.apk"),
            fakeApk("split_config.pt.apk"),
            fakeApk("split_config.fr.apk"),
            fakeApk("split_config.de.apk"),
        )
        val ptDevice = DeviceSpec(abis = listOf("arm64-v8a"), densityDpi = 480, languages = setOf("pt", "en"))
        val res = filterSplits(apks, ptDevice)
        assertTrue(res is SplitFilterResult.Selected)
        val names = (res as SplitFilterResult.Selected).splits.map { it.name }
        assertEquals(listOf("base.apk", "split_config.en.apk", "split_config.pt.apk"), names)
    }

    @Test fun parsesDevicePropertiesAndFallsBackGracefully() {
        assertEquals(
            listOf("arm64-v8a", "armeabi-v7a", "armeabi"),
            parseAbis("arm64-v8a,armeabi-v7a,armeabi\n", listOf("x86_64")),
        )
        assertEquals(listOf("x86_64"), parseAbis("  \n", listOf("x86_64")))
        assertEquals(420, parseDensityDpi("420\n", "", 320))
        assertEquals(480, parseDensityDpi("", "Physical density: 420\nOverride density: 480\n", 320))
        assertEquals(320, parseDensityDpi("", "not a number", 320))
        assertEquals(setOf("pt", "es", "en"), parseLanguages("pt-PT", "es_ES", "en"))
    }

    // ---- Session commands, progress aggregation & abandon on failure ----

    @Test fun sessionCommandAppendsTheUserInstallReasonOnlyWhenAsked() {
        assertEquals(
            "pm install-create -r -d --bypass-low-target-sdk-block --install-reason 4",
            createSessionCommand(bypass = true, userInstall = true),
        )
        assertEquals("pm install-create -r -d --install-reason 4", createSessionCommand(bypass = false, userInstall = true))
        assertEquals("pm install-create -r -d --bypass-low-target-sdk-block", createSessionCommand(bypass = true, userInstall = false))
        assertEquals("pm install-create -r -d", createSessionCommand(bypass = false, userInstall = false))
    }

    @Test fun sessionAndObbCommandsAreFormattedAndSanitized() {
        assertEquals(
            "pm install-create -r -d --bypass-low-target-sdk-block",
            createSessionCommand(bypass = true),
        )
        assertEquals("pm install-create -r -d", createSessionCommand(bypass = false))
        assertEquals(123456L, parseSessionId("Success: created install session [123456]\r\n"))
        assertNull(parseSessionId("Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]"))
        assertNull(parseSessionId("Failure [not Success: [999]]"))
        assertEquals(
            "cmd package install-write -S 4096 123456 base.apk -",
            installWriteCommand(123456L, "splits/base.apk", 4096L),
        )
        assertEquals(
            "cmd package install-write -S 1024 123456 bad_name_1_.apk -",
            installWriteCommand(123456L, "../bad name(1).apk", 1024L),
        )
        assertEquals(
            "mkdir -p '/sdcard/Android/obb/com.example.game'",
            obbMkdirCommand("com.example.game"),
        )
        assertEquals(
            "head -c 8192 > '/sdcard/Android/obb/com.example.game/main.1.com.example.game.obb'",
            obbWriteCommand("com.example.game", "Android/obb/com.example.game/main.1.com.example.game.obb", 8192L),
        )
        assertEquals("pm install-commit 123456", installCommitCommand(123456L))
        assertEquals("pm install-abandon 123456", installAbandonCommand(123456L))
    }

    private class FakeAdbClient(
        private val onShell: (String) -> String = { "Success" },
        private val onWrite: (command: String, size: Long, input: InputStream, onProgress: (Long) -> Unit) -> String =
            { _, size, input, onProgress ->
                val buf = ByteArray(64)
                var total = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    onProgress(total)
                }
                assertEquals(size, total)
                "Success: streamed $size bytes"
            },
    ) : AdbClient {
        val shellCommands = mutableListOf<String>()
        val writeCommands = mutableListOf<Pair<String, Long>>()

        override val isConnected: Boolean = true
        override fun pair(host: String, port: Int, code: String) = Unit
        override fun connect(host: String, port: Int) = Unit
        override fun disconnect() = Unit

        override fun shell(command: String): String {
            shellCommands += command
            return onShell(command)
        }

        override fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit): String {
            writeCommands += command to size
            return onWrite(command, size, apk, onProgress)
        }
    }

    @Test fun multiSplitAndObbSessionAggregatesProgressAndCommits() {
        val adb = FakeAdbClient(
            onShell = { cmd ->
                when {
                    cmd == DisableAdbVerifyCommand || cmd == DisableVerifierCommand -> ""
                    cmd == "pm install-create -r -d --bypass-low-target-sdk-block" ->
                        "Error: Unknown option: --bypass-low-target-sdk-block"
                    cmd == "pm install-create -r -d" ->
                        "Success: created install session [778899]"
                    cmd.startsWith("mkdir -p") -> ""
                    cmd == "pm install-commit 778899" -> "Success"
                    else -> "Failure [UNEXPECTED: $cmd]"
                }
            },
            onWrite = { cmd, size, input, onProgress ->
                val drained = input.readBytes().size.toLong()
                assertEquals(size, drained)
                onProgress(size / 2)
                onProgress(size)
                if (cmd.startsWith("head -c")) "" else "Success: streamed $size bytes"
            },
        )
        val splits = listOf(
            fakeApk("base.apk", 200),
            fakeApk("split_config.arm64_v8a.apk", 100),
        )
        val obbs = listOf(
            ExtractedFile(
                entryPath = "Android/obb/com.example.game/main.1.com.example.game.obb",
                name = "main.1.com.example.game.obb",
                size = 100,
                obbPackageName = "com.example.game",
                bytes = ByteArray(100),
            ),
        )
        val progressEvents = mutableListOf<Pair<Long, Long>>()
        val result = installBundleSession(
            adb = adb,
            splits = splits,
            obbs = obbs,
            packageName = "com.example.game",
            onProgress = { sent, total -> progressEvents += sent to total },
        )
        assertTrue(result.success)
        assertEquals(
            listOf(
                DisableAdbVerifyCommand,
                DisableVerifierCommand,
                "pm install-create -r -d --bypass-low-target-sdk-block",
                "pm install-create -r -d",
                "pm install-commit 778899",
                "mkdir -p '/sdcard/Android/obb/com.example.game'",
            ),
            adb.shellCommands,
        )
        assertEquals(
            listOf(
                "cmd package install-write -S 200 778899 base.apk -" to 200L,
                "cmd package install-write -S 100 778899 split_config.arm64_v8a.apk -" to 100L,
                "head -c 100 > '/sdcard/Android/obb/com.example.game/main.1.com.example.game.obb'" to 100L,
            ),
            adb.writeCommands,
        )
        // Progress advances monotonically from 0 to 400 (0% to 99% via installPhase).
        assertEquals(0L to 400L, progressEvents.first())
        assertEquals(400L to 400L, progressEvents.last())
        for (i in 0 until progressEvents.size - 1) {
            assertTrue(progressEvents[i].first <= progressEvents[i + 1].first)
        }
        assertEquals(PhaseState(InstallPhase.Installing, 99), installPhase(400L, 400L, answered = false))
    }

    @Test fun abandonsSessionWhenInstallWriteFails() {
        val adb = FakeAdbClient(
            onShell = { cmd ->
                when {
                    cmd.startsWith("pm install-create") -> "Success: created install session [4242]"
                    cmd == "pm install-abandon 4242" -> "Success"
                    else -> "Failure [UNEXPECTED]"
                }
            },
            onWrite = { cmd, _, _, _ ->
                if ("split_config" in cmd) "Failure [INSTALL_PARSE_FAILED_NOT_APK]"
                else "Success: streamed 100 bytes"
            },
        )
        val splits = listOf(fakeApk("base.apk", 100), fakeApk("split_config.arm64_v8a.apk", 100))
        val result = installBundleSession(adb, splits)
        assertFalse(result.success)
        assertEquals("Failure [INSTALL_PARSE_FAILED_NOT_APK]", result.line)
        assertTrue("pm install-abandon 4242" in adb.shellCommands)
        assertFalse(adb.shellCommands.any { it.startsWith("pm install-commit") })
    }

    @Test fun abandonsSessionWhenExceptionIsThrownDuringStreaming() {
        val adb = FakeAdbClient(
            onShell = { cmd ->
                when {
                    cmd.startsWith("pm install-create") -> "Success: created install session [5555]"
                    cmd == "pm install-abandon 5555" -> "Success"
                    else -> "Success"
                }
            },
            onWrite = { _, _, _, _ -> throw IOException("Stream closed") },
        )
        var caught = false
        try {
            installBundleSession(adb, listOf(fakeApk("base.apk", 100)))
        } catch (e: IOException) {
            caught = true
        }
        assertTrue(caught)
        assertTrue("pm install-abandon 5555" in adb.shellCommands)
    }

    // ---- Package name, OBB destination and zip caps ----

    private fun obbFile(name: String, pkg: String?, claims: List<String> = emptyList()) = ExtractedFile(
        entryPath = "Android/obb/${pkg ?: "x"}/$name",
        name = name,
        size = 10,
        obbPackageName = pkg,
        otherPackageClaims = claims,
        bytes = ByteArray(10),
    )

    @Test fun packageNameComesFromBaseApkNotJson() {
        val honest = checkBundlePackage("com.real.app", listOf("com.real.app", "com.real.app"), claimed = "com.real.app")
        assertEquals(BundlePackageCheck("com.real.app", null), honest)
        assertEquals(BundlePackageCheck("com.real.app", null), checkBundlePackage("com.real.app", listOf("com.real.app"), claimed = null))
        // The JSON names another app: the name stays the APK's, and the bundle is flagged.
        val lying = checkBundlePackage("com.real.app", listOf("com.real.app"), claimed = "com.victim.app")
        assertEquals("com.real.app", lying.packageName)
        assertEquals(BundlePackageProblem.Mismatch, lying.problem)
        // Unreadable base APK: no name at all, never the JSON's.
        assertEquals(BundlePackageCheck(null, BundlePackageProblem.Unreadable), checkBundlePackage(null, listOf(null), claimed = "com.victim.app"))
    }

    @Test fun bundleWithMismatchedSplitPackageIsBlocked() {
        val mixed = checkBundlePackage("com.real.app", listOf("com.real.app", "com.other.app"), claimed = null)
        assertEquals(BundlePackageProblem.Mismatch, mixed.problem)
        val configSplits = checkBundlePackage("com.real.app", listOf("com.real.app", null), claimed = null)
        assertNull(configSplits.problem)
        assertEquals("com.real.app", configSplits.packageName)
    }

    @Test fun obbMismatchedPackageIsRejected() {
        val pkg = "com.example.game"
        val cases = listOf(
            listOf(obbFile("main.1.$pkg.obb", "com.victim.app")),
            listOf(obbFile("main.1.com.victim.app.obb", pkg)),
            listOf(obbFile("main.1.$pkg.obb", pkg, claims = listOf("com.victim.app"))),
        )
        for (obbs in cases) {
            val adb = FakeAdbClient()
            val result = installBundleSession(adb, listOf(fakeApk("base.apk", 100)), obbs, packageName = pkg)
            assertFalse(result.success)
            assertTrue(ObbOtherAppCode in result.line)
            assertEquals(R.string.reason_obb_other_app, pmFailure(result.line).reason)
            // Nothing was written, not even a session.
            assertTrue(adb.shellCommands.isEmpty())
            assertTrue(adb.writeCommands.isEmpty())
        }
        // No known package at all: the OBB cannot be placed anywhere.
        val none = FakeAdbClient()
        assertFalse(installBundleSession(none, listOf(fakeApk("base.apk", 100)), listOf(obbFile("main.1.$pkg.obb", pkg)), packageName = null).success)
        assertTrue(none.shellCommands.isEmpty())
        assertTrue(obbBelongsTo(obbFile("main.1.$pkg.obb", pkg), pkg))
    }

    @Test fun obbWrittenOnlyAfterCommit() {
        val pkg = "com.example.game"
        val events = mutableListOf<String>()
        fun adbWith(commit: String, obbWrite: String) = FakeAdbClient(
            onShell = { cmd ->
                events += cmd
                when {
                    cmd.startsWith("pm install-create") -> "Success: created install session [31]"
                    cmd == "pm install-commit 31" -> commit
                    else -> ""
                }
            },
            onWrite = { cmd, size, input, _ ->
                events += cmd.substringBefore(' ')
                input.readBytes()
                if (cmd.startsWith("head -c")) obbWrite else "Success: streamed $size bytes"
            },
        )
        val obbs = listOf(obbFile("main.1.$pkg.obb", pkg))

        // Success: install-write, commit, and only then the OBB directory and file.
        val ok = installBundleSession(adbWith("Success", ""), listOf(fakeApk("base.apk", 100)), obbs, packageName = pkg)
        assertTrue(ok.success)
        assertNull(ok.obbFailure)
        val commitAt = events.indexOf("pm install-commit 31")
        assertTrue(commitAt > 0)
        assertTrue(events.indexOfFirst { it.startsWith("mkdir") } > commitAt)
        assertTrue(events.indexOfFirst { it == "head" } > commitAt)

        // A failed commit writes nothing.
        events.clear()
        val failed = installBundleSession(adbWith("Failure [INSTALL_FAILED_VERSION_DOWNGRADE]", ""), listOf(fakeApk("base.apk", 100)), obbs, packageName = pkg)
        assertFalse(failed.success)
        assertTrue(events.none { it.startsWith("mkdir") || it == "head" })

        // The install worked but the OBB write failed: still reported, never a silent success.
        events.clear()
        val partial = installBundleSession(adbWith("Success", "head: write error"), listOf(fakeApk("base.apk", 100)), obbs, packageName = pkg)
        assertTrue(partial.success)
        assertEquals("head: write error", partial.obbFailure)
    }

    @Test fun zipEntryCountAndUncompressedSizeCapped() {
        assertTrue(zipWithinLimits(MaxZipEntries, MaxZipUncompressedBytes))
        assertFalse(zipWithinLimits(MaxZipEntries + 1, 10L))
        assertFalse(zipWithinLimits(10, MaxZipUncompressedBytes + 1))
        assertFalse(zipWithinLimits(10, -1L))
        assertTrue(hasRoomToExtract(freeBytes = 1_050L, extractBytes = 1_000L))
        assertFalse(hasRoomToExtract(freeBytes = 1_049L, extractBytes = 1_000L))

        fun zipWithEntries(count: Int) = makeZip(
            "AndroidManifest.xml" to "manifest".toByteArray(),
            *Array(count - 1) { i -> "res/f$i" to ByteArray(1) },
        )
        val ok = inspectBytes(zipWithEntries(MaxZipEntries))
        assertTrue(ok is PackageInspectResult.Valid)
        val tooMany = inspectBytes(zipWithEntries(MaxZipEntries + 1))
        assertEquals(PackageInspectResult.Invalid(R.string.reason_too_complex), tooMany)
    }

    @Test fun allRegexPatternsEscapeLiteralBracesAndBracketsForAndroidIcu() {
        val classes = listOf(
            Class.forName("app.gogogadget.PackageBundleKt"),
            Class.forName("app.gogogadget.AdbLogicKt"),
            Class.forName("app.gogogadget.InstallLogicKt"),
            Class.forName("app.gogogadget.SecurityShieldKt"),
            Class.forName("app.gogogadget.VirusTotalKt"),
            Class.forName("app.gogogadget.StaticAnalyzerKt"),
        )
        val regexPatterns = mutableListOf<Pair<String, String>>()
        for (cls in classes) {
            for (field in cls.declaredFields) {
                field.isAccessible = true
                when (val value = field.get(null)) {
                    is Regex -> regexPatterns += "${cls.simpleName}.${field.name}" to value.pattern
                    is Iterable<*> -> {
                        for ((idx, item) in value.withIndex()) {
                            if (item is Pair<*, *> && item.second is Regex) {
                                regexPatterns += "${cls.simpleName}.${field.name}[$idx]" to (item.second as Regex).pattern
                            }
                        }
                    }
                }
            }
        }
        assertTrue(regexPatterns.size >= 25)
        for ((name, pattern) in regexPatterns) {
            assertFalse(
                "Pattern $name ($pattern) contains unescaped brace or bracket for Android ICU",
                hasUnescapedAndroidIcuBraceOrBracket(pattern),
            )
        }
        assertTrue(hasUnescapedAndroidIcuBraceOrBracket("""\{[^{}]*}"""))
        assertTrue(hasUnescapedAndroidIcuBraceOrBracket("""Success:.*\[(\d+)]"""))
        assertFalse(hasUnescapedAndroidIcuBraceOrBracket("""\{[^{}]*\}"""))
        assertFalse(hasUnescapedAndroidIcuBraceOrBracket("""Success:.*\[(\d+)\]"""))
    }

    private fun hasUnescapedAndroidIcuBraceOrBracket(pattern: String): Boolean {
        val quantifierBody = Regex("""^\d+(?:,\d*)?$""")
        var i = 0
        var inCharClass = false
        var classStart = -1
        while (i < pattern.length) {
            val c = pattern[i]
            if (c == '\\') {
                i += 2
                continue
            }
            if (inCharClass) {
                if (c == ']' && i > classStart + 1 && !(i == classStart + 2 && pattern[classStart + 1] == '^')) {
                    inCharClass = false
                }
                i++
                continue
            }
            when (c) {
                '[' -> {
                    inCharClass = true
                    classStart = i
                    i++
                }
                ']', '}' -> return true
                '{' -> {
                    val close = pattern.indexOf('}', i + 1)
                    if (close < 0) return true
                    val body = pattern.substring(i + 1, close)
                    if (!quantifierBody.matches(body)) return true
                    i = close + 1
                }
                else -> i++
            }
        }
        return inCharClass
    }
}
