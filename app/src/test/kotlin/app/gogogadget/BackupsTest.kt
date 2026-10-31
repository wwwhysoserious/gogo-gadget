package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.InputStream
import java.nio.file.Files

/** Unit tests for Phase 5: Auto-backup & 1-tap Reversion ([BackupManager]). */
class BackupsTest {

    private class FakeBackupAdbClient(
        private val pmPathOutput: String,
        private val apkPayload: ByteArray = "test_apk_content".toByteArray(Charsets.UTF_8),
    ) : AdbClient {
        val shellCommands = mutableListOf<String>()
        val pulledPaths = mutableListOf<String>()

        override val isConnected: Boolean = true
        override fun pair(host: String, port: Int, code: String) = Unit
        override fun connect(host: String, port: Int) = Unit
        override fun disconnect() = Unit

        override fun shell(command: String): String {
            shellCommands += command
            return pmPathOutput
        }

        override fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit): String =
            "Success"

        override fun pull(remotePath: String, destFile: File): Boolean {
            pulledPaths += remotePath
            destFile.parentFile?.mkdirs()
            destFile.writeBytes(apkPayload)
            return true
        }
    }

    // 1. Parsing pm path output
    @Test
    fun parsePmPathOutputHandlesSingleAndSplitApks() {
        val backupManager = BackupManager(backupsDir = File("/tmp"))

        val singleOutput = "package:/data/app/~~xyz123/com.example.app-abc456/base.apk\n"
        val singlePaths = backupManager.parsePmPathOutput(singleOutput)
        assertEquals(listOf("/data/app/~~xyz123/com.example.app-abc456/base.apk"), singlePaths)

        val splitOutput = """
            package:/data/app/~~xyz123/com.example.split-abc456/base.apk
            package:/data/app/~~xyz123/com.example.split-abc456/split_config.arm64_v8a.apk
            package:/data/app/~~xyz123/com.example.split-abc456/split_config.xxhdpi.apk
        """.trimIndent()
        val splitPaths = backupManager.parsePmPathOutput(splitOutput)
        assertEquals(3, splitPaths.size)
        assertEquals("/data/app/~~xyz123/com.example.split-abc456/base.apk", splitPaths[0])
        assertEquals("/data/app/~~xyz123/com.example.split-abc456/split_config.arm64_v8a.apk", splitPaths[1])
        assertEquals("/data/app/~~xyz123/com.example.split-abc456/split_config.xxhdpi.apk", splitPaths[2])

        // Empty output or error
        assertTrue(backupManager.parsePmPathOutput("").isEmpty())
        assertTrue(backupManager.parsePmPathOutput("Error: package not found").isEmpty())
    }

    // 2. Metadata save and read
    @Test
    fun metadataSaveAndReadPreservesAllFields() {
        val tempDir = Files.createTempDirectory("backup_meta_test_").toFile()
        try {
            val backupManager = BackupManager(backupsDir = tempDir)
            val meta = BackupMetadata(
                packageName = "app.test.demo",
                appName = "Demo App",
                versionCode = 42L,
                versionName = "2.1.0",
                timestamp = 1729900000000L,
                apkFileNames = listOf("base.apk", "split_config.arm64_v8a.apk"),
            )

            val pkgDir = File(tempDir, meta.packageName)
            pkgDir.mkdirs()
            backupManager.saveMetadata(pkgDir, meta)

            val readBack = backupManager.readMetadata(pkgDir)
            assertNotNull(readBack)
            assertEquals("app.test.demo", readBack?.packageName)
            assertEquals("Demo App", readBack?.appName)
            assertEquals(42L, readBack?.versionCode)
            assertEquals("2.1.0", readBack?.versionName)
            assertEquals(1729900000000L, readBack?.timestamp)
            assertEquals(listOf("base.apk", "split_config.arm64_v8a.apk"), readBack?.apkFileNames)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    // 3. Backup creation, 1-version limit (overwrite), and deletion
    @Test
    fun backupCreationEnforcesOneVersionLimitPerPackage() {
        val tempDir = Files.createTempDirectory("backup_lifecycle_test_").toFile()
        try {
            val backupManager = BackupManager(backupsDir = tempDir)
            val adb = FakeBackupAdbClient(
                pmPathOutput = "package:/data/app/com.test.pkg/base.apk\n",
                apkPayload = ByteArray(1024) { 0x55 },
            )

            // Step 1: Create initial backup of v10
            val installedV10 = InstalledAppInfo(
                versionCode = 10L,
                sigSha256 = "dummy_sig",
                appName = "Test App",
                versionName = "1.0",
            )
            val item1 = backupManager.createBackup(adb, "com.test.pkg", installedV10, "tv", "TV")
            assertNotNull(item1)
            assertEquals(10L, item1?.versionCode)
            assertEquals("Test App", item1?.appName)
            assertEquals(1024L, item1?.totalSizeBytes)

            val list1 = backupManager.listBackups()
            assertEquals(1, list1.size)
            assertEquals(10L, list1[0].versionCode)

            // Step 2: Create second backup of v11 for the same package -> Must overwrite v10 (1 version limit!)
            val installedV11 = InstalledAppInfo(
                versionCode = 11L,
                sigSha256 = "dummy_sig",
                appName = "Test App",
                versionName = "1.1",
            )
            val item2 = backupManager.createBackup(adb, "com.test.pkg", installedV11, "tv", "TV")
            assertNotNull(item2)
            assertEquals(11L, item2?.versionCode)

            val list2 = backupManager.listBackups()
            assertEquals("Only 1 version per package must be retained", 1, list2.size)
            assertEquals(11L, list2[0].versionCode)
            assertEquals("1.1", list2[0].versionName)

            // Step 3: Deletion frees storage
            val deleted = backupManager.deleteBackup("tv", "com.test.pkg")
            assertTrue(deleted)
            val list3 = backupManager.listBackups()
            assertTrue("Backups list should be empty after deletion", list3.isEmpty())
            assertFalse(File(tempDir, "tv/com.test.pkg").exists())
        } finally {
            tempDir.deleteRecursively()
        }
    }

    // 4. Restore / Revert command generation
    @Test
    fun revertCommandsIncludeDowngradeAndReinstallFlags() {
        val singleCmd = streamInstallCommand(size = 5000L, bypass = true, userInstall = false)
        assertTrue("Single APK revert must use -r", singleCmd.contains(" -r "))
        assertTrue("Single APK revert must use -d for downgrade", singleCmd.contains(" -d"))

        val sessionCreateCmd = createSessionCommand(bypass = true, userInstall = false)
        assertTrue("Session revert must use -r", sessionCreateCmd.contains(" -r "))
        assertTrue("Session revert must use -d for downgrade", sessionCreateCmd.contains(" -d"))
    }
}
