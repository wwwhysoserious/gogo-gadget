package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.InputStream
import java.nio.file.Files

class BackupDevicesTest {
    private fun item(pkg: String, device: String, name: String? = null) = AppBackupItem(
        packageName = pkg, appName = pkg, versionName = "1", versionCode = 1L,
        timestamp = 0L, totalSizeBytes = 1L, apkFiles = emptyList<File>(), deviceId = device, deviceName = name,
    )

    private class PullingAdb : AdbClient {
        override val isConnected = true
        override fun pair(host: String, port: Int, code: String) = Unit
        override fun connect(host: String, port: Int) = Unit
        override fun disconnect() = Unit
        override fun shell(command: String) = "package:/data/app/x/base.apk\n"
        override fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit) = "Success"
        override fun pull(remotePath: String, destFile: File): Boolean {
            destFile.parentFile?.mkdirs()
            destFile.writeBytes(ByteArray(8) { 1 })
            return true
        }
    }

    @Test fun deviceIdPrefersLocalThenKeyThenHost() {
        assertEquals("local", backupDeviceId(true, "abc", "127.0.0.1"))
        assertEquals("abc-1", backupDeviceId(false, "abc-1", "192.168.1.5"))
        assertEquals("192.168.1.5", backupDeviceId(false, null, "192.168.1.5"))
        assertEquals("_unassigned", backupDeviceId(false, null, ".."))
    }

    @Test fun deviceIdCannotEscapeTheBackupsFolder() {
        val id = backupDeviceId(false, "../../etc/x", "h")
        assertFalse(id.contains("/"))
        assertEquals("backups/$id/p", File("backups", id).resolve("p").path.removePrefix("./"))
    }

    @Test fun pathIsDeviceThenPackage() {
        assertEquals(File("/r/tv/com.a"), backupDir(File("/r"), "tv", "com.a"))
    }

    @Test fun sameAppOnTwoDevicesIsKeptSeparately() {
        val root = Files.createTempDirectory("backup_devices_").toFile()
        try {
            val manager = BackupManager(backupsDir = root)
            manager.createBackup(PullingAdb(), "com.a", null, "local", "Phone")
            manager.createBackup(PullingAdb(), "com.a", null, "tv", "TV")
            manager.createBackup(PullingAdb(), "com.a", null, "tv", "TV")
            val list = manager.listBackups()
            assertEquals(setOf("local", "tv"), list.map { it.deviceId }.toSet())
            assertEquals(2, list.size)
            assertEquals("TV", list.first { it.deviceId == "tv" }.deviceName)
            manager.deleteBackup("tv", "com.a")
            assertEquals(listOf("local"), manager.listBackups().map { it.deviceId })
        } finally {
            root.deleteRecursively()
        }
    }

    @Test fun legacyFoldersMoveToUnassignedOnceAndAreKept() {
        val root = Files.createTempDirectory("backup_migrate_").toFile()
        try {
            File(root, "com.old").mkdirs()
            File(root, "com.old/base.apk").writeBytes(ByteArray(4) { 1 })
            File(root, "tv/com.new").mkdirs()
            File(root, "tv/com.new/base.apk").writeBytes(ByteArray(4) { 1 })
            migrateLegacyBackups(root)
            migrateLegacyBackups(root)
            assertTrue(File(root, "_unassigned/com.old/base.apk").exists())
            assertFalse(File(root, "com.old").exists())
            assertTrue(File(root, "tv/com.new/base.apk").exists())
            val old = BackupManager(backupsDir = root).listBackups().first { it.packageName == "com.old" }
            assertEquals("_unassigned", old.deviceId)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test fun migrationNeverOverwritesAnExistingTarget() {
        val root = Files.createTempDirectory("backup_migrate2_").toFile()
        try {
            File(root, "com.old").mkdirs()
            File(root, "com.old/base.apk").writeBytes(ByteArray(4) { 1 })
            File(root, "_unassigned/com.old").mkdirs()
            File(root, "_unassigned/com.old/base.apk").writeBytes(ByteArray(9) { 2 })
            migrateLegacyBackups(root)
            assertTrue(File(root, "com.old/base.apk").exists())
            assertEquals(9L, File(root, "_unassigned/com.old/base.apk").length())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test fun revertOnlyOnTheSameDevice() {
        assertTrue(canRevertBackup("tv", "tv"))
        assertFalse(canRevertBackup("local", "tv"))
        assertFalse(canRevertBackup("_unassigned", "tv"))
        assertFalse(canRevertBackup("tv", null))
    }

    @Test fun connectedShowsOnlyThatDeviceAndNoDeviceShowsNothing() {
        val all = listOf(item("a", "tv"), item("a", "local"), item("b", "_unassigned"))
        assertEquals(listOf("tv"), visibleBackups(all, "tv").map { it.deviceId })
        assertTrue(visibleBackups(all, null).isEmpty())
    }

    @Test fun everyBackupIsRemovedWhenAllRevertsSucceed() {
        val a = item("a", "tv")
        val b = item("b", "tv")
        assertEquals(listOf(a, b), backupsToRemoveAfterRevert(listOf(a to true, b to true)))
    }

    @Test fun noBackupIsRemovedWhenAllRevertsFail() {
        val results = listOf(item("a", "tv") to false, item("b", "tv") to false)
        assertTrue(backupsToRemoveAfterRevert(results).isEmpty())
    }

    @Test fun onlyRevertedBackupsAreRemovedWhenResultsAreMixed() {
        val a = item("a", "tv")
        val b = item("b", "tv")
        val c = item("c", "tv")
        assertEquals(listOf(a, c), backupsToRemoveAfterRevert(listOf(a to true, b to false, c to true)))
    }
}
