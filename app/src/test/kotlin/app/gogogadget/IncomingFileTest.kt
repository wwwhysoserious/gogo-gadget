package app.gogogadget

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class IncomingFileTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun zip(vararg entries: String): File = tmp.newFile().also { f ->
        ZipOutputStream(f.outputStream()).use { out ->
            for (name in entries) {
                out.putNextEntry(ZipEntry(name))
                out.write(1)
                out.closeEntry()
            }
        }
    }

    @Test fun startsOnlyWithADeviceAndNoRunningInstall() {
        assertTrue(pendingFileReady(connected = true, installing = false))
        assertFalse(pendingFileReady(connected = false, installing = false))
        assertFalse(pendingFileReady(connected = true, installing = true))
        assertFalse(pendingFileReady(connected = false, installing = true))
    }

    @Test fun displayNameLosesPathAndControlCharacters() {
        assertEquals("app.xapk", incomingDisplayName("/storage/emulated/0/Download/../app.xapk"))
        assertEquals("ab.apk", incomingDisplayName("a\nb.apk"))
        assertEquals("package", incomingDisplayName(null))
        assertEquals("package", incomingDisplayName("dir/"))
    }

    @Test fun apkAndBundlesAreInstallable() {
        assertTrue(looksInstallable(zip("AndroidManifest.xml", "classes.dex")))
        assertTrue(looksInstallable(zip("manifest.json", "base.apk", "config.en.apk")))
        assertTrue(looksInstallable(zip("Android/obb/pkg/main.1.pkg.obb", "pkg/BASE.APK")))
        // Changed in 0.9.50 (audit F23): a root manifest makes it ONE app, and an .apk inside it (a helper app) is data.
        assertTrue(looksInstallable(zip("AndroidManifest.xml", "classes.dex", "assets/stub.apk")))
    }

    @Test fun otherZipsAndNonZipsAreNot() {
        assertFalse(looksInstallable(zip("readme.txt", "photos/a.jpg")))
        assertFalse(looksInstallable(tmp.newFile().also { it.writeText("not a zip") }))
        assertFalse(looksInstallable(tmp.newFile()))
    }
}
