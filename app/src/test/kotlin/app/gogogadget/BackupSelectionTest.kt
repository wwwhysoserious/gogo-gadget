package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class BackupSelectionTest {
    private fun item(pkg: String) = AppBackupItem(
        packageName = pkg, appName = pkg, versionName = "1", versionCode = 1L,
        timestamp = 0L, totalSizeBytes = 1L, apkFiles = emptyList<File>(),
    )

    @Test fun toggleAddsThenRemoves() {
        val once = toggleSelection(emptySet(), "k")
        assertEquals(setOf("k"), once)
        assertEquals(emptySet<String>(), toggleSelection(once, "k"))
    }

    @Test fun selectAllUsesOnlyVisibleItems() {
        assertEquals(setOf("_unassigned/a", "_unassigned/b"), selectAllVisible(listOf(item("a"), item("b"))))
    }

    @Test fun allVisibleSelectedNeedsAtLeastOneItem() {
        assertFalse(allVisibleSelected(emptySet(), emptyList()))
        assertTrue(allVisibleSelected(setOf("_unassigned/a", "_unassigned/b"), listOf(item("a"), item("b"))))
        assertFalse(allVisibleSelected(setOf("_unassigned/a"), listOf(item("a"), item("b"))))
    }

    @Test fun pruneDropsDeletedPackages() {
        assertEquals(setOf("_unassigned/a"), pruneSelection(setOf("_unassigned/a", "gone"), listOf(item("a"))))
    }

    @Test fun filterMatchesNameOrPackageIgnoringCase() {
        val list = listOf(item("com.Foo.app"), item("org.bar"))
        assertEquals(listOf("com.Foo.app"), filterBackups(list, " foo ").map { it.packageName })
        assertEquals(2, filterBackups(list, "").size)
    }
}
