package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppLanguageTest {
    @Test fun emptyOrBlankTagShowsSystemLabel() {
        assertEquals("System", languageRowLabel(null, "System"))
        assertEquals("System", languageRowLabel("", "System"))
        assertEquals("System", languageRowLabel("  ", "System"))
    }

    @Test fun garbageTagShowsSystemLabel() {
        assertEquals("Sistema", languageRowLabel("-", "Sistema"))
    }

    @Test fun languagesAreNamedInTheirOwnLanguage() {
        assertEquals("Français", languageRowLabel("fr", "System"))
        assertEquals("Español", languageRowLabel("es", "System"))
        assertEquals("English", languageRowLabel("en", "System"))
    }

    @Test fun portugalPortugueseKeepsItsRegion() {
        val label = languageRowLabel("pt-PT", "System")
        assertTrue(label, label.startsWith("Português"))
    }

    @Test fun perAppLanguageNeedsApi33() {
        assertFalse(appLanguageSupported(30))
        assertFalse(appLanguageSupported(32))
        assertTrue(appLanguageSupported(33))
        assertTrue(appLanguageSupported(35))
    }
}
