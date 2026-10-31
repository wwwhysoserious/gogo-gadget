package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ContrastTest {
    private val palettes = mapOf("Light" to LightPalette, "Blue" to BluePalette, "Dark" to DarkPalette)

    private fun assertRatio(name: String, label: String, fg: Long, bg: Long, min: Double) {
        val ratio = contrastRatio(fg, bg)
        assertTrue("$name $label: ${"%.2f".format(ratio)}:1 is below $min:1", ratio >= min)
    }

    @Test fun ratioMatchesTheWcagReferenceValues() {
        assertEquals(21.0, contrastRatio(0xFF000000, 0xFFFFFFFF), 0.001)
        assertEquals(1.0, contrastRatio(0xFF1565C0, 0xFF1565C0), 0.001)
        assertEquals(contrastRatio(0xFF1565C0, 0xFFFFFFFF), contrastRatio(0xFFFFFFFF, 0xFF1565C0), 0.0001)
    }

    @Test fun textAndSecondaryReadOnBackgroundAndSurface() {
        for ((name, p) in palettes) {
            for (base in listOf("background" to p.background, "surface" to p.surface)) {
                assertRatio(name, "text on ${base.first}", p.text, base.second, 4.5)
                assertRatio(name, "secondary on ${base.first}", p.secondary, base.second, 4.5)
            }
        }
    }

    @Test fun successAndErrorAreVisibleOnTheBackground() {
        for ((name, p) in palettes) {
            assertRatio(name, "success on background", p.success, p.background, 3.0)
            assertRatio(name, "error on background", p.error, p.background, 3.0)
        }
    }

    @Test fun buttonLabelsReadOnTheirButton() {
        for ((name, p) in palettes) assertRatio(name, "button label", p.buttonContent, p.buttonContainer, 3.0)
    }

    @Test fun lightAndBlueUseOnlyOpaqueColours() {
        for ((name, p) in listOf("Light" to LightPalette, "Blue" to BluePalette)) {
            val all = listOf(
                p.background, p.text, p.secondary, p.divider, p.surface, p.accent, p.buttonContainer, p.buttonContent,
                p.indicator, p.navInactive, p.success, p.error, p.track, p.trackLine,
            )
            all.forEach { assertEquals("$name has a translucent colour ${java.lang.Long.toHexString(it)}", 0xFFL, (it shr 24) and 0xFF) }
        }
    }

    @Test fun floatingSurfacesAreOpaqueInEveryTheme() {
        for ((name, p) in palettes) assertEquals(name, 0xFFL, (opaque(p.surface) shr 24) and 0xFF)
        assertEquals(0xFF123456L, opaque(0x1F123456))
    }

    @Test fun panelsStandOutFromTheBackground() {
        // Light and Blue panels are told apart by their surface colour and a border; neither may equal the background.
        for ((name, p) in listOf("Light" to LightPalette, "Blue" to BluePalette)) {
            assertTrue("$name surface equals background", p.surface != p.background)
            assertTrue("$name border equals surface", p.divider != p.surface && p.divider != p.background)
        }
    }

    @Test fun darkPaletteIsUnchanged() {
        assertEquals(0xFF000000, DarkPalette.background)
        assertEquals(0xFFFFFFFF, DarkPalette.text)
        assertEquals(0xFF9AA6B5, DarkPalette.secondary)
        assertEquals(0xFF1F2933, DarkPalette.divider)
        assertEquals(0xFF0A0A0A, DarkPalette.surface)
        assertEquals(0xFF2196F3, DarkPalette.accent)
        assertEquals(0xFF12A150, DarkPalette.success)
        assertEquals(0xFFF04438, DarkPalette.error)
        assertEquals(0xFF0A0A0A, DarkPalette.track)
        assertEquals(0x40FFFFFF, DarkPalette.trackLine)
    }
}
