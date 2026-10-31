package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyMaskTest {
    private val dot = '•'

    @Test fun longKeyShowsEightBulletsAndTheLastFour() {
        val key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789aba3f9"
        assertEquals("$dot$dot$dot$dot$dot$dot$dot${dot}a3f9", maskKey(key))
    }

    @Test fun neverShowsMoreThanFourCharacters() {
        val key = "k".repeat(10) + "WXYZ"
        val shown = maskKey(key).filter { it != dot }
        assertEquals("WXYZ", shown)
        assertFalse(maskKey(key).contains("kkkk"))
    }

    @Test fun shortKeysRevealAtMostHalfAndNeverMoreThanFour() {
        for (length in 1..8) {
            val key = "abcdefgh".take(length)
            val shown = maskKey(key).count { it != dot }
            assertTrue("length $length shows $shown", shown <= 4 && shown <= length / 2)
        }
        assertEquals("$dot$dot$dot$dot$dot$dot$dot$dot", maskKey("a"))
    }

    @Test fun blankKeyShowsNothing() {
        assertEquals("", maskKey(null))
        assertEquals("", maskKey(""))
        assertEquals("", maskKey("   "))
    }

    @Test fun surroundingSpacesAreIgnored() {
        assertEquals(maskKey("0123456789abcdef"), maskKey("  0123456789abcdef \n"))
    }

    @Test fun maskIsNeverLongerThanEightBulletsAndFourCharacters() {
        assertTrue(maskKey("x".repeat(500)).length <= 12)
    }
}
