package app.gogogadget

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TerminalTailTest {
    @Test
    fun followsWhenExactlyAtBottom() = assertTrue(shouldFollowTail(value = 500, maxValue = 500, thresholdPx = 60))

    @Test
    fun followsWhenWithinThreshold() = assertTrue(shouldFollowTail(value = 450, maxValue = 500, thresholdPx = 60))

    @Test
    fun doesNotFollowWhenScrolledUp() = assertFalse(shouldFollowTail(value = 100, maxValue = 500, thresholdPx = 60))

    @Test
    fun followsWhenContentIsShorterThanViewport() = assertTrue(shouldFollowTail(value = 0, maxValue = 0, thresholdPx = 60))
}
