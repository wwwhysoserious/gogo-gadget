package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream

class OutputAndPairingTest {
    // ---- end marker ----

    @Test fun markerIsAppendedAfterTheCommand() {
        assertEquals("getprop ro.product.model; echo $EndMarker", withEndMarker("getprop ro.product.model"))
    }

    @Test fun outputIsCutAtTheMarkerLine() {
        assertEquals("Pixel 8", outputBeforeMarker("Pixel 8\n$EndMarker\n"))
        assertEquals("Pixel 8", outputBeforeMarker("Pixel 8\r\n$EndMarker\r\n"))
        assertEquals("", outputBeforeMarker("$EndMarker\n"))
        assertEquals("a\nb", outputBeforeMarker("a\nb\n$EndMarker"))
    }

    @Test fun noMarkerMeansUnfinished() {
        assertNull(outputBeforeMarker(""))
        assertNull(outputBeforeMarker("Pixel 8\n"))
        assertNull(outputBeforeMarker("Pixel 8\n__GOGO_EN"))
    }

    @Test fun markerInsideTheEchoedCommandDoesNotCount() {
        assertNull(outputBeforeMarker("getprop x; echo $EndMarker\n"))
    }

    @Test fun installIsCompleteAtSuccessFailureOrMarker() {
        assertFalse(isInstallOutputComplete(""))
        assertFalse(isInstallOutputComplete("Performing Streamed Install\n"))
        assertTrue(isInstallOutputComplete("Success\n"))
        assertTrue(isInstallOutputComplete("Failure [INSTALL_FAILED_VERSION_DOWNGRADE]\n"))
        assertTrue(isInstallOutputComplete("Error: Unknown option: --bypass-low-target-sdk-block\n$EndMarker\n"))
        assertFalse(isInstallOutputComplete("Not a Success yet\n"))
    }

    // ---- readUntil ----

    private fun slow(vararg chunks: String, then: () -> Int = { -1 }): InputStream = object : InputStream() {
        private val queue = ArrayDeque(chunks.map { it.toByteArray() })
        override fun read() = throw UnsupportedOperationException()
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val next = queue.removeFirstOrNull() ?: return then()
            next.copyInto(b, off)
            return next.size
        }
    }

    @Test fun readUntilStopsAtTheMarkerWithoutWaitingForEof() {
        // After the marker the stream would block forever (here: fail the test) if it were read again.
        val input = slow("Success\n", "$EndMarker\n", then = { throw AssertionError("read past the marker") })
        val out = readUntil(input) { outputBeforeMarker(it) != null }
        assertEquals("Success", outputBeforeMarker(out))
    }

    @Test fun readUntilAssemblesChunksIncludingASplitMarker() {
        val input = slow("ok\n__GOGO", "_END__", "\nignored", then = { throw AssertionError("read past the marker") })
        assertEquals("ok", outputBeforeMarker(readUntil(input) { outputBeforeMarker(it) != null }))
    }

    @Test fun readUntilReturnsWhatArrivedOnEof() {
        val out = readUntil(ByteArrayInputStream("partial".toByteArray())) { false }
        assertEquals("partial", out)
    }

    @Test fun readUntilTreatsAReadErrorAsTheEnd() {
        val out = readUntil(slow("Failure [X]", then = { throw IOException("Stream closed") })) { false }
        assertEquals("Failure [X]", out)
    }

    @Test fun readUntilKeepsMultibyteCharactersSplitAcrossChunks() {
        val bytes = "é\n$EndMarker\n".toByteArray()
        val input = object : InputStream() {
            var i = 0
            override fun read() = throw UnsupportedOperationException()
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (i >= bytes.size) return -1
                b[off] = bytes[i++]
                return 1
            }
        }
        assertEquals("é", outputBeforeMarker(readUntil(input) { outputBeforeMarker(it) != null }))
    }

    // ---- install timing and errors ----

    @Test fun installTimeoutGrowsWithSizeAndIsCapped() {
        assertEquals(60_000L, installTimeoutMs(0))
        assertTrue(installTimeoutMs(10_000_000) > installTimeoutMs(1_000_000))
        assertEquals(9 * 60_000L, installTimeoutMs(Long.MAX_VALUE))
        assertEquals(60_000L, installTimeoutMs(-5))
    }

    @Test fun onlyAGoneSessionIsAConnectionLoss() {
        assertTrue(installErrorIsConnectionLoss(sessionConnected = false))
        assertFalse(installErrorIsConnectionLoss(sessionConnected = true))
    }

    // ---- paste / code validation ----

    @Test fun codesMustBeSixAsciiDigits() {
        assertEquals("123456", parsePairingCode("123456"))
        assertEquals("123456", parsePairingCode(" 123 456\n"))
        assertEquals("123456", parsePairingCode("123-456"))
        for (bad in listOf(null, "", "12345", "1234567", "12345a", "abcdef", "12 34 5", "١٢٣٤٥٦", "code 123456")) {
            assertNull(bad, parsePairingCode(bad))
        }
    }

    // ---- notification reply ----

    @Test fun validCodeWithAPortIsSubmitted() {
        val d = decideReply("123 456", port = 37123)
        assertTrue(d is ReplyDecision.Submit)
        assertEquals("123456", (d as ReplyDecision.Submit).code)
        assertEquals(37123, d.port)
    }

    @Test fun submitNeverExposesTheCodeInToString() {
        assertFalse("123456" in decideReply("123456", 1).toString())
    }

    @Test fun badCodeIsReportedWhenThereIsAPort() {
        assertEquals(ReplyDecision.BadCode, decideReply("12", port = 1))
        assertEquals(ReplyDecision.BadCode, decideReply(null, port = 40000))
    }

    @Test fun noPortMeansSearchAgain() {
        assertEquals(ReplyDecision.NoPort, decideReply("123456", port = -1))
        assertEquals(ReplyDecision.NoPort, decideReply("123456", port = 0))
        assertEquals(ReplyDecision.NoPort, decideReply("123456", port = 70000))
    }
}
