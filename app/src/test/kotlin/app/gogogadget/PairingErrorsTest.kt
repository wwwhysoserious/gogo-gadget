package app.gogogadget

import io.github.muntashirakon.adb.AdbPairingRequiredException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.EOFException
import java.io.IOException
import java.net.ConnectException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.InvalidKeyException
import java.security.KeyManagementException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException

class PairingErrorsTest {
    private fun pair(e: Throwable) = classifyError(e, Phase.Pair, local = true)

    // ---- BUG: a key that cannot be made or loaded was only a KeyError while pairing ----

    @Test fun anyKeyFailureIsAKeyErrorInEveryPhase() {
        val failures = listOf(
            AdbKeyException(IllegalStateException("Cannot read the ADB key")),
            InvalidKeyException("Invalid key length"),
            KeyStoreException("Keystore operation failed"),
            UnrecoverableKeyException("no key"),
            ProviderException("Failed to generate key"),
            IOException("outer", AdbKeyException(RuntimeException())),
        )
        for (failure in failures) for (phase in Phase.values()) {
            assertEquals("$failure in $phase", AdbError.KeyError, classifyError(failure, phase, local = true))
        }
    }

    // ---- BUG: sockets Android or the peer closed, and unavailable TLS, fell into "Something went wrong" ----

    @Test fun aSocketThePeerClosedIsPairingClosed() {
        for (message in listOf("Connection reset", "Connection reset by peer", "Broken pipe", "Socket closed",
            "Software caused connection abort", "recvfrom failed: ECONNRESET (Connection reset by peer)")) {
            assertEquals(message, AdbError.PairingClosed, pair(SocketException(message)))
        }
        assertEquals(AdbError.PairingClosed, pair(IOException("Connection closed with errors.")))
        assertEquals(AdbError.PairingClosed, pair(IOException("wrapped", SocketException("Connection reset"))))
    }

    @Test fun aSocketTheSystemForbidsIsUnreachable() {
        assertEquals(AdbError.PairingUnreachable, pair(SocketException("socket failed: EPERM (Operation not permitted)")))
    }

    @Test fun missingTlsOneThreeIsATlsFailure() {
        assertEquals(AdbError.TlsFailed, pair(NoSuchAlgorithmException("TLSv1.3 isn't supported on your platform.")))
        assertEquals(AdbError.TlsFailed, pair(KeyManagementException("init failed")))
        assertEquals(AdbError.TlsFailed, pair(SSLException(ClassNotFoundException("org.conscrypt.Conscrypt"))))
    }

    @Test fun whatIsStillUnknownStaysFailed() {
        assertEquals(AdbError.Failed, pair(IllegalStateException()))
        assertEquals(AdbError.Failed, pair(IOException("Unable to create PairingAuthCtx.")))
        assertEquals(AdbError.Failed, pair(SocketException("something new")))
        assertEquals(AdbError.Failed, pair(NullPointerException()))
    }

    @Test fun theOldMappingsStillHold() {
        assertEquals(AdbError.WrongCode, pair(EOFException()))
        assertEquals(AdbError.WrongCode, pair(IOException("Could not exchange peer info.")))
        assertEquals(AdbError.PairingUnreachable, pair(ConnectException("Connection refused")))
        assertEquals(AdbError.PairingUnreachable, pair(SocketTimeoutException()))
        assertEquals(AdbError.PairingRequired, classifyError(AdbPairingRequiredException("x"), Phase.Connect, local = true))
    }

    // ---- the details a field report needs ----

    @Test fun theNotificationNamesTheClassOnly() {
        assertEquals("SocketException", exceptionName(SocketException("Connection reset 123456")))
        assertEquals("IllegalStateException", exceptionName(IllegalStateException("secret")))
        // An anonymous subclass has no simple name: the last part of the class name is used.
        assertTrue(exceptionName(object : IOException("x") {}).isNotEmpty())
    }

    @Test fun theFailureTextHasADetailsLineOnlyWhenThereIsOne() {
        assertEquals("Something went wrong.\nDetails: SocketException", failureText("Something went wrong.", "Details: SocketException"))
        assertEquals("Something went wrong.", failureText("Something went wrong.", null))
    }

    @Test fun theLogLineHasTheClassAndMessageButNeverACodeOrKey() {
        assertEquals("> pair: failed - SocketException: Connection reset", failureLine("pair", SocketException("Connection reset")))
        assertEquals("> pair: failed - IOException: code ****** here", failureLine("pair", IOException("code 792972 here")))
        assertEquals("secret ... ******", maskSecrets("secret " + "A".repeat(40) + " 123456"))
    }

    @Test fun everyErrorHasAMessage() {
        assertTrue(AdbError.PairingClosed.message != AdbError.Failed.message)
        assertEquals(AdbError.values().size, AdbError.values().map { it.name }.toSet().size)
    }

    // ---- the terminal log ----

    @Test fun theTerminalLogKeepsTheOrderAndTheNewestLines() {
        val log = TerminalLog(maxLines = 3)
        listOf("one", "two", "three", "four").forEach(log::add)
        assertEquals(listOf("two", "three", "four"), log.lines.value)
        log.clear()
        assertTrue(log.lines.value.isEmpty())
    }

    @Test fun theTerminalLogMasksCodesKeysAndControlCharacters() {
        val log = TerminalLog()
        log.add("> pair: failed - IOException: code 792972\nnext")
        log.add("> key " + "B".repeat(50))
        assertEquals(listOf("> pair: failed - IOException: code ****** next", "> key ..."), log.lines.value)
    }

    // ---- BUG: libadb reuses the TLS context of the first key it ever saw ----

    @Test fun theCachedTlsContextIsDroppedSoTheNextHandshakeUsesTheKeyInUse() {
        val field = Class.forName("io.github.muntashirakon.adb.SslUtils").getDeclaredField("sslContext").apply { isAccessible = true }
        field.set(null, SSLContext.getDefault())
        assertNotNull(LibAdbTls.cached())
        assertTrue(LibAdbTls.reset())
        assertNull(LibAdbTls.cached())
        // Nothing cached is fine too.
        assertTrue(LibAdbTls.reset())
        assertFalse(LibAdbTls.cached() != null)
    }
}
