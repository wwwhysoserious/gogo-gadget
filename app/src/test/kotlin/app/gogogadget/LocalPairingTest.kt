package app.gogogadget

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.io.InputStream
import java.net.ConnectException
import java.net.SocketException
import java.security.KeyStoreException
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class LocalPairingTest {
    /** Records what the pairing and the key deletion did, in order; [onPair] is the behaviour of one pairing. */
    private class FakeAdb : AdbClient {
        val events: MutableList<String> = Collections.synchronizedList(mutableListOf())
        var onPair: (String) -> Unit = {}

        override val isConnected = false
        override fun pair(host: String, port: Int, code: String) = pair(host, port, code, IdentityName.Shared)
        override fun pair(host: String, port: Int, code: String, identity: IdentityName) {
            events += "pair $host ${identity.id}"
            onPair(host)
            events += "paired $host"
        }
        override fun connect(host: String, port: Int) = Unit
        override fun deleteIdentity(identity: IdentityName) {
            events += "delete ${identity.id}"
        }
        override fun shell(command: String) = ""
        override fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit) = ""
        override fun disconnect() = Unit
    }

    private val own = setOf("192.168.1.20", "100.98.120.20")
    private val lines = mutableListOf<String>()
    private fun pairing(adb: AdbClient, lock: Mutex = Mutex(), hosts: List<String> = listOf("127.0.0.1")): PairOutcome =
        runBlocking { runLocalPairing(adb, lock, hosts, 40935, "792972") { lines += it } }

    // ---- BUG: deleteIdentity(Local) raced with the pairing service (which took no lock) ----

    @Test fun aKeyIsNeverDeletedWhileAPairingUsesIt() {
        val adb = FakeAdb()
        val lock = Mutex()
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        adb.onPair = { started.countDown(); release.await(5, TimeUnit.SECONDS) }
        val pairingThread = thread { pairing(adb, lock) }
        assertTrue(started.await(5, TimeUnit.SECONDS))
        // What the model does when this phone is forgotten: the deletion takes the same lock.
        val deleting = thread { runBlocking { lock.withLock { adb.deleteIdentity(IdentityName.Local) } } }
        Thread.sleep(150)
        assertFalse("the key was deleted under a pairing", adb.events.any { it.startsWith("delete") })
        release.countDown()
        pairingThread.join(5000)
        deleting.join(5000)
        assertEquals(listOf("pair 127.0.0.1 local", "paired 127.0.0.1", "delete local"), adb.events)
    }

    @Test fun theLockIsFreeAgainWhateverTheOutcome() {
        val lock = Mutex()
        pairing(FakeAdb(), lock)
        assertFalse(lock.isLocked)
        pairing(FakeAdb().apply { onPair = { throw IllegalStateException("boom") } }, lock)
        assertFalse(lock.isLocked)
    }

    @Test fun thePairingServiceUsesTheLocalKey() {
        val adb = FakeAdb()
        assertEquals(PairOutcome.Paired, pairing(adb))
        assertEquals("pair 127.0.0.1 local", adb.events.first())
    }

    // ---- BUG: an unknown failure left no trace ----

    @Test fun anUnknownFailureStaysFailedButKeepsItsClassMessageAndNeverTheCode() {
        val adb = FakeAdb().apply { onPair = { throw IllegalStateException("peer sent 792972 and then died") } }
        val outcome = pairing(adb) as PairOutcome.Failed
        assertEquals(AdbError.Failed, outcome.error)
        assertEquals("IllegalStateException", outcome.exceptionName)
        assertEquals("IllegalStateException: peer sent ****** and then died", outcome.detail)
        assertTrue(lines.any { it.contains("IllegalStateException") && it.contains("[Failed]") })
        assertTrue(lines.none { it.contains("792972") })
    }

    @Test fun aFailureWhileMakingTheKeyIsAKeyError() {
        val wrapped = FakeAdb().apply { onPair = { throw AdbKeyException(IllegalStateException("Cannot read the ADB key")) } }
        assertEquals(AdbError.KeyError, (pairing(wrapped) as PairOutcome.Failed).error)
        val raw = FakeAdb().apply { onPair = { throw KeyStoreException("Keystore operation failed") } }
        assertEquals(AdbError.KeyError, (pairing(raw) as PairOutcome.Failed).error)
    }

    @Test fun aClosedSocketIsNamedNotJustFailed() {
        val adb = FakeAdb().apply { onPair = { throw SocketException("Connection reset") } }
        val outcome = pairing(adb) as PairOutcome.Failed
        assertEquals(AdbError.PairingClosed, outcome.error)
        assertEquals("SocketException", outcome.exceptionName)
    }

    // ---- hosts ----

    @Test fun onlyARefusedConnectionMovesOnToTheNextHost() {
        val refused = FakeAdb().apply { onPair = { host -> if (host == "127.0.0.1") throw ConnectException("refused") } }
        assertEquals(PairOutcome.Paired, pairing(refused, hosts = listOf("127.0.0.1", "100.98.120.20")))
        assertEquals(listOf("pair 127.0.0.1 local", "pair 100.98.120.20 local", "paired 100.98.120.20"), refused.events)

        val reset = FakeAdb().apply { onPair = { throw SocketException("Connection reset") } }
        pairing(reset, hosts = listOf("127.0.0.1", "100.98.120.20"))
        assertEquals(listOf("pair 127.0.0.1 local"), reset.events)
    }

    @Test fun theServiceTriesLoopbackThenTheDialogsOwnAddress() {
        // The pairing dialog showed 100.98.120.20 (a CGNAT/Tailscale-range address of this phone).
        assertEquals(listOf("127.0.0.1", "100.98.120.20"), servicePairingHosts("100.98.120.20", own))
        assertEquals(listOf("127.0.0.1"), servicePairingHosts(null, own))
        assertEquals(listOf("127.0.0.1"), servicePairingHosts("  ", own))
        assertEquals(listOf("127.0.0.1"), servicePairingHosts("127.0.0.1", own))
        // The extra travels in a PendingIntent: an address that is not this phone's is never connected to.
        assertEquals(listOf("127.0.0.1"), servicePairingHosts("192.168.1.99", own))
    }

    @Test fun refusedMeansAConnectExceptionAnywhereInTheChain() {
        assertTrue(isRefused(IOException("x", ConnectException("refused"))))
        assertFalse(isRefused(IOException("Broken pipe")))
    }
}
