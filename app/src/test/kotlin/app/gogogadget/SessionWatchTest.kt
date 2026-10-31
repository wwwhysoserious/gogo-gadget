package app.gogogadget

import java.io.InputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** [SessionWatch] with a scripted client and a real lock: what it pings, when it gives up, and what it never closes. */
class SessionWatchTest {
    private class FakeAdb : AdbClient {
        @Volatile var alive = true
        @Volatile var session = 7L
        val answers = ArrayDeque<Throwable?>()
        val pingTimeouts = mutableListOf<Long>()
        val kills = AtomicInteger()
        val disconnects = AtomicInteger()
        var onPing: () -> Unit = {}
        var onKill: () -> Unit = {}

        override val isConnected get() = alive
        override val isAlive get() = alive
        override val sessionId get() = session
        override fun pair(host: String, port: Int, code: String) = Unit
        override fun connect(host: String, port: Int) = Unit
        override fun shell(command: String) = ""
        override fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit) = ""
        override fun ping(timeoutMs: Long) {
            pingTimeouts += timeoutMs
            onPing()
            answers.removeFirstOrNull()?.let { throw it }
        }
        override fun kill() {
            kills.incrementAndGet()
            onKill()
        }
        override fun disconnect() {
            disconnects.incrementAndGet()
        }
    }

    private val adb = FakeAdb()
    private val lock = Mutex()
    private val log = TerminalLog()
    private val device = Device("TV", "192.168.1.20", 41234, false)
    private var generation = 3
    private var state = ConnectionState.Connected
    private val lost = mutableListOf<String>()
    private val watch = SessionWatch(adb, lock, log, { SessionSnapshot(generation, adb.sessionId, device, state) }, io = Dispatchers.Unconfined)
    private val session = SessionSnapshot(3, 7, device, ConnectionState.Connected)

    private fun check(keepalive: Boolean = true) = runBlocking { watch.check(session, keepalive) { lost += it } }

    @Test fun aBusyLockMeansTheSessionIsWorkingAndNothingIsPinged() {
        runBlocking { lock.lock() }
        assertEquals(WatchResult.Skipped, check())
        assertTrue(adb.pingTimeouts.isEmpty())
        lock.unlock()
    }

    @Test fun noKeepaliveRequestedMeansNoPing() {
        assertEquals(WatchResult.Skipped, check(keepalive = false))
        assertTrue(adb.pingTimeouts.isEmpty())
    }

    @Test fun anAnsweredPingKeepsTheSessionAndFreesTheLock() {
        assertEquals(WatchResult.Alive, check())
        assertEquals(listOf(FirstPingMs), adb.pingTimeouts)
        assertFalse(lock.isLocked)
    }

    @Test fun oneFailedPingIsOnlySuspect() {
        adb.answers += java.net.SocketTimeoutException("slow")
        assertEquals(WatchResult.Suspect, check())
        assertTrue(lost.isEmpty())
        assertEquals(0, adb.disconnects.get())
        assertEquals(0, adb.kills.get())
    }

    @Test fun twoFailedPingsLoseTheSessionWithAReasonAndALogLine() {
        adb.answers += java.net.SocketTimeoutException("slow")
        adb.answers += java.net.SocketTimeoutException("slower")
        assertEquals(WatchResult.Suspect, check())
        assertEquals(WatchResult.Lost, check())
        assertEquals(listOf(FirstPingMs, SecondPingMs), adb.pingTimeouts)
        assertEquals(1, lost.size)
        assertTrue(lost.single(), "SocketTimeoutException" in lost.single())
        assertEquals(listOf(lostLine(lost.single())), log.lines.value)
        assertEquals(1, adb.kills.get())
        assertEquals(1, adb.disconnects.get())
    }

    @Test fun aLibraryThatReportsTheConnectionEndedLosesItAtOnceWithoutAPing() {
        adb.alive = false
        assertEquals(WatchResult.Lost, check(keepalive = false))
        assertTrue(adb.pingTimeouts.isEmpty())
        assertEquals(1, lost.size)
        assertEquals(1, adb.disconnects.get())
    }

    @Test fun anOperationThatBeginsDuringThePingClosesNothing() {
        adb.answers += java.net.SocketTimeoutException("slow")
        adb.answers += java.net.SocketTimeoutException("slower")
        check()
        adb.onPing = { generation++ }
        assertEquals(WatchResult.Skipped, check())
        assertTrue(lost.isEmpty())
        assertEquals(0, adb.kills.get())
        assertEquals(0, adb.disconnects.get())
    }

    @Test fun aNewerSessionIsNeverClosedByAnOldVerdict() {
        adb.alive = false
        adb.session = 8
        assertEquals(WatchResult.Skipped, check())
        assertEquals(0, adb.kills.get())
        assertEquals(0, adb.disconnects.get())
        assertTrue(lost.isEmpty())
    }

    @Test fun aStateThatIsNoLongerConnectedIsLeftAlone() {
        adb.alive = false
        state = ConnectionState.Error
        assertEquals(WatchResult.Skipped, check())
        assertEquals(0, adb.disconnects.get())
    }

    // The contract behind the abort: kill() takes no lock, so it frees a lock held by a call stuck on a dead socket.
    @Test fun killFreesALockHeldByACallStuckOnTheDeadSocket() {
        val held = CountDownLatch(1)
        val released = CountDownLatch(1)
        adb.onKill = { released.countDown() }
        val stuck = thread {
            runBlocking { lock.withLock { held.countDown(); released.await(5, TimeUnit.SECONDS) } }
        }
        assertTrue(held.await(5, TimeUnit.SECONDS))
        adb.alive = false
        assertEquals(WatchResult.Lost, check(keepalive = false))
        stuck.join(5_000)
        assertEquals(1, adb.kills.get())
        assertEquals(1, adb.disconnects.get())
        assertFalse(lock.isLocked)
    }
}
