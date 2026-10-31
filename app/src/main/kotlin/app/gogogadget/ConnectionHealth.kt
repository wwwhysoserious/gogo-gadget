package app.gogogadget

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

// Pure logic for the health of the connection: no Android classes, no network, unit-tested.
//
// Two separate machines. The connected session goes Healthy -> Suspect -> Lost (the library's own flags and one
// keepalive, never a TCP probe). Every other saved device goes Unknown -> Available -> Unavailable (TCP probes only,
// never touching ADB).

// ---- The connected session ----

/** Healthy until [failuresToLose] pings in a row fail; a connection the library reports as ended is lost at once. */
class LivenessTracker(private val failuresToLose: Int = 2) {
    enum class Verdict { Healthy, Suspect, Lost }

    private var failures = 0

    /** True after a failed ping, while the next one decides. */
    val suspect: Boolean get() = failures in 1 until failuresToLose

    /** The library says the connection is over (the reader thread ended): not slowness, so no second chance. */
    fun onFlagsDead(): Verdict {
        failures = failuresToLose
        return Verdict.Lost
    }

    fun onPing(ok: Boolean): Verdict {
        if (ok) {
            failures = 0
            return Verdict.Healthy
        }
        failures++
        return if (failures >= failuresToLose) Verdict.Lost else Verdict.Suspect
    }

    fun reset() {
        failures = 0
    }
}

/** What identifies one connected session: a verdict about it is dropped once any part has moved on. */
data class SessionSnapshot(val generation: Int, val sessionId: Long, val device: Device?, val state: ConnectionState)

/** A loss may only be applied to the very session it was found for, still connected. */
fun shouldApplyLoss(
    generation: Int, generationNow: Int,
    sessionId: Long, sessionIdNow: Long,
    device: Device?, deviceNow: Device?,
    state: ConnectionState,
): Boolean = state == ConnectionState.Connected && device != null && device == deviceNow &&
    generation == generationNow && sessionId == sessionIdNow

/** The keepalive only runs while the app is visible, on a network device, and while nothing is being installed or restored. */
fun keepaliveAllowed(foreground: Boolean, local: Boolean, busy: Boolean): Boolean = foreground && !local && !busy

enum class WatchResult { Skipped, Alive, Suspect, Lost }

const val FirstPingMs = 8_000L
const val SecondPingMs = 10_000L

/**
 * Looks after the session of [snapshot]: the library's flags (free), and on request one keepalive under [adbLock]
 * (only if the lock is free: a busy lock means the session is working, i.e. alive). The ping gets 8 s the first time
 * and 10 s the second; two failures in a row lose the session. Whatever is found is applied only if the session is
 * still the same ([shouldApplyLoss]), checked again inside the lock, and the session is closed with [AdbClient.kill]
 * first so a call stuck on a dead socket lets go of the lock.
 */
class SessionWatch(
    private val adb: AdbClient,
    private val adbLock: Mutex,
    private val log: TerminalLog,
    private val snapshot: () -> SessionSnapshot,
    private val tracker: LivenessTracker = LivenessTracker(),
    private val io: CoroutineDispatcher = Dispatchers.IO,
) {
    fun reset() = tracker.reset()

    fun isCurrent(session: SessionSnapshot): Boolean = snapshot().let {
        shouldApplyLoss(session.generation, it.generation, session.sessionId, it.sessionId, session.device, it.device, it.state)
    }

    /** One look; [onLost] runs on the caller's context, only if the loss still applies. */
    suspend fun check(session: SessionSnapshot, keepalive: Boolean, onLost: (String) -> Unit): WatchResult {
        if (!isCurrent(session)) return WatchResult.Skipped
        if (!adb.isAlive) {
            tracker.onFlagsDead()
            return lose(session, "the library reports the connection as ended", onLost)
        }
        if (!keepalive || !adbLock.tryLock()) return WatchResult.Skipped
        val (verdict, failure) = try {
            if (!isCurrent(session)) return WatchResult.Skipped
            val timeout = if (tracker.suspect) SecondPingMs else FirstPingMs
            val error = withContext(io) { runCatching { adb.ping(timeout) }.exceptionOrNull() }
            // The user may have moved on while the ping ran: its answer is about a session that is gone.
            if (!isCurrent(session)) return WatchResult.Skipped
            tracker.onPing(error == null) to error
        } finally {
            adbLock.unlock()
        }
        return when (verdict) {
            LivenessTracker.Verdict.Healthy -> WatchResult.Alive
            LivenessTracker.Verdict.Suspect -> WatchResult.Suspect
            LivenessTracker.Verdict.Lost -> lose(session, "no answer to 2 pings (${failure?.let(::diagnostic)})", onLost)
        }
    }

    private suspend fun lose(session: SessionSnapshot, reason: String, onLost: (String) -> Unit): WatchResult {
        val closed = withContext(io) {
            if (!isCurrent(session)) return@withContext false
            // Lock-free first: whoever holds the lock may be stuck on this very socket.
            runCatching { adb.kill() }
            adbLock.withLock {
                if (!isCurrent(session)) return@withLock false
                runCatching { adb.disconnect() }
                true
            }
        }
        if (!closed || !isCurrent(session)) return WatchResult.Skipped
        log.add(lostLine(reason))
        onLost(reason)
        return WatchResult.Lost
    }
}

fun lostLine(reason: String) = "> session: lost - $reason"

// ---- The saved devices that are not connected ----

enum class Availability { Unknown, Available, Unavailable }

/**
 * Remembers what the probes found per host. Every host starts [Availability.Unknown] (grey); the first answer makes it
 * available, and only [missesToDrop] failed probes in a row make an available host unavailable again.
 */
class AvailabilityTracker(private val missesToDrop: Int = 2) {
    private val states = HashMap<String, Availability>()
    private val misses = HashMap<String, Int>()

    fun stateOf(host: String): Availability = states[normalise(host)] ?: Availability.Unknown

    fun record(host: String, up: Boolean): Availability {
        val key = normalise(host)
        val next = when {
            up -> {
                misses.remove(key)
                Availability.Available
            }
            states[key] == Availability.Available -> {
                val missed = (misses[key] ?: 0) + 1
                if (missed >= missesToDrop) {
                    misses.remove(key)
                    Availability.Unavailable
                } else {
                    misses[key] = missed
                    Availability.Available
                }
            }
            else -> Availability.Unavailable
        }
        states[key] = next
        return next
    }

    fun available(): Set<String> = states.filterValues { it == Availability.Available }.keys.toSet()

    /** Forgets every host that is not in [hosts] (forgotten, connected now, or on another network): it starts Unknown again. */
    fun retain(hosts: Collection<String>) {
        val keep = hosts.map(::normalise).toSet()
        states.keys.retainAll(keep)
        misses.keys.retainAll(keep)
    }
}

/** The saved devices worth a TCP probe: on a network this phone is on, not this phone, and not the one connected. */
fun probeTargets(recent: List<Target>, own: Collection<String>, subnets: Set<String>, connectedHost: String?): List<Target> {
    val seen = mutableSetOf<String>()
    return recent.filter { t ->
        val subnet = deviceSubnet(t)
        val tailnet = isTailscaleV4(t.host) && hasTailscaleAddress(own)
        !isLocalHost(t.host, own) && (tailnet || (subnet != null && subnet in subnets)) &&
            (connectedHost == null || normalise(t.host) != normalise(connectedHost)) && seen.add(normalise(t.host))
    }
}

/** True when mDNS announces a connect port of a probed host that the last probe did not try. */
fun hasNewConnectPorts(tested: Map<String, Set<Int>>, hosts: Collection<String>, found: List<Found>): Boolean =
    hosts.any { host ->
        found.any { it.kind == FoundKind.Connect && normalise(it.host) == normalise(host) && it.port !in tested[normalise(host)].orEmpty() }
    }

/** On start the app reconnects to the last device only if it is this phone or on a network this phone is on. */
fun startupReconnect(recent: List<Target>, own: Collection<String>, subnets: Set<String>): Target? =
    recent.firstOrNull()?.takeIf { t ->
        isLocalHost(t.host, own) || (isTailscaleV4(t.host) && hasTailscaleAddress(own)) || deviceSubnet(t).let { it != null && it in subnets }
    }
