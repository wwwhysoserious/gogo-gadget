package app.gogogadget

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.ConnectException

const val LoopbackHost = "127.0.0.1"

/**
 * Hosts the notification service tries, in order: loopback first (what Shizuku does), then the address the pairing
 * dialog showed when it really is one of this phone's own addresses (the [seen] host travels in the notification, so
 * it is checked again here).
 */
fun servicePairingHosts(seen: String?, own: Collection<String>): List<String> =
    listOfNotNull(LoopbackHost, seen?.trim()?.takeIf { it.isNotEmpty() && isLocalHost(it, own) }).distinct()

/** True when nothing was exchanged: the connection itself was refused. Only then is another address worth a try. */
fun isRefused(e: Throwable): Boolean = generateSequence(e) { it.cause }.take(8).any { it is ConnectException }

/**
 * Pairs [identity] with the pairing service at [port], one host after the other; only a refused connection moves on to
 * the next host. Throws the last failure. Blocks: call it off the main thread, with the ADB lock held.
 */
fun pairAcross(adb: AdbClient, hosts: List<String>, port: Int, code: String, identity: IdentityName) {
    var failure: Throwable? = null
    for (host in hosts) {
        try {
            adb.pair(host, port, code, identity)
            return
        } catch (e: Throwable) {
            failure = e
            if (!isRefused(e)) break
        }
    }
    throw failure ?: IllegalArgumentException("No pairing host")
}

/** How one pairing attempt of this phone ended; [exceptionName] and [detail] never hold the code. */
sealed interface PairOutcome {
    data object Paired : PairOutcome

    class Failed(val error: AdbError, val detail: String, val exceptionName: String) : PairOutcome
}

/**
 * The whole pairing of this phone as the notification service runs it: under the shared ADB [lock], so a key that is
 * being deleted (or made) is never in use, with every failure classified and written to [log]. A failure that
 * [classifyError] does not know stays [AdbError.Failed] but always carries the exception class and message. Blocks the
 * calling thread while it pairs: call it off the main thread.
 */
suspend fun runLocalPairing(
    adb: AdbClient,
    lock: Mutex,
    hosts: List<String>,
    port: Int,
    code: String,
    log: (String) -> Unit,
): PairOutcome = lock.withLock {
    log("> pair: this device, identity ${IdentityName.Local.id}, port $port")
    try {
        pairAcross(adb, hosts, port, code, IdentityName.Local)
        log("> pair: paired")
        PairOutcome.Paired
    } catch (e: CancellationException) {
        throw e
    } catch (t: Throwable) {
        val error = classifyError(t, Phase.Pair, local = true)
        log(failureLine("pair", t) + " [${error.name}]")
        PairOutcome.Failed(error, diagnostic(t), exceptionName(t))
    }
}
