package app.gogogadget

import android.content.Context
import io.github.muntashirakon.adb.AbsAdbConnectionManager
import io.github.muntashirakon.adb.AdbConnection
import io.github.muntashirakon.adb.AdbStream
import io.github.muntashirakon.adb.PairingConnectionCtx
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.SocketTimeoutException
import java.security.PrivateKey
import java.security.cert.Certificate
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Everything the app needs from ADB. Blocking calls: run them off the main thread. */
interface AdbClient {
    val isConnected: Boolean

    /** Counts the successful [connect] calls; 0 without a session. A verdict about an older session can be told apart by it. */
    val sessionId: Long get() = 0L

    /** The library's own liveness flags. Takes no library lock and never blocks, so it is safe on any thread. */
    val isAlive: Boolean get() = isConnected

    /** Pairs with the device's pairing service. Never log [code]. */
    fun pair(host: String, port: Int, code: String)

    fun connect(host: String, port: Int)

    /** Like [pair] with the ADB key of [identity]; clients with a single key ignore it. */
    fun pair(host: String, port: Int, code: String, identity: IdentityName) = pair(host, port, code)

    fun connect(host: String, port: Int, identity: IdentityName) = connect(host, port)

    /** Deletes the key of [identity] (closing its session); the next use creates a new one. */
    fun deleteIdentity(identity: IdentityName) {}

    /** Runs a shell command and returns its output. */
    fun shell(command: String): String

    /**
     * Streams exactly [size] bytes from [apk] into [command] (`cmd package install -S <size> ...`) and returns
     * its output. Works for any connected device, local or not. [onProgress] gets the bytes written so far, about ten
     * times a second and once more when the last byte is out.
     */
    fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit = {}): String

    /**
     * Streams exactly [size] bytes from [input] into [command] over a binary-safe `exec:` stream and returns its
     * output, reporting bytes written so far via [onProgress].
     */
    fun writeStream(command: String, size: Long, input: InputStream, onProgress: (Long) -> Unit = {}): String =
        install(command, size, input, onProgress)

    /**
     * Pulls a remote file from the target device to [destFile]. Returns true if successfully saved.
     */
    fun pull(remotePath: String, destFile: File): Boolean = false

    /** A round trip to the device that gives up after [timeoutMs]; throws when the device does not answer in time. */
    fun ping(timeoutMs: Long) {
        if (PingAnswer !in shell(PingCommand)) throw IOException("Unexpected answer to the ping")
    }

    /**
     * Closes the live session (or the connect in progress) without taking any library lock, so a call stuck on a dead
     * socket lets go. [disconnect] may wait behind such a call; this never does.
     */
    fun kill() {}

    fun disconnect()
}

const val PingAnswer = "gogo"
const val PingCommand = "echo $PingAnswer"

/** Holds one ADB key (loaded or made on first use) for the library; a failure on the way is an [AdbKeyException]. */
private class KeyedManager(context: Context, name: IdentityName, keyLock: Any) : AbsAdbConnectionManager() {
    // A lazy that throws is retried on the next call. Making and deleting key files never interleave ([keyLock]).
    private val identity by lazy {
        try {
            synchronized(keyLock) { AdbKeyStore(context, name).loadOrCreate() }
        } catch (e: AdbKeyException) {
            throw e
        } catch (e: Exception) {
            throw AdbKeyException(e)
        } catch (e: LinkageError) {
            throw AdbKeyException(e)
        }
    }

    init {
        // adbd on Android 11+ (minSdk 30) speaks protocol 30.
        setApi(30)
        setTimeout(ConnectTimeoutSeconds, TimeUnit.SECONDS)
    }

    /** The key, loaded now: callers get the [AdbKeyException] here instead of from inside the library. */
    fun keys(): AdbIdentity = identity

    override fun getPrivateKey(): PrivateKey = identity.privateKey
    override fun getCertificate(): Certificate = identity.certificate
    override fun getDeviceName(): String = DeviceName
}

// A little longer than the app's own 45 s Allow watchdog, which closes the socket first.
private const val ConnectTimeoutSeconds = 50L
private const val ShellTimeoutMs = 30_000L
private const val PullTimeoutMs = 120_000L

// Opening a stream waits for the device's answer with no timeout of its own: on a half-open connection it never returns.
private const val OpenTimeoutMs = 15_000L
private const val PairTimeoutMs = 25_000L
private const val DeviceName = "GoGo Gadget"

/** [note] gets the odd line worth showing in the terminal log (a TLS reset that failed). */
class LibAdbClient(context: Context, private val note: (String) -> Unit = {}) : AdbClient {
    private val appContext = context.applicationContext
    private val managers = HashMap<IdentityName, KeyedManager>()

    // Taken while a key is made or deleted, so a delete never lands in the middle of a key being made.
    private val keyLock = Any()

    // The manager that holds the live session; shell, install and pull go through it.
    @Volatile private var active: AbsAdbConnectionManager? = null

    // The pairing in flight, so [disconnect] can end it (a pairing socket belongs to no manager).
    @Volatile private var pairing: PairingConnectionCtx? = null

    // The library's connection of the live session and the thread that is connecting: [kill] and [isAlive] use them
    // without ever touching the library's lock.
    @Volatile private var live: AdbConnection? = null
    @Volatile private var connecting: Thread? = null
    private val sessions = AtomicLong()

    private fun managerFor(name: IdentityName): KeyedManager = synchronized(managers) {
        managers.getOrPut(name) { KeyedManager(appContext, name, keyLock) }
    }

    private val manager: AbsAdbConnectionManager get() = active ?: managerFor(IdentityName.Shared)

    override val isConnected: Boolean get() = active?.isConnected == true

    override val sessionId: Long get() = if (live != null) sessions.get() else 0L

    override val isAlive: Boolean get() = live?.let { it.isConnected && it.isConnectionEstablished } == true

    // See LibAdbTls: the library would reuse the TLS context of the first key it ever saw.
    private fun freshTlsContext() {
        if (!LibAdbTls.reset()) note("> tls: the cached TLS context could not be reset")
    }

    override fun pair(host: String, port: Int, code: String) = pair(host, port, code, IdentityName.Shared)

    // Not AbsAdbConnectionManager.pair: that gives no handle on the socket, so a pairing that hangs could neither be
    // cancelled nor time out, and would keep the ADB lock for good.
    override fun pair(host: String, port: Int, code: String, identity: IdentityName) {
        val keys = managerFor(identity).keys()
        freshTlsContext()
        val ctx = PairingConnectionCtx(host, port, code.toByteArray(Charsets.UTF_8), keys.privateKey, keys.certificate, DeviceName)
        pairing = ctx
        val late = AtomicBoolean()
        val timer = watchdog.schedule({ late.set(true); runCatching { ctx.close() } }, PairTimeoutMs, TimeUnit.MILLISECONDS)
        try {
            ctx.start()
        } catch (e: Exception) {
            if (late.get()) throw SocketTimeoutException("The pairing service didn't answer in ${PairTimeoutMs / 1000} s.")
            throw e
        } finally {
            timer.cancel(false)
            if (pairing === ctx) pairing = null
            // Closing also wipes the code from memory; it throws if the connection never got as far as TLS.
            runCatching { ctx.close() }
        }
    }

    override fun connect(host: String, port: Int) = connect(host, port, IdentityName.Shared)

    override fun connect(host: String, port: Int, identity: IdentityName) {
        disconnect()
        val next = managerFor(identity)
        next.keys()
        freshTlsContext()
        connecting = Thread.currentThread()
        try {
            if (!next.connect(host, port)) throw IOException("Timed out while connecting")
        } catch (t: Throwable) {
            // A failed connect must not leave its socket and reader thread open until the next connect.
            runCatching { next.disconnect() }
            throw t
        } finally {
            connecting = null
            // A kill that came in late must not leave the flag set on a pooled thread.
            Thread.interrupted()
        }
        live = next.adbConnection
        sessions.incrementAndGet()
        active = next
    }

    override fun deleteIdentity(identity: IdentityName) {
        synchronized(keyLock) {
            // Everything becomes this phone's key, the shared key and every per-device key found on disk or in the Keystore.
            val keys = expandIdentities(appContext, setOf(identity))
            for (key in keys) {
                val doomed = synchronized(managers) { managers.remove(key) }
                if (doomed != null) {
                    runCatching { doomed.disconnect() }
                    if (active === doomed) {
                        active = null
                        live = null
                    }
                }
            }
            // The cached TLS context still holds a key that is about to go (one context for every identity).
            freshTlsContext()
            var failure: Exception? = null
            for (key in keys) {
                try {
                    AdbKeyStore(appContext, key).delete()
                } catch (e: Exception) {
                    // The others are still deleted; the caller keeps the mark and tries again.
                    failure = failure ?: e
                }
            }
            failure?.let { throw it }
        }
    }

    // Read until the end marker, never until EOF; a timeout closes only this stream, never the session.
    override fun shell(command: String): String = shellWithin(command, ShellTimeoutMs, OpenTimeoutMs)

    // Both the opening of the stream and the reading are bounded, so a dead device never keeps the ADB lock for long.
    private fun shellWithin(command: String, readMs: Long, openMs: Long): String {
        val output = openStream("shell:${withEndMarker(command)}", openMs).use { stream ->
            stream.guarded(readMs) { readUntil(stream.openInputStream()) { outputBeforeMarker(it) != null } }
        }
        return outputBeforeMarker(output) ?: throw IOException("The device closed the connection before finishing.")
    }

    override fun ping(timeoutMs: Long) {
        if (PingAnswer !in shellWithin(PingCommand, timeoutMs, timeoutMs)) throw IOException("Unexpected answer to the ping")
    }

    /**
     * [AbsAdbConnectionManager.openStream] on a helper thread, given up after [ms]: the library waits for the device's
     * answer with no timeout, and interrupting its thread is what lets that wait (and the library's lock) go.
     */
    private fun openStream(command: String, ms: Long): AdbStream {
        val target = manager
        val task = streamPool.submit<AdbStream> { target.openStream(command) }
        try {
            return task.get(ms, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            // A stream that opened just now would never be closed by anyone else.
            if (!task.cancel(true)) runCatching { task.get().close() }
            throw SocketTimeoutException("The device didn't open a stream in ${ms / 1000} s.")
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        }
    }

    // "exec:" keeps stdin binary-safe (no pty); the command stops reading after -S bytes, so no EOF is needed.
    override fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit): String {
        val output = openStream("exec:${withEndMarker(command)}", OpenTimeoutMs).use { stream ->
            stream.guarded(installTimeoutMs(size)) {
                val writeError = try {
                    writeExactly(stream.openOutputStream(), apk, size, onProgress)
                    null
                } catch (e: IOException) {
                    e
                }
                // A device that rejects the command (an old Android and the bypass flag) stops reading and
                // closes the stream: its message is the result, not a lost connection.
                val said = readUntil(stream.openInputStream(), ::isInstallOutputComplete)
                if (writeError != null && said.isBlank()) throw writeError
                said
            }
        }
        return outputBeforeMarker(output) ?: output
    }

    private fun writeExactly(out: OutputStream, apk: InputStream, size: Long, onProgress: (Long) -> Unit) {
        val buffer = ByteArray(64 * 1024)
        val throttle = ProgressThrottle()
        var left = size
        while (left > 0) {
            val n = apk.read(buffer, 0, minOf(buffer.size.toLong(), left).toInt())
            if (n < 0) throw FileEndedException(size)
            out.write(buffer, 0, n)
            left -= n
            val sent = size - left
            if (throttle.shouldReport(System.nanoTime() / 1_000_000L, sent, size)) onProgress(sent)
        }
        out.flush()
    }

    override fun pull(remotePath: String, destFile: File): Boolean {
        destFile.parentFile?.mkdirs()
        val local = java.io.File(remotePath)
        if (local.exists() && local.canRead()) {
            return try {
                local.copyTo(destFile, overwrite = true)
                destFile.exists() && destFile.length() > 0L
            } catch (_: Throwable) {
                false
            }
        }
        return try {
            val safePath = remotePath.replace("'", "'\\''")
            openStream("exec:cat '$safePath'", OpenTimeoutMs).use { stream ->
                stream.guarded(PullTimeoutMs) {
                    destFile.outputStream().use { output ->
                        stream.openInputStream().copyTo(output, 64 * 1024)
                    }
                }
            }
            destFile.exists() && destFile.length() > 0L
        } catch (_: Throwable) {
            false
        }
    }

    override fun kill() {
        // Interrupting ends a connect that waits for the device; closing the connection ends a stream that waits for it.
        connecting?.interrupt()
        live?.let { runCatching { it.close() } }
    }

    override fun disconnect() {
        pairing?.let { runCatching { it.close() } }
        val all = synchronized(managers) { managers.values.toList() }
        all.forEach { runCatching { it.disconnect() } }
        active = null
        live = null
    }
}

/** The picked file ended before the size the system reported; the install cannot succeed. */
class FileEndedException(size: Long) : IOException("The file ended before $size bytes")

private val watchdog = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "adb-watchdog").apply { isDaemon = true } }
private val streamPool = Executors.newCachedThreadPool { r -> Thread(r, "adb-open").apply { isDaemon = true } }

/**
 * Runs [block]; if it takes longer than [ms] this stream (not the session) is closed under it, which unblocks its
 * reads and writes, and the call throws.
 */
private fun <T> AdbStream.guarded(ms: Long, block: () -> T): T {
    val late = AtomicBoolean()
    val timer = watchdog.schedule({ late.set(true); runCatching { close() } }, ms, TimeUnit.MILLISECONDS)
    val result = try {
        block()
    } catch (e: IOException) {
        if (late.get()) throw SocketTimeoutException("The device didn't answer in ${ms / 1000} s.") else throw e
    } finally {
        timer.cancel(false)
    }
    if (late.get()) throw SocketTimeoutException("The device didn't answer in ${ms / 1000} s.")
    return result
}
