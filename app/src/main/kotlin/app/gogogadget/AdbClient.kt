package app.gogogadget

import android.content.Context
import io.github.muntashirakon.adb.AbsAdbConnectionManager
import io.github.muntashirakon.adb.AdbStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.SocketTimeoutException
import java.security.PrivateKey
import java.security.cert.Certificate
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Everything the app needs from ADB. Blocking calls: run them off the main thread. */
interface AdbClient {
    val isConnected: Boolean

    /** Pairs with the device's pairing service. Never log [code]. */
    fun pair(host: String, port: Int, code: String)

    fun connect(host: String, port: Int)

    /** Runs a shell command and returns its output. */
    fun shell(command: String): String

    /**
     * Streams exactly [size] bytes from [apk] into [command] (`cmd package install -S <size> ...`) and returns
     * its output. Works for any connected device, local or not. [onProgress] gets the bytes written so far, about ten
     * times a second and once more when the last byte is out.
     */
    fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit = {}): String

    fun disconnect()
}

class LibAdbClient(context: Context) : AdbClient {
    // A failure here is reported as a key error (a lazy that throws is retried on the next call).
    private val identity by lazy {
        try {
            AdbKeyStore(context.applicationContext).loadOrCreate()
        } catch (e: Exception) {
            throw AdbKeyException(e)
        }
    }

    private val manager by lazy {
        object : AbsAdbConnectionManager() {
            init {
                // adbd on Android 11+ (minSdk 30) speaks protocol 30.
                setApi(30)
                setTimeout(ConnectTimeoutSeconds, TimeUnit.SECONDS)
            }

            override fun getPrivateKey(): PrivateKey = identity.privateKey
            override fun getCertificate(): Certificate = identity.certificate
            override fun getDeviceName(): String = "GoGo Gadget"
        }
    }

    override val isConnected: Boolean get() = manager.isConnected

    override fun pair(host: String, port: Int, code: String) {
        manager.pair(host, port, code)
    }

    override fun connect(host: String, port: Int) {
        manager.disconnect()
        if (!manager.connect(host, port)) {
            manager.disconnect()
            throw IOException("Timed out while connecting")
        }
    }

    // Read until the end marker, never until EOF; a timeout closes only this stream, never the session.
    override fun shell(command: String): String {
        val output = manager.openStream("shell:${withEndMarker(command)}").use { stream ->
            stream.guarded(ShellTimeoutMs) { readUntil(stream.openInputStream()) { outputBeforeMarker(it) != null } }
        }
        return outputBeforeMarker(output) ?: throw IOException("The device closed the connection before finishing.")
    }

    // "exec:" keeps stdin binary-safe (no pty); the command stops reading after -S bytes, so no EOF is needed.
    override fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit): String {
        val output = manager.openStream("exec:${withEndMarker(command)}").use { stream ->
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

    override fun disconnect() {
        manager.disconnect()
    }

    private companion object {
        // A little longer than the app's own 45 s Allow watchdog, which closes the socket first.
        const val ConnectTimeoutSeconds = 50L
        const val ShellTimeoutMs = 30_000L
    }
}

/** The picked file ended before the size the system reported; the install cannot succeed. */
class FileEndedException(size: Long) : IOException("The file ended before $size bytes")

private val watchdog = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "adb-watchdog").apply { isDaemon = true } }

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
