package app.gogogadget

import android.app.Application
import android.content.Context
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.provider.Settings
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException

/**
 * The last install attempt. [name] is the package name (or file name) once known; [percent] is 0..100 and stays
 * visible with the result. A failure has a [reason] (string resource, null when unknown) and the raw [raw] line.
 */
data class InstallStatus(
    val working: Boolean,
    val ok: Boolean = false,
    val name: String = "",
    val percent: Int = 0,
    val phase: InstallPhase = InstallPhase.Sending,
    val reason: Int? = null,
    val raw: String? = null,
)

private const val PREFS = "devices"
private const val KEY_RECENT = "recent"
private const val OP_PREFIX = "op"
private const val MAX_MODEL_LENGTH = 64
private const val LOOPBACK = "127.0.0.1"
private const val RESCAN_AFTER_MS = 5_000L
private const val CONNECT_TIMEOUT_MS = 25_000L
private const val NETWORK_PORT_WAIT_MS = 2_000L
private const val PAIR_TIMEOUT_MS = 25_000L
private const val INSTALL_TIMEOUT_MS = 10 * 60_000L

class ConnectionModel(
    app: Application,
    private val adb: AdbClient,
    private val discovery: DeviceDiscovery,
    private val pairing: PairingLauncher,
) : AndroidViewModel(app) {
    constructor(app: Application) : this(app, Graph.adb(app), Graph.discovery(app), ServicePairingLauncher(app))

    private val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    var connection by mutableStateOf(Connection())
        private set
    var recent by mutableStateOf(forgetPorts(decodeRecents(prefs.getString(KEY_RECENT, null))))
        private set
    var install by mutableStateOf<InstallStatus?>(null)
        private set

    /** Device being paired, and its pairing port: null until mDNS sees the pairing dialog (or a manual port is given). */
    var pairTarget by mutableStateOf<Target?>(null)
        private set
    var pairPort by mutableStateOf<Int?>(null)
        private set

    /** The pairing service mDNS last reported for [pairTarget]; its host is tried first for this device. */
    private var pairSeen: Found? = null

    val found = discovery.found

    private var job: Job? = null
    private var installJob: Job? = null
    private var abortJob: Job? = null
    private var generation = 0

    /** True while the pairing was done by the notification service, so the connect result is reported there too. */
    private var viaService = false

    /** ADB calls run one at a time, so a late call from an old operation cannot touch a newer session. */
    private val adbLock = Mutex()
    private val scanReasons = mutableSetOf<String>()

    init {
        PairingBridge.onPaired = ::pairedByService
        // Reconnect quietly to the last device with the stored key.
        recent.firstOrNull()?.let { connect(it, silent = true) }
    }

    fun thisDevice(): Target {
        val name = Settings.Global.getString(getApplication<Application>().contentResolver, "device_name")
        return Target(name?.takeIf { it.isNotBlank() } ?: Build.MODEL, LOOPBACK, 0)
    }

    fun scanForPicker(on: Boolean) = scan("picker", on)

    private fun scan(reason: String, on: Boolean) {
        val wasScanning = scanReasons.isNotEmpty()
        if (on) scanReasons += reason else scanReasons -= reason
        val scanning = scanReasons.isNotEmpty()
        if (scanning && !wasScanning) discovery.acquire()
        if (!scanning && wasScanning) discovery.release()
    }

    // ---- Connecting and pairing ----

    fun connect(target: Target, silent: Boolean = false) {
        pairing.stop()
        begin()
        job = viewModelScope.launch { run(target, silent = silent) }
    }

    fun startPairing(target: Target, pairingPort: Int? = null) {
        begin()
        enterPairing(target, pairingPort?.takeIf { it > 0 }, null)
    }

    private fun enterPairing(target: Target, port: Int?, error: AdbError?, detail: String? = null) {
        val own = ownAddresses()
        val local = isLocalHost(target.host, own)
        pairTarget = target
        pairPort = port
        pairSeen = null
        connection = Connection(
            ConnectionState.Pairing,
            Device(target.name, target.host, target.port, local),
            error,
            detail,
        )
        scan("pair", true)
        // This phone: the notification asks for the code (when allowed) and the dialog stays visible. Any other
        // device: the code is typed in the app only.
        if (local && pairing.canPost()) pairing.start() else pairing.stop()
        job = viewModelScope.launch {
            // The port is never typed: follow the pairing dialog's service as it appears, changes or goes away.
            found.map { resolvePairing(target, it, own) }.distinctUntilChanged().collect { seen ->
                pairSeen = seen
                if (seen != null || port == null) pairPort = seen?.port ?: port
            }
        }
    }

    private fun pairingThisDevice() = connection.state == ConnectionState.Pairing && connection.device?.local == true

    /** Re-evaluates the notification, e.g. after the user granted the permission while pairing this phone. */
    fun notificationsChanged() {
        if (pairingThisDevice() && pairing.canPost()) pairing.start()
    }

    fun notificationsAllowed(): Boolean = pairing.canPost()

    /** Shows the pairing notification again (this phone only), e.g. after they were closed. */
    fun repostNotification() {
        if (pairingThisDevice() && pairing.canPost()) pairing.restart()
    }

    /** The pairing service paired this phone from its notification: connect, the port comes from mDNS. */
    private fun pairedByService() {
        viewModelScope.launch {
            val target = pairTarget ?: return@launch
            if (connection.state != ConnectionState.Pairing) return@launch
            begin()
            viaService = true
            job = viewModelScope.launch { run(target, silent = false, paired = true) }
        }
    }

    /** Called with the six digits once typed and the port is known; the code is never stored or logged. */
    fun submitCode(code: String) {
        val target = pairTarget ?: return
        val port = pairPort ?: return
        val seen = pairSeen
        val typedPort = port.takeIf { seen == null }
        // Pairing from the app closes the notification way.
        pairing.stop()
        pairing.dismiss()
        begin()
        viaService = false
        job = viewModelScope.launch {
            val own = ownAddresses()
            val local = isLocalHost(target.host, own)
            connection = Connection(ConnectionState.Connecting, Device(target.name, target.host, target.port, local))
            val hosts = pairingHosts(target, seen, local, LOOPBACK)
            var failure: Exception? = null
            for (host in hosts) {
                try {
                    blocking(PAIR_TIMEOUT_MS) { adb.pair(host, port, code) }
                    failure = null
                    break
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    failure = e
                    // Only a refused connection is worth another address: nothing was exchanged yet.
                    if (generateSequence<Throwable>(e) { it.cause }.take(8).none { it is ConnectException }) break
                }
            }
            failure?.let {
                // enterPairing asks for the code again.
                enterPairing(target, typedPort, classifyError(it, Phase.Pair, local), diagnostic(it))
                return@launch
            }
            run(target, silent = false, paired = true)
        }
    }

    fun cancel() {
        pairing.stop()
        pairing.dismiss()
        begin()
        viaService = false
        pairTarget = null
        connection = Connection()
        abortAdb(onlyIfBusy = false)
    }

    private fun begin() {
        generation++
        job?.cancel()
        installJob?.cancel()
        installJob = null
        install = null
        scan("pair", false)
        scanReasons.filter { it.startsWith(OP_PREFIX) }.forEach { scan(it, false) }
        // A blocking call from the old operation cannot be interrupted; closing the socket makes it fail
        // so the next call can take the lock. Later calls wait for this to finish first.
        abortAdb(onlyIfBusy = true)
    }

    private fun abortAdb(onlyIfBusy: Boolean) {
        if (onlyIfBusy && !adbLock.isLocked) return
        val previous = abortJob
        abortJob = viewModelScope.launch(NonCancellable + Dispatchers.IO) {
            previous?.join()
            runCatching { adb.disconnect() }
        }
    }

    private fun fail(error: AdbError, detail: String? = null) {
        scan("pair", false)
        scanReasons.filter { it.startsWith(OP_PREFIX) }.forEach { scan(it, false) }
        connection = Connection(ConnectionState.Error, connection.device, error, detail)
        finishNotification(error.message)
    }

    /** Reports the end of a pairing that went through the notification service in that notification too. */
    private fun finishNotification(message: Int) {
        if (viaService) pairing.report(message)
        viaService = false
    }

    private suspend fun run(target: Target, silent: Boolean, paired: Boolean = false) {
        val own = ownAddresses()
        val local = isLocalHost(target.host, own)
        val host = if (local) LOOPBACK else target.host
        connection = Connection(ConnectionState.Connecting, Device(target.name, host, target.port, local))
        val opKey = "$OP_PREFIX$generation"
        scan(opKey, true)
        // Right after pairing no Allow prompt is expected, and a silent reconnect stays quiet.
        val quiet = silent || paired
        try {
            val port = when {
                target.port > 0 -> target.port
                local -> findConnectPort(target, own, paired)
                else -> networkConnectPort(0, findNetworkPort(target.host))
            }
            if (port == null || firstStep(local, port) == FirstStep.PairNow) {
                // Only this phone gets here: Wireless debugging is off or was never paired.
                when (noPortAction(silent, paired)) {
                    NoPortAction.GoIdle -> connection = Connection()
                    NoPortAction.StartPairing -> { viaService = false; enterPairing(target, null, null) }
                    NoPortAction.ReportMissing -> fail(AdbError.NoConnectPort)
                }
                return
            }
            // Connect straight away: if the device shows "Allow debugging?", the user taps Allow on it. adbd waits for
            // that tap with no timeout of its own, so the watchdog gives up after 45 s.
            connection = connection.copy(note = allowNoteFor(local, quiet))
            blocking(connectTimeoutMs(quiet)) { adb.connect(host, port) }
            val name = if (local) target.name else networkDisplayName(target.name, target.host, deviceModel())
            val device = Device(name, host, port, local)
            connection = Connection(ConnectionState.Connected, device)
            finishNotification(R.string.notif_connected)
            saveRecent(Target(name, host, 0), own)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val error = connectFailure(e, local, quiet)
            when (nextAfterConnectFailure(error, local, silent)) {
                Next.GoIdle -> connection = Connection()
                // This phone: the notification service; another device: the code typed in the app. Both follow the
                // pairing dialog's own mDNS service, so no port is typed.
                Next.PairWithNotification, Next.PairWithCodeInApp -> { viaService = false; enterPairing(target, null, null) }
                Next.Fail -> fail(error, diagnostic(e))
            }
        } finally {
            scan(opKey, false)
        }
    }

    /** Wireless debugging port of a network device, if mDNS shows it soon; otherwise the caller uses 5555. */
    private suspend fun findNetworkPort(host: String): Int? =
        mdnsConnectPort(host, found.value)
            ?: withTimeoutOrNull(NETWORK_PORT_WAIT_MS) { found.map { mdnsConnectPort(host, it) }.filterNotNull().first() }

    /** Waits for the connect service; after pairing it is looked up again halfway, as it may appear late. */
    private suspend fun findConnectPort(target: Target, own: Set<String>, paired: Boolean): Int? {
        suspend fun look(ms: Long) = withTimeoutOrNull(ms) {
            found.map { resolveConnectPort(target, it, own) }.filterNotNull().first()
        }
        val total = connectPortWaitMs(paired)
        if (!paired) return look(total)
        return look(RESCAN_AFTER_MS) ?: run {
            discovery.restart()
            look(total - RESCAN_AFTER_MS)
        }
    }

    private suspend fun deviceModel(): String? = try {
        // A late answer must not tear down the session that was just established.
        blocking(CONNECT_TIMEOUT_MS, disconnectOnTimeout = false) { adb.shell("getprop ro.product.model") }
            .trim().take(MAX_MODEL_LENGTH).ifEmpty { null }
    } catch (e: IOException) {
        null
    }

    private fun saveRecent(target: Target, own: Set<String>) {
        recent = addRecent(recent, target, own)
        prefs.edit().putString(KEY_RECENT, encodeRecents(recent)).apply()
    }

    /**
     * Runs a blocking call off the main thread, one at a time; gives up (and drops the late result) after
     * [timeoutMs]. A call that timed out in the current generation closes the session unless
     * [disconnectOnTimeout] is false.
     */
    private suspend fun <T> blocking(timeoutMs: Long, disconnectOnTimeout: Boolean = true, block: () -> T): T {
        val mine = generation
        val work: Deferred<T> = viewModelScope.async(Dispatchers.IO) {
            abortJob?.join()
            adbLock.withLock { block() }
        }
        fun abandon() = work.invokeOnCompletion {
            if (!disconnectOnTimeout) return@invokeOnCompletion
            viewModelScope.launch(Dispatchers.IO) {
                adbLock.withLock { if (mine == generation) runCatching { adb.disconnect() } }
            }
        }
        try {
            return withTimeout(timeoutMs) { work.await() }
        } catch (e: TimeoutCancellationException) {
            abandon()
            throw WatchdogTimeoutException()
        } catch (e: CancellationException) {
            abandon()
            throw e
        }
    }

    // ---- Installing ----

    /** [uri] is null when the picker was cancelled; only one install runs at a time. */
    fun installFrom(uri: Uri?) {
        if (uri == null || connection.state != ConnectionState.Connected || install?.working == true) return
        install = InstallStatus(working = true)
        installJob = viewModelScope.launch {
            val result = try {
                installApk(uri)
            } catch (e: CancellationException) {
                // A reconnect clears `install` first, so this only shows when the job was cancelled in place.
                if (install?.working == true) install = failed(install, transferFailure(e, null))
                throw e
            } catch (e: IOException) {
                // Only a gone session is a lost connection; a stream that ended or timed out leaves it up.
                val lost = installErrorIsConnectionLoss(adb.isConnected)
                if (lost) connection = Connection(ConnectionState.Error, connection.device, AdbError.ConnectionLost, diagnostic(e))
                failed(install, transferFailure(e, diagnostic(e), sessionConnected = !lost))
            } catch (e: Exception) {
                failed(install, transferFailure(e, diagnostic(e)))
            }
            install = result
        }
    }

    private fun failed(status: InstallStatus?, failure: InstallFailure) =
        (status ?: InstallStatus(false)).copy(working = false, ok = false, reason = failure.reason, raw = failure.raw)

    private fun failure(res: Int) = failed(install, InstallFailure(res, null))

    /** Streams the APK through the ADB connection: nothing is copied to the device. The app only makes a short-lived cache copy to read the package name. */
    private suspend fun installApk(uri: Uri): InstallStatus {
        val resolver = getApplication<Application>().contentResolver
        val (fileName, size) = withContext(Dispatchers.IO) { fileInfo(uri) }
        val mine = generation
        val generic = getApplication<Application>().getString(R.string.unnamed_package)
        install = install?.copy(name = installLabel(null, fileName, generic))
        if (!isSingleApk(fileName)) return failure(R.string.err_read_file)
        if (size == null || size <= 0) return failure(R.string.err_read_file)
        // The name shown is the applicationId when the manifest can be read, else the file name.
        val label = installLabel(withContext(Dispatchers.IO) { packageNameOf(uri) }, fileName, generic)
        if (mine != generation) throw CancellationException()
        install = install?.copy(name = label)
        fun report(sent: Long) {
            if (mine != generation) return
            val state = installPhase(sent, size, answered = false)
            install = install?.takeIf { it.working }?.copy(percent = state.percent, phase = state.phase)
        }
        // The client's own watchdog times the stream out; a slow install must never close the whole session.
        suspend fun attempt(bypass: Boolean): String? = blocking(INSTALL_TIMEOUT_MS, disconnectOnTimeout = false) {
            report(0)
            resolver.openInputStream(uri)?.use { adb.install(streamInstallCommand(size, bypass), size, it, ::report) }
        }
        var output = attempt(bypass = true) ?: return failure(R.string.err_read_file)
        if (shouldRetryWithoutBypass(output)) output = attempt(bypass = false) ?: return failure(R.string.err_read_file)
        val result = parsePmOutput(output)
        val status = install ?: InstallStatus(false, name = label)
        return if (result.success) status.copy(working = false, ok = true, percent = 100, phase = InstallPhase.Done)
        else failed(status, pmFailure(result.line))
    }

    /**
     * The applicationId from the APK's manifest, read by the platform on a temporary copy in the app cache (the
     * picked file is a content Uri); null when it cannot be read. The copy is always deleted.
     */
    private fun packageNameOf(uri: Uri): String? {
        val app = getApplication<Application>()
        val copy = File.createTempFile("parse", ".apk", app.cacheDir)
        return try {
            app.contentResolver.openInputStream(uri)?.use { input -> copy.outputStream().use { input.copyTo(it) } }
                ?: return null
            @Suppress("DEPRECATION")
            app.packageManager.getPackageArchiveInfo(copy.path, 0)?.packageName
        } catch (e: Exception) {
            null
        } finally {
            copy.delete()
        }
    }

    private fun fileInfo(uri: Uri): Pair<String?, Long?> = runCatching {
        getApplication<Application>().contentResolver
            .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)
            ?.use { c ->
                if (!c.moveToFirst()) return@use null
                val name = c.getColumnIndex(OpenableColumns.DISPLAY_NAME).takeIf { it >= 0 }?.let(c::getString)
                val size = c.getColumnIndex(OpenableColumns.SIZE).takeIf { it >= 0 && !c.isNull(it) }?.let(c::getLong)
                name to size
            }
    }.getOrNull() ?: (null to null)

    fun installUnavailable() {
        install = InstallStatus(false, reason = R.string.err_no_picker)
    }

    override fun onCleared() {
        PairingBridge.onPaired = null
        pairing.stop()
        if (scanReasons.isNotEmpty()) discovery.release()
        scanReasons.clear()
        Thread { runCatching { adb.disconnect() } }.start()
    }
}
