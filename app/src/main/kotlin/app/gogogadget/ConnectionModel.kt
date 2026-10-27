package app.gogogadget

import android.app.Application
import android.content.Context
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.provider.Settings
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.ensureActive
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

/** The Security shield asks to send [fileCount] unknown files ([totalBytes] in all) to VirusTotal; answers carry the [id]. */
data class UploadPrompt(val id: Int, val fileCount: Int, val totalBytes: Long)

/**
 * Interactive Caution Prompt (Yellow Tier):
 * The Security shield asks the user to acknowledge caution/mod risk on a YELLOW tier package; answers carry the [id].
 */
data class CautionPrompt(val id: Int, val packageName: String?, val reason: ShieldWarningReason, val detail: String)

/**
 * Checks whether an installation is permitted under the 3-Color Security Tier Architecture:
 * - Green / Clean: always permitted.
 * - Shield Off (null): permitted.
 * - Yellow: permitted ONLY if [userOverridden] is true AND all warning reasons are Yellow severity.
 * - Red: NEVER permitted. Protected fail-closed.
 */
fun mayInstall(verdict: ShieldVerdict?, userOverridden: Boolean = false): Boolean =
    verdict == null || verdict is ShieldVerdict.Clean ||
        (userOverridden && verdict is ShieldVerdict.Warning && verdict.reasons.all { it.severity() == SecuritySeverity.Yellow })

/**
 * Gate that suspends install execution on a YELLOW warning and awaits user decision.
 */
class CautionGate {
    private var lastId = 0
    private var pending: Pair<Int, CompletableDeferred<Boolean>>? = null

    fun open(): Pair<Int, CompletableDeferred<Boolean>> {
        pending?.second?.complete(false)
        return (++lastId to CompletableDeferred<Boolean>()).also { pending = it }
    }

    fun answer(id: Int, confirmed: Boolean) {
        pending?.takeIf { it.first == id }?.second?.complete(confirmed)
    }

    fun declinePending() {
        pending?.second?.complete(false)
    }

    fun close(question: Pair<Int, CompletableDeferred<Boolean>>) {
        if (pending === question) pending = null
    }
}

/** What the shield decided, and the files (with size and SHA-256) it checked, so they can be compared again before streaming. */
private data class ShieldRun(
    val verdict: ShieldVerdict?,
    val scanned: List<ScannedFile>,
    val installedInfo: InstalledAppInfo? = null,
)

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
    val shieldVerdict: ShieldVerdict? = null,
    val shieldChecking: Boolean = false,
    val uploadPrompt: UploadPrompt? = null,
    val cautionPrompt: CautionPrompt? = null,
    val logs: List<String> = emptyList(),
    /** The shield was switched off for this install, so the package was not checked. */
    val shieldOff: Boolean = false,
    val sourceUri: Uri? = null,
    val userAuthorized: Boolean = false,
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
    val shieldSettings = ShieldSettingsStore(app)
    private val installSettings = InstallSettingsStore(app)

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

    /** The pending upload question; used on the main thread only. */
    private val uploadGate = UploadGate()

    /** The pending caution confirmation question; used on the main thread only. */
    private val cautionGate = CautionGate()

    val backupManager = BackupManager(app)
    var backups by mutableStateOf<List<AppBackupItem>>(emptyList())
        private set

    var cautionPrompt by mutableStateOf<CautionPrompt?>(null)
        private set

    /** Shared by every VirusTotal request (lookups, upload calls, polling): the public API allows 4 per minute. */
    private val vtPacer = RequestPacer()

    /** True while the pairing was done by the notification service, so the connect result is reported there too. */
    private var viaService = false

    /** ADB calls run one at a time, so a late call from an old operation cannot touch a newer session. */
    private val adbLock = Mutex()
    private val scanReasons = mutableSetOf<String>()

    init {
        PairingBridge.onPaired = ::pairedByService
        refreshBackups()
        // Reconnect quietly to the last device with the stored key.
        recent.firstOrNull()?.let { connect(it, silent = true) }
    }

    fun refreshBackups() {
        viewModelScope.launch(Dispatchers.IO) {
            val list = backupManager.listBackups()
            withContext(Dispatchers.Main) {
                backups = list
            }
        }
    }

    fun confirmCaution(promptId: Int) {
        cautionGate.answer(promptId, true)
    }

    fun cancelCaution(promptId: Int) {
        cautionGate.answer(promptId, false)
    }

    fun deleteBackup(packageName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            backupManager.deleteBackup(packageName)
            val updated = backupManager.listBackups()
            withContext(Dispatchers.Main) {
                backups = updated
            }
        }
    }

    fun revertBackup(backup: AppBackupItem) {
        if (connection.state != ConnectionState.Connected || install?.working == true) return
        val mine = generation
        val label = backup.appName.ifBlank { backup.packageName }
        install = InstallStatus(working = true, name = label, phase = InstallPhase.Sending, percent = 0)
        installJob = viewModelScope.launch {
            appendLog(mine, "> revert: restoring v${backup.versionCode}...")
            try {
                val outcome = blocking(INSTALL_TIMEOUT_MS, disconnectOnTimeout = false) {
                    if (backup.apkFiles.size == 1) {
                        val apkFile = backup.apkFiles.first()
                        val apkSize = apkFile.length()
                        fun report(sent: Long) = updateInstallProgress(mine, sent, apkSize)
                        report(0)
                        val cmd = streamInstallCommand(apkSize, bypass = true, userInstall = false)
                        postLog(mine, "> adb: $cmd")
                        val output = apkFile.inputStream().use { input ->
                            adb.install(cmd, apkSize, input, ::report)
                        }
                        parsePmOutput(output)
                    } else {
                        val splits = backup.apkFiles.map { file ->
                            ExtractedFile(
                                entryPath = file.name,
                                name = file.name,
                                size = file.length(),
                                file = file,
                            )
                        }
                        installBundleSession(
                            adb = adb,
                            splits = splits,
                            obbs = emptyList(),
                            packageName = backup.packageName,
                            onProgress = { sent, total -> updateInstallProgress(mine, sent, total) },
                            onLog = { line -> postLog(mine, line) },
                            userInstall = false,
                        )
                    }
                }
                appendLog(mine, "> pm: ${outcome.line.ifBlank { if (outcome.success) "Success" else "Failure" }}")
                val status = install ?: InstallStatus(false, name = label)
                install = if (outcome.success) {
                    status.copy(working = false, ok = true, percent = 100, phase = InstallPhase.Done)
                } else {
                    failed(status, pmFailure(outcome.line))
                }
            } catch (e: CancellationException) {
                if (install?.working == true) install = failed(install, transferFailure(e, null))
                throw e
            } catch (t: Throwable) {
                install = failed(install, transferFailure(t, diagnostic(t)))
            }
        }
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
        // A pending upload question counts as "no".
        uploadGate.declinePending()
        cautionGate.declinePending()
        cautionPrompt = null
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
        val shieldOn = shieldSettings.shieldEnabled
        val initialPhase = if (shieldOn) InstallPhase.Checking else InstallPhase.Sending
        install = InstallStatus(working = true, phase = initialPhase, shieldChecking = shieldOn, sourceUri = uri)
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
            } catch (t: Throwable) {
                failed(install, transferFailure(t, diagnostic(t)))
            }
            install = result
        }
    }

    private fun failed(status: InstallStatus?, failure: InstallFailure) =
        (status ?: InstallStatus(false)).copy(
            working = false,
            ok = false,
            reason = failure.reason,
            raw = failure.raw,
            shieldVerdict = status?.shieldVerdict,
            shieldChecking = false,
            uploadPrompt = null,
            sourceUri = status?.sourceUri,
            logs = status?.logs.orEmpty() + listOfNotNull(failure.raw?.takeIf { it.isNotBlank() }?.let { "> error: $it" }),
        )

    private fun failure(res: Int) = failed(install, InstallFailure(res, null))

    private fun appendLog(mine: Int, line: String) {
        if (mine == generation) {
            install = install?.copy(logs = install?.logs.orEmpty() + line)
        }
    }

    private fun postLog(mine: Int, line: String) {
        viewModelScope.launch {
            appendLog(mine, line)
        }
    }

    private fun formatByteSize(bytes: Long): String = when {
        bytes >= 1024L * 1024L -> String.format(java.util.Locale.US, "%.2f MB (%d B)", bytes / (1024.0 * 1024.0), bytes)
        bytes >= 1024L -> String.format(java.util.Locale.US, "%.1f KB (%d B)", bytes / 1024.0, bytes)
        else -> "$bytes B"
    }

    private fun updateInstallProgress(mine: Int, sent: Long, total: Long) {
        val state = installPhase(sent, total, answered = false)
        viewModelScope.launch {
            if (mine == generation) {
                install = install?.takeIf { it.working }?.copy(percent = state.percent, phase = state.phase)
            }
        }
    }

    /**
     * Runs the Antivirus shield check (SHA-256 + offline signature/manifest analysis + a VirusTotal lookup of every APK,
     * and an upload of unknown ones when the user agrees). Returns null when the shield is disabled, otherwise a
     * [ShieldVerdict.Clean] or [ShieldVerdict.Warning]: whatever could not be proven clean is blocked.
     */
    private suspend fun verifyPackageWithShield(
        mine: Int,
        app: Application,
        sourceFile: File,
        displayName: String,
        bundle: ExtractedBundle,
        pkg: String?,
        pkgProblem: BundlePackageProblem?,
        isLocalDevice: Boolean,
    ): ShieldRun {
        val installedInfo = if (!pkg.isNullOrBlank() && pkgProblem == null) {
            try {
                blocking(CONNECT_TIMEOUT_MS, disconnectOnTimeout = false) {
                    queryInstalledAppInfo(adb, pkg, app.takeIf { isLocalDevice })
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                null
            }
        } else {
            null
        }

        if (!shieldSettings.shieldEnabled) {
            appendLog(mine, "> shield: OFF (disabled in settings)")
            if (mine == generation) install = install?.copy(shieldOff = true)
            return ShieldRun(null, emptyList(), installedInfo)
        }
        appendLog(mine, "> shield: scanning archive, X.509 certificates & AndroidManifest.xml...")

        val (sha256, offline) = withContext(Dispatchers.IO) {
            val hash = sha256Hex(sourceFile)
            val archiveApk = if (bundle.format == PackageFormat.SingleApk) sourceFile else bundle.findBaseApk()?.file
            val candidateInfo = archiveApk?.let { queryArchiveAppInfo(app, it) } ?: InstalledAppInfo(null, null)
            val report = analyzePackageOffline(
                sourceFile = sourceFile,
                bundle = bundle,
                installedSigSha256 = installedInfo?.sigSha256,
                installedVersionCode = installedInfo?.versionCode,
                candidateSigSha256 = candidateInfo.sigSha256,
                candidateVersionCode = candidateInfo.versionCode,
                candidateDebugOrTest = candidateInfo.debugOrTestSigned,
                candidateCertSubject = candidateInfo.certSubject,
            )
            hash to report
        }

        appendLog(mine, "> sha256: $sha256")
        if (pkgProblem != null) {
            appendLog(
                mine,
                if (pkgProblem == BundlePackageProblem.Unreadable) "> package: package name unreadable"
                else "> package: the name in the bundle does not match its APK files",
            )
            appendLog(mine, "> shield verdict: BLOCKED (${ShieldWarningReason.PackageMismatch.name})")
            return ShieldRun(ShieldVerdict.Warning(sha256, listOf(ShieldWarningReason.PackageMismatch), 0, 0, offline), emptyList(), installedInfo)
        }
        offline.versionCode?.let { vc ->
            appendLog(mine, "> versionCode: $vc${installedInfo?.versionCode?.let { " (installed on target: $it)" }.orEmpty()}")
        }
        val sigDetail = offline.certSubject ?: offline.signerSha256?.let(::truncateSha256) ?: "unknown"
        when {
            !offline.signed && offline.signerSha256 == null -> appendLog(mine, "> signature: UNSIGNED (signer certificate unreadable)")
            !offline.signed -> appendLog(mine, "> signature: UNSIGNED (a split has no V1/V2/V3 certificate)")
            offline.debugOrTestSigned -> appendLog(mine, "> signature: UNTRUSTED TEST/MOD KEY ($sigDetail)")
            offline.signatureMismatch -> appendLog(mine, "> signature: MISMATCH vs installed app ($sigDetail)")
            else -> appendLog(mine, "> signature: certificate read ($sigDetail), not verified here: the Android installer does that")
        }
        if (offline.allPermissions.isEmpty()) {
            appendLog(mine, "> permissions: 0 requested in AndroidManifest.xml (none granted by GoGo)")
        } else {
            appendLog(
                mine,
                "> permissions (${offline.allPermissions.size} requested, none granted by GoGo — user decides): ${offline.allPermissions.joinToString(", ")}",
            )
        }
        if (offline.highRiskPermissions.isNotEmpty()) {
            appendLog(mine, "> high-risk flags: ${offline.highRiskPermissions.joinToString(", ")}")
        }

        val combinedOffline = if (shieldSettings.deepScanEnabled) {
            appendLog(mine, "> deep scan: analyzing bytecode & assets...")
            val deepScanResult = withContext(Dispatchers.IO) {
                StaticAnalyzer.analyzeApkOrBundle(
                    sourceFile = sourceFile,
                    bundle = bundle,
                    permissions = offline.allPermissions,
                    packageName = pkg,
                )
            }
            if (mine != generation) throw CancellationException()
            if (deepScanResult.issues.isNotEmpty()) {
                for (issue in deepScanResult.issues) {
                    appendLog(mine, "> deep scan: found ${issue.reason.name} (${issue.detail})")
                }
                val combinedReasons = (offline.reasons + deepScanResult.issues.map { it.reason }).distinct()
                val primaryDetail = deepScanResult.issues.first().detail
                offline.copy(reasons = combinedReasons, issueDetail = primaryDetail)
            } else {
                appendLog(mine, "> deep scan: clean (0 dropper/adware signatures, ${deepScanResult.dexCount} DEX files inspected)")
                offline
            }
        } else {
            offline
        }

        val apiKey = withContext(Dispatchers.IO) { shieldSettings.loadVirusTotalApiKey() }?.takeIf { it.isNotBlank() }
        if (mine != generation) throw CancellationException()
        val trusted = isTrustedUpdate(combinedOffline, installedInfo)
        // The unit of proof is each APK; the container is never looked up. OBB files are data and are not scanned.
        if (bundle.obbs.isNotEmpty()) appendLog(mine, "> virustotal: ${bundle.obbs.size} .obb file(s) are data and are not scanned")
        val targets = if (bundle.format == PackageFormat.SingleApk) {
            listOf(displayName to sourceFile)
        } else {
            bundle.apks.map { it.name to it.file }
        }
        val evidence = mutableListOf<ShieldFileEvidence>()
        val filesBySha = mutableMapOf<String, File>()
        val scanned = mutableListOf<ScannedFile>()
        if (apiKey == null) appendLog(mine, "> virustotal: no API key set, no lookup")
        for ((name, file) in targets) {
            val size = file?.length() ?: 0L
            val sha = file?.let { withContext(Dispatchers.IO) { sha256Hex(it) } }.orEmpty()
            if (file != null && sha.isNotEmpty()) {
                filesBySha[sha] = file
                scanned += ScannedFile(file, size, sha)
            }
            var res: VtLookupResult = VtLookupResult.Unavailable
            if (apiKey != null && sha.isNotEmpty() && evidence.none { it.vt == VtLookupResult.InvalidKey }) {
                vtPacer.await()
                res = withContext(Dispatchers.IO) { checkVirusTotalHash(sha, apiKey) }
                if (mine != generation) throw CancellationException()
                appendLog(mine, vtLookupLine(sha, name, res))
            }
            evidence += ShieldFileEvidence(name, size, sha, res)
        }

        val first = evaluateShieldVerdict(sha256, combinedOffline, apiKey != null, trusted, evidence)
        val verdict = if (first is ShieldVerdict.NeedsUpload && apiKey != null) {
            resolveUpload(mine, first, filesBySha, evidence, apiKey, trusted, sha256, combinedOffline)
        } else {
            first
        }
        when (verdict) {
            is ShieldVerdict.Clean -> appendLog(
                mine,
                "> shield verdict: PASS (" + when {
                    verdict.trustedUpdate -> "update of the installed app, same signature" + (verdict.vtSummary?.let { ", VirusTotal $it" }.orEmpty())
                    else -> "VirusTotal ${verdict.vtSummary}"
                } + ")",
            )
            is ShieldVerdict.Warning -> {
                val tier = securityTierOf(verdict)
                if (tier == SecurityTier.Yellow) {
                    appendLog(mine, "> shield verdict: CAUTION (${verdict.reasons.joinToString(", ") { it.name }})")
                } else {
                    appendLog(mine, "> shield verdict: BLOCKED (${verdict.reasons.joinToString(", ") { it.name }})")
                }
            }
            is ShieldVerdict.NeedsUpload -> appendLog(mine, "> shield verdict: BLOCKED (${ShieldWarningReason.VirusTotalUnreachable.name})")
        }
        return ShieldRun(
            if (verdict is ShieldVerdict.NeedsUpload) {
                ShieldVerdict.Warning(sha256, listOf(ShieldWarningReason.VirusTotalUnreachable), 0, 0, combinedOffline)
            } else {
                verdict
            },
            scanned,
            installedInfo,
        )
    }

    private fun vtLookupLine(sha: String, name: String, res: VtLookupResult): String {
        val head = "> virustotal: ${sha.take(12)} $name:"
        return when (res) {
            is VtLookupResult.Found -> "$head ${res.malicious} malicious, ${res.suspicious} suspicious / ${res.total} engines, " +
                analysisAgeText(res.lastAnalysisDate, System.currentTimeMillis() / 1000L)
            VtLookupResult.UnknownHash -> "$head not in database"
            VtLookupResult.InvalidKey -> "$head API key rejected"
            VtLookupResult.RateLimited -> "$head rate limited"
            VtLookupResult.Unavailable -> "$head unreachable"
        }
    }

    /**
     * Asks the user before sending the unknown files to VirusTotal, uploads them and waits for the analysis, then
     * decides again. "No", a new install, a reconnect or a failure at any step all end as a Warning.
     */
    private suspend fun resolveUpload(
        mine: Int,
        needs: ShieldVerdict.NeedsUpload,
        filesBySha: Map<String, File>,
        evidence: List<ShieldFileEvidence>,
        apiKey: String,
        trusted: Boolean,
        sha256: String,
        offline: OfflineScanReport,
    ): ShieldVerdict {
        fun warn(reason: ShieldWarningReason) = ShieldVerdict.Warning(sha256, listOf(reason), 0, 0, offline)
        val candidates = needs.files.distinctBy { it.sha256 }
        val totalBytes = candidates.sumOf { it.sizeBytes }
        val question = uploadGate.open()
        install = install?.copy(shieldChecking = false, uploadPrompt = UploadPrompt(question.first, candidates.size, totalBytes))
        val confirmed = try {
            question.second.await()
        } finally {
            uploadGate.close(question)
            if (mine == generation) install = install?.copy(uploadPrompt = null, shieldChecking = true)
        }
        if (mine != generation) throw CancellationException()
        if (!confirmed) {
            appendLog(mine, "> virustotal: upload declined, the file stays unverified")
            return warn(ShieldWarningReason.NotKnownToVirusTotal)
        }

        val updated = evidence.toMutableList()
        var sentBefore = 0L
        for (candidate in candidates) {
            val file = filesBySha[candidate.sha256] ?: return warn(ShieldWarningReason.VirusTotalUnreachable)
            appendLog(mine, "> virustotal: upload ${formatUploadSize(candidate.sizeBytes)} ${candidate.name} (${candidate.sha256.take(12)})")
            install = install?.copy(phase = InstallPhase.Uploading, percent = 0)
            val throttle = ProgressThrottle()
            val base = sentBefore
            vtPacer.await()
            val upload = withContext(Dispatchers.IO) {
                uploadFileToVirusTotal(file, apiKey) { sent, _ ->
                    // Stops the transfer when the install was cancelled; the caller sees a CancellationException.
                    ensureActive()
                    if (throttle.shouldReport(System.currentTimeMillis(), sent, candidate.sizeBytes)) {
                        updateUploadProgress(mine, base + sent, totalBytes)
                    }
                }
            }
            if (mine != generation) throw CancellationException()
            val analysisId = (upload as? VtUploadResult.Started)?.analysisId
            if (analysisId == null) {
                appendLog(mine, "> virustotal: upload failed (${upload::class.simpleName})")
                return warn(ShieldWarningReason.VirusTotalUnreachable)
            }
            sentBefore += candidate.sizeBytes
            install = install?.copy(phase = InstallPhase.Analysing, percent = 99)
            appendLog(mine, "> virustotal: analysis queued for ${candidate.name}, waiting (up to 10 min)")
            val result = awaitVirusTotalAnalysis(analysisId, apiKey, vtPacer)
            if (mine != generation) throw CancellationException()
            if (result !is VtLookupResult.Found) {
                appendLog(mine, "> virustotal: analysis of ${candidate.name} did not complete (${result::class.simpleName})")
                return warn(ShieldWarningReason.VirusTotalUnreachable)
            }
            appendLog(mine, "> virustotal: analysis completed ${candidate.name}: ${result.malicious} malicious, ${result.suspicious} suspicious / ${result.total} engines")
            updated.replaceAll { if (it.sha256 == candidate.sha256) it.copy(vt = result) else it }
        }
        install = install?.copy(phase = InstallPhase.Checking, percent = 0)
        val again = evaluateShieldVerdict(sha256, offline, hasKey = true, trustedUpdate = trusted, files = updated)
        return if (again is ShieldVerdict.NeedsUpload) warn(ShieldWarningReason.VirusTotalUnreachable) else again
    }

    /** The user's answer to the upload prompt [promptId]; called on the main thread. An answer to an older prompt is ignored. */
    fun confirmUpload(promptId: Int) {
        uploadGate.answer(promptId, true)
    }

    fun cancelUpload(promptId: Int) {
        uploadGate.answer(promptId, false)
    }

    private fun updateUploadProgress(mine: Int, sent: Long, total: Long) {
        viewModelScope.launch {
            if (mine == generation && install?.phase == InstallPhase.Uploading) {
                install = install?.copy(percent = installPercent(sent, total, false))
            }
        }
    }

    /** The [ShieldVerdict.Warning] to show for a verdict that must not install: any verdict that is not a Warning is shown as unreachable. */
    private fun blockedBy(verdict: ShieldVerdict?): ShieldVerdict.Warning = verdict as? ShieldVerdict.Warning
        ?: ShieldVerdict.Warning(
            (verdict as? ShieldVerdict.NeedsUpload)?.sha256.orEmpty(),
            listOf(ShieldWarningReason.VirusTotalUnreachable),
            0,
            0,
            verdict?.offline,
        )

    private fun shieldBlockedStatus(label: String, verdict: ShieldVerdict.Warning, logs: List<String>): InstallStatus {
        val primaryReasonRes = when (verdict.reasons.firstOrNull()) {
            ShieldWarningReason.MalwareDetected -> R.string.shield_warn_malware_short
            ShieldWarningReason.UnsignedPackage -> R.string.shield_warn_unsigned
            ShieldWarningReason.DebugOrTestCertificate -> R.string.shield_warn_debug_cert
            ShieldWarningReason.SignatureMismatch -> R.string.shield_warn_signature
            ShieldWarningReason.VersionDowngrade -> R.string.shield_warn_downgrade
            ShieldWarningReason.VirusTotalKeyMissing -> R.string.shield_warn_vt_key_missing
            ShieldWarningReason.NotKnownToVirusTotal -> R.string.shield_warn_not_known
            ShieldWarningReason.VirusTotalUnreachable -> R.string.shield_warn_vt_unreachable
            ShieldWarningReason.TooFewEngines -> R.string.shield_warn_few_engines
            ShieldWarningReason.TooLargeToVerify -> R.string.shield_warn_too_large
            ShieldWarningReason.PackageMismatch -> R.string.shield_warn_package_mismatch
            ShieldWarningReason.DropperDetected -> R.string.shield_warn_dropper_short
            ShieldWarningReason.AdwareDetected -> R.string.shield_warn_adware_short
            ShieldWarningReason.AbusivePermissions -> R.string.shield_warn_abusive_permissions_short
            ShieldWarningReason.SelfUpdaterPermission -> R.string.shield_warn_self_updater
            null -> R.string.shield_blocked_generic
        }
        return InstallStatus(
            working = false,
            ok = false,
            name = label,
            percent = 100,
            phase = InstallPhase.Done,
            reason = primaryReasonRes,
            shieldVerdict = verdict,
            shieldChecking = false,
            logs = logs,
        )
    }

    private suspend fun resolveCautionPrompt(
        mine: Int,
        label: String,
        pkg: String?,
        verdict: ShieldVerdict?,
    ): Boolean {
        if (verdict !is ShieldVerdict.Warning) return false
        val tier = securityTierOf(verdict)
        if (tier != SecurityTier.Yellow) return false

        val primaryReason = verdict.reasons.first()
        val detail = when (primaryReason) {
            ShieldWarningReason.DropperDetected ->
                verdict.offline?.issueDetail ?: "Dynamic class loader (DexClassLoader) found in bytecode"
            ShieldWarningReason.DebugOrTestCertificate ->
                verdict.offline?.certSubject?.let { "Signed with test/mod certificate ($it)" }
                    ?: "Signed with untrusted public debug or test certificate"
            ShieldWarningReason.NotKnownToVirusTotal ->
                "File hash is not present in VirusTotal threat database"
            ShieldWarningReason.VirusTotalKeyMissing ->
                "No VirusTotal API key configured in Settings"
            else ->
                verdict.offline?.issueDetail ?: "Potential mod or dynamic code risk detected"
        }
        val question = cautionGate.open()
        val prompt = CautionPrompt(question.first, pkg, primaryReason, detail)
        cautionPrompt = prompt
        install = install?.copy(cautionPrompt = prompt, shieldChecking = false)
        val proceed = try {
            question.second.await()
        } finally {
            cautionGate.close(question)
            if (mine == generation) {
                cautionPrompt = null
                install = install?.copy(cautionPrompt = null)
            }
        }
        if (mine != generation) throw CancellationException()
        if (!proceed) {
            appendLog(mine, "> install: cancelled by user")
            return false
        }
        appendLog(mine, "> security override: risk acknowledged by user, proceeding with installation")
        return true
    }

    private suspend fun performAutoBackup(
        mine: Int,
        pkg: String?,
        installedInfo: InstalledAppInfo?,
    ) {
        if (installedInfo?.versionCode == null || pkg.isNullOrBlank()) return
        try {
            val item = withContext(Dispatchers.IO) {
                backupManager.createBackup(adb, pkg, installedInfo)
            }
            if (item != null) {
                appendLog(mine, "> backup: saved v${item.versionCode} to local backup")
                refreshBackups()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
        }
    }

    /**
     * Inspects the picked file by content (magic bytes and ZIP central directory), runs the Antivirus shield when
     * enabled, and installs it over ADB: single APKs use the fast single-command stream, while APKS/XAPK/APKM/ZIP
     * bundles extract into a dedicated temporary directory under external/internal cache, filter splits for the
     * target device, and run a multi-APK session (plus OBB streaming when present). The temporary directory is
     * always deleted in `finally`.
     */
    private suspend fun installApk(uri: Uri): InstallStatus {
        val app = getApplication<Application>()
        val resolver = app.contentResolver
        val (fileName, size) = withContext(Dispatchers.IO) { fileInfo(uri) }
        val mine = generation
        val userInstall = installSettings.homeShortcut
        val generic = app.getString(R.string.unnamed_package)
        install = install?.copy(name = installLabel(null, fileName, generic))
        if (size != null && size <= 0) return failure(R.string.err_read_file)

        val baseCache = app.externalCacheDir ?: app.cacheDir
        val bundleDir = File(baseCache, "bundle_${System.nanoTime()}")
        try {
            val sourceFile = File(bundleDir, "source.pkg")
            val copied = withContext(Dispatchers.IO) {
                bundleDir.mkdirs()
                resolver.openInputStream(uri)?.use { input ->
                    sourceFile.outputStream().use { output -> input.copyTo(output, 64 * 1024) }
                }
            }
            if (copied == null || copied <= 0L || sourceFile.length() <= 0L) {
                return failure(R.string.err_read_file)
            }
            appendLog(mine, "> source: ${fileName ?: uri.lastPathSegment ?: "package"} (${formatByteSize(sourceFile.length())})")

            val inspected = withContext(Dispatchers.IO) {
                inspectAndExtractPackage(sourceFile, bundleDir)
            }
            if (inspected is PackageInspectResult.Invalid) {
                appendLog(mine, "> container: INVALID ARCHIVE")
                return failure(inspected.reasonRes)
            }
            val bundle = (inspected as PackageInspectResult.Valid).bundle
            val isLocalDevice = connection.device?.local == true

            if (bundle.format == PackageFormat.SingleApk) {
                val apkSize = sourceFile.length()
                if (apkSize <= 0L) return failure(R.string.err_read_file)
                appendLog(mine, "> container: SINGLE APK")
                val pkg = withContext(Dispatchers.IO) { packageNameOfFile(sourceFile) }
                val pkgProblem = BundlePackageProblem.Unreadable.takeIf { pkg == null }
                appendLog(mine, "> package: ${pkg ?: "unknown"}")
                if (userInstall) appendLog(mine, "> shortcut: on (the launcher adds the icon by itself on a new install; updates keep their icon)")
                val label = installLabel(pkg, fileName, generic)
                if (mine != generation) throw CancellationException()
                install = install?.copy(name = label)
                val shield = verifyPackageWithShield(mine, app, sourceFile, installLabel(null, fileName, "package.apk"), bundle, pkg, pkgProblem, isLocalDevice)
                val verdict = shield.verdict
                if (mine != generation) throw CancellationException()
                install = install?.copy(shieldVerdict = verdict, shieldChecking = false)
                var userOverridden = false
                if (verdict is ShieldVerdict.Warning) {
                    if (securityTierOf(verdict) == SecurityTier.Yellow) {
                        val proceed = resolveCautionPrompt(mine, label, pkg, verdict)
                        if (!proceed) {
                            return InstallStatus(
                                working = false,
                                ok = false,
                                name = label,
                                percent = 100,
                                phase = InstallPhase.Done,
                                reason = R.string.reason_cancelled,
                                shieldVerdict = verdict,
                                logs = install?.logs.orEmpty(),
                            )
                        }
                        userOverridden = true
                        install = install?.copy(userAuthorized = true)
                    } else {
                        return shieldBlockedStatus(label, blockedBy(verdict), install?.logs.orEmpty())
                    }
                }
                if (!mayInstall(verdict, userOverridden)) {
                    return shieldBlockedStatus(label, blockedBy(verdict), install?.logs.orEmpty())
                }
                // The checked file must still be the file that is streamed.
                suspend fun changedAfterScan(): Boolean {
                    val changed = verdict != null && withContext(Dispatchers.IO) { !filesUnchangedSinceScan(shield.scanned, listOf(sourceFile)) }
                    if (changed) appendLog(mine, "> shield: the file changed after it was checked, nothing was installed")
                    return changed
                }
                if (changedAfterScan()) return failure(R.string.reason_file_changed)
                performAutoBackup(mine, pkg, shield.installedInfo)
                install = install?.copy(phase = InstallPhase.Sending, percent = 0)
                appendLog(mine, "> adb: ${streamInstallCommand(apkSize, bypass = true, userInstall)} (none granted by GoGo)")
                fun report(sent: Long) = updateInstallProgress(mine, sent, apkSize)
                // The client's own watchdog times the stream out; a slow install must never close the whole session.
                suspend fun attempt(bypass: Boolean): String = blocking(INSTALL_TIMEOUT_MS, disconnectOnTimeout = false) {
                    check(mayInstall(verdict, userOverridden)) { "The shield did not clear this package" }
                    report(0)
                    // Keep Google Play Protect out of ADB installs.
                    adb.shell(DisableAdbVerifyCommand)
                    adb.shell(DisableVerifierCommand)
                    sourceFile.inputStream().use { adb.install(streamInstallCommand(apkSize, bypass, userInstall), apkSize, it, ::report) }
                }
                var output = attempt(bypass = true)
                if (shouldRetryWithoutBypass(output)) {
                    if (changedAfterScan()) return failure(R.string.reason_file_changed)
                    appendLog(mine, "> adb: retrying ${streamInstallCommand(apkSize, bypass = false, userInstall)}")
                    output = attempt(bypass = false)
                }
                val result = parsePmOutput(output)
                appendLog(mine, "> pm: ${result.line.ifBlank { if (result.success) "Success" else "Failure" }}")
                val status = install ?: InstallStatus(false, name = label, shieldVerdict = verdict, shieldChecking = false)
                return if (result.success) status.copy(working = false, ok = true, percent = 100, phase = InstallPhase.Done)
                else failed(status, pmFailure(result.line))
            }

            // Bundle (APKS / XAPK / APKM / Split ZIP): detect package name from manifest.json / info.json or base APK,
            // run shield check, then delete sourceFile immediately so we do not hold 2x disk space during streaming.
            appendLog(mine, "> container: ${bundle.format.name.uppercase(java.util.Locale.US)} (${bundle.apks.size} apk splits, ${bundle.obbs.size} obb files)")
            // The package name comes from the APK files themselves, never from the bundle's own metadata.
            val pkgCheck = withContext(Dispatchers.IO) {
                checkBundlePackage(
                    basePackage = bundle.findBaseApk()?.file?.let(::packageNameOfFile),
                    splitPackages = bundle.apks.map { split -> split.file?.let(::packageNameOfFile) },
                    claimed = bundle.packageName,
                )
            }
            val pkg = pkgCheck.packageName
            appendLog(mine, "> package: ${pkg ?: "unknown"}")
            if (userInstall) appendLog(mine, "> shortcut: on (the launcher adds the icon by itself on a new install; updates keep their icon)")
            val label = installLabel(pkg, fileName, generic)
            if (mine != generation) throw CancellationException()
            install = install?.copy(name = label)
            val shield = verifyPackageWithShield(mine, app, sourceFile, installLabel(null, fileName, "package.apk"), bundle, pkg, pkgCheck.problem, isLocalDevice)
            val verdict = shield.verdict
            if (mine != generation) throw CancellationException()
            install = install?.copy(shieldVerdict = verdict, shieldChecking = false)
            var userOverridden = false
            if (verdict is ShieldVerdict.Warning) {
                if (securityTierOf(verdict) == SecurityTier.Yellow) {
                    val proceed = resolveCautionPrompt(mine, label, pkg, verdict)
                    if (!proceed) {
                        return InstallStatus(
                            working = false,
                            ok = false,
                            name = label,
                            percent = 100,
                            phase = InstallPhase.Done,
                            reason = R.string.reason_cancelled,
                            shieldVerdict = verdict,
                            logs = install?.logs.orEmpty(),
                        )
                    }
                    userOverridden = true
                } else {
                    return shieldBlockedStatus(label, blockedBy(verdict), install?.logs.orEmpty())
                }
            }
            if (!mayInstall(verdict, userOverridden)) {
                return shieldBlockedStatus(label, blockedBy(verdict), install?.logs.orEmpty())
            }
            withContext(Dispatchers.IO) {
                runCatching { sourceFile.delete() }
            }
            if (mine != generation) throw CancellationException()
            performAutoBackup(mine, pkg, shield.installedInfo)
            install = install?.copy(phase = InstallPhase.Sending, percent = 0)

            val localAbis = Build.SUPPORTED_ABIS.toList()
            val localDpi = app.resources.displayMetrics.densityDpi
            val localLang = java.util.Locale.getDefault().language

            val outcome = blocking(INSTALL_TIMEOUT_MS, disconnectOnTimeout = false) {
                val deviceSpec = queryDeviceSpec(adb, localAbis, localDpi, localLang)
                postLog(mine, "> target spec: abis=${deviceSpec.abis.joinToString(",")}, dpi=${deviceSpec.densityDpi ?: "auto"}, langs=${deviceSpec.languages.joinToString(",")}")
                when (val filtered = filterSplits(bundle.apks, deviceSpec, bundle.baseApkName, pkg)) {
                    is SplitFilterResult.IncompatibleAbi -> {
                        postLog(mine, "> split filter: ABORT — no matching ABI split for target device")
                        BundleOutcome.FailedReason(filtered.reasonRes)
                    }
                    is SplitFilterResult.Selected -> {
                        postLog(mine, "> split filter: selected ${filtered.splits.size}/${bundle.apks.size} splits (${filtered.splits.joinToString(", ") { it.name }})")
                        // Every split that is streamed must still be the file that was checked.
                        if (verdict != null && !filesUnchangedSinceScan(shield.scanned, filtered.splits.map { it.file })) {
                            postLog(mine, "> shield: a split changed after it was checked, nothing was installed")
                            return@blocking BundleOutcome.FailedReason(R.string.reason_file_changed)
                        }
                        check(mayInstall(verdict, userOverridden)) { "The shield did not clear this package" }
                        val result = installBundleSession(
                            adb = adb,
                            splits = filtered.splits,
                            obbs = bundle.obbs,
                            packageName = pkg,
                            onProgress = { sent, total -> updateInstallProgress(mine, sent, total) },
                            onLog = { line -> postLog(mine, line) },
                            userInstall = userInstall,
                        )
                        BundleOutcome.Pm(result)
                    }
                }
            }

            val status = install ?: InstallStatus(false, name = label, shieldVerdict = verdict, shieldChecking = false)
            return when (outcome) {
                is BundleOutcome.FailedReason -> failed(status, InstallFailure(outcome.reasonRes, null))
                is BundleOutcome.Pm -> {
                    appendLog(mine, "> pm: ${outcome.result.line.ifBlank { if (outcome.result.success) "Success" else "Failure" }}")
                    val latestStatus = install ?: status
                    val obbFailure = outcome.result.obbFailure
                    when {
                        // Installed, but the OBB data files are missing: say so, never a silent success.
                        outcome.result.success && obbFailure != null -> failed(latestStatus, InstallFailure(R.string.reason_obb_not_copied, obbFailure))
                        outcome.result.success -> {
                            var keptUri: Uri? = uri
                            if (installSettings.deleteApk) {
                                val deleted = runCatching {
                                    DocumentsContract.deleteDocument(resolver, uri)
                                }.getOrDefault(false)
                                if (deleted) {
                                    appendLog(mine, "> file: auto-deleted source package after installation")
                                    keptUri = null
                                }
                            }
                            latestStatus.copy(
                                working = false,
                                ok = true,
                                percent = 100,
                                phase = InstallPhase.Done,
                                sourceUri = keptUri,
                            )
                        }
                        else -> failed(latestStatus, pmFailure(outcome.result.line))
                    }
                }
            }
        } finally {
            withContext(NonCancellable + Dispatchers.IO) {
                runCatching { bundleDir.deleteRecursively() }
            }
        }
    }

    private sealed interface BundleOutcome {
        data class FailedReason(val reasonRes: Int) : BundleOutcome
        data class Pm(val result: PmResult) : BundleOutcome
    }

    private fun packageNameOfFile(apkFile: File): String? = try {
        @Suppress("DEPRECATION")
        getApplication<Application>().packageManager.getPackageArchiveInfo(apkFile.path, 0)?.packageName
    } catch (t: Throwable) {
        null
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

    fun deleteSourcePackage() {
        val uri = install?.sourceUri ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val app = getApplication<Application>()
            val deleted = runCatching {
                DocumentsContract.deleteDocument(app.contentResolver, uri)
            }.getOrDefault(false)
            withContext(Dispatchers.Main) {
                if (deleted) {
                    install = install?.copy(
                        sourceUri = null,
                        logs = install?.logs.orEmpty() + "> file: deleted source package from storage",
                    )
                } else {
                    install = install?.copy(
                        logs = install?.logs.orEmpty() + "> file: unable to delete (storage permission or provider does not allow deletion)",
                    )
                }
            }
        }
    }

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
