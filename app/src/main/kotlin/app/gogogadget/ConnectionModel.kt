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
    val shieldVerdict: ShieldVerdict? = null,
    val shieldChecking: Boolean = false,
    val logs: List<String> = emptyList(),
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
        val shieldOn = shieldSettings.shieldEnabled
        val initialPhase = if (shieldOn) InstallPhase.Checking else InstallPhase.Sending
        install = InstallStatus(working = true, phase = initialPhase, shieldChecking = shieldOn)
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
     * Runs the Antivirus shield check (SHA-256 + offline signature/manifest analysis + optional VirusTotal lookup).
     * Returns null when the shield is disabled, or the evaluated [ShieldVerdict] when enabled.
     */
    private suspend fun verifyPackageWithShield(
        mine: Int,
        app: Application,
        sourceFile: File,
        bundle: ExtractedBundle,
        pkg: String?,
        isLocalDevice: Boolean,
    ): ShieldVerdict? {
        if (!shieldSettings.shieldEnabled) {
            appendLog(mine, "> shield: OFF (disabled in settings)")
            return null
        }
        appendLog(mine, "> shield: scanning archive, X.509 certificates & AndroidManifest.xml...")
        val installedInfo = if (!pkg.isNullOrBlank()) {
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
        offline.versionCode?.let { vc ->
            appendLog(mine, "> versionCode: $vc${installedInfo?.versionCode?.let { " (installed on target: $it)" }.orEmpty()}")
        }
        val sigDetail = offline.certSubject ?: offline.signerSha256?.let(::truncateSha256) ?: "unknown"
        when {
            !offline.signed -> appendLog(mine, "> signature: UNSIGNED (no valid V1/V2/V3 certificate)")
            offline.debugOrTestSigned -> appendLog(mine, "> signature: UNTRUSTED TEST/MOD KEY ($sigDetail)")
            offline.signatureMismatch -> appendLog(mine, "> signature: MISMATCH vs installed app ($sigDetail)")
            else -> appendLog(mine, "> signature: VALID ($sigDetail)")
        }
        if (offline.allPermissions.isEmpty()) {
            appendLog(mine, "> permissions: 0 requested in AndroidManifest.xml (0 auto-granted)")
        } else {
            appendLog(
                mine,
                "> permissions (${offline.allPermissions.size} requested, 0 auto-granted — user decides): ${offline.allPermissions.joinToString(", ")}",
            )
        }
        if (offline.highRiskPermissions.isNotEmpty()) {
            appendLog(mine, "> high-risk flags: ${offline.highRiskPermissions.joinToString(", ")}")
        }

        val apiKey = withContext(Dispatchers.IO) { shieldSettings.loadVirusTotalApiKey() }
        val vt = if (!apiKey.isNullOrBlank()) {
            appendLog(mine, "> virustotal: GET /api/v3/files/${truncateSha256(sha256)}...")
            val res = withContext(Dispatchers.IO) { checkVirusTotalHash(sha256, apiKey) }
            when (res) {
                is VtLookupResult.Found -> appendLog(mine, "> virustotal: ${res.malicious} malicious, ${res.suspicious} suspicious / ${res.total} engines")
                VtLookupResult.UnknownHash -> appendLog(mine, "> virustotal: hash not in database (404)")
                VtLookupResult.InvalidKey -> appendLog(mine, "> virustotal: API key rejected (401/403)")
                VtLookupResult.RateLimited -> appendLog(mine, "> virustotal: rate limited (429)")
                VtLookupResult.Unavailable -> appendLog(mine, "> virustotal: unreachable / offline")
            }
            res
        } else {
            appendLog(mine, "> virustotal: skipped (no API key configured — offline shield only)")
            null
        }

        val verdict = evaluateShieldVerdict(
            sha256 = sha256,
            offline = offline,
            vt = vt,
            deepScanEnabled = shieldSettings.deepScanEnabled,
            fileSizeBytes = sourceFile.length(),
        )
        when (verdict) {
            is ShieldVerdict.Clean -> appendLog(mine, "> shield verdict: PASS — proceeding with zero-trust install (no -g flag)")
            is ShieldVerdict.Warning -> appendLog(mine, "> shield verdict: BLOCKED (${verdict.reasons.joinToString(", ") { it.name }}) — installation aborted")
        }
        return verdict
    }

    private fun shieldBlockedStatus(label: String, verdict: ShieldVerdict.Warning, logs: List<String>): InstallStatus {
        val primaryReasonRes = when (verdict.reasons.firstOrNull()) {
            ShieldWarningReason.MalwareDetected -> R.string.shield_warn_malware_short
            ShieldWarningReason.UnsignedPackage -> R.string.shield_warn_unsigned
            ShieldWarningReason.DebugOrTestCertificate -> R.string.shield_warn_debug_cert
            ShieldWarningReason.SignatureMismatch -> R.string.shield_warn_signature
            ShieldWarningReason.VersionDowngrade -> R.string.shield_warn_downgrade
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
                appendLog(mine, "> package: ${pkg ?: "unknown"}")
                if (userInstall) appendLog(mine, "> shortcut: on (the launcher adds the icon by itself on a new install; updates keep their icon)")
                val label = installLabel(pkg, fileName, generic)
                if (mine != generation) throw CancellationException()
                install = install?.copy(name = label)
                val verdict = verifyPackageWithShield(mine, app, sourceFile, bundle, pkg, isLocalDevice)
                if (mine != generation) throw CancellationException()
                install = install?.copy(shieldVerdict = verdict, shieldChecking = false)
                if (verdict is ShieldVerdict.Warning) {
                    return shieldBlockedStatus(label, verdict, install?.logs.orEmpty())
                }
                install = install?.copy(phase = InstallPhase.Sending, percent = 0)
                appendLog(mine, "> adb: ${streamInstallCommand(apkSize, bypass = true, userInstall)} (0 permissions granted)")
                fun report(sent: Long) = updateInstallProgress(mine, sent, apkSize)
                // The client's own watchdog times the stream out; a slow install must never close the whole session.
                suspend fun attempt(bypass: Boolean): String = blocking(INSTALL_TIMEOUT_MS, disconnectOnTimeout = false) {
                    report(0)
                    sourceFile.inputStream().use { adb.install(streamInstallCommand(apkSize, bypass, userInstall), apkSize, it, ::report) }
                }
                var output = attempt(bypass = true)
                if (shouldRetryWithoutBypass(output)) {
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
            val pkg = withContext(Dispatchers.IO) {
                bundle.packageName ?: bundle.findBaseApk()?.file?.let(::packageNameOfFile)
            }
            appendLog(mine, "> package: ${pkg ?: "unknown"}")
            if (userInstall) appendLog(mine, "> shortcut: on (the launcher adds the icon by itself on a new install; updates keep their icon)")
            val label = installLabel(pkg, fileName, generic)
            if (mine != generation) throw CancellationException()
            install = install?.copy(name = label)
            val verdict = verifyPackageWithShield(mine, app, sourceFile, bundle, pkg, isLocalDevice)
            if (mine != generation) throw CancellationException()
            install = install?.copy(shieldVerdict = verdict, shieldChecking = false)
            if (verdict is ShieldVerdict.Warning) {
                return shieldBlockedStatus(label, verdict, install?.logs.orEmpty())
            }
            withContext(Dispatchers.IO) {
                runCatching { sourceFile.delete() }
            }
            if (mine != generation) throw CancellationException()
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
                    if (outcome.result.success) latestStatus.copy(working = false, ok = true, percent = 100, phase = InstallPhase.Done)
                    else failed(latestStatus, pmFailure(outcome.result.line))
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
