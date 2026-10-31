package app.gogogadget

import android.app.Application
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.SystemClock
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
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicLong

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

// Keys marked for deletion live in a file of their own: resetting the device list clears PREFS but must not forget them.
private const val IDENTITY_PREFS = "identities"
private const val KEY_PENDING_DELETE = "pending_delete"
private const val OP_PREFIX = "op"
private const val MAX_MODEL_LENGTH = 64
private const val LOOPBACK = "127.0.0.1"
private const val PROBE_TIMEOUT_MS = 1_200
private const val PROBE_PARALLEL = 4
private const val PROBE_MDNS_WAIT_MS = 1_500L
private const val PROBE_EVERY_MS = 20_000L
private const val PROBE_SCAN = "probe"
private const val SUBNET_SCAN_EVERY_MS = 30_000L

// A network device is tried by TCP before ADB: the library connects with no timeout of its own and holds its lock meanwhile.
private const val CONNECT_PROBE_MS = 3_000
private const val NETWORK_PORT_POLL_MS = 500L
private const val LAST_PORT_PREFIX = "last_port_"

private const val WATCH_TICK_MS = 2_000L
private const val KEEPALIVE_MS = 25_000L
private const val SUSPECT_RETRY_MS = 5_000L
private const val LONG_AWAY_MS = 30_000L
private const val RESCAN_AFTER_MS = 5_000L
private const val CONNECT_TIMEOUT_MS = 25_000L
private const val PAIR_TIMEOUT_MS = 25_000L
private const val INSTALL_TIMEOUT_MS = 10 * 60_000L
private const val INCOMING_DIR = "incoming"

class ConnectionModel(
    app: Application,
    private val adb: AdbClient,
    private val discovery: DeviceDiscovery,
    private val pairing: PairingLauncher,
    /** Shared with the pairing service: whoever uses, makes or deletes an ADB key holds it. */
    private val adbLock: Mutex = Graph.adbLock,
    private val log: TerminalLog = Graph.log,
) : AndroidViewModel(app) {
    constructor(app: Application) : this(app, Graph.adb(app), Graph.discovery(app), ServicePairingLauncher(app))

    private val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val identityPrefs = app.getSharedPreferences(IDENTITY_PREFS, Context.MODE_PRIVATE)

    /** Connecting, pairing and forgetting, oldest line first (also what the pairing service did). */
    val terminal = log.lines
    val shieldSettings = ShieldSettingsStore(app)
    private val installSettings = InstallSettingsStore(app)

    var connection by mutableStateOf(Connection())
        private set
    var recent by mutableStateOf(forgetPorts(decodeRecents(prefs.getString(KEY_RECENT, null))))
        private set
    /**
     * Hosts of current-network devices whose TCP probe succeeded ([availability] decides, with its hysteresis); a device
     * that is not in it is grey. Empty until the first probe answers, and never cleared between probes.
     */
    var reachable by mutableStateOf<Set<String>>(emptySet())
        private set

    /** The /24 subnets of this phone's private addresses, refreshed by every probe. */
    var subnets by mutableStateOf(currentSubnets(ownAddresses()))
        private set
    private val availability = AvailabilityTracker()
    private var probeJob: Job? = null
private var subnetJob: Job? = null
private var subnetScanAt = 0L
    private var probeRuns = 0

    // The ports the last probe tried per host: an mDNS port that is not among them is worth another probe.
    private var testedPorts: Map<String, Set<Int>> = emptyMap()
    private var foregroundJob: Job? = null
    private var foreground = false
    private var hiddenAt = 0L

    /** Device ids handed to network devices that are not saved yet, so a retry or the pairing keeps the same key. */
    private val provisionalIds = HashMap<String, String>()

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
    private var watchJob: Job? = null

    // Read by the session watch from IO threads too.
    @Volatile private var generation = 0

    private val watch = SessionWatch(adb, adbLock, log, ::sessionSnapshot)

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

    /** Verdicts of the last 48 h by SHA-256; the file is read lazily and only from IO or lookup code. */
    private val reputationCache by lazy { ReputationCache(File(app.filesDir, "reputation_cache.json")) }

    /** Forgets the stored online verdicts: they came with a key that was just changed or removed. */
    fun clearReputationCache() {
        viewModelScope.launch(Dispatchers.IO) {
            reputationCache.clear(ShieldSource.VirusTotal)
        }
    }

    /** True while the pairing was done by the notification service, so the connect result is reported there too. */
    private var viaService = false

    // ADB calls run one at a time ([adbLock]), so a late call from an old operation cannot touch a newer session.
    private val scanReasons = mutableSetOf<String>()

    init {
        PairingBridge.onPaired = ::pairedByService
        PairingBridge.onFailed = ::pairFailedByService
        // A deletion the app was killed in the middle of is finished before anything connects (connects wait for it).
        decodeIdentities(identityPrefs.getString(KEY_PENDING_DELETE, null)).takeIf { it.isNotEmpty() }?.let {
            log.add("> keys: finishing the deletion of ${encodeIdentities(it)}")
            abortAdb(onlyIfBusy = false, deleting = it, disconnect = false)
        }
        backupManager.migrateLegacy()
        refreshBackups()
        // Reconnect quietly to the last device with the stored key, but only if it is on a network this phone is on.
        startupReconnect(recent, ownAddresses(), subnets)?.let { connect(it, silent = true) }
    }

    private fun sessionSnapshot() = SessionSnapshot(generation, adb.sessionId, connection.device, connection.state)

    /** Something works on the session through the ADB lock: an install, a restore or its backup. */
    private fun sessionBusy() = install?.working == true

    /**
     * The session is checked before work is started on it, without a round trip: a dead one is reported now instead of
     * after minutes of scanning. [AdbClient.isAlive] takes no library lock, so the main thread may ask.
     */
    private fun sessionAlive(): Boolean {
        if (adb.isAlive) return true
        loseSession("the library reports the connection as ended")
        return false
    }

    private fun loseSession(reason: String) {
        log.add(lostLine(reason))
        dropSession(reason)
    }

    /** The app came to the front or went away; the pings and the probes only run in front. */
    @OptIn(FlowPreview::class)
    fun appVisible(on: Boolean) {
        if (on == foreground) return
        foreground = on
        foregroundJob?.cancel()
        if (!on) {
            hiddenAt = SystemClock.elapsedRealtime()
            probeJob?.cancel()
            subnetJob?.cancel()
            subnetScanAt = 0L
            return
        }
        val away = SystemClock.elapsedRealtime() - hiddenAt
        if (connection.state == ConnectionState.Connected) watchSession(pingNow = hiddenAt > 0 && away > LONG_AWAY_MS)
        foregroundJob = viewModelScope.launch {
            // An mDNS port the last probe did not try (a device that just turned Wireless debugging on) probes again.
            launch {
                found.debounce(500).collect { list ->
                    if (hasNewConnectPorts(testedPorts, recent.map { it.host }, list)) probeDevices()
                }
            }
            while (true) {
                probeDevices()
                delay(PROBE_EVERY_MS)
            }
        }
    }

    /**
     * Looks after the connected session until it ends: the library's flags every [WATCH_TICK_MS] (free), and one
     * keepalive every [KEEPALIVE_MS] (see [SessionWatch]), in front only and never while something works on the session.
     */
    private fun watchSession(pingNow: Boolean = false) {
        watchJob?.cancel()
        val session = sessionSnapshot().takeIf { it.state == ConnectionState.Connected && it.device != null } ?: return
        watchJob = viewModelScope.launch {
            var untilPing = if (pingNow) 0L else KEEPALIVE_MS
            while (watch.isCurrent(session)) {
                val due = untilPing <= 0
                val ping = due && keepaliveAllowed(foreground, session.device?.local != false, sessionBusy())
                when (watch.check(session, ping, ::dropSession)) {
                    WatchResult.Lost -> return@launch
                    WatchResult.Alive -> untilPing = KEEPALIVE_MS
                    WatchResult.Suspect -> untilPing = SUSPECT_RETRY_MS
                    WatchResult.Skipped -> {}
                }
                delay(WATCH_TICK_MS)
                untilPing -= WATCH_TICK_MS
            }
        }
    }

    /** The session is over: the card says why. The watch has logged it already. */
    private fun dropSession(reason: String) {
        connection = Connection(ConnectionState.Error, connection.device, AdbError.ConnectionLost, reason)
        // The lost device is a saved device like any other now: the probe says whether it is back.
        probeDevices()
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
        // The question may have waited for minutes: a session that died meanwhile ends the install now, as declined.
        if (!sessionAlive()) {
            cautionGate.answer(promptId, false)
            return
        }
        cautionGate.answer(promptId, true)
    }

    fun cancelCaution(promptId: Int) {
        cautionGate.answer(promptId, false)
    }

    fun deleteBackup(backup: AppBackupItem) = deleteBackups(listOf(backup))

    fun deleteBackups(list: List<AppBackupItem>) {
        viewModelScope.launch(Dispatchers.IO) {
            list.forEach { backupManager.deleteBackup(it.deviceId, it.packageName) }
            val updated = backupManager.listBackups()
            withContext(Dispatchers.Main) {
                backups = updated
            }
        }
    }

    fun revertBackup(backup: AppBackupItem) = revertBackups(listOf(backup))

    /** Reverts the given backups one after another; a failure is logged and the queue carries on. */
    fun revertBackups(all: List<AppBackupItem>) {
        // Only what came from the connected device: a copy of another device's app is never pushed here.
        val connectedId = connection.device?.backupId()
        val list = all.filter { canRevertBackup(it.deviceId, connectedId) }
        if (list.isEmpty() || connection.state != ConnectionState.Connected || install?.working == true) return
        if (!sessionAlive()) return
        val mine = generation
        val total = list.size
        install = InstallStatus(working = true, name = list.first().appName.ifBlank { list.first().packageName }, phase = InstallPhase.Sending, percent = 0)
        installJob = viewModelScope.launch {
            val failedNames = mutableListOf<String>()
            val results = mutableListOf<Pair<AppBackupItem, Boolean>>()
            for ((index, backup) in list.withIndex()) {
                val label = backup.appName.ifBlank { backup.packageName }
                val tag = if (total > 1) "${index + 1}/$total " else ""
                install = install?.copy(name = if (total > 1) "$tag$label" else label, percent = 0, phase = InstallPhase.Sending, working = true)
                val ok = revertOne(mine, backup, label, tag)
                if (!ok) failedNames += label
                results += backup to ok
            }
            // A reverted app is installed again: its backup is no longer needed. Failed ones keep theirs.
            val removable = backupsToRemoveAfterRevert(results)
            if (removable.isNotEmpty()) {
                for (backup in removable) {
                    withContext(Dispatchers.IO) { backupManager.deleteBackup(backup.deviceId, backup.packageName) }
                    appendLog(mine, "> backup: removed ${backup.appName.ifBlank { backup.packageName }} (now installed)")
                }
                backups = withContext(Dispatchers.IO) { backupManager.listBackups() }
            }
            if (total > 1) {
                val done = total - failedNames.size
                appendLog(mine, "> revert: $done of $total reverted" + if (failedNames.isEmpty()) "" else ", failed: ${failedNames.joinToString(", ")}")
                val status = install ?: InstallStatus(false, name = "")
                install = if (failedNames.isEmpty()) status.copy(working = false, ok = true, percent = 100, phase = InstallPhase.Done, name = "$done/$total")
                else status.copy(working = false, ok = false, percent = 100, phase = InstallPhase.Done, name = "$done/$total", reason = R.string.reason_unknown)
            }
        }
    }

    /** Reverts one backup. Returns true on success. With a single backup it also sets the final status. */
    private suspend fun revertOne(mine: Int, backup: AppBackupItem, label: String, tag: String): Boolean {
        val single = tag.isEmpty()
        run {
            appendLog(mine, "> revert: ${tag}restoring $label v${backup.versionCode}...")
            // The saved files must still be the ones that were pulled from the device.
            val check = withContext(Dispatchers.IO) { verifyBackupFiles(backup) }
            if (check is BackupCheck.Changed) {
                appendLog(mine, "> revert: ${tag}refused, the saved file changed since the backup (${check.files.joinToString(", ")})")
                if (single) install = failed(install, InstallFailure(R.string.reason_file_changed, null))
                return false
            }
            if (check == BackupCheck.NoHash) appendLog(mine, "> revert: ${tag}this backup has no saved hash (made by an older version), Android still checks the signer")
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
                if (single) {
                    val status = install ?: InstallStatus(false, name = label)
                    install = if (outcome.success) {
                        status.copy(working = false, ok = true, percent = 100, phase = InstallPhase.Done)
                    } else {
                        failed(status, pmFailure(outcome.line))
                    }
                }
                return outcome.success
            } catch (e: CancellationException) {
                if (install?.working == true) install = failed(install, transferFailure(e, null))
                throw e
            } catch (t: Throwable) {
                appendLog(mine, "> revert: $label failed (${t.javaClass.simpleName})")
                if (single) install = failed(install, transferFailure(t, diagnostic(t)))
                return false
            }
        }
    }

    fun thisDevice(): Target {
        val name = Settings.Global.getString(getApplication<Application>().contentResolver, "device_name")
        return Target(name?.takeIf { it.isNotBlank() } ?: Build.MODEL, LOOPBACK, 0)
    }

    /**
     * Probes the saved devices of the current network that are not connected (a TCP connect to each candidate port,
     * [PROBE_TIMEOUT_MS] each, at most [PROBE_PARALLEL] at a time) and posts the result on the main thread. The
     * connected device is never probed: its session has its own watch. mDNS runs during the probe, so a device with
     * Wireless debugging is found on its random port. Only a device that accepts a connection is reachable (an mDNS entry
     * alone is not trusted: it outlives a switched-off device), and an available one needs two failed probes in a row to
     * go grey ([AvailabilityTracker]). Nothing is cleared while the probe runs, so the list never flickers.
     */
    fun probeDevices() {
        probeJob?.cancel()
        val own = ownAddresses()
        subnets = currentSubnets(own)
        val connectedHost = connection.device?.takeIf { connection.state == ConnectionState.Connected }?.host
        scanSubnets(own)
        val targets = probeTargets(recent, own, subnets, connectedHost)
        availability.retain(targets.map { it.host })
        if (targets.isEmpty()) {
            reachable = keepSavedHosts(availability.available(), recent)
            return
        }
        // Its own reason each run: an older run that is still ending must not switch off the scan of the new one.
        val reason = "$PROBE_SCAN${++probeRuns}"
        probeJob = viewModelScope.launch {
            val alreadyScanning = scanReasons.isNotEmpty()
            scan(reason, true)
            try {
                val hints = targets.associate { it.host to lastGoodPort(it.host) }
                val portsOf = { t: Target, announced: List<Found> ->
                    probePorts(t.port, announcedPorts(t.host, announced), hints[t.host])
                }
                var plan = targets.associateWith { portsOf(it, found.value) }
                val up = HashMap<String, Boolean>()
                probeRound(plan).forEach { (host, port) -> up[host] = port != null }
                // Hosts that did not answer and that mDNS has not shown yet may still appear in a moment.
                // Tailscale nodes are probed at once on 5555 and the last good port: mDNS does not cross the tailnet.
                val silent = targets.filter {
                    up[it.host] != true && !isTailscaleV4(it.host) && announcedPorts(it.host, found.value).isEmpty()
                }
                if (silent.isNotEmpty() && !alreadyScanning) {
                    val late = withTimeoutOrNull(PROBE_MDNS_WAIT_MS) {
                        found.first { list -> silent.any { announcedPorts(it.host, list).isNotEmpty() } }
                    }
                    if (late != null) {
                        val again = silent.associateWith { portsOf(it, late) }
                        probeRound(again).forEach { (host, port) -> up[host] = port != null }
                        plan = plan + again
                    }
                }
                targets.forEach { availability.record(it.host, up[it.host] == true) }
                testedPorts = plan.entries.associate { (t, ports) -> normalise(t.host) to ports.toSet() }
                // A device forgotten while the probe ran must not show up as available.
                reachable = keepSavedHosts(availability.available(), recent)
            } finally {
                scan(reason, false)
            }
        }
    }

    /** Sweeps the private LAN /24 networks on 5555; responders join "Devices on this network". */
    private fun scanSubnets(own: Collection<String>) {
        val now = SystemClock.elapsedRealtime()
        if (subnetJob?.isActive == true || (subnetScanAt != 0L && now - subnetScanAt < SUBNET_SCAN_EVERY_MS)) return
        val hosts = SubnetScanner.candidates(own)
        if (hosts.isEmpty()) return
        subnetScanAt = now
        val names = recent.associate { normalise(it.host) to it.name }
        subnetJob = viewModelScope.launch {
            discovery.publishProbed(SubnetScanner.scan(hosts, names))
        }
    }

    private fun announcedPorts(host: String, found: List<Found>): List<Int> =
        found.filter { it.kind == FoundKind.Connect && normalise(it.host) == normalise(host) }.map { it.port }

    /** For each target the first of its ports that accepts a TCP connection, or null. */
    private suspend fun probeRound(plan: Map<Target, List<Int>>): Map<String, Int?> {
        val gate = Semaphore(PROBE_PARALLEL)
        return withContext(Dispatchers.IO) {
            plan.map { (t, ports) ->
                async { gate.withPermit { t.host to ports.firstOrNull { tcpReachable(t.host, it, PROBE_TIMEOUT_MS) } } }
            }.awaitAll().toMap()
        }
    }

    private fun tcpReachable(host: String, port: Int, timeoutMs: Int): Boolean = try {
        Socket().use { socket -> socket.connect(InetSocketAddress(host, port), timeoutMs) }
        true
    } catch (e: IOException) {
        false
    }

    // The port of the last good connection to a host: a hint for the probe, never the truth (Wireless debugging changes it).
    private fun lastGoodPort(host: String): Int? = prefs.getInt(LAST_PORT_PREFIX + normalise(host), 0).takeIf { it > 0 }

    private fun saveLastGoodPort(host: String, port: Int) {
        prefs.edit().putInt(LAST_PORT_PREFIX + normalise(host), port).apply()
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

    /**
     * The target with the id of its key: a saved device keeps its own (none: the shared key of earlier versions), a
     * device that is not saved yet gets a new id, kept until it is saved or forgotten.
     */
    private fun identified(target: Target): Target {
        val own = ownAddresses()
        return withDeviceId(target, recent, own) { provisionalIds.getOrPut(normalise(target.host)) { newDeviceId() } }
    }

    fun connect(target: Target, silent: Boolean = false) {
        pairing.stop()
        begin()
        val device = identified(target)
        job = viewModelScope.launch { run(device, silent = silent) }
    }

    fun startPairing(target: Target, pairingPort: Int? = null) {
        begin()
        enterPairing(identified(target), pairingPort?.takeIf { it > 0 }, null)
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

    /** The pairing service failed: show it on the card (the service is gone) and keep the details for the report. */
    private fun pairFailedByService(error: AdbError, detail: String) {
        viewModelScope.launch {
            if (connection.state != ConnectionState.Pairing) return@launch
            connection = connection.copy(error = error, detail = detail)
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
            val identity = identityFor(target.host, own, target.deviceId)
            log.add("> pair: ${if (local) "this device" else "network device"}, identity ${identity.id}, port $port")
            val failure: Throwable? = try {
                blocking(PAIR_TIMEOUT_MS) { pairAcross(adb, hosts, port, code, identity) }
                null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                e
            }
            failure?.let {
                // enterPairing asks for the code again.
                val error = classifyError(it, Phase.Pair, local)
                log.add(failureLine("pair", it) + " [${error.name}]")
                enterPairing(target, typedPort, error, diagnostic(it))
                return@launch
            }
            log.add("> pair: paired")
            run(target, silent = false, paired = true)
        }
    }

    fun cancel() {
        cancelPendingFile()
        pairing.stop()
        pairing.dismiss()
        endSession()
        abortAdb(onlyIfBusy = false)
        viewModelScope.launch(Dispatchers.IO) {
            val app = getApplication<Application>()
            // Installs now stage in the private cache; folders left in the external one by older versions are cleaned too.
            listOfNotNull(app.cacheDir, app.externalCacheDir).forEach { baseCache ->
                baseCache.listFiles { f -> f.isDirectory && (f.name.startsWith("bundle_") || f.name == INCOMING_DIR) }?.forEach {
                    runCatching { it.deleteRecursively() }
                }
            }
        }
    }

    /** Stops whatever runs and goes back to "not connected"; the ADB socket is closed by [abortAdb]. */
    private fun endSession() {
        begin()
        viaService = false
        pairTarget = null
        pairPort = null
        pairSeen = null
        connection = Connection()
    }

    private fun begin() {
        generation++
        watchJob?.cancel()
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

    /**
     * Closes the ADB sockets ([disconnect]: false keeps the session of another device alive) and then deletes the
     * keys in [deleting]. The deletion waits for [adbLock], so it never lands in the middle of a pairing or connect
     * that uses the key, and every later call waits for this job.
     */
    private fun abortAdb(onlyIfBusy: Boolean, deleting: Set<IdentityName> = emptySet(), disconnect: Boolean = true) {
        if (onlyIfBusy && !adbLock.isLocked) return
        val previous = abortJob
        abortJob = viewModelScope.launch(NonCancellable + Dispatchers.IO) {
            previous?.join()
            if (disconnect) {
                // Lock-free first: the call being aborted may hold the library's lock while it waits for a dead device.
                runCatching { adb.kill() }
                runCatching { adb.disconnect() }
            }
            if (deleting.isNotEmpty()) deleteKeys(deleting)
        }
    }

    private suspend fun deleteKeys(identities: Set<IdentityName>) = adbLock.withLock {
        for (identity in identities) {
            try {
                adb.deleteIdentity(identity)
                unmarkPendingDelete(identity)
                log.add("> keys: deleted the ${identity.id} key")
            } catch (e: Throwable) {
                // Stays marked: the next start tries again.
                log.add(failureLine("keys", e))
            }
        }
    }

    // The mark outlives the process: a key that was to be deleted is deleted at the next start if the app was killed.
    private fun markPendingDelete(identities: Set<IdentityName>) {
        val all = decodeIdentities(identityPrefs.getString(KEY_PENDING_DELETE, null)) + identities
        identityPrefs.edit().putString(KEY_PENDING_DELETE, encodeIdentities(all)).apply()
    }

    private fun unmarkPendingDelete(identity: IdentityName) {
        val left = decodeIdentities(identityPrefs.getString(KEY_PENDING_DELETE, null)) - identity
        identityPrefs.edit().putString(KEY_PENDING_DELETE, encodeIdentities(left)).apply()
    }

    private fun fail(error: AdbError, cause: Throwable? = null) {
        scan("pair", false)
        scanReasons.filter { it.startsWith(OP_PREFIX) }.forEach { scan(it, false) }
        val detail = cause?.let(::diagnostic) ?: error.name
        connection = Connection(ConnectionState.Error, connection.device, error, detail)
        // With a cause, the caller has already logged it (and the class and message with it).
        if (cause == null) log.add("> connect: ${error.name}")
        finishNotification(error.message, cause?.let(::exceptionName))
    }

    /** Reports the end of a pairing that went through the notification service in that notification too. */
    private fun finishNotification(message: Int, details: String? = null) {
        if (viaService) pairing.report(message, details)
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
                local && target.port > 0 -> target.port
                local -> findConnectPort(target, own, paired)
                else -> findNetworkPort(target, paired)
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
            blocking(connectTimeoutMs(quiet)) { adb.connect(host, port, identityFor(target.host, own, target.deviceId)) }
            val name = if (local) target.name else networkDisplayName(target.name, target.host, deviceModel())
            val device = Device(name, host, port, local, target.deviceId)
            connection = Connection(ConnectionState.Connected, device)
            watch.reset()
            watchSession()
            finishNotification(R.string.notif_connected)
            if (!local) saveLastGoodPort(host, port)
            saveRecent(Target(name, host, 0, subnetOf(host), target.deviceId.takeUnless { local }), own)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            val error = connectFailure(e, local, quiet)
            // Quiet reconnects stay off the card but not out of the log: it is what a field report needs.
            log.add(failureLine("connect", e) + " [${error.name}]")
            when (nextAfterConnectFailure(error, local, silent)) {
                Next.GoIdle -> connection = Connection()
                // This phone: the notification service; another device: the code typed in the app. Both follow the
                // pairing dialog's own mDNS service, so no port is typed.
                Next.PairWithNotification, Next.PairWithCodeInApp -> { viaService = false; enterPairing(target, null, null) }
                Next.Fail -> fail(error, e)
            }
        } finally {
            scan(opKey, false)
        }
    }

    /**
     * The port to connect a network device on: the explicit one, or the first of [connectPortCandidates] (what mDNS
     * shows now, the last good port, 5555) that accepts a TCP connection, looked for as long as [connectPortWaitMs]
     * (the service may still be appearing, as after pairing). The library connects with no timeout of its own and
     * holds its lock meanwhile, so a device that does not answer fails here, quickly and cancellably, as unreachable.
     */
    private suspend fun findNetworkPort(target: Target, paired: Boolean): Int {
        val host = target.host
        suspend fun firstUp(ports: List<Int>): Int? = withContext(Dispatchers.IO) {
            ports.map { port -> async { port to tcpReachable(host, port, CONNECT_PROBE_MS) } }.awaitAll().firstOrNull { it.second }?.first
        }
        target.port.takeIf { it > 0 }?.let { explicit ->
            return firstUp(listOf(explicit)) ?: throw ConnectException("No answer from the device on port $explicit")
        }
        val port = withTimeoutOrNull(connectPortWaitMs(paired)) {
            var up: Int? = null
            while (up == null) {
                up = firstUp(connectPortCandidates(mdnsConnectPort(host, found.value), lastGoodPort(host)))
                if (up == null) delay(NETWORK_PORT_POLL_MS)
            }
            up
        }
        return port ?: throw ConnectException("No answer from the device on its debugging port")
    }

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
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        // The library turns an interrupted wait into an IllegalStateException; the model name is not worth failing the connect for.
        null
    }

    private fun saveRecent(target: Target, own: Set<String>) {
        provisionalIds.remove(normalise(target.host))
        recent = addRecent(recent, target, own)
        prefs.edit().putString(KEY_RECENT, encodeRecents(recent)).apply()
    }

    /**
     * Removes [target] from the saved devices and ends any session with it: connection, connecting or pairing (and its
     * notification) all go back to "not connected". This device can be forgotten like any other; its row stays
     * offered in the list as a choice, but neither saved nor connected. Forgetting a device also deletes its own ADB
     * key (this phone's, or the one of a network device), after the pairing notification is gone and under
     * [adbLock]; the session of another device is not touched by it. A device saved by 0.9.24 or earlier uses the
     * shared key, which stays for the others: it is added again with a new key of its own, never the shared one.
     * When no saved device is left, every connection preference is cleared like on a first open ([resetConnections]).
     */
    fun forget(target: Target) {
        val plan = planForget(connection, recent, target, ownAddresses())
        // The service goes first: it must not pair with a key that is about to be deleted.
        if (plan.stopPairing) {
            pairing.stop()
            pairing.dismiss()
        }
        log.add("> forget: ${target.name.ifBlank { target.host }}")
        // A key made for this host before it was ever saved (a pairing that did not finish) goes with it.
        val unsaved = provisionalIds.remove(normalise(target.host))?.let { IdentityName.Network(it) }
        val doomed = if (unsaved == null || IdentityName.Everything in plan.doomed) plan.doomed else plan.doomed + unsaved
        recent = plan.recent
        prefs.edit().remove(LAST_PORT_PREFIX + normalise(target.host)).apply()
        availability.retain(recent.map { it.host })
        reachable = keepSavedHosts(reachable, recent)
        if (plan.resetToFirstRun) {
            resetConnections()
            return
        }
        if (plan.endSession) {
            endSession()
            connection = plan.connection
        }
        prefs.edit().putString(KEY_RECENT, encodeRecents(recent)).apply()
        if (plan.endSession || doomed.isNotEmpty()) {
            // Android trusts the key it paired: deleting that key makes the device ask for authorisation again.
            if (doomed.isNotEmpty()) markPendingDelete(doomed)
            abortAdb(onlyIfBusy = false, deleting = doomed, disconnect = plan.endSession)
        }
    }

    /**
     * Back to a first open: stops any connection or pairing, empties the saved devices and clears everything stored
     * in the connection preferences, and deletes every ADB key (this phone's, the shared one and each device's), so
     * every device has to be paired again. User settings (theme, language, icon, shield, install options, backups) are not touched.
     */
    fun resetConnections() {
        pairing.stop()
        pairing.dismiss()
        endSession()
        probeJob?.cancel()
        recent = emptyList()
        availability.retain(emptyList())
        reachable = emptySet()
        prefs.edit().clear().apply()
        provisionalIds.clear()
        val everything = setOf(IdentityName.Everything)
        markPendingDelete(everything)
        abortAdb(onlyIfBusy = false, deleting = everything)
    }

    /**
     * Runs a blocking call off the main thread, one at a time; gives up (and drops the late result) after
     * [timeoutMs]. A call that timed out in the current generation closes the session unless
     * [disconnectOnTimeout] is false.
     */
    private suspend fun <T> blocking(timeoutMs: Long, disconnectOnTimeout: Boolean = true, block: () -> T): T {
        val mine = generation
        // The session as it was when this call got the lock (-1 until then); 0 while a connect is under way.
        val session = AtomicLong(-1L)
        val work: Deferred<T> = viewModelScope.async(Dispatchers.IO) {
            abortJob?.join()
            adbLock.withLock {
                session.set(adb.sessionId)
                block()
            }
        }
        fun abandon() {
            if (!disconnectOnTimeout) return
            // The work may be stuck on a dead socket and keep the ADB lock for as long as that lasts; closing the
            // session lets it go. Only the session this call began with, never a newer one.
            if (!work.isCompleted) viewModelScope.launch(Dispatchers.IO) {
                if (mine == generation && session.get() == adb.sessionId) runCatching { adb.kill() }
            }
            work.invokeOnCompletion {
                viewModelScope.launch(Dispatchers.IO) {
                    adbLock.withLock { if (mine == generation) runCatching { adb.disconnect() } }
                }
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
    fun installFrom(uri: Uri?): Boolean = installFrom(uri, null, null)

    /**
     * [name] replaces the provider's display name and [ownedCopy] is our own cache copy of a package that came from
     * outside: it is deleted when the install ends and the source is never offered for deletion. True when the install started.
     */
    private fun installFrom(uri: Uri?, name: String?, ownedCopy: File?): Boolean {
        if (uri == null || connection.state != ConnectionState.Connected || install?.working == true) return false
        if (!sessionAlive()) return false
        val shieldOn = shieldSettings.shieldEnabled
        val initialPhase = if (shieldOn) InstallPhase.Checking else InstallPhase.Sending
        install = InstallStatus(working = true, phase = initialPhase, shieldChecking = shieldOn, sourceUri = uri.takeIf { ownedCopy == null })
        installJob = viewModelScope.launch {
            val result = try {
                installApk(uri, name)
            } catch (e: CancellationException) {
                // A reconnect clears `install` first, so this only shows when the job was cancelled in place.
                if (install?.working == true) install = failed(install, transferFailure(e, null))
                throw e
            } catch (e: IOException) {
                // Only a gone session is a lost connection; a stream that ended or timed out leaves it up.
                // Off the main thread: whatever the client is, the answer must never block the UI.
                val lost = installErrorIsConnectionLoss(withContext(Dispatchers.IO) { adb.isAlive })
                if (lost) connection = Connection(ConnectionState.Error, connection.device, AdbError.ConnectionLost, diagnostic(e))
                failed(install, transferFailure(e, diagnostic(e), sessionConnected = !lost))
            } catch (t: Throwable) {
                failed(install, transferFailure(t, diagnostic(t)))
            }
            install = settleSourceFile(uri.takeIf { ownedCopy == null }, result)
        }
        if (ownedCopy != null) installJob?.invokeOnCompletion { ownedCopy.parentFile?.deleteRecursively() }
        return true
    }

    // ---- Packages opened from other apps ("Open with", Share) ----

    /** The one file waiting for a device (or for the running install); a newer one replaces it. */
    var pendingFile by mutableStateOf<IncomingFile?>(null)
        private set

    // Leftovers of a previous process; copying waits for it so it never deletes a fresh copy.
    private val incomingCleanup = viewModelScope.launch(Dispatchers.IO) { File(getApplication<Application>().cacheDir, INCOMING_DIR).deleteRecursively() }

    /** Copies [uri] now (the grant is temporary), checks it, and installs it as soon as it can: see [startPendingFile]. */
    fun receiveFile(uri: Uri) {
        viewModelScope.launch {
            incomingCleanup.join()
            val incoming = withContext(Dispatchers.IO) { copyIncoming(uri) }
            if (incoming == null) {
                log.add("> file: not an installable package")
                if (install?.working != true) install = InstallStatus(false, reason = R.string.err_not_installable)
                return@launch
            }
            pendingFile?.let {
                log.add("> file: ${it.name} replaced by ${incoming.name}")
                it.file.parentFile?.deleteRecursively()
            }
            log.add("> file: ${incoming.name} waiting for an install slot")
            pendingFile = incoming
            startPendingFile()
        }
    }

    /** Null (and no copy left) when the file cannot be read or is not an APK or a bundle of APKs. */
    private fun copyIncoming(uri: Uri): IncomingFile? {
        val app = getApplication<Application>()
        val dir = File(app.cacheDir, "$INCOMING_DIR/${System.nanoTime()}")
        val copy = File(dir, "source.pkg")
        val ok = runCatching {
            // A file: Uri must not reach into this app's own private storage.
            if (uri.scheme == "file" && uri.path?.let { File(it).canonicalPath.startsWith(File(app.applicationInfo.dataDir).canonicalPath) } != false) return@runCatching false
            dir.mkdirs()
            val copied = app.contentResolver.openInputStream(uri)?.use { input -> copy.outputStream().use { input.copyTo(it, 64 * 1024) } }
            copied != null && copied > 0L && looksInstallable(copy)
        }.getOrDefault(false)
        if (!ok) {
            dir.deleteRecursively()
            return null
        }
        return IncomingFile(incomingDisplayName(fileInfo(uri).first ?: uri.lastPathSegment), copy)
    }

    /** Starts the waiting file when a device is connected and nothing is installing; called again whenever either changes. */
    fun startPendingFile() {
        val waiting = pendingFile ?: return
        if (!pendingFileReady(connection.state == ConnectionState.Connected, install?.working == true)) return
        if (installFrom(Uri.fromFile(waiting.file), waiting.name, waiting.file)) pendingFile = null
    }

    fun cancelPendingFile() {
        pendingFile?.file?.parentFile?.deleteRecursively()
        pendingFile = null
    }

    /**
     * Applies "Delete APK after install" to the finished [result]: Off drops the button, On keeps it, Automatic deletes
     * the picked file after a successful install and says so in the terminal.
     */
    private suspend fun settleSourceFile(uri: Uri?, result: InstallStatus): InstallStatus =
        if (uri == null) result.copy(sourceUri = null) else when (deleteSourceAction(installSettings.deleteSourceMode, result.ok)) {
            DeleteSourceAction.None -> result.copy(sourceUri = null)
            DeleteSourceAction.OfferButton -> result
            DeleteSourceAction.DeleteNow -> {
                val resolver = getApplication<Application>().contentResolver
                val deleted = withContext(Dispatchers.IO) {
                    runCatching { DocumentsContract.deleteDocument(resolver, uri) }.getOrDefault(false)
                }
                val line = if (deleted) "> file: auto-deleted source package after installation"
                else "> file: automatic delete failed (storage permission or provider does not allow deletion)"
                result.copy(sourceUri = null, logs = result.logs + line)
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
                // Not "not installed": the device could not be asked, so the installed version is unknown.
                InstalledAppInfo(null, null, queryFailed = true)
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
                candidateMinSdk = candidateInfo.minSdk,
                candidateTargetSdk = candidateInfo.targetSdk,
                candidateLineageSha256 = candidateInfo.lineageSha256,
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

        // Whatever could not be checked is a finding of its own: the Shield never reports "clean" for part of a package.
        val extraIssues = mutableListOf<StaticAnalysisIssue>()
        if (installedInfo?.queryFailed == true) {
            appendLog(mine, "> installed version: the device could not be asked, no downgrade or signer comparison was possible")
            extraIssues += StaticAnalysisIssue(
                ShieldWarningReason.ScanIncomplete,
                "The installed version could not be read from the device",
                IssueCode.InstalledQueryFailed,
            )
        }
        val scanIssues = mutableListOf<StaticAnalysisIssue>()
        var trackers: List<String> = emptyList()
        if (shieldSettings.deepScanEnabled) {
            appendLog(mine, "> deep scan: analyzing bytecode & assets...")
            val deepScanResult = withContext(Dispatchers.IO) {
                StaticAnalyzer.analyzeApkOrBundle(
                    sourceFile = sourceFile,
                    bundle = bundle,
                    permissions = offline.allPermissions + offline.capabilities,
                    packageName = pkg,
                )
            }
            if (mine != generation) throw CancellationException()
            trackers = deepScanResult.trackers
            if (deepScanResult.trackers.isNotEmpty()) {
                appendLog(mine, "> trackers (informational): ${deepScanResult.trackers.size} found: ${deepScanResult.trackers.joinToString(", ")}")
            }
            deepScanResult.notes.forEach { appendLog(mine, "> deep scan note: $it") }
            for (issue in deepScanResult.issues) {
                appendLog(mine, "> deep scan: found ${issue.reason.name} (${issue.detail})${issue.apk?.let { " in $it" }.orEmpty()}")
            }
            scanIssues += deepScanResult.issues
            if (deepScanResult.issues.none { it.reason == ShieldWarningReason.ScanIncomplete }) {
                appendLog(
                    mine,
                    "> deep scan: ${deepScanResult.dexInspected} of ${deepScanResult.dexCount} DEX files fully inspected, " +
                        "${deepScanResult.issues.size} finding(s)",
                )
            } else {
                appendLog(mine, "> deep scan: INCOMPLETE, part of the package could not be inspected (not reported as clean)")
            }
        } else {
            appendLog(mine, "> deep scan: off (dropper, adware, permission and native-library rules were not run)")
        }
        val allIssues = extraIssues + scanIssues
        val combinedOffline = offline.copy(
            reasons = (offline.reasons + allIssues.map { it.reason }).distinct(),
            // A structural problem found by the archive checks keeps its own description.
            issueDetail = offline.issueDetail ?: allIssues.firstOrNull()?.detail,
            trackers = trackers,
            issues = allIssues,
        )

        val apiKey = withContext(Dispatchers.IO) { shieldSettings.loadVirusTotalApiKey() }?.takeIf { it.isNotBlank() }
        if (mine != generation) throw CancellationException()
        val trusted = isTrustedUpdate(combinedOffline, installedInfo)
        // The unit of proof is each APK; the container is never looked up. OBB files are data and are not scanned.
        if (bundle.obbs.isNotEmpty()) appendLog(mine, "> reputation: ${bundle.obbs.size} .obb file(s) are data and are not scanned")
        val baseName = if (bundle.format == PackageFormat.SingleApk) null else bundle.findBaseApk()?.entryPath
        val targets = if (bundle.format == PackageFormat.SingleApk) {
            listOf(Triple(displayName, sourceFile, true))
        } else {
            bundle.apks.map { Triple(it.name, it.file, baseName == null || it.entryPath == baseName) }
        }
        val evidence = mutableListOf<ShieldFileEvidence>()
        val filesBySha = mutableMapOf<String, File>()
        val scanned = mutableListOf<ScannedFile>()
        if (apiKey == null) {
            appendLog(mine, "> reputation: no API key set, not checked by online engines (on-device checks only)")
        }
        // A source whose key was rejected is not asked again for the next file of the same package.
        var vtKeyBad = false
        for ((name, file, isBase) in targets) {
            val size = file?.length() ?: 0L
            val sha = file?.let { withContext(Dispatchers.IO) { sha256Hex(it) } }.orEmpty()
            if (file != null && sha.isNotEmpty()) {
                filesBySha[sha] = file
                scanned += ScannedFile(file, size, sha)
            }
            // Resource-only splits carry no code: they are not looked up (the offline checks above covered them).
            val lookup = file == null || needsReputationLookup(isBase, apkEntryNames(file) ?: listOf("classes.dex"))
            if (!lookup) {
                appendLog(mine, "> reputation: ${sha.take(12)} $name: resource-only split, not looked up")
                evidence += ShieldFileEvidence(name, size, sha, lookedUp = false)
                continue
            }
            val askVt = apiKey != null && !vtKeyBad && sha.isNotEmpty()
            var answers = ReputationLookup(SourceLookup(null), SourceLookup(null))
            if (askVt) {
                // IO thread: the cache reads and writes a file. Its notes are logged afterwards, from the main thread.
                val notes = mutableListOf<String>()
                answers = withContext(Dispatchers.IO) {
                    val vtLookup: (suspend () -> VtLookupResult)? = if (apiKey == null) null else {
                        { vtPacer.await(); checkVirusTotalHash(sha, apiKey) }
                    }
                    lookupBothSources(
                        sha, reputationCache,
                        vt = vtLookup,
                        md = null,
                        note = { notes += "> reputation: ${sha.take(12)} $it" },
                    )
                }
                notes.forEach { appendLog(mine, it) }
                if (mine != generation) throw CancellationException()
                answers.vt.result?.let { appendLog(mine, vtLookupLine(sha, name, ShieldSource.VirusTotal, it)) }
                if (answers.vt.result == VtLookupResult.InvalidKey) vtKeyBad = true
            }
            evidence += ShieldFileEvidence(
                name, size, sha,
                vt = answers.vt.result, md = null,
                vtInfo = answers.vt.info, mdInfo = SourceInfo(),
            )
        }

        val first = evaluateShieldVerdict(
            sha256, combinedOffline, apiKey != null, trusted, evidence,
            canUpload = apiKey != null, displayName = displayName,
        )
        val verdict = if (first is ShieldVerdict.NeedsUpload && apiKey != null) {
            resolveUpload(mine, first, filesBySha, evidence, apiKey, trusted, sha256, combinedOffline, displayName)
        } else {
            first
        }
        when (verdict) {
            is ShieldVerdict.Clean -> appendLog(
                mine,
                "> shield verdict: PASS (" + when {
                    verdict.trustedUpdate -> "update of the installed app, same signature" + (verdict.vtSummary?.let { ", online engines $it" }.orEmpty())
                    else -> "online engines ${verdict.vtSummary}"
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
            is ShieldVerdict.NeedsUpload -> appendLog(mine, "> shield verdict: CAUTION (${ShieldWarningReason.VirusTotalUnreachable.name})")
        }
        return ShieldRun(
            if (verdict is ShieldVerdict.NeedsUpload) {
                ShieldVerdict.Warning(sha256, listOf(ShieldWarningReason.VirusTotalUnreachable), 0, 0, combinedOffline, verdict.report)
            } else {
                verdict
            },
            scanned,
            installedInfo,
        )
    }

    private fun vtLookupLine(sha: String, name: String, source: ShieldSource, res: VtLookupResult): String {
        val head = "> reputation: ${sha.take(12)} $name: ${source.displayName}"
        return when (res) {
            is VtLookupResult.Found -> {
                val names = res.detections.take(6).joinToString("; ") { "${it.engine}: ${it.label.ifBlank { "(no name)" }}" }
                "$head ${res.malicious} malicious, ${res.suspicious} suspicious / ${res.total} engines, " +
                    analysisAgeText(res.lastAnalysisDate, System.currentTimeMillis() / 1000L) +
                    (if (names.isNotEmpty()) " [$names]" else "")
            }
            VtLookupResult.UnknownHash -> "$head not in database"
            VtLookupResult.InvalidKey -> "$head API key rejected"
            VtLookupResult.RateLimited -> "$head rate limited"
            VtLookupResult.Unavailable -> "$head unreachable (no connection, timeout or service error)"
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
        displayName: String,
    ): ShieldVerdict {
        // The same decision without the upload offer: it already lists every other reason plus "not known". [extra] is
        // added when the upload itself failed.
        fun stayUnverified(extra: ShieldWarningReason? = null, files: List<ShieldFileEvidence> = evidence): ShieldVerdict {
            val base = evaluateShieldVerdict(sha256, offline, true, trusted, files, canUpload = false, displayName = displayName)
            if (extra == null || base !is ShieldVerdict.Warning) return base
            return base.copy(reasons = orderedByGravity(base.reasons + extra))
        }
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
            return stayUnverified()
        }

        val updated = evidence.toMutableList()
        var sentBefore = 0L
        for (candidate in candidates) {
            val file = filesBySha[candidate.sha256] ?: return stayUnverified(ShieldWarningReason.VirusTotalUnreachable)
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
                return stayUnverified(ShieldWarningReason.VirusTotalUnreachable)
            }
            sentBefore += candidate.sizeBytes
            install = install?.copy(phase = InstallPhase.Analysing, percent = 99)
            appendLog(mine, "> virustotal: analysis queued for ${candidate.name}, waiting (up to 10 min)")
            val result = awaitVirusTotalAnalysis(analysisId, apiKey, vtPacer)
            if (mine != generation) throw CancellationException()
            if (result !is VtLookupResult.Found) {
                appendLog(mine, "> virustotal: analysis of ${candidate.name} did not complete (${result::class.simpleName})")
                return stayUnverified(ShieldWarningReason.VirusTotalUnreachable)
            }
            appendLog(mine, "> virustotal: analysis completed ${candidate.name}: ${result.malicious} malicious, ${result.suspicious} suspicious / ${result.total} engines")
            val info = SourceInfo(fromCache = false, checkedAtMs = System.currentTimeMillis())
            updated.replaceAll { if (it.sha256 == candidate.sha256) it.copy(vt = result, vtInfo = info) else it }
        }
        install = install?.copy(phase = InstallPhase.Checking, percent = 0)
        val again = evaluateShieldVerdict(sha256, offline, hasKey = true, trustedUpdate = trusted, files = updated, displayName = displayName)
        return if (again is ShieldVerdict.NeedsUpload) stayUnverified(ShieldWarningReason.VirusTotalUnreachable, updated) else again
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
            verdict?.report,
        )

    private fun shieldBlockedStatus(label: String, verdict: ShieldVerdict.Warning, logs: List<String>): InstallStatus {
        // The reasons arrive ordered by gravity, so the sentence on the main button is about the most serious one.
        val primaryReasonRes = verdict.reasons.firstOrNull()?.let(::shortReasonRes) ?: R.string.shield_blocked_generic
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

        // The card lists every reason in the user's language; this English line is only for the terminal log.
        val primaryReason = verdict.reasons.first()
        val detail = verdict.reasons.joinToString(", ") { it.name }
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
        // Off: nothing is read from the device and nothing is written; backups already saved stay as they are.
        val enabled = installSettings.backupBeforeUpdate
        if (!shouldBackupBeforeUpdate(enabled, pkg, installedInfo?.versionCode)) {
            if (!enabled && installedInfo?.versionCode != null) appendLog(mine, "> backup: off, the installed version is not saved")
            return
        }
        if (pkg == null) return
        val device = connection.device ?: return
        try {
            // Under the ADB lock like every other call, so it never overlaps a keepalive or another shell.
            val item = blocking(INSTALL_TIMEOUT_MS, disconnectOnTimeout = false) {
                backupManager.createBackup(adb, pkg, installedInfo, device.backupId(), device.name)
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
    private suspend fun installApk(uri: Uri, nameHint: String? = null): InstallStatus {
        val app = getApplication<Application>()
        val resolver = app.contentResolver
        val (queriedName, size) = withContext(Dispatchers.IO) { fileInfo(uri) }
        val fileName = nameHint ?: queriedName
        val mine = generation
        val userInstall = installSettings.homeShortcut
        val generic = app.getString(R.string.unnamed_package)
        install = install?.copy(name = installLabel(null, fileName, generic))
        if (size != null && size <= 0) return failure(R.string.err_read_file)

        // The app's private cache: no other app can swap a file between the check and the install (external storage can be
        // written by other apps on older Android versions).
        val baseCache = app.cacheDir
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
                suspend fun attempt(bypass: Boolean, testOnly: Boolean = false): String = blocking(INSTALL_TIMEOUT_MS, disconnectOnTimeout = false) {
                    check(mayInstall(verdict, userOverridden)) { "The shield did not clear this package" }
                    report(0)
                    // Keep Google Play Protect out of ADB installs; the previous settings are put back after the attempts.
                    adb.shell(DisableAdbVerifyCommand)
                    adb.shell(DisableVerifierCommand)
                    sourceFile.inputStream().use { adb.install(streamInstallCommand(apkSize, bypass, userInstall, testOnly), apkSize, it, ::report) }
                }
                val savedVerifier = blocking(CONNECT_TIMEOUT_MS, disconnectOnTimeout = false) { readVerifierSettings(adb) }
                var output = ""
                try {
                    output = attempt(bypass = true)
                    var usedBypass = true
                    if (shouldRetryWithoutBypass(output)) {
                        if (changedAfterScan()) return failure(R.string.reason_file_changed)
                        appendLog(mine, "> adb: retrying ${streamInstallCommand(apkSize, bypass = false, userInstall)}")
                        output = attempt(bypass = false)
                        usedBypass = false
                    }
                    if (isTestOnlyFailure(output)) {
                        if (changedAfterScan()) return failure(R.string.reason_file_changed)
                        appendLog(mine, "> adb: test-only package detected, retrying with -t")
                        output = attempt(bypass = usedBypass, testOnly = true)
                    }
                } finally {
                    withContext(NonCancellable) {
                        runCatching {
                            blocking(CONNECT_TIMEOUT_MS, disconnectOnTimeout = false) {
                                restoreVerifierSettings(adb, savedVerifier) { line -> postLog(mine, line) }
                            }
                        }
                    }
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
                    install = install?.copy(userAuthorized = true)
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
                        var result = installBundleSession(
                            adb = adb,
                            splits = filtered.splits,
                            obbs = bundle.obbs,
                            packageName = pkg,
                            onProgress = { sent, total -> updateInstallProgress(mine, sent, total) },
                            onLog = { line -> postLog(mine, line) },
                            userInstall = userInstall,
                        )
                        if (isTestOnlyFailure(result.line)) {
                            if (verdict != null && !filesUnchangedSinceScan(shield.scanned, filtered.splits.map { it.file })) {
                                postLog(mine, "> shield: a split changed after it was checked, nothing was installed")
                                return@blocking BundleOutcome.FailedReason(R.string.reason_file_changed)
                            }
                            postLog(mine, "> adb: test-only split detected, retrying with -t")
                            result = installBundleSession(
                                adb = adb,
                                splits = filtered.splits,
                                obbs = bundle.obbs,
                                packageName = pkg,
                                onProgress = { sent, total -> updateInstallProgress(mine, sent, total) },
                                onLog = { line -> postLog(mine, line) },
                                userInstall = userInstall,
                                testOnly = true,
                            )
                        }
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
                            latestStatus.copy(
                                working = false,
                                ok = true,
                                percent = 100,
                                phase = InstallPhase.Done,
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
        PairingBridge.onFailed = null
        pairing.stop()
        if (scanReasons.isNotEmpty()) discovery.release()
        scanReasons.clear()
        Thread { runCatching { adb.disconnect() } }.start()
    }
}
