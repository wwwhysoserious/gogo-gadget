package app.gogogadget

import io.github.muntashirakon.adb.AdbAuthenticationFailedException
import io.github.muntashirakon.adb.AdbPairingRequiredException
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException

// Pure logic for the ADB layer: no Android classes, no network, fully unit-tested.

/** A device to connect to. [port] 0 means "look it up by mDNS". */
data class Target(val name: String, val host: String, val port: Int)

/** [Remote] is the Android/Google TV remote service: every such device announces it, debugging on or not. */
enum class FoundKind { Connect, Pairing, Remote }

/** A service seen on the network by mDNS. */
data class Found(val name: String, val host: String, val port: Int, val kind: FoundKind)

data class Endpoint(val host: String, val port: Int)

private fun normalise(host: String): String =
    host.trim().removeSurrounding("[", "]").substringBefore('%').lowercase().removePrefix("::ffff:")

private fun ipv4Octets(host: String): List<Int>? {
    val parts = host.split('.')
    if (parts.size != 4) return null
    val octets = parts.map { p -> p.takeIf { it.length in 1..3 && it.all(Char::isDigit) }?.toInt() }
    return if (octets.any { it == null || it > 255 }) null else octets.map { it!! }
}

/** True for loopback (127.0.0.0/8, ::1, localhost) or any address of this device's own interfaces. */
fun isLocalHost(host: String, ownAddresses: Collection<String>): Boolean {
    val h = normalise(host)
    if (h == "localhost" || h == "::1") return true
    if (ipv4Octets(h)?.first() == 127) return true
    return ownAddresses.any { normalise(it) == h }
}

fun parsePort(text: String): Int? = text.trim().toIntOrNull()?.takeIf { it in 1..65535 }

private val HostLabel = Regex("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")

fun isValidHost(host: String): Boolean {
    val h = normalise(host)
    if (h.isEmpty() || h.length > 253) return false
    if (':' in h) return h.count { it == ':' } >= 2 && h.all { it in "0123456789abcdef:." }
    if (h.all { it.isDigit() || it == '.' }) return ipv4Octets(h) != null
    return h.split('.').all { HostLabel.matches(it) }
}

/** Private or link-local addresses only: the app never talks to the internet. */
fun isLanHost(host: String): Boolean {
    val h = normalise(host)
    ipv4Octets(h)?.let { (a, b) ->
        return a == 10 || a == 127 || (a == 172 && b in 16..31) || (a == 192 && b == 168) || (a == 169 && b == 254)
    }
    if (':' in h) return h == "::1" || h.startsWith("fe8") || h.startsWith("fe9") || h.startsWith("fea") ||
        h.startsWith("feb") || h.startsWith("fc") || h.startsWith("fd")
    return h == "localhost" || h.endsWith(".local")
}

/** Validates the manual-entry fields; a blank port means 0 (find it by mDNS), a typed one must be valid. */
fun parseEndpoint(host: String, port: String): Endpoint? {
    val p = if (port.isBlank()) 0 else parsePort(port) ?: return null
    return if (isValidHost(host) && isLanHost(host)) Endpoint(host.trim(), p) else null
}

/** Connect port for [target]: its own, or the best mDNS match (any local service for this device). */
fun resolveConnectPort(target: Target, found: List<Found>, ownAddresses: Collection<String>): Int? {
    if (target.port > 0) return target.port
    val wantLocal = isLocalHost(target.host, ownAddresses)
    return found.firstOrNull {
        it.kind == FoundKind.Connect &&
            if (wantLocal) isLocalHost(it.host, ownAddresses) else normalise(it.host) == normalise(target.host)
    }?.port
}

/** The pairing service of [target] seen by mDNS, same matching rules as [resolveConnectPort]. */
fun resolvePairing(target: Target, found: List<Found>, ownAddresses: Collection<String>): Found? {
    val wantLocal = isLocalHost(target.host, ownAddresses)
    return found.firstOrNull {
        it.kind == FoundKind.Pairing &&
            if (wantLocal) isLocalHost(it.host, ownAddresses) else normalise(it.host) == normalise(target.host)
    }
}

fun resolvePairingPort(target: Target, found: List<Found>, ownAddresses: Collection<String>): Int? =
    resolvePairing(target, found, ownAddresses)?.port

/**
 * Hosts to try for pairing, in order. For this device the pairing dialog shows the Wi-Fi address, so that comes
 * first (when mDNS reported it) and loopback is the fallback; any other device only has its own host.
 */
fun pairingHosts(target: Target, seen: Found?, local: Boolean, loopback: String): List<String> =
    if (local) listOfNotNull(seen?.host, loopback).distinct() else listOf(target.host)

/** What to do when mDNS shows no connect port for a target. */
enum class NoPortAction { GoIdle, StartPairing, ReportMissing }

/** Silent reconnects stay quiet; a first connect goes to pairing; after pairing a missing port is an error. */
fun noPortAction(silent: Boolean, paired: Boolean): NoPortAction = when {
    silent -> NoPortAction.GoIdle
    paired -> NoPortAction.ReportMissing
    else -> NoPortAction.StartPairing
}

/** How long to look for the connect port: longer right after pairing, when the service is still appearing. */
fun connectPortWaitMs(paired: Boolean): Long = if (paired) 15_000L else 5_000L

/** `host:port`, with IPv6 hosts in brackets. */
fun hostPort(host: String, port: Int): String = if (':' in host) "[$host]:$port" else "$host:$port"

// ---- Errors ----

enum class AdbError(val message: Int) {
    WirelessDebuggingOff(R.string.err_wd_off),
    WrongCode(R.string.err_wrong_code),
    TlsFailed(R.string.err_tls_failed),
    PairingUnreachable(R.string.err_pairing_unreachable),
    NoConnectPort(R.string.err_no_connect_port),
    PairingRequired(R.string.err_pairing_required),
    KeyError(R.string.err_key),
    AllowTimeout(R.string.err_allow_timeout),
    ConnectionLost(R.string.err_connection_lost),
    Unreachable(R.string.err_unreachable),
    Failed(R.string.err_failed),
}

enum class Phase { Pair, Connect, Session }

/** The app's own ADB key could not be loaded or created. */
class AdbKeyException(cause: Throwable) : Exception("The ADB key could not be loaded", cause)

/**
 * Maps a failure to the short message shown to the user. While pairing only the errors that really mean a refused
 * code say so (the device closes the connection, or the encrypted exchange does not complete); a failed TLS
 * handshake, an unreachable service or anything else gets its own message.
 */
fun classifyError(e: Throwable, phase: Phase, local: Boolean): AdbError {
    val chain = generateSequence(e) { it.cause }.take(8).toList()
    if (phase == Phase.Pair) return classifyPairing(chain)
    return when {
        chain.any { it is AdbPairingRequiredException || it is AdbAuthenticationFailedException } -> AdbError.PairingRequired
        chain.any { it is ConnectException } ->
            if (local) AdbError.WirelessDebuggingOff else AdbError.Unreachable
        chain.any { it is SocketTimeoutException || it is NoRouteToHostException || it is UnknownHostException } ->
            AdbError.Unreachable
        phase == Phase.Connect && e is InterruptedException -> AdbError.Unreachable
        phase == Phase.Session && e is IOException -> AdbError.ConnectionLost
        else -> AdbError.Failed
    }
}

// Messages thrown by libadb-android's PairingConnectionCtx when the SPAKE2 exchange ends without success.
private val PairingRefusedMessages = listOf("Exchanging message wasn't successful", "Could not exchange peer info")

private fun classifyPairing(chain: List<Throwable>): AdbError = when {
    chain.any { it is AdbKeyException } -> AdbError.KeyError
    chain.any { it is SSLException } -> AdbError.TlsFailed
    chain.any { it is ConnectException || it is SocketTimeoutException || it is NoRouteToHostException ||
        it is UnknownHostException } -> AdbError.PairingUnreachable
    chain.any { it is EOFException || PairingRefusedMessages.any { m -> it.message?.contains(m) == true } } ->
        AdbError.WrongCode
    else -> AdbError.Failed
}

// ---- Diagnostics ----

private val SixDigits = Regex("(?<!\\d)\\d{6}(?!\\d)")
private val LongToken = Regex("[A-Za-z0-9+/=_-]{32,}")
private const val DetailMaxLength = 160
private const val DetailChainLength = 3

/**
 * One short line for the error screen: exception class and message of the failure and its causes. Digit runs of
 * the length of a pairing code and anything that looks like key material are masked; the code itself is never
 * passed in here.
 */
fun diagnostic(e: Throwable): String =
    generateSequence(e) { it.cause }.take(DetailChainLength)
        .joinToString(" < ") { t -> (t.javaClass.simpleName.ifEmpty { t.javaClass.name } + (t.message?.let { ": $it" } ?: "")) }
        .map { if (it.isISOControl()) ' ' else it }.joinToString("")
        .replace(SixDigits, "******")
        .replace(LongToken, "...")
        .take(DetailMaxLength)

// ---- Installing ----

data class PmResult(val success: Boolean, val line: String)

/** Reads the output of `pm install`: only a "Success" line counts as success. */
fun parsePmOutput(output: String): PmResult {
    val lines = output.replace("\r", "").lines().map { it.trim() }.filter { it.isNotEmpty() }
    if (lines.any { it == "Success" || it.startsWith("Success:") }) return PmResult(true, "Success")
    val failure = lines.firstOrNull { it.startsWith("Failure") || it.startsWith("Error") || it.startsWith("Exception") }
    return PmResult(false, failure ?: lines.lastOrNull() ?: "No output from pm")
}

/** Older Android versions do not know the bypass flag; then the install is retried without it. */
fun shouldRetryWithoutBypass(output: String): Boolean {
    val o = output.lowercase()
    return "unknown option" in o || "unknown argument" in o || ("bypass-low-target-sdk-block" in o && "error" in o)
}

/** PackageManager.INSTALL_REASON_USER: with it, a new install makes the launcher add the app icon to the home screen. */
const val InstallReasonUser = 4

/** Streams an APK of [size] bytes from stdin, so nothing has to be readable on the device. */
fun streamInstallCommand(size: Long, bypass: Boolean, userInstall: Boolean = false): String =
    "cmd package install -S $size -r -d${if (bypass) " --bypass-low-target-sdk-block" else ""}" +
        if (userInstall) " --install-reason $InstallReasonUser" else ""

/** Where the in-app pairing form for another device stands, from the typed code and the pairing port (null until mDNS sees the dialog). */
enum class PairingStep { EnterCode, WaitingForDialog, Submit }

/**
 * A complete code typed before the port is known stays pending (in memory only) and is submitted the moment the port
 * appears; with the port known, a complete code is submitted at once.
 */
fun pairingStep(code: String, port: Int?): PairingStep = when {
    code.length != PairingCodeLength || !code.all { it in '0'..'9' } -> PairingStep.EnterCode
    port == null -> PairingStep.WaitingForDialog
    else -> PairingStep.Submit
}

/** What the "This device" pairing screen says: the code is typed in the notification, so only the dialog matters. */
enum class LocalPairingStatus { WaitingForDialog, DialogFound }

fun localPairingStatus(port: Int?): LocalPairingStatus =
    if (port != null) LocalPairingStatus.DialogFound else LocalPairingStatus.WaitingForDialog

const val PairingCodeLength = 6

/**
 * Six ASCII digits out of typed or pasted text (spaces and hyphens, as in "123 456", are ignored); null for anything
 * else. Shared by the notification and the in-app field.
 */
fun parsePairingCode(text: CharSequence?): String? =
    text?.filterNot { it.isWhitespace() || it == '-' }?.toString()
        ?.takeIf { it.length == PairingCodeLength && it.all { c -> c in '0'..'9' } }

/** What the pairing service does with a reply typed in its notification. The code is never part of [toString]. */
sealed interface ReplyDecision {
    class Submit(val code: String, val port: Int) : ReplyDecision {
        override fun toString() = "Submit(port=$port)"
    }
    data object BadCode : ReplyDecision
    data object NoPort : ReplyDecision
}

/** [port] comes from the PendingIntent extras (the service may have been killed since it was found); -1 if absent. */
fun decideReply(raw: CharSequence?, port: Int): ReplyDecision {
    if (port !in 1..65535) return ReplyDecision.NoPort
    val code = parsePairingCode(raw) ?: return ReplyDecision.BadCode
    return ReplyDecision.Submit(code, port)
}

// ---- This device: only accept the pairing dialog of this phone (Shizuku's rule) ----

private fun sameHost(a: String, b: String) = normalise(a) == normalise(b)

/**
 * True when [port] is already taken on this phone: [bind] tries to bind 127.0.0.1:[port] and throws an
 * [IOException] if that fails, which is only the case when a service of this phone listens there.
 */
fun isPortBoundLocally(port: Int, bind: (Int) -> Unit): Boolean = try {
    bind(port)
    false
} catch (e: IOException) {
    true
}

/**
 * The pairing service that belongs to this phone: its host is one of this device's own interface addresses AND its
 * port is bound locally ([portBound]). Another device's dialog on the same Wi-Fi fails both tests.
 */
fun acceptOwnPairing(found: List<Found>, ownAddresses: Collection<String>, portBound: (Int) -> Boolean): Found? =
    found.firstOrNull { f ->
        f.kind == FoundKind.Pairing && ownAddresses.any { sameHost(it, f.host) } && portBound(f.port)
    }

// ---- Network devices: the ClaimTV way (connect first, the other device asks to Allow) ----

/** Classic network debugging (`adb tcpip 5555`) does not announce itself over mDNS. */
const val ClassicAdbPort = 5555

/** A device on the network with everything mDNS told about it, merged per host. */
data class NetDevice(val host: String, val name: String?, val connectPort: Int?, val pairPort: Int?)

/**
 * Merges the services of every other device on the network per IPv4 host (this phone's own services are left
 * out). The friendly name comes from the remote service only: adb services are named `adb-<serial>-xyz`.
 */
fun mergeByHost(found: List<Found>, ownAddresses: Collection<String>): List<NetDevice> {
    val hosts = LinkedHashMap<String, NetDevice>()
    for (f in found) {
        if (ipv4Octets(normalise(f.host)) == null || isLocalHost(f.host, ownAddresses)) continue
        val key = normalise(f.host)
        val old = hosts[key] ?: NetDevice(key, null, null, null)
        hosts[key] = when (f.kind) {
            FoundKind.Remote -> old.copy(name = f.name.takeIf { it.isNotBlank() } ?: old.name)
            FoundKind.Pairing -> old.copy(pairPort = f.port)
            FoundKind.Connect -> old.copy(connectPort = f.port)
        }
    }
    return hosts.values.toList()
}

/** Port for a network device: the one given, else the Wireless debugging port seen by mDNS, else 5555. */
fun networkConnectPort(explicit: Int, mdnsPort: Int?): Int =
    explicit.takeIf { it > 0 } ?: mdnsPort ?: ClassicAdbPort

/** mDNS connect port of the network device at [host], if any. */
fun mdnsConnectPort(host: String, found: List<Found>): Int? =
    found.lastOrNull { it.kind == FoundKind.Connect && sameHost(it.host, host) }?.port

/** Tapping a device in the list: connect (port 5555 when mDNS shows no connect service), or pair if only its pairing dialog is open. */
sealed interface TapAction {
    data class Connect(val port: Int) : TapAction
    data class Pair(val pairPort: Int) : TapAction
}

fun tapAction(device: NetDevice): TapAction = when {
    device.connectPort != null -> TapAction.Connect(device.connectPort)
    device.pairPort != null -> TapAction.Pair(device.pairPort)
    else -> TapAction.Connect(ClassicAdbPort)
}

/** Friendly name from the remote service, else the device's model, else its address. */
fun networkDisplayName(friendly: String?, host: String, model: String?): String =
    friendly?.trim()?.takeIf { it.isNotEmpty() && !sameHost(it, host) }
        ?: model?.trim()?.takeIf { it.isNotEmpty() }
        ?: host

// ---- Which method pairs which target ----

/** This phone pairs through the notification (the dialog stays visible); other devices ask for the code in the app. */
enum class PairingMethod { Notification, InAppCode }

fun pairingMethod(local: Boolean): PairingMethod = if (local) PairingMethod.Notification else PairingMethod.InAppCode

enum class FirstStep { DirectConnect, PairNow }

/**
 * First thing to do for a target. Any network device is connected to straight away (the other device shows its own
 * Allow prompt). This phone is connected to first only if its connect port is known; otherwise Wireless debugging is
 * off or was never paired and pairing starts at once.
 */
fun firstStep(local: Boolean, connectPort: Int?): FirstStep =
    if (local && connectPort == null) FirstStep.PairNow else FirstStep.DirectConnect

enum class Next { GoIdle, PairWithNotification, PairWithCodeInApp, Fail }

/**
 * What follows a failed direct connect. Only "pairing required" (also reported for a refused key) leads to pairing:
 * by notification for this phone, by the code typed in the app for another device. Silent reconnects stay quiet.
 */
fun nextAfterConnectFailure(error: AdbError, local: Boolean, silent: Boolean): Next = when {
    silent -> Next.GoIdle
    error == AdbError.PairingRequired ->
        if (pairingMethod(local) == PairingMethod.Notification) Next.PairWithNotification else Next.PairWithCodeInApp
    else -> Next.Fail
}

/** Time the other device gets to show its Allow prompt: adbd waits for the tap with no timeout of its own. */
const val AllowWaitMs = 45_000L
private const val SilentConnectMs = 25_000L

fun connectTimeoutMs(silent: Boolean): Long = if (silent) SilentConnectMs else AllowWaitMs

/** Message under "Connecting…" while an Allow prompt may be showing; none for silent reconnects. */
fun allowNoteFor(local: Boolean, silent: Boolean): Int? = when {
    silent -> null
    local -> R.string.allow_note_local
    else -> R.string.allow_note_network
}

/** Thrown by the app's own watchdog when a call took longer than allowed. */
class WatchdogTimeoutException : SocketTimeoutException("Timed out")

/** A connect that ran into the watchdog while someone had to tap Allow gets its own message. */
fun connectFailure(e: Throwable, local: Boolean, silent: Boolean): AdbError {
    val error = classifyError(e, Phase.Connect, local)
    val watchdog = generateSequence(e) { it.cause }.take(8).any { it is WatchdogTimeoutException }
    return if (watchdog && !silent && error == AdbError.Unreachable) AdbError.AllowTimeout else error
}

// ---- Reading command output ----

/**
 * Printed after every command (`; echo <marker>`). libadb's reader can block when the device closes a stream right
 * after its last bytes, so output is read until this line shows up and never until end-of-stream.
 */
const val EndMarker = "__GOGO_END__"

private val MarkerLine = Regex("(?m)^$EndMarker\\r?$")

fun withEndMarker(command: String): String = "$command; echo $EndMarker"

/** The output before the marker line, or null while the marker has not arrived (the command is unfinished). */
fun outputBeforeMarker(output: String): String? =
    MarkerLine.find(output)?.let { output.substring(0, it.range.first).trim() }

/** Install output is complete at the marker, or as soon as `pm` has printed its Success/Failure line. */
fun isInstallOutputComplete(output: String): Boolean =
    outputBeforeMarker(output) != null ||
        output.lineSequence().map { it.trim() }.any { it == "Success" || it.startsWith("Success:") || it.startsWith("Failure") }

private const val MaxOutputBytes = 1 shl 20

/**
 * Reads [input] until [done] accepts the text so far. End-of-stream and a read error also end it (whatever arrived is
 * returned); a stream that stays silent is the caller's watchdog's business. Output is capped at 1 MiB.
 */
fun readUntil(input: InputStream, done: (String) -> Boolean): String {
    val out = ByteArrayOutputStream()
    val buf = ByteArray(8192)
    while (out.size() < MaxOutputBytes && !done(out.toString(Charsets.UTF_8))) {
        val n = try { input.read(buf) } catch (e: IOException) { -1 }
        if (n < 0) break
        out.write(buf, 0, n)
    }
    return out.toString(Charsets.UTF_8)
}

/** Time allowed for one install: a minute plus the file at 100 KB/s, never more than nine minutes. */
fun installTimeoutMs(size: Long): Long = (60_000L + size.coerceAtLeast(0) / 100).coerceAtMost(9 * 60_000L)

/**
 * A failed install call only means the connection is lost when the session itself is gone; a stream that ended or
 * timed out while the session is healthy is an install failure and the session stays up.
 */
fun installErrorIsConnectionLoss(sessionConnected: Boolean): Boolean = !sessionConnected

// ---- Recent devices (name, host, port only: nothing secret) ----

const val MaxRecent = 5

private fun clean(s: String) = s.replace('\t', ' ').replace('\n', ' ').trim()

fun encodeRecents(list: List<Target>): String =
    list.joinToString("\n") { "${clean(it.name)}\t${clean(it.host)}\t${it.port}" }

fun decodeRecents(text: String?): List<Target> =
    text.orEmpty().lines().mapNotNull { line ->
        val f = line.split('\t')
        val port = f.getOrNull(2)?.toIntOrNull()
        if (f.size == 3 && f[1].isNotEmpty() && port != null && port in 0..65535) Target(f[0], f[1], port) else null
    }

/** Connect ports change whenever Wireless debugging is toggled, so recents keep none and use mDNS. */
fun forgetPorts(list: List<Target>): List<Target> = list.map { it.copy(port = 0) }

/** Puts [target] first; a device already listed (same host, or both this device) is not repeated. */
fun addRecent(list: List<Target>, target: Target, ownAddresses: Collection<String>): List<Target> {
    fun same(a: Target) = normalise(a.host) == normalise(target.host) ||
        (isLocalHost(a.host, ownAddresses) && isLocalHost(target.host, ownAddresses))
    return (listOf(target) + list.filterNot(::same)).take(MaxRecent)
}
