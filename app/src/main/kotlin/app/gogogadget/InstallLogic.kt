package app.gogogadget

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import java.io.EOFException
import java.io.IOException
import java.net.SocketException
import java.net.SocketTimeoutException

// Pure logic for the install progress bar and the result line: no Android classes, fully unit-tested.

private const val ProgressIntervalMs = 100L

/**
 * Percentage of the install: bytes streamed over the total, capped at 99 until the device has answered
 * ([done] is true only for a Success from pm, which is the only way to reach 100 while running).
 */
fun installPercent(sent: Long, total: Long, done: Boolean): Int = when {
    done -> 100
    total <= 0 -> 0
    else -> (sent.coerceAtLeast(0) * 100 / total).toInt().coerceIn(0, 99)
}

/**
 * Percentage filled by the bar: [percent] while running, and the full 100 once the install has finished so the
 * result ("Success" on green or "Not installed" on red) sits on a full bar.
 */
fun barFillPercent(working: Boolean, percent: Int): Int = if (working) percent.coerceIn(0, 100) else 100

/** Result mark shown next to the package name once the installation finishes. */
enum class PackageResultMark { None, Check, Cross }

fun packageResultMark(working: Boolean, ok: Boolean): PackageResultMark = when {
    working -> PackageResultMark.None
    ok -> PackageResultMark.Check
    else -> PackageResultMark.Cross
}

/**
 * What the caption inside the button says: checking the package, uploading it to VirusTotal, waiting for VirusTotal's
 * analysis, bytes still going out, waiting for pm's answer, or finished.
 */
enum class InstallPhase { Checking, Uploading, Analysing, Sending, Installing, Done }

data class PhaseState(val phase: InstallPhase, val percent: Int)

/**
 * Phase and bar percentage from the bytes streamed so far. Once all bytes are out and pm has not answered the
 * phase is Installing with the bar held at 99; [answered] is true only for a Success from pm (100).
 */
fun installPhase(sent: Long, total: Long, answered: Boolean): PhaseState = when {
    answered -> PhaseState(InstallPhase.Done, 100)
    total > 0 && sent >= total -> PhaseState(InstallPhase.Installing, 99)
    else -> PhaseState(InstallPhase.Sending, installPercent(sent, total, false))
}

/**
 * Width in pixels of the solid fill for [percent] inside an inner area [innerPx] wide: exactly 0 at 0 and exactly
 * [innerPx] at 100, rounded down in between. [percent] is clamped to 0..100; a negative [innerPx] counts as 0.
 */
fun fillWidthPx(innerPx: Int, percent: Int): Int =
    (innerPx.coerceAtLeast(0).toLong() * percent.coerceIn(0, 100) / 100).toInt()

/** Lets about ten progress updates per second through; the first and the last (all bytes sent) always pass. */
class ProgressThrottle(private val intervalMs: Long = ProgressIntervalMs) {
    private var last: Long? = null

    fun shouldReport(nowMs: Long, sent: Long, total: Long): Boolean {
        val before = last
        val pass = before == null || sent >= total || nowMs - before >= intervalMs
        if (pass) last = nowMs
        return pass
    }
}

private val PackageName = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

/** What the result line calls the package: its applicationId, else the file name, else a generic word. */
fun installLabel(packageName: String?, fileName: String?, generic: String): String =
    packageName?.trim()?.takeIf { PackageName.matches(it) }
        ?: fileName?.let(::decodeFileName)?.takeIf { it.isNotEmpty() }
        ?: generic

private val Percent = Regex("(%[0-9A-Fa-f]{2})+")

/**
 * The file name as shown: `+` turned into a space, percent escapes (`%20`, `%2F`) decoded as UTF-8, and any folder
 * part dropped. Display only; the file itself is never touched. Text that is not valid escaping is left as it is.
 */
fun decodeFileName(name: String): String {
    val decoded = Percent.replace(name.trim().replace('+', ' ')) { m ->
        val bytes = m.value.split('%').drop(1).map { it.toInt(16).toByte() }.toByteArray()
        val text = bytes.toString(Charsets.UTF_8)
        if ('\uFFFD' in text) m.value else text
    }
    return decoded.substringAfterLast('/').trim()
}

/** Why an install failed: one plain sentence (string resource) and, for diagnostics, the raw pm line or exception. */
data class InstallFailure(val reason: Int, val raw: String?)

private val PmCode = Regex("INSTALL_[A-Z_]+")

private val PmReasons = mapOf(
    "INSTALL_FAILED_VERSION_DOWNGRADE" to R.string.reason_downgrade,
    "INSTALL_FAILED_UPDATE_INCOMPATIBLE" to R.string.reason_signature,
    "INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES" to R.string.reason_signature,
    "INSTALL_FAILED_INSUFFICIENT_STORAGE" to R.string.reason_storage,
    "INSTALL_FAILED_OLDER_SDK" to R.string.reason_older_sdk,
    "INSTALL_FAILED_NO_MATCHING_ABIS" to R.string.reason_abis,
    "INSTALL_FAILED_ALREADY_EXISTS" to R.string.reason_exists,
    "INSTALL_FAILED_USER_RESTRICTED" to R.string.reason_restricted,
    ObbOtherAppCode to R.string.reason_obb_other_app,
)

/** Maps a pm failure line to a plain reason; a line with no known code is "unknown", never a guess. */
fun pmFailure(line: String): InstallFailure {
    val code = PmCode.find(line)?.value
    val reason = when {
        code == null -> R.string.reason_unknown
        PmReasons.containsKey(code) -> PmReasons.getValue(code)
        code.startsWith("INSTALL_PARSE_FAILED_") -> R.string.reason_parse
        else -> R.string.reason_unknown
    }
    return InstallFailure(reason, line)
}

private val ClosedHints = listOf("closed", "broken pipe", "connection reset", "connection abort", "end of stream")

private fun isConnectionDrop(t: Throwable) =
    t is EOFException || t is SocketException || (t is IOException && ClosedHints.any { t.message?.contains(it, true) == true })

/**
 * Failure of the transfer itself (no pm answer), from the exception chain alone: a cancelled install, a timeout, an
 * unreadable file, or a dropped connection (the session is gone, or the exception says the socket/stream closed).
 * Anything else is "unknown".
 */
fun transferFailure(e: Throwable, detail: String?, sessionConnected: Boolean = true): InstallFailure {
    val chain = generateSequence(e) { it.cause }.take(8).toList()
    val reason = when {
        chain.any { it is CancellationException && it !is TimeoutCancellationException } -> R.string.reason_cancelled
        chain.any { it is FileEndedException } -> R.string.err_read_file
        chain.any { it is SocketTimeoutException } -> R.string.reason_timeout
        chain.any { it is IOException } && !sessionConnected -> R.string.reason_connection_lost
        chain.any(::isConnectionDrop) -> R.string.reason_connection_lost
        else -> R.string.reason_unknown
    }
    return InstallFailure(reason, detail)
}

