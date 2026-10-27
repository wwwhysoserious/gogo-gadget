package app.gogogadget

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import android.os.SystemClock
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.Locale
import java.util.UUID

// VirusTotal v3 upload and analysis polling, plus the request pacer for the public API limit (4 per minute).
// The API key is only ever sent in the `x-apikey` header: it is never logged and never part of an exception text.

internal const val VtBase = "https://www.virustotal.com/api/v3"
private const val VtSmallUploadBytes = 32L * 1024L * 1024L
private const val VtConnectTimeoutMs = 15_000
private const val VtPollTimeoutMs = 15_000
private const val VtUploadReadTimeoutMs = 180_000
private const val UploadBufferBytes = 64 * 1024
private const val MaxPollFailures = 3

const val VtPollIntervalMs = 20_000L
const val VtAnalysisTimeoutMs = 10 * 60_000L

// All Regex patterns escape literal `{`, `}`, `[`, and `]` outside character classes for Android ICU compatibility.
private val VtAnalysisIdRegex = Regex("^[A-Za-z0-9=_+-]+$")
private val UnsafeFileNameChars = Regex("[^A-Za-z0-9._-]")

/**
 * Sliding-window limiter: at most [maxRequests] requests in any [windowMs]. [reserve] books the next slot and returns
 * how long the caller must wait before sending (0 when free). [clock] must be monotonic (the default is
 * [SystemClock.elapsedRealtime], so a wall-clock change cannot shorten the wait); it is injectable for tests.
 */
class RequestPacer(
    private val maxRequests: Int = 4,
    private val windowMs: Long = 60_000L,
    private val clock: () -> Long = SystemClock::elapsedRealtime,
) {
    private val slots = java.util.ArrayDeque<Long>()

    @Synchronized
    fun reserve(): Long {
        val now = clock()
        val wait = if (slots.size < maxRequests) 0L else maxOf(0L, slots.first() + windowMs - now)
        slots.addLast(now + wait)
        if (slots.size > maxRequests) slots.removeFirst()
        return wait
    }
}

/** Waits until the pacer allows the next request. */
suspend fun RequestPacer.await() {
    val wait = reserve()
    if (wait > 0L) delay(wait)
}

/** `12.3 MB` (binary megabytes, one decimal) for the prompt and the log. */
fun formatUploadSize(bytes: Long): String = String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))

// ---- Analysis polling ----

sealed interface VtAnalysisPoll {
    data class Done(val result: VtLookupResult.Found) : VtAnalysisPoll
    data object Pending : VtAnalysisPoll
    data object RateLimited : VtAnalysisPoll
    data object InvalidKey : VtAnalysisPoll
    data object Failed : VtAnalysisPoll
}

/**
 * Pure parser for `GET /api/v3/analyses/{id}`: `completed` with `stats` -> [VtAnalysisPoll.Done]; `queued` or
 * `in-progress` -> Pending; 429 -> RateLimited (keep polling); 401/403 -> InvalidKey; anything else -> Failed.
 */
fun parseVirusTotalAnalysis(httpCode: Int, body: String): VtAnalysisPoll = when (httpCode) {
    200 -> try {
        val attributes = JSONObject(body).getJSONObject("data").getJSONObject("attributes")
        when (attributes.getString("status")) {
            "completed" -> vtStatsToFound(attributes.getJSONObject("stats"), attributes.optLong("date", -1L).takeIf { it > 0L })
                ?.let { VtAnalysisPoll.Done(it) } ?: VtAnalysisPoll.Failed
            "queued", "in-progress" -> VtAnalysisPoll.Pending
            else -> VtAnalysisPoll.Failed
        }
    } catch (_: JSONException) {
        VtAnalysisPoll.Failed
    }
    429 -> VtAnalysisPoll.RateLimited
    401, 403 -> VtAnalysisPoll.InvalidKey
    else -> VtAnalysisPoll.Failed
}

private fun pollVirusTotalAnalysis(analysisId: String, apiKey: String): VtAnalysisPoll {
    var conn: HttpURLConnection? = null
    return try {
        conn = openVt("$VtBase/analyses/$analysisId", "GET", apiKey, VtPollTimeoutMs)
        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)?.use { readVtBody(it) }.orEmpty()
        parseVirusTotalAnalysis(code, body)
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        VtAnalysisPoll.Failed
    } finally {
        runCatching { conn?.disconnect() }
    }
}

/**
 * Polls the analysis every [intervalMs] for up to [timeoutMs]. [VtLookupResult.Found] when it completes,
 * [VtLookupResult.InvalidKey] on 401/403, otherwise [VtLookupResult.Unavailable] (timeout or repeated failures).
 * A 429 is not a failure: it waits and keeps polling. Never throws except for cancellation.
 */
suspend fun awaitVirusTotalAnalysis(
    analysisId: String,
    apiKey: String,
    pacer: RequestPacer,
    intervalMs: Long = VtPollIntervalMs,
    timeoutMs: Long = VtAnalysisTimeoutMs,
): VtLookupResult {
    val cleanKey = apiKey.trim().takeIf { it.isNotEmpty() } ?: return VtLookupResult.InvalidKey
    if (!VtAnalysisIdRegex.matches(analysisId)) return VtLookupResult.Unavailable
    val deadline = System.nanoTime() + timeoutMs * 1_000_000L
    var failures = 0
    while (true) {
        pacer.await()
        when (val poll = withContext(Dispatchers.IO) { pollVirusTotalAnalysis(analysisId, cleanKey) }) {
            is VtAnalysisPoll.Done -> return poll.result
            VtAnalysisPoll.InvalidKey -> return VtLookupResult.InvalidKey
            VtAnalysisPoll.Failed -> if (++failures >= MaxPollFailures) return VtLookupResult.Unavailable
            VtAnalysisPoll.Pending, VtAnalysisPoll.RateLimited -> failures = 0
        }
        if (System.nanoTime() + intervalMs * 1_000_000L > deadline) return VtLookupResult.Unavailable
        delay(intervalMs)
    }
}

// ---- Upload ----

sealed interface VtUploadResult {
    data class Started(val analysisId: String) : VtUploadResult
    data object InvalidKey : VtUploadResult
    data object RateLimited : VtUploadResult
    data object Failed : VtUploadResult
}

/** The analysis id out of an upload response (`data.id`), or null. */
fun parseVirusTotalUploadResponse(httpCode: Int, body: String): VtUploadResult = when (httpCode) {
    200 -> try {
        val id = JSONObject(body).getJSONObject("data").getString("id")
        if (VtAnalysisIdRegex.matches(id)) VtUploadResult.Started(id) else VtUploadResult.Failed
    } catch (_: JSONException) {
        VtUploadResult.Failed
    }
    401, 403 -> VtUploadResult.InvalidKey
    429 -> VtUploadResult.RateLimited
    else -> VtUploadResult.Failed
}

/**
 * True for an `https` URL on `virustotal.com` or a subdomain, with no user info and no custom port: the only places the
 * API key may be sent to.
 */
fun isAllowedVirusTotalHost(url: String): Boolean {
    val uri = try { URI(url) } catch (_: Exception) { return false }
    if (!"https".equals(uri.scheme, ignoreCase = true) || uri.rawUserInfo != null) return false
    if (uri.port != -1 && uri.port != 443) return false
    val host = uri.host?.lowercase(Locale.US) ?: return false
    return host == "virustotal.com" || host.endsWith(".virustotal.com")
}

/**
 * The single-use URL out of `GET /files/upload_url` (`{"data":"<url>"}`), switched to https; null when missing, not
 * http(s), or not on a VirusTotal host.
 */
fun parseVirusTotalUploadUrl(body: String): String? {
    val raw = runCatching { (JSONObject(body).opt("data") as? String)?.trim() }.getOrNull() ?: return null
    val secure = when {
        raw.startsWith("https://") -> raw
        raw.startsWith("http://") -> "https://" + raw.removePrefix("http://")
        else -> return null
    }
    return secure.takeIf(::isAllowedVirusTotalHost)
}

/** Opens a request that never follows a redirect and never sends the API key off VirusTotal. */
internal fun openVt(
    url: String,
    method: String,
    apiKey: String,
    readTimeoutMs: Int,
    connectTimeoutMs: Int = VtConnectTimeoutMs,
): HttpURLConnection {
    if (!isAllowedVirusTotalHost(url)) throw IOException("Not a VirusTotal address")
    return (URL(url).openConnection() as HttpURLConnection).apply {
        requestMethod = method
        connectTimeout = connectTimeoutMs
        readTimeout = readTimeoutMs
        useCaches = false
        instanceFollowRedirects = false
        setRequestProperty("Accept", "application/json")
        setRequestProperty("x-apikey", apiKey)
    }
}

private fun fetchUploadUrl(apiKey: String): String? {
    var conn: HttpURLConnection? = null
    return try {
        conn = openVt("$VtBase/files/upload_url", "GET", apiKey, VtPollTimeoutMs)
        val code = conn.responseCode
        if (code != 200) return null
        parseVirusTotalUploadUrl(conn.inputStream.use { readVtBody(it) }.orEmpty())
    } finally {
        runCatching { conn?.disconnect() }
    }
}

/**
 * Uploads [file] as `multipart/form-data` (field `file`) and returns the analysis id. Streams from disk with a fixed
 * length, so a file of any size never sits in memory. Up to 32 MB it goes to `/files`; larger files first ask for a
 * single-use upload URL. [onProgress] gets (bytes of the file sent, file size) and may throw to stop the upload
 * (a [CancellationException] is rethrown). Never throws otherwise.
 */
fun uploadFileToVirusTotal(file: File, apiKey: String, onProgress: (Long, Long) -> Unit = { _, _ -> }): VtUploadResult {
    val cleanKey = apiKey.trim().takeIf { it.isNotEmpty() } ?: return VtUploadResult.InvalidKey
    var conn: HttpURLConnection? = null
    return try {
        val size = file.length()
        if (size <= 0L) return VtUploadResult.Failed
        val target = if (size <= VtSmallUploadBytes) "$VtBase/files" else fetchUploadUrl(cleanKey) ?: return VtUploadResult.Failed
        val boundary = "gogo" + UUID.randomUUID().toString().replace("-", "")
        val safeName = file.name.replace(UnsafeFileNameChars, "_")
        val head = ("--$boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"$safeName\"\r\n" +
            "Content-Type: application/octet-stream\r\n\r\n").toByteArray(Charsets.US_ASCII)
        val tail = "\r\n--$boundary--\r\n".toByteArray(Charsets.US_ASCII)
        conn = openVt(target, "POST", cleanKey, VtUploadReadTimeoutMs).apply {
            doOutput = true
            setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
            setFixedLengthStreamingMode(head.size + size + tail.size)
        }
        conn.outputStream.use { out ->
            out.write(head)
            file.inputStream().use { input ->
                val buffer = ByteArray(UploadBufferBytes)
                var sent = 0L
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    out.write(buffer, 0, read)
                    sent += read
                    onProgress(sent, size)
                }
            }
            out.write(tail)
        }
        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)?.use { readVtBody(it) }.orEmpty()
        parseVirusTotalUploadResponse(code, body)
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        VtUploadResult.Failed
    } finally {
        runCatching { conn?.disconnect() }
    }
}

/**
 * The one pending "send to VirusTotal?" question. Every question gets a new id and the buttons answer with that id,
 * so a late tap on an old prompt cannot answer a newer one. Use it on the main thread only.
 */
class UploadGate {
    private var lastId = 0
    private var pending: Pair<Int, CompletableDeferred<Boolean>>? = null

    /** Opens a question (a still-open older one counts as "no"). */
    fun open(): Pair<Int, CompletableDeferred<Boolean>> {
        pending?.second?.complete(false)
        return (++lastId to CompletableDeferred<Boolean>()).also { pending = it }
    }

    /** Answers the question with this [id]; any other id changes nothing. */
    fun answer(id: Int, confirmed: Boolean) {
        pending?.takeIf { it.first == id }?.second?.complete(confirmed)
    }

    /** Counts the open question as "no". */
    fun declinePending() {
        pending?.second?.complete(false)
    }

    fun close(question: Pair<Int, CompletableDeferred<Boolean>>) {
        if (pending === question) pending = null
    }
}
