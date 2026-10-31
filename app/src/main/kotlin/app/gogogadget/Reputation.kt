package app.gogogadget

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.Locale

// Online reputation beyond VirusTotal: a persistent verdict cache (48 h, per source), the MetaDefender Cloud hash lookup and
// the parallel lookup of both sources.
// Only the SHA-256 hash ever leaves the device here. API keys travel only in a request header and are never logged.

/** How long a stored verdict is trusted. */
const val ReputationTtlMs = 48L * 60L * 60L * 1000L

private const val MaxCacheEntries = 2000
private const val MdBase = "https://api.metadefender.com/v4"
private const val MdTimeoutMs = 10_000

/** MetaDefender `scan_all_result_i` values that mean "clean" and "flagged"; anything else is not a usable verdict. */
private val MdCleanResults = setOf(0, 7)
private val MdFlaggedResults = setOf(1, 2, 4, 6, 8)

// ---- Verdict cache ----

/** A stored verdict and when the service gave it. */
data class CachedFound(val found: VtLookupResult.Found, val storedAtMs: Long)

/**
 * Remembers the verdict of a file for [ReputationTtlMs], per SHA-256 AND per source, with the engine names, the analysis
 * date and the time it was stored. Kept in a small JSON [file] (null keeps it in memory only). Writes are best effort: a
 * failure just means the next run asks again. Entries written by older versions (no source) are dropped on load.
 */
class ReputationCache(private val file: File?, private val clock: () -> Long = System::currentTimeMillis) {
    private data class Entry(
        val source: ShieldSource,
        val malicious: Int,
        val suspicious: Int,
        val total: Int,
        val storedAt: Long,
        val analysisDate: Long?,
        val detections: List<EngineFlag>,
    )

    private val entries = LinkedHashMap<String, Entry>()

    init {
        load()
    }

    private fun keyOf(sha256: String, source: ShieldSource) = sha256.trim().lowercase(Locale.US) + "|" + source.name

    @Synchronized
    fun get(sha256: String, source: ShieldSource): CachedFound? {
        val key = keyOf(sha256, source)
        val entry = entries[key] ?: return null
        if (clock() - entry.storedAt !in 0..ReputationTtlMs) {
            entries.remove(key)
            save()
            return null
        }
        return CachedFound(
            VtLookupResult.Found(entry.malicious, entry.suspicious, entry.total, entry.analysisDate, entry.detections),
            entry.storedAt,
        )
    }

    @Synchronized
    fun put(sha256: String, source: ShieldSource, found: VtLookupResult.Found) {
        val key = keyOf(sha256, source)
        entries.remove(key)
        entries[key] = Entry(source, found.malicious, found.suspicious, found.total, clock(), found.lastAnalysisDate, found.detections)
        while (entries.size > MaxCacheEntries) entries.remove(entries.keys.first())
        save()
    }

    /** Forgets everything one source said (its key changed or was deleted). */
    @Synchronized
    fun clear(source: ShieldSource) {
        if (entries.values.removeAll { it.source == source }) save()
    }

    private fun load() {
        val source = file?.takeIf { it.isFile && it.length() in 1..8_000_000L } ?: return
        try {
            val list = JSONObject(source.readText()).getJSONArray("entries")
            val now = clock()
            for (i in 0 until list.length()) {
                val item = list.getJSONObject(i)
                val sha = item.getString("sha")
                val src = when (item.optString("src")) {
                    "vt" -> ShieldSource.VirusTotal
                    "md" -> ShieldSource.MetaDefender
                    else -> continue
                }
                val at = item.getLong("at")
                if (sha.length != 64 || now - at !in 0..ReputationTtlMs) continue
                val m = item.getInt("m")
                val s = item.getInt("s")
                val t = item.getInt("t")
                if (m < 0 || s < 0 || t < 0) continue
                val date = item.optLong("d", -1L).takeIf { it > 0L }
                val flags = mutableListOf<EngineFlag>()
                val stored = item.optJSONArray("f")
                if (stored != null) {
                    for (j in 0 until minOf(stored.length(), 200)) {
                        val row = stored.optJSONArray(j) ?: continue
                        flags += EngineFlag(row.optString(0), row.optString(1), row.optString(2, "malicious"))
                    }
                }
                entries[keyOf(sha, src)] = Entry(src, m, s, t, at, date, flags)
            }
        } catch (_: JSONException) {
            entries.clear()
        } catch (_: IOException) {
            entries.clear()
        }
    }

    private fun save() {
        val target = file ?: return
        try {
            val list = JSONArray()
            for ((key, e) in entries) {
                val flags = JSONArray()
                for (flag in e.detections) flags.put(JSONArray().put(flag.engine).put(flag.label).put(flag.category))
                list.put(
                    JSONObject()
                        .put("sha", key.substringBefore('|'))
                        .put("src", if (e.source == ShieldSource.VirusTotal) "vt" else "md")
                        .put("m", e.malicious).put("s", e.suspicious).put("t", e.total).put("at", e.storedAt)
                        .put("d", e.analysisDate ?: -1L)
                        .put("f", flags),
                )
            }
            val temp = File(target.parentFile, target.name + ".tmp")
            temp.writeText(JSONObject().put("entries", list).toString())
            if (!temp.renameTo(target)) {
                target.writeText(temp.readText())
                temp.delete()
            }
        } catch (_: IOException) {
            // Best effort.
        }
    }
}

// ---- MetaDefender Cloud ----

/**
 * Strict parser for `GET /v4/hash/{sha256}`: `404` unknown, `401`/`403` bad key, `429` rate limited. A `200` needs
 * `scan_results` with non-negative `total_avs` and `total_detected_avs`; `file_info.sha256` must equal [sha256] when
 * present, and `scan_all_result_i` must be a clean or flagged code (any other code is not a verdict). Anything else is
 * [VtLookupResult.Unavailable].
 */
fun parseMetaDefenderResponse(httpCode: Int, body: String, sha256: String): VtLookupResult = when (httpCode) {
    200 -> parseMetaDefenderFile(body, sha256)
    404 -> VtLookupResult.UnknownHash
    401, 403 -> VtLookupResult.InvalidKey
    429 -> VtLookupResult.RateLimited
    else -> VtLookupResult.Unavailable
}

private fun parseMetaDefenderFile(body: String, sha256: String): VtLookupResult = try {
    val root = JSONObject(body)
    val results = root.getJSONObject("scan_results")
    val info = root.optJSONObject("file_info")
    val reported = info?.optString("sha256").orEmpty()
    val total = results.getInt("total_avs")
    val detected = results.getInt("total_detected_avs")
    val code = if (results.has("scan_all_result_i")) results.getInt("scan_all_result_i") else if (detected > 0) 1 else 0
    val flags = parseMetaDefenderDetections(results.optJSONObject("scan_details"))
    when {
        reported.isNotEmpty() && !reported.equals(sha256, ignoreCase = true) -> VtLookupResult.Unavailable
        total < 0 || detected < 0 || detected > total -> VtLookupResult.Unavailable
        code in MdFlaggedResults -> VtLookupResult.Found(maxOf(detected, 1), 0, total, detections = flags)
        code in MdCleanResults && detected == 0 -> VtLookupResult.Found(0, 0, total)
        detected > 0 -> VtLookupResult.Found(detected, 0, total, detections = flags)
        else -> VtLookupResult.Unavailable
    }
} catch (_: JSONException) {
    VtLookupResult.Unavailable
}

/**
 * The engines that flagged the file in `scan_results.scan_details` (`{"<engine>": {"threat_found": "Trojan.X", "scan_result_i": 1}}`):
 * those with a non-empty `threat_found` and a flagged `scan_result_i` (or none). `scan_result_i` 2 is "suspicious". Missing or
 * malformed details give an empty list; the counters always come from `total_avs` and `total_detected_avs`.
 */
internal fun parseMetaDefenderDetections(details: JSONObject?): List<EngineFlag> {
    if (details == null) return emptyList()
    val flags = mutableListOf<EngineFlag>()
    val names = details.keys()
    while (names.hasNext() && flags.size < 200) {
        val engine = names.next()
        val item = details.optJSONObject(engine) ?: continue
        val threat = if (item.isNull("threat_found")) "" else item.optString("threat_found").trim()
        if (threat.isEmpty()) continue
        val code = if (item.has("scan_result_i")) item.optInt("scan_result_i", -1) else 1
        if (code !in MdFlaggedResults) continue
        flags += EngineFlag(engine, threat, if (code == 2) "suspicious" else "malicious")
    }
    return flags.sortedBy { it.engine.lowercase(Locale.US) }
}

/** True only for `https://api.metadefender.com` (default port, no user info): the one place the key may be sent to. */
fun isAllowedMetaDefenderHost(url: String): Boolean {
    val uri = try { URI(url) } catch (_: Exception) { return false }
    if (!"https".equals(uri.scheme, ignoreCase = true) || uri.rawUserInfo != null) return false
    if (uri.port != -1 && uri.port != 443) return false
    return uri.host?.lowercase(Locale.US) == "api.metadefender.com"
}

/** Looks [sha256] up on MetaDefender Cloud with header `apikey`. Never throws except for cancellation; errors are [VtLookupResult.Unavailable]. */
fun checkMetaDefenderHash(sha256: String, apiKey: String, timeoutMs: Int = MdTimeoutMs): VtLookupResult {
    val hash = sha256.trim().lowercase(Locale.US).takeIf { h -> h.length == 64 && h.all { it in '0'..'9' || it in 'a'..'f' } }
        ?: return VtLookupResult.Unavailable
    val key = apiKey.trim().takeIf { it.isNotEmpty() } ?: return VtLookupResult.InvalidKey
    val url = "$MdBase/hash/$hash"
    if (!isAllowedMetaDefenderHost(url)) return VtLookupResult.Unavailable
    var conn: HttpURLConnection? = null
    return try {
        conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            useCaches = false
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/json")
            setRequestProperty("apikey", key)
        }
        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)?.use { readVtBody(it) }.orEmpty()
        parseMetaDefenderResponse(code, body, hash)
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        VtLookupResult.Unavailable
    } finally {
        runCatching { conn?.disconnect() }
    }
}

// ---- Asking both sources ----

/** One source's answer: [result] is null when the source was not asked (no key). */
data class SourceLookup(val result: VtLookupResult?, val info: SourceInfo = SourceInfo())

/** The answers of the two sources for one file. */
data class ReputationLookup(val vt: SourceLookup, val md: SourceLookup)

/** How long one source may take (its own pacer wait included) before it counts as unreachable. */
const val SourceTimeoutMs = 45_000L

private suspend fun lookupOne(
    source: ShieldSource,
    sha256: String,
    cache: ReputationCache?,
    ask: (suspend () -> VtLookupResult)?,
    timeoutMs: Long,
    clock: () -> Long,
    note: (String) -> Unit,
): SourceLookup {
    if (ask == null) return SourceLookup(null)
    cache?.get(sha256, source)?.let {
        note("${source.displayName}: cache hit (verdict stored less than 48 h ago)")
        return SourceLookup(it.found, SourceInfo(fromCache = true, checkedAtMs = it.storedAtMs))
    }
    val result = coroutineScope {
        val pending = async {
            try {
                ask()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Throwable) {
                VtLookupResult.Unavailable
            }
        }
        val answer = withTimeoutOrNull(timeoutMs) { pending.await() }
        if (answer == null) pending.cancel()
        answer
    }
    if (result == null) {
        note("${source.displayName}: no answer within ${timeoutMs / 1000} s")
        return SourceLookup(VtLookupResult.Unavailable)
    }
    note("${source.displayName} answered: ${result::class.simpleName}")
    val now = clock()
    if (result is VtLookupResult.Found) cache?.put(sha256, source, result)
    return SourceLookup(result, SourceInfo(fromCache = false, checkedAtMs = now))
}

/**
 * Asks BOTH sources at the same time, each with its own timeout and its own cache entry; a source without a key ([vt] or
 * [md] null) is not asked. One source failing never hides the other one's answer. [note] gets one short line per source
 * (no keys, no secrets).
 */
suspend fun lookupBothSources(
    sha256: String,
    cache: ReputationCache?,
    vt: (suspend () -> VtLookupResult)?,
    md: (suspend () -> VtLookupResult)?,
    timeoutMs: Long = SourceTimeoutMs,
    clock: () -> Long = System::currentTimeMillis,
    note: (String) -> Unit = {},
): ReputationLookup = coroutineScope {
    val vtJob = async { lookupOne(ShieldSource.VirusTotal, sha256, cache, vt, timeoutMs, clock, note) }
    val mdJob = async { lookupOne(ShieldSource.MetaDefender, sha256, cache, md, timeoutMs, clock, note) }
    ReputationLookup(vtJob.await(), mdJob.await())
}
