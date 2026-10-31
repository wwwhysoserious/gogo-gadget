package app.gogogadget

import java.util.Locale

// GoGo's own antivirus report: what each online source said about each APK, the engine detections merged across sources,
// the classification of those detections (serious or light) and the colour that follows. Pure code, no Android classes,
// so every rule here has a JVM unit test. The only data that leaves the device is a SHA-256 hash.

/** The online antivirus services the Shield can ask. */
enum class ShieldSource(val displayName: String) {
    VirusTotal("VirusTotal"),
    MetaDefender("MetaDefender"),
}

/** What one source said about one file. */
enum class SourceStatus { Answered, UnknownHash, Unavailable, RateLimited, InvalidKey, NotQueried }

/** One engine's flag. [category] is `malicious` or `suspicious`; [label] is the detection name the engine gave (may be empty). */
data class EngineFlag(val engine: String, val label: String, val category: String = "malicious")

enum class DetectionSeverity { Serious, Light }

/** The outcome of the engine counting rules: nothing flagged, a light finding (Yellow), or a severe one (Red). */
enum class EngineLevel { Clean, Light, Severe }

/** From this many distinct flagging engines a file is Red, whatever the detection names are. */
const val RedEngineCount = 4

/** An online analysis older than this many days is not proof by itself (malware that is newer than the analysis is still "clean"). */
const val StaleAnalysisDays = 30L

// ---- Detection classifier ----

internal enum class KeywordMatch { Exact, Prefix, Contains }

/**
 * One row of the documented keyword table. [notWithHeuristic] keeps a word from counting when the same name carries a
 * heuristic marker (`Heur.Dropper.Gen` is a guess, `Trojan-Dropper.AndroidOS.Agent` is a family).
 */
internal data class SeriousKeyword(val word: String, val match: KeywordMatch, val notWithHeuristic: Boolean = false)

/**
 * Detection-name words that make ONE flagging engine serious (the file is Red even with 1 to 3 engines). Names are split
 * into lower-case tokens on every character that is not a letter or digit, then matched per [KeywordMatch].
 * `rat` and `miner` are Exact on purpose: as a substring they would hit "operation", "generate" or "mineral".
 */
internal val SeriousDetectionKeywords: List<SeriousKeyword> = listOf(
    SeriousKeyword("trojan", KeywordMatch.Contains),
    SeriousKeyword("troj", KeywordMatch.Exact),
    SeriousKeyword("spyware", KeywordMatch.Contains),
    SeriousKeyword("spy", KeywordMatch.Prefix),
    SeriousKeyword("ransom", KeywordMatch.Contains),
    SeriousKeyword("banker", KeywordMatch.Contains),
    SeriousKeyword("bankbot", KeywordMatch.Contains),
    SeriousKeyword("backdoor", KeywordMatch.Contains),
    SeriousKeyword("rootkit", KeywordMatch.Contains),
    SeriousKeyword("stealer", KeywordMatch.Contains),
    SeriousKeyword("keylog", KeywordMatch.Prefix),
    SeriousKeyword("dropper", KeywordMatch.Prefix, notWithHeuristic = true),
    SeriousKeyword("worm", KeywordMatch.Prefix),
    SeriousKeyword("exploit", KeywordMatch.Prefix),
    SeriousKeyword("rat", KeywordMatch.Exact),
    SeriousKeyword("botnet", KeywordMatch.Contains),
    SeriousKeyword("miner", KeywordMatch.Exact),
    SeriousKeyword("coinminer", KeywordMatch.Contains),
    SeriousKeyword("cryptominer", KeywordMatch.Contains),
    SeriousKeyword("smsreg", KeywordMatch.Contains),
    SeriousKeyword("fraud", KeywordMatch.Contains),
)

/** Words that mark a name as a guess by the engine, not a known family. */
internal val HeuristicTokens: Set<String> = setOf(
    "heur", "heuristic", "ml", "ai", "suspicious", "susp", "packed", "packer", "artemis",
    "behav", "behavior", "behaviour", "reputation", "unsafe", "obfuscated", "obfus",
)

/** Words for unwanted but not malicious software: they never make a file Red on their own. */
internal val GreyTokens: Set<String> = setOf(
    "adware", "riskware", "pua", "pup", "hacktool", "grayware", "greyware", "unwanted", "potentially",
)

/** Platform, wrapper and filler words that are not a malware family name. */
internal val NoiseTokens: Set<String> = HeuristicTokens + GreyTokens + setOf(
    "android", "androidos", "andr", "linux", "apk", "app", "application", "variant", "agent", "malware", "malicious",
    "virus", "threat", "tool", "program", "not", "dex", "jar", "sample", "score", "confidence", "high", "low", "medium",
    "trusted", "multi", "other", "engine", "detected", "detection", "file", "script", "unclassified", "of",
    "generic", "gen",
)

private val NonAlnumRegex = Regex("[^a-z0-9]+")

internal fun detectionTokens(label: String): List<String> =
    label.lowercase(Locale.ROOT).split(NonAlnumRegex).filter { it.isNotEmpty() }

private fun matchesKeyword(token: String, keyword: SeriousKeyword): Boolean = when (keyword.match) {
    KeywordMatch.Exact -> token == keyword.word
    KeywordMatch.Prefix -> token.startsWith(keyword.word)
    KeywordMatch.Contains -> token.contains(keyword.word)
}

/**
 * Classifies one engine flag, in this order:
 * 1. a word of [SeriousDetectionKeywords] in the name: [DetectionSeverity.Serious];
 * 2. a grey or heuristic marker (adware, riskware, pua, hacktool, not-a-virus, heur, ml, suspicious...): Light;
 * 3. category `malicious` with a family name left after the noise words (a token of 4 or more letters): Serious;
 * 4. anything else (an empty name, `suspicious` category without a keyword): Light.
 */
fun classifyDetection(flag: EngineFlag): DetectionSeverity {
    val tokens = detectionTokens(flag.label)
    val squashed = flag.label.lowercase(Locale.ROOT).filter { it.isLetterOrDigit() }
    val heuristic = tokens.any { it in HeuristicTokens }
    val keywordHit = SeriousDetectionKeywords.any { keyword ->
        !(keyword.notWithHeuristic && heuristic) && tokens.any { matchesKeyword(it, keyword) }
    }
    if (keywordHit) return DetectionSeverity.Serious
    val grey = heuristic || tokens.any { it in GreyTokens } || "notavirus" in squashed
    if (grey) return DetectionSeverity.Light
    if (flag.category.equals("malicious", ignoreCase = true)) {
        val hasFamily = tokens.any { token -> token.length >= 4 && token.all { it in 'a'..'z' } && token !in NoiseTokens }
        if (hasFamily) return DetectionSeverity.Serious
    }
    return DetectionSeverity.Light
}

private fun engineKey(flag: EngineFlag): String =
    flag.engine.lowercase(Locale.ROOT).filter { it.isLetterOrDigit() }.ifEmpty { "label:" + flag.label.lowercase(Locale.ROOT) }

/** What the engine flags add up to. [flaggedEngines] counts distinct engines (or [countOnly] when the source gave no names). */
data class EngineAssessment(
    val level: EngineLevel,
    val flaggedEngines: Int,
    val seriousEngines: Int,
)

/**
 * The owner's rule: 0 flags is clean; 1 to 3 engines is Yellow (the user decides) unless one of them is serious, which
 * is Red; [RedEngineCount] or more engines is Red. The same engine seen by two sources counts once. [countOnly] is the
 * flag count of a source that gave counts but no names (a stored verdict, a service without per-engine data): it can
 * only raise the engine count, and without a name nothing in it can be serious.
 */
fun assessEngineFlags(flags: List<EngineFlag>, countOnly: Int = 0): EngineAssessment {
    val groups = flags.groupBy { engineKey(it) }
    val serious = groups.values.count { group -> group.any { classifyDetection(it) == DetectionSeverity.Serious } }
    val flagged = maxOf(groups.size, countOnly)
    val level = when {
        flagged == 0 -> EngineLevel.Clean
        flagged >= RedEngineCount || serious > 0 -> EngineLevel.Severe
        else -> EngineLevel.Light
    }
    return EngineAssessment(level, flagged, serious)
}

// ---- Per-source and per-file report ----

/** What one [source] said about one file. */
data class SourceReport(
    val source: ShieldSource,
    val status: SourceStatus,
    val flagged: Int = 0,
    val total: Int = 0,
    /** Epoch seconds of the analysis, null when the service did not say. */
    val analysisDate: Long? = null,
    val fromCache: Boolean = false,
    /** Epoch milliseconds when the answer was obtained from the service. */
    val checkedAtMs: Long? = null,
    val flags: List<EngineFlag> = emptyList(),
)

/** Metadata of where an answer came from. */
data class SourceInfo(val fromCache: Boolean = false, val checkedAtMs: Long? = null)

/** [result] null means the source was not asked (no key, or an earlier answer made the question pointless). */
fun sourceReportOf(source: ShieldSource, result: VtLookupResult?, info: SourceInfo = SourceInfo()): SourceReport = when (result) {
    null -> SourceReport(source, SourceStatus.NotQueried)
    is VtLookupResult.Found -> SourceReport(
        source, SourceStatus.Answered, result.malicious + result.suspicious, result.total,
        result.lastAnalysisDate, info.fromCache, info.checkedAtMs, result.detections,
    )
    VtLookupResult.UnknownHash -> SourceReport(source, SourceStatus.UnknownHash, fromCache = info.fromCache, checkedAtMs = info.checkedAtMs)
    VtLookupResult.InvalidKey -> SourceReport(source, SourceStatus.InvalidKey)
    VtLookupResult.RateLimited -> SourceReport(source, SourceStatus.RateLimited)
    VtLookupResult.Unavailable -> SourceReport(source, SourceStatus.Unavailable)
}

/** One APK of the package as the report shows it. */
data class ReportFile(
    val name: String,
    val sizeBytes: Long,
    val sha256: String,
    /** False for a resource-only split: it is not looked up online. */
    val lookedUp: Boolean,
    val sources: List<SourceReport>,
    val assessment: EngineAssessment,
) {
    fun source(source: ShieldSource): SourceReport? = sources.firstOrNull { it.source == source }
}

/** A detection name merged across sources and files, with who flagged it. */
data class MergedDetection(
    val name: String,
    val engines: List<String>,
    val sources: List<ShieldSource>,
    val files: List<String>,
    val severity: DetectionSeverity,
)

/**
 * GoGo's weighted report. [flaggedEngines] and [totalEngines] describe the worst file; [level] is the worst of all files.
 * [analysedName] and [analysedSha256] name what the user picked (for a bundle, the container).
 */
data class ShieldReport(
    val analysedName: String,
    val analysedSha256: String,
    val files: List<ReportFile>,
    val level: EngineLevel,
    val flaggedEngines: Int,
    val totalEngines: Int,
    val detections: List<MergedDetection>,
    /** `VirusTotal 0/70 · MetaDefender 0/38`, null when no source answered. */
    val summary: String?,
)

private fun fileAssessment(sources: List<SourceReport>): EngineAssessment {
    val answered = sources.filter { it.status == SourceStatus.Answered }
    val flags = answered.flatMap { it.flags }
    val countOnly = answered.maxOfOrNull { it.flagged } ?: 0
    return assessEngineFlags(flags, countOnly)
}

/** Merges the detections of every file: one entry per distinct name, listing the engines, sources and APKs. */
internal fun mergeDetections(files: List<ReportFile>): List<MergedDetection> {
    data class Row(val fileName: String, val source: ShieldSource, val flag: EngineFlag)
    val rows = files.filter { it.lookedUp }.flatMap { file ->
        file.sources.flatMap { report -> report.flags.map { Row(file.name, report.source, it) } }
    }
    return rows
        .filter { it.flag.label.isNotBlank() }
        .groupBy { it.flag.label.trim().lowercase(Locale.ROOT) }
        .map { (_, group) ->
            MergedDetection(
                name = group.first().flag.label.trim(),
                engines = group.map { it.flag.engine }.distinct().sorted(),
                sources = group.map { it.source }.distinct(),
                files = group.map { it.fileName }.distinct(),
                severity = if (group.any { classifyDetection(it.flag) == DetectionSeverity.Serious }) DetectionSeverity.Serious else DetectionSeverity.Light,
            )
        }
        .sortedWith(compareBy<MergedDetection> { it.severity.ordinal }.thenByDescending { it.engines.size }.thenBy { it.name.lowercase(Locale.ROOT) })
}

/**
 * `VirusTotal 1/70 · MetaDefender 0/38`: per source, the file with the most flags (then the fewest engines). A package
 * with several looked-up APKs adds `(×N)`. Null when no source answered for any file.
 */
internal fun onlineSummaryOf(files: List<ReportFile>): String? {
    val looked = files.filter { it.lookedUp }
    val parts = ShieldSource.entries.mapNotNull { source ->
        val answered = looked.mapNotNull { file -> file.source(source)?.takeIf { it.status == SourceStatus.Answered } }
        val pick = answered.sortedWith(compareByDescending<SourceReport> { it.flagged }.thenBy { it.total }).firstOrNull()
        pick?.let { "${source.displayName} ${it.flagged}/${it.total}" }
    }
    if (parts.isEmpty()) return null
    val base = parts.joinToString(" · ")
    return if (looked.size > 1) "$base (×${looked.size})" else base
}

/** Builds the report from what was learned about each file. [analysedName] and [analysedSha256] are what the user picked. */
fun buildShieldReport(analysedName: String, analysedSha256: String, files: List<ShieldFileEvidence>): ShieldReport {
    val reportFiles = files.map { file ->
        val sources = if (file.lookedUp) {
            listOfNotNull(
                sourceReportOf(ShieldSource.VirusTotal, file.vt, file.vtInfo),
                file.md?.let { sourceReportOf(ShieldSource.MetaDefender, it, file.mdInfo) },
            )
        } else {
            emptyList()
        }
        ReportFile(file.name, file.sizeBytes, file.sha256, file.lookedUp, sources, fileAssessment(sources))
    }
    val looked = reportFiles.filter { it.lookedUp }
    val worst = looked.sortedWith(
        compareByDescending<ReportFile> { it.assessment.level.ordinal }.thenByDescending { it.assessment.flaggedEngines },
    ).firstOrNull()
    val level = worst?.assessment?.level ?: EngineLevel.Clean
    val flagged = worst?.assessment?.flaggedEngines ?: 0
    val total = worst?.sources.orEmpty().filter { it.status == SourceStatus.Answered }.maxOfOrNull { it.total } ?: 0
    return ShieldReport(
        analysedName = analysedName,
        analysedSha256 = analysedSha256,
        files = reportFiles,
        level = level,
        flaggedEngines = flagged,
        totalEngines = total,
        detections = mergeDetections(reportFiles),
        summary = onlineSummaryOf(reportFiles),
    )
}

// ---- Report links ----

/** A secondary "see the source" link for a file that [source] actually answered about. */
data class ReportLink(val source: ShieldSource, val fileName: String, val sha256: String, val url: String)

fun virusTotalReportUrl(sha256: String): String = "https://www.virustotal.com/gui/file/$sha256"

/** The MetaDefender results page for a hash. This URL shape was given by the owner and has not been opened by the code's author. */
fun metaDefenderReportUrl(sha256: String): String = "https://metadefender.opswat.com/results/file/$sha256/hash/overview"

private fun isSha256Hex(value: String): Boolean = value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

/** One link per looked-up APK and per source that answered with a verdict, using the hash that was actually looked up. */
fun reportLinks(report: ShieldReport): List<ReportLink> = report.files
    .filter { it.lookedUp && isSha256Hex(it.sha256) }
    .flatMap { file ->
        file.sources.filter { it.status == SourceStatus.Answered }.map { src ->
            val url = if (src.source == ShieldSource.VirusTotal) virusTotalReportUrl(file.sha256) else metaDefenderReportUrl(file.sha256)
            ReportLink(src.source, file.name, file.sha256, url)
        }
    }

// ---- Reasons order and card colour ----

/** Red reasons first, then Yellow, each group in the order of [ShieldWarningReason]. The most serious reason leads the list. */
fun orderedByGravity(reasons: Collection<ShieldWarningReason>): List<ShieldWarningReason> =
    reasons.distinct().sortedWith(compareBy<ShieldWarningReason> { it.severity().ordinal }.thenBy { it.ordinal })

/** How the Shield card is drawn once the decision is known. */
enum class ShieldCardTone { Green, Caution, CautionDeclined, CautionAuthorized, Blocked }

/**
 * The card colour comes from the tier and the user's decision, never from the decision alone: a Yellow that the user
 * refused is a caution that was declined, not a block; a Red is always a block; a Yellow the user accepted is authorized.
 * [userAuthorized] must be true for a package that was installed after "install anyway", single APK or bundle.
 */
fun shieldCardTone(verdict: ShieldVerdict, userAuthorized: Boolean): ShieldCardTone = when (securityTierOf(verdict)) {
    SecurityTier.Green -> ShieldCardTone.Green
    SecurityTier.Red -> ShieldCardTone.Blocked
    SecurityTier.Yellow -> when {
        verdict is ShieldVerdict.NeedsUpload -> ShieldCardTone.Caution
        userAuthorized -> ShieldCardTone.CautionAuthorized
        else -> ShieldCardTone.CautionDeclined
    }
}
