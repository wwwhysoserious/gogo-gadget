package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.9.50: the detection classifier, the engine thresholds, GoGo's merged report, its links and the card colour. */
class ShieldReportTest {
    private val sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    private fun malicious(label: String, engine: String = "E") = EngineFlag(engine, label, "malicious")
    private fun suspicious(label: String, engine: String = "E") = EngineFlag(engine, label, "suspicious")

    // ---- Classifier: serious names ----

    @Test fun everyWordOfTheOwnersSeriousListMakesADetectionSerious() {
        val serious = listOf(
            "Android.Trojan.Agent.A", "Trojan-Dropper.AndroidOS.Agent.a", "HEUR:Trojan-Spy.AndroidOS.Foo.b", "Android/Spy.Banker.A",
            "Android.Spyware.X", "Android.Ransom.Locker", "Android.Banker.Z", "Android.BankBot.Z", "Backdoor.Android.X", "Android.Rootkit.Q",
            "Android.Stealer.Y", "Android.InfoStealer.Y", "Keylogger.Android.Z", "Android.Keylog.Z", "Android.Worm.A", "Android.Exploit.CVE",
            "Android.RAT.Foo", "Android.Botnet.X", "Android.CoinMiner.A", "Android.Miner.B", "Android.CryptoMiner.C", "Android.SMSreg.AE",
            "Android.SmsFraud.X", "Troj/Droid-AB", "Android.Dropper.Agent",
        )
        for (name in serious) {
            assertEquals(name, DetectionSeverity.Serious, classifyDetection(malicious(name)))
            // The keyword is enough, whatever the category.
            assertEquals("$name (suspicious)", DetectionSeverity.Serious, classifyDetection(suspicious(name)))
        }
    }

    @Test fun aMaliciousVerdictWithAKnownFamilyNameIsSeriousEvenWithoutAKeyword() {
        assertEquals(DetectionSeverity.Serious, classifyDetection(malicious("Android.Hqwar.Gen")))
        assertEquals(DetectionSeverity.Serious, classifyDetection(malicious("Gen:Variant.Mikey.1234")))
        assertEquals(DetectionSeverity.Serious, classifyDetection(malicious("Android/Agent.Smforw!tr")))
    }

    // ---- Classifier: grey and heuristic labels ----

    @Test fun adwareRiskwareAndHeuristicLabelsAreLightOnTheirOwn() {
        val light = listOf(
            "Android.Riskware.Agent", "Adware.Airpush", "Android.PUA.Foo", "PUP.Optional.Bar", "HackTool.Android.LuckyPatcher",
            "not-a-virus:HEUR:AdWare.AndroidOS.Ewind.a", "not-a-virus:HEUR:RiskTool.AndroidOS.Foo", "Android.PUA.Gen", "Heur.Dropper.Gen",
            "Generic.Malware.AI", "Artemis!ABCDEF123", "Static AI - Suspicious APK", "Win32:Evo-gen [Susp]", "Packed.Android.X",
            "ML.Attribute.HighConfidence", "Android.Agent.XYZ", "Malware", "Suspicious", "Heuristic.Android.Foo",
        )
        for (name in light) {
            assertEquals(name, DetectionSeverity.Light, classifyDetection(malicious(name)))
        }
    }

    @Test fun anEmptyNameAndASuspiciousCategoryAloneAreLight() {
        assertEquals(DetectionSeverity.Light, classifyDetection(malicious("")))
        assertEquals(DetectionSeverity.Light, classifyDetection(EngineFlag("E", "", "suspicious")))
        // Category suspicious with a family-looking name but no keyword is not enough.
        assertEquals(DetectionSeverity.Light, classifyDetection(suspicious("Android.Hqwar.Gen")))
    }

    @Test fun keywordsMatchWholeWordsNotSubstrings() {
        // "rat" and "miner" are exact words: they must not fire on "operation", "pirate", "generate" or "minerva".
        for (name in listOf("Operation.Generate.Pirate", "Pirated.Content", "Minerva.Tool", "Moderate.Rating", "Corporation.X")) {
            assertEquals(name, DetectionSeverity.Light, classifyDetection(suspicious(name)))
        }
        // A dropper name that is a heuristic guess is not a family.
        assertEquals(DetectionSeverity.Light, classifyDetection(suspicious("Heur.Dropper.Gen")))
        assertEquals(DetectionSeverity.Serious, classifyDetection(suspicious("Trojan-Dropper.AndroidOS.Agent")))
    }

    // ---- Engine thresholds ----

    @Test fun oneToThreeLightEnginesAreYellowAndFourOrMoreAreRed() {
        fun light(n: Int) = (1..n).map { malicious("Adware.Foo$it", "Engine$it") }
        assertEquals(EngineLevel.Clean, assessEngineFlags(emptyList()).level)
        assertEquals(EngineLevel.Light, assessEngineFlags(light(1)).level)
        assertEquals(EngineLevel.Light, assessEngineFlags(light(3)).level)
        assertEquals(EngineLevel.Severe, assessEngineFlags(light(4)).level)
        assertEquals(EngineLevel.Severe, assessEngineFlags(light(30)).level)
    }

    @Test fun oneSeriousDetectionIsRedAmongLightOnes() {
        val flags = listOf(malicious("Riskware.A", "E1"), malicious("Android.Trojan.B", "E2"), malicious("Adware.C", "E3"))
        val assessment = assessEngineFlags(flags)
        assertEquals(EngineLevel.Severe, assessment.level)
        assertEquals(3, assessment.flaggedEngines)
        assertEquals(1, assessment.seriousEngines)
    }

    @Test fun theSameEngineCountsOnceAndCountsWithoutNamesRaiseTheTotal() {
        val twice = listOf(malicious("Adware.A", "Kaspersky"), malicious("Adware.A", "kaspersky"), malicious("Riskware.B", "Kaspersky "))
        assertEquals(1, assessEngineFlags(twice).flaggedEngines)
        assertEquals(EngineLevel.Light, assessEngineFlags(twice).level)
        // A source that gave only counts: 2 flags and 1 name, so 2 engines.
        assertEquals(2, assessEngineFlags(listOf(malicious("Adware.A")), countOnly = 2).flaggedEngines)
        assertEquals(EngineLevel.Severe, assessEngineFlags(emptyList(), countOnly = 4).level)
        assertEquals(EngineLevel.Light, assessEngineFlags(emptyList(), countOnly = 3).level)
    }

    // ---- Report: sources, merged detections, summary ----

    private fun evidence(name: String, vt: VtLookupResult?, md: VtLookupResult? = null, hash: String = name.padEnd(64, 'e'), lookedUp: Boolean = true) =
        ShieldFileEvidence(name, 1000L, hash, vt = vt, md = md, lookedUp = lookedUp)

    @Test fun detectionsAreMergedAcrossSourcesWithTheirEnginesAndSeverity() {
        val vt = VtLookupResult.Found(
            3, 0, 70, 1L,
            listOf(
                EngineFlag("Kaspersky", "Android.Trojan.Agent"), EngineFlag("Fortinet", "android.trojan.agent"),
                EngineFlag("Zillya", "Riskware.Foo"),
            ),
        )
        val md = VtLookupResult.Found(2, 0, 38, null, listOf(EngineFlag("Avira", "Android.Trojan.Agent"), EngineFlag("ClamAV", "Riskware.Foo")))
        val report = buildShieldReport("x.apk", sha, listOf(evidence("base.apk", vt, md)))
        assertEquals(EngineLevel.Severe, report.level)
        assertEquals(2, report.detections.size)
        val trojan = report.detections.first()
        assertEquals("Android.Trojan.Agent", trojan.name)
        assertEquals(DetectionSeverity.Serious, trojan.severity)
        assertEquals(listOf("Avira", "Fortinet", "Kaspersky"), trojan.engines)
        assertEquals(listOf(ShieldSource.VirusTotal, ShieldSource.MetaDefender), trojan.sources)
        assertEquals(listOf("base.apk"), trojan.files)
        val riskware = report.detections.last()
        assertEquals(DetectionSeverity.Light, riskware.severity)
        assertEquals(listOf("ClamAV", "Zillya"), riskware.engines)
        // 5 distinct engines (Kaspersky, Fortinet, Zillya, Avira, ClamAV) flagged something.
        assertEquals(5, report.flaggedEngines)
    }

    @Test fun inABundleEveryDetectionNamesTheApkThatTriggeredIt() {
        val clean = VtLookupResult.Found(0, 0, 70, 1L)
        val bad = VtLookupResult.Found(1, 0, 70, 1L, listOf(EngineFlag("Kaspersky", "Android.Trojan.Agent")))
        val report = buildShieldReport("bundle.apks", sha, listOf(evidence("base.apk", clean), evidence("config.apk", bad)))
        assertEquals(listOf("config.apk"), report.detections.single().files)
        assertEquals(EngineLevel.Severe, report.level)
        assertEquals("bundle.apks", report.analysedName)
        assertEquals(sha, report.analysedSha256)
    }

    @Test fun sourceReportsCarryTheStatusOfEverySource() {
        assertEquals(SourceStatus.NotQueried, sourceReportOf(ShieldSource.VirusTotal, null).status)
        assertEquals(SourceStatus.UnknownHash, sourceReportOf(ShieldSource.VirusTotal, VtLookupResult.UnknownHash).status)
        assertEquals(SourceStatus.Unavailable, sourceReportOf(ShieldSource.VirusTotal, VtLookupResult.Unavailable).status)
        assertEquals(SourceStatus.RateLimited, sourceReportOf(ShieldSource.MetaDefender, VtLookupResult.RateLimited).status)
        assertEquals(SourceStatus.InvalidKey, sourceReportOf(ShieldSource.MetaDefender, VtLookupResult.InvalidKey).status)
        val answered = sourceReportOf(ShieldSource.VirusTotal, VtLookupResult.Found(1, 2, 60, 99L), SourceInfo(fromCache = true, checkedAtMs = 5L))
        assertEquals(SourceStatus.Answered, answered.status)
        assertEquals(3, answered.flagged)
        assertEquals(60, answered.total)
        assertEquals(99L, answered.analysisDate)
        assertTrue(answered.fromCache)
        assertEquals(5L, answered.checkedAtMs)
    }

    // ---- Links ----

    @Test fun linksExistOnlyForSourcesThatAnsweredAndUseTheHashThatWasLookedUp() {
        val hashA = "a".repeat(64)
        val hashB = "b".repeat(64)
        val report = buildShieldReport(
            "bundle.apks", sha,
            listOf(
                evidence("base.apk", VtLookupResult.Found(0, 0, 70, 1L), VtLookupResult.UnknownHash, hashA),
                evidence("split.apk", VtLookupResult.Unavailable, VtLookupResult.Found(0, 0, 38), hashB),
                evidence("res.apk", null, null, "c".repeat(64), lookedUp = false),
            ),
        )
        val links = reportLinks(report)
        assertEquals(
            listOf(
                ReportLink(ShieldSource.VirusTotal, "base.apk", hashA, "https://www.virustotal.com/gui/file/$hashA"),
                ReportLink(ShieldSource.MetaDefender, "split.apk", hashB, "https://metadefender.opswat.com/results/file/$hashB/hash/overview"),
            ),
            links,
        )
        // The container hash (sha) was never looked up, so no link uses it.
        assertTrue(links.none { sha in it.url })
    }

    @Test fun noLinkWhenNothingAnsweredOrTheHashIsNotAHash() {
        assertTrue(reportLinks(buildShieldReport("a.apk", sha, listOf(evidence("a", VtLookupResult.UnknownHash, VtLookupResult.RateLimited)))).isEmpty())
        assertTrue(reportLinks(buildShieldReport("a.apk", sha, listOf(evidence("a", null, null)))).isEmpty())
        assertTrue(reportLinks(buildShieldReport("a.apk", sha, listOf(evidence("a", VtLookupResult.Found(0, 0, 70, 1L), hash = "not-a-hash")))).isEmpty())
    }

    // ---- Summary ----

    @Test fun theSummaryNamesEachSourceThatAnswered() {
        val one = buildShieldReport("a", sha, listOf(evidence("a", VtLookupResult.Found(2, 1, 70, 1L))))
        assertEquals("VirusTotal 3/70", one.summary)
        val mdOnly = buildShieldReport("a", sha, listOf(evidence("a", VtLookupResult.Unavailable, VtLookupResult.Found(0, 0, 38))))
        assertEquals("MetaDefender 0/38", mdOnly.summary)
        assertNull(buildShieldReport("a", sha, listOf(evidence("a", VtLookupResult.UnknownHash))).summary)
        assertNull(buildShieldReport("a", sha, emptyList()).summary)
    }

    // ---- Order and colour ----

    @Test fun redReasonsComeFirstAndEachGroupKeepsTheOrderOfGravity() {
        val ordered = orderedByGravity(
            listOf(
                ShieldWarningReason.SelfUpdaterPermission,
                ShieldWarningReason.DropperDetected,
                ShieldWarningReason.AdwareDetected,
                ShieldWarningReason.DropperDetected,
                ShieldWarningReason.MalwareDetected,
                ShieldWarningReason.VirusTotalKeyMissing,
            ),
        )
        assertEquals(
            listOf(
                ShieldWarningReason.MalwareDetected,
                ShieldWarningReason.AdwareDetected,
                ShieldWarningReason.DropperDetected,
                ShieldWarningReason.VirusTotalKeyMissing,
                ShieldWarningReason.SelfUpdaterPermission,
            ),
            ordered,
        )
        // The first Red is always before the first Yellow, whatever the input order.
        val all = orderedByGravity(ShieldWarningReason.entries.reversed())
        val firstYellow = all.indexOfFirst { it.severity() == SecuritySeverity.Yellow }
        assertTrue(all.take(firstYellow).all { it.severity() == SecuritySeverity.Red })
        assertTrue(all.drop(firstYellow).all { it.severity() == SecuritySeverity.Yellow })
    }

    @Test fun theCardColourFollowsTheTierAndTheDecision() {
        val clean = ShieldVerdict.Clean(sha, "VirusTotal 0/70")
        val yellow = ShieldVerdict.Warning(sha, listOf(ShieldWarningReason.DropperDetected), 0, 70)
        val red = ShieldVerdict.Warning(sha, listOf(ShieldWarningReason.MalwareDetected), 5, 70)
        val mixed = ShieldVerdict.Warning(sha, listOf(ShieldWarningReason.DropperDetected, ShieldWarningReason.SignatureMismatch), 0, 0)
        assertEquals(ShieldCardTone.Green, shieldCardTone(clean, userAuthorized = false))
        // A Yellow the user refused is a declined caution, not a red block (audit F12).
        assertEquals(ShieldCardTone.CautionDeclined, shieldCardTone(yellow, userAuthorized = false))
        // A Yellow the user accepted is authorized, single APK or bundle.
        assertEquals(ShieldCardTone.CautionAuthorized, shieldCardTone(yellow, userAuthorized = true))
        // Red is a block, whatever the flag says.
        assertEquals(ShieldCardTone.Blocked, shieldCardTone(red, userAuthorized = false))
        assertEquals(ShieldCardTone.Blocked, shieldCardTone(red, userAuthorized = true))
        assertEquals(ShieldCardTone.Blocked, shieldCardTone(mixed, userAuthorized = true))
        assertEquals(ShieldCardTone.Caution, shieldCardTone(ShieldVerdict.NeedsUpload(sha, emptyList()), userAuthorized = false))
        assertFalse(shieldCardTone(yellow, false) == shieldCardTone(red, false))
    }
}
