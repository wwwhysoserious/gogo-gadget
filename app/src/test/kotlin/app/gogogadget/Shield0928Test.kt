package app.gogogadget

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** 0.9.28: reachability, resource-only splits, format hardening, compromised keys, rotation, trackers, native code, reputation. */
class Shield0928Test {
    private val sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    private val clean = OfflineScanReport(
        signed = true, debugOrTestSigned = false, signerSha256 = "aa".repeat(32), versionCode = 10L,
        highRiskPermissions = emptySet(), versionDowngrade = false, signatureMismatch = false, reasons = emptyList(),
    )

    private fun zip(vararg entries: Pair<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { z ->
            for ((name, data) in entries) {
                z.putNextEntry(ZipEntry(name))
                z.write(data)
                z.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private fun tempDir(): File = Files.createTempDirectory("shield0928_").toFile()

    private fun elf(machine: Int, elfClass: Int, tail: ByteArray = ByteArray(0)): ByteArray {
        val head = ByteArray(64)
        head[0] = 0x7F; head[1] = 'E'.code.toByte(); head[2] = 'L'.code.toByte(); head[3] = 'F'.code.toByte()
        head[4] = elfClass.toByte(); head[5] = 1; head[6] = 1
        head[18] = (machine and 0xFF).toByte(); head[19] = (machine shr 8).toByte()
        return head + tail
    }

    // ---- A. Device availability ----

    @Test fun onlyConnectedAndAvailableDevicesAreSelectable() {
        assertTrue(isDeviceSelectable(DeviceStatus.CONNECTED))
        assertTrue(isDeviceSelectable(DeviceStatus.AVAILABLE))
        assertFalse(isDeviceSelectable(DeviceStatus.UNAVAILABLE))
        assertFalse(isDeviceSelectable(DeviceStatus.OTHER_NETWORK))
    }

    @Test fun aSavedDeviceThatIsNotReachableIsUnavailableAndNotSelectable() {
        val tv = Target("TV", "192.168.1.50", 5555)
        val sections = deviceMenuEntries(Target("Phone", "127.0.0.1", 0), listOf(tv), setOf("192.168.1"), emptySet(), null)
        val entry = sections.thisNetwork.first { !it.local }
        assertEquals(DeviceStatus.UNAVAILABLE, entry.status)
        assertFalse(isDeviceSelectable(entry.status))
        val up = deviceMenuEntries(Target("Phone", "127.0.0.1", 0), listOf(tv), setOf("192.168.1"), setOf("192.168.1.50"), null)
        assertTrue(isDeviceSelectable(up.thisNetwork.first { !it.local }.status))
    }

    @Test fun probePortsTriesTheSavedPortAndTheAnnouncedOnesOnce() {
        assertEquals(listOf(5555), probePorts(0, emptyList()))
        assertEquals(listOf(40123, 37001, 5555), probePorts(40123, listOf(37001, 40123, 0, 70000)))
    }

    // ---- F1. Resource-only splits ----

    @Test fun onlyTheBaseAndSplitsWithCodeAreLookedUp() {
        assertTrue(needsReputationLookup(true, listOf("res/a.png")))
        assertFalse(needsReputationLookup(false, listOf("AndroidManifest.xml", "resources.arsc", "res/values-pt/strings.xml")))
        assertTrue(needsReputationLookup(false, listOf("classes.dex")))
        assertTrue(needsReputationLookup(false, listOf("classes3.dex")))
        assertTrue(needsReputationLookup(false, listOf("lib/arm64-v8a/libfoo.so")))
        assertFalse(needsReputationLookup(false, listOf("assets/libfoo.so.txt", "assets/classes.dex.bak")))
    }

    @Test fun aResourceOnlySplitDoesNotStopAGreenVerdict() {
        val files = listOf(
            ShieldFileEvidence("base.apk", 1000L, "a".repeat(64), VtLookupResult.Found(0, 0, 60)),
            ShieldFileEvidence("config.pt.apk", 10L, "b".repeat(64), VtLookupResult.Unavailable, lookedUp = false),
        )
        assertTrue(evaluateShieldVerdict(sha, clean, true, false, files) is ShieldVerdict.Clean)
    }

    // ---- E. No keys ----

    @Test fun withoutAnyKeyANewAppIsAtMostYellowAndNeverGreen() {
        val files = listOf(ShieldFileEvidence("a.apk", 1000L, "a".repeat(64), VtLookupResult.Found(0, 0, 70)))
        val v = evaluateShieldVerdict(sha, clean, false, false, files) as ShieldVerdict.Warning
        assertEquals(listOf(ShieldWarningReason.VirusTotalKeyMissing), v.reasons)
        assertEquals(SecurityTier.Yellow, securityTierOf(v))
    }

    @Test fun redStillBlocksWithoutKeys() {
        val bad = clean.copy(reasons = listOf(ShieldWarningReason.CompromisedKey))
        val v = evaluateShieldVerdict(sha, bad, false, false, emptyList())
        assertEquals(SecurityTier.Red, securityTierOf(v))
        assertFalse(mayInstall(v, userOverridden = true))
    }

    // ---- F3. Unknown hash ----

    @Test fun unknownEverywhereWithACleanScanIsYellowWhenNothingCanBeUploaded() {
        val files = listOf(ShieldFileEvidence("a.apk", 1000L, "a".repeat(64), VtLookupResult.UnknownHash))
        val v = evaluateShieldVerdict(sha, clean, true, false, files, canUpload = false) as ShieldVerdict.Warning
        assertEquals(listOf(ShieldWarningReason.NotKnownToVirusTotal), v.reasons)
        assertTrue(mayInstall(v, userOverridden = true))
        // With a VirusTotal key the upload is only offered, and declining it ends as the same Yellow.
        assertTrue(evaluateShieldVerdict(sha, clean, true, false, files) is ShieldVerdict.NeedsUpload)
        assertFalse(mayInstall(evaluateShieldVerdict(sha, clean, true, false, files)))
    }

    // ---- F2. Janus and BadPack ----

    @Test fun aV1OnlySignatureIsRejectedOnlyWhenTheAppDoesNotNeedPreV2Platforms() {
        assertTrue(isV1OnlyRejected(true, false, 24, null))
        assertTrue(isV1OnlyRejected(true, false, 21, 30))
        assertFalse(isV1OnlyRejected(true, false, 21, 28))
        assertFalse(isV1OnlyRejected(true, false, null, null))
        assertFalse(isV1OnlyRejected(true, true, 26, 34))
        assertFalse(isV1OnlyRejected(false, false, 26, 34))
    }

    @Test fun aV1OnlyApkWithModernSdkLevelsIsRed() {
        val dir = tempDir()
        try {
            val identity = generateAdbIdentity("CN=Someone,O=Example,C=PT")
            val file = File(dir, "v1.apk").apply {
                writeBytes(zip("AndroidManifest.xml" to "versionCode=\"3\"".toByteArray(), "META-INF/CERT.RSA" to identity.certificate.encoded, "classes.dex" to ByteArray(8)))
            }
            val bundle = (inspectAndExtractPackage(file, dir) as PackageInspectResult.Valid).bundle
            val modern = analyzePackageOffline(file, bundle, candidateMinSdk = 26, candidateTargetSdk = 34)
            assertTrue(ShieldWarningReason.LegacySignatureOnly in modern.reasons)
            assertEquals(SecurityTier.Red, securityTierOf(ShieldVerdict.Warning(sha, modern.reasons, 0, 0, modern)))
            val old = analyzePackageOffline(file, bundle, candidateMinSdk = 19, candidateTargetSdk = 25)
            assertFalse(ShieldWarningReason.LegacySignatureOnly in old.reasons)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun aConsistentArchiveHasNoStructureProblem() {
        val dir = tempDir()
        try {
            val f = File(dir, "ok.apk").apply { writeBytes(zip("a.txt" to "hello".toByteArray(), "b/c.bin" to ByteArray(500) { it.toByte() })) }
            assertNull(zipStructureProblem(f))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun badPackMismatchesBetweenCentralDirectoryAndLocalHeadersAreFound() {
        val dir = tempDir()
        try {
            val good = zip("a.txt" to "hello hello hello".toByteArray(), "b.txt" to "world world world".toByteArray())
            // Local header of the first entry sits at offset 0: method at 8, name at 30.
            val method = good.copyOf().also { it[8] = 0 }
            assertNotNull(zipStructureProblem(File(dir, "m.apk").apply { writeBytes(method) }))
            val name = good.copyOf().also { it[30] = 'x'.code.toByte() }
            assertNotNull(zipStructureProblem(File(dir, "n.apk").apply { writeBytes(name) }))
            // Second central directory name made equal to the first: a duplicate name.
            val cdStart = String(good, Charsets.ISO_8859_1).lastIndexOf("b.txt")
            val dup = good.copyOf().also { it[cdStart] = 'a'.code.toByte() }
            assertEquals("duplicate entry name", zipStructureProblem(File(dir, "d.apk").apply { writeBytes(dup) }))
            // Trailing junk after the end record.
            assertNotNull(zipStructureProblem(File(dir, "t.apk").apply { writeBytes(good + ByteArray(7)) }))
            // Not an archive at all.
            assertNotNull(zipStructureProblem(File(dir, "x.apk").apply { writeBytes(ByteArray(100)) }))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun aMalformedArchiveIsReportedAsRed() {
        val dir = tempDir()
        try {
            val identity = generateAdbIdentity("CN=Someone,O=Example,C=PT")
            val bytes = zip("AndroidManifest.xml" to "versionCode=\"3\"".toByteArray(), "META-INF/CERT.RSA" to identity.certificate.encoded)
            val file = File(dir, "bad.apk").apply { writeBytes(bytes.copyOf().also { it[8] = 0 }) }
            val bundle = (inspectAndExtractPackage(file, dir) as? PackageInspectResult.Valid)?.bundle ?: return
            val report = analyzePackageOffline(file, bundle)
            assertTrue(ShieldWarningReason.MalformedArchive in report.reasons)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun aDexInFrontOfAnArchiveIsAJanusPolyglot() {
        val dir = tempDir()
        try {
            assertTrue(isJanusPolyglot(File(dir, "j.apk").apply { writeBytes(DexMagic + ByteArray(40)) }))
            assertFalse(isJanusPolyglot(File(dir, "z.apk").apply { writeBytes(zip("a" to ByteArray(3))) }))
        } finally {
            dir.deleteRecursively()
        }
    }

    // ---- F4. Compromised keys and rotation ----

    @Test fun leakedPlatformKeysAreRedButTheAospTestKeyStaysYellow() {
        assertEquals(3, CompromisedPlatformKeySha256s.size)
        assertTrue(CompromisedPlatformKeySha256s.all { it in KnownTestKeySha256s && it.length == 64 })
        val testKey = "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc"
        assertFalse(testKey in CompromisedPlatformKeySha256s)
        assertEquals(SecuritySeverity.Red, ShieldWarningReason.CompromisedKey.severity())
    }

    @Test fun aCompromisedSignerBlocksTheInstall() {
        val dir = tempDir()
        try {
            val file = File(dir, "p.apk").apply { writeBytes(zip("AndroidManifest.xml" to "versionCode=\"3\"".toByteArray(), "classes.dex" to ByteArray(8))) }
            val bundle = (inspectAndExtractPackage(file, dir) as PackageInspectResult.Valid).bundle
            val platform = CompromisedPlatformKeySha256s.first()
            val report = analyzePackageOffline(file, bundle, candidateSigSha256 = platform)
            assertTrue(ShieldWarningReason.CompromisedKey in report.reasons)
            val ok = analyzePackageOffline(file, bundle, candidateSigSha256 = "cc".repeat(32))
            assertFalse(ShieldWarningReason.CompromisedKey in ok.reasons)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun certificateFactsCarryTheCompromisedFlag() {
        val facts = mergeSignerFacts(emptyList(), listOf(ParsedCertInfo("aa".repeat(32), false, null, compromised = true)))
        assertTrue(facts.compromised)
        assertFalse(mergeSignerFacts(emptyList(), listOf(ParsedCertInfo("aa".repeat(32), false))).compromised)
    }

    @Test fun aRotatedSignerIsAcceptedWhenTheInstalledOneIsInItsLineage() {
        val dir = tempDir()
        try {
            val file = File(dir, "r.apk").apply { writeBytes(zip("AndroidManifest.xml" to "versionCode=\"9\"".toByteArray(), "classes.dex" to ByteArray(8))) }
            val bundle = (inspectAndExtractPackage(file, dir) as PackageInspectResult.Valid).bundle
            val oldSigner = "aa".repeat(32)
            val newSigner = "bb".repeat(32)
            val rotated = analyzePackageOffline(
                file, bundle, installedSigSha256 = oldSigner, installedVersionCode = 5L,
                candidateSigSha256 = newSigner, candidateLineageSha256 = listOf(oldSigner, newSigner),
            )
            assertFalse(rotated.signatureMismatch)
            assertFalse(ShieldWarningReason.SignatureMismatch in rotated.reasons)
            val stranger = analyzePackageOffline(
                file, bundle, installedSigSha256 = oldSigner, installedVersionCode = 5L,
                candidateSigSha256 = newSigner, candidateLineageSha256 = listOf("cc".repeat(32), newSigner),
            )
            assertTrue(ShieldWarningReason.SignatureMismatch in stranger.reasons)
            // A rotated update of the installed app is a trusted update.
            val report = clean.copy(signerSha256 = newSigner, signerLineageSha256 = setOf(oldSigner, newSigner), versionCode = 9L)
            assertTrue(isTrustedUpdate(report, InstalledAppInfo(5L, oldSigner)))
            assertFalse(isTrustedUpdate(report.copy(signerLineageSha256 = emptySet()), InstalledAppInfo(5L, oldSigner)))
        } finally {
            dir.deleteRecursively()
        }
    }

    // ---- F5. Trackers and native code ----

    @Test fun knownTrackerPackagesAreMatchedInDottedAndDescriptorForm() {
        assertEquals("AppsFlyer", matchTracker("com.appsflyer.AppsFlyerLib"))
        assertEquals("Adjust", matchTracker("Lcom/adjust/sdk/Adjust;"))
        assertEquals("Branch", matchTracker("io.branch.referral.Branch"))
        assertEquals("Google Firebase Analytics", matchTracker("com.google.firebase.analytics.FirebaseAnalytics"))
        assertEquals("Facebook Ads", matchTracker("com.facebook.ads.AdView"))
        assertNull(matchTracker("com.appsflyerx.Other"))
        assertNull(matchTracker("app.gogogadget.Main"))
        assertNull(matchTracker(""))
        assertEquals(setOf("Flurry", "Mixpanel"), findTrackers(listOf("com.flurry.sdk.A", "Lcom/mixpanel/android/MixpanelAPI;", "kotlin.Unit")))
    }

    @Test fun nativeLibrariesMustBeRealElfFilesForTheirFolder() {
        val ok = inspectNativeLibrary("lib/arm64-v8a/libfoo.so", elf(183, 2, "JNI_OnLoad".toByteArray()))
        assertEquals(NativeVerdict.Valid, ok.verdict)
        assertTrue(ok.exportsJniOnLoad)
        assertEquals(NativeVerdict.InvalidElf, inspectNativeLibrary("lib/arm64-v8a/libfoo.so", "MZ not elf".toByteArray()).verdict)
        assertEquals(NativeVerdict.InvalidElf, inspectNativeLibrary("lib/arm64-v8a/libfoo.so", elf(40, 1)).verdict)
        assertEquals(NativeVerdict.InvalidElf, inspectNativeLibrary("lib/x86_64/libfoo.so", elf(62, 1)).verdict)
        assertEquals(NativeVerdict.Valid, inspectNativeLibrary("lib/armeabi-v7a/libfoo.so", elf(40, 1)).verdict)
        assertEquals(NativeVerdict.Valid, inspectNativeLibrary("lib/mips/libfoo.so", elf(8, 1)).verdict)
    }

    @Test fun instrumentationMarkersAndPackerNamesAreSuspicious() {
        val frida = inspectNativeLibrary("lib/arm64-v8a/libhook.so", elf(183, 2, "xx frida-gadget xx".toByteArray()))
        assertEquals(NativeVerdict.Suspicious, frida.verdict)
        assertEquals(NativeVerdict.Suspicious, inspectNativeLibrary("lib/arm64-v8a/libjiagu_64.so", elf(183, 2)).verdict)
        assertEquals(SecuritySeverity.Yellow, ShieldWarningReason.SuspiciousNativeCode.severity())
        // Changed in 0.9.50 (audit F22): a filler or wrong-platform .so is Yellow, the user decides.
        assertEquals(SecuritySeverity.Yellow, ShieldWarningReason.InvalidNativeLibrary.severity())
    }

    @Test fun theDeepScanReportsNativeFindingsFromTheApk() {
        val dir = tempDir()
        try {
            val disguised = File(dir, "d.apk").apply { writeBytes(zip("classes.dex" to ByteArray(4), "lib/arm64-v8a/libx.so" to "not an elf".toByteArray())) }
            val r1 = StaticAnalyzer.analyzeApkFile(disguised)
            assertTrue(r1.issues.any { it.reason == ShieldWarningReason.InvalidNativeLibrary })
            val fine = File(dir, "f.apk").apply { writeBytes(zip("lib/arm64-v8a/libx.so" to elf(183, 2))) }
            assertTrue(StaticAnalyzer.analyzeApkFile(fine).issues.isEmpty())
        } finally {
            dir.deleteRecursively()
        }
    }

    // ---- F6. Reputation ----

    private val md200 = """{"file_info":{"sha256":"$sha"},"scan_results":{"scan_all_result_i":0,"total_avs":38,"total_detected_avs":0}}"""

    @Test fun metaDefenderResponsesAreParsedStrictly() {
        assertEquals(VtLookupResult.Found(0, 0, 38), parseMetaDefenderResponse(200, md200, sha))
        assertEquals(
            VtLookupResult.Found(5, 0, 38),
            parseMetaDefenderResponse(200, md200.replace("\"scan_all_result_i\":0", "\"scan_all_result_i\":1").replace("\"total_detected_avs\":0", "\"total_detected_avs\":5"), sha),
        )
        assertEquals(VtLookupResult.UnknownHash, parseMetaDefenderResponse(404, "{\"$sha\":\"Not Found\"}", sha))
        assertEquals(VtLookupResult.InvalidKey, parseMetaDefenderResponse(401, "", sha))
        assertEquals(VtLookupResult.RateLimited, parseMetaDefenderResponse(429, "", sha))
        assertEquals(VtLookupResult.Unavailable, parseMetaDefenderResponse(500, "", sha))
        assertEquals(VtLookupResult.Unavailable, parseMetaDefenderResponse(200, "not json", sha))
        assertEquals(VtLookupResult.Unavailable, parseMetaDefenderResponse(200, "{}", sha))
        assertEquals(VtLookupResult.Unavailable, parseMetaDefenderResponse(200, md200.replace(sha, "0".repeat(64)), sha))
        assertEquals(VtLookupResult.Unavailable, parseMetaDefenderResponse(200, md200.replace("\"scan_all_result_i\":0", "\"scan_all_result_i\":3"), sha))
        assertEquals(VtLookupResult.Unavailable, parseMetaDefenderResponse(200, md200.replace("\"total_avs\":38", "\"total_avs\":\"x\""), sha))
    }

    @Test fun metaDefenderKeysGoOnlyToItsOwnHost() {
        assertTrue(isAllowedMetaDefenderHost("https://api.metadefender.com/v4/hash/$sha"))
        assertFalse(isAllowedMetaDefenderHost("http://api.metadefender.com/v4/hash/$sha"))
        assertFalse(isAllowedMetaDefenderHost("https://api.metadefender.com.evil.example/v4"))
        assertFalse(isAllowedMetaDefenderHost("https://user@api.metadefender.com/v4"))
        assertFalse(isAllowedMetaDefenderHost("https://metadefender.opswat.com/"))
    }

    @Test fun metaDefenderDetectionsComeFromScanDetails() {
        val body = """{"file_info":{"sha256":"$sha"},"scan_results":{"scan_all_result_i":1,"total_avs":38,"total_detected_avs":2,
            "scan_details":{
              "EngineB":{"threat_found":"Android.Riskware.Agent","scan_result_i":1},
              "EngineA":{"threat_found":"Trojan.Android.Foo","scan_result_i":2},
              "EngineC":{"threat_found":"","scan_result_i":0},
              "EngineD":{"scan_result_i":0}}}}"""
        val found = parseMetaDefenderResponse(200, body, sha) as VtLookupResult.Found
        assertEquals(2, found.malicious)
        assertEquals(38, found.total)
        assertEquals(
            listOf(EngineFlag("EngineA", "Trojan.Android.Foo", "suspicious"), EngineFlag("EngineB", "Android.Riskware.Agent", "malicious")),
            found.detections,
        )
        // Without scan_details only the counters are known.
        assertTrue((parseMetaDefenderResponse(200, md200.replace("\"total_detected_avs\":0", "\"total_detected_avs\":2").replace("\"scan_all_result_i\":0", "\"scan_all_result_i\":1"), sha) as VtLookupResult.Found).detections.isEmpty())
    }

    @Test fun virusTotalDetectionsComeFromLastAnalysisResults() {
        val body = """{"data":{"id":"$sha","attributes":{"last_analysis_date":1700000000,
            "last_analysis_stats":{"malicious":2,"suspicious":1,"harmless":0,"undetected":60},
            "last_analysis_results":{
              "Kaspersky":{"category":"malicious","result":"HEUR:Trojan-Dropper.AndroidOS.Agent.a"},
              "Zillya":{"category":"suspicious","result":null},
              "Acme":{"category":"undetected","result":null},
              "Fortinet":{"category":"malicious","result":"Android/Agent.XYZ!tr"},
              "Broken":"not an object"}}}}"""
        val found = parseVirusTotalResponse(200, body, sha) as VtLookupResult.Found
        assertEquals(2, found.malicious)
        assertEquals(1, found.suspicious)
        assertEquals(63, found.total)
        assertEquals(
            listOf(
                EngineFlag("Fortinet", "Android/Agent.XYZ!tr", "malicious"),
                EngineFlag("Kaspersky", "HEUR:Trojan-Dropper.AndroidOS.Agent.a", "malicious"),
                EngineFlag("Zillya", "", "suspicious"),
            ),
            found.detections,
        )
        // Without last_analysis_results the counters still work.
        assertTrue(parseVirusTotalDetections(null).isEmpty())
    }

    @Test fun theCacheKeepsAVerdictPerSourceFor48HoursAndSurvivesARestart() {
        val dir = tempDir()
        try {
            val file = File(dir, "rep.json")
            var now = 1_000_000L
            val cache = ReputationCache(file) { now }
            assertNull(cache.get(sha, ShieldSource.VirusTotal))
            val flags = listOf(EngineFlag("EngineA", "Riskware.A"))
            val stored = VtLookupResult.Found(0, 1, 60, 1_700_000_000L, flags)
            cache.put(sha, ShieldSource.VirusTotal, stored)
            now += ReputationTtlMs - 1
            // The source, the analysis date, the engine names and the time it was stored all survive.
            val hit = cache.get(sha, ShieldSource.VirusTotal)
            assertEquals(stored, hit?.found)
            assertEquals(1_000_000L, hit?.storedAtMs)
            assertEquals(stored, ReputationCache(file) { now }.get(sha, ShieldSource.VirusTotal)?.found)
            // Another source has its own entry: MetaDefender never gets VirusTotal's verdict.
            assertNull(cache.get(sha, ShieldSource.MetaDefender))
            now += 2
            assertNull(cache.get(sha, ShieldSource.VirusTotal))
            assertNull(ReputationCache(file) { now }.get(sha, ShieldSource.VirusTotal))
            file.writeText("garbage")
            assertNull(ReputationCache(file) { now }.get(sha, ShieldSource.VirusTotal))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun changingAKeyForgetsOnlyThatSourcesVerdictsAndOldEntriesWithoutASourceAreDropped() {
        val dir = tempDir()
        try {
            val file = File(dir, "rep.json")
            val cache = ReputationCache(file) { 5_000L }
            cache.put(sha, ShieldSource.VirusTotal, VtLookupResult.Found(0, 0, 60))
            cache.put(sha, ShieldSource.MetaDefender, VtLookupResult.Found(0, 0, 38))
            cache.clear(ShieldSource.VirusTotal)
            assertNull(cache.get(sha, ShieldSource.VirusTotal))
            assertEquals(38, cache.get(sha, ShieldSource.MetaDefender)?.found?.total)
            assertNull(ReputationCache(file) { 5_000L }.get(sha, ShieldSource.VirusTotal))
            // The format of 0.9.49 had no source: such a verdict could be from either service, so it is not used.
            file.writeText("""{"entries":[{"sha":"$sha","m":0,"s":0,"t":60,"at":4000}]}""")
            val old = ReputationCache(file) { 5_000L }
            assertNull(old.get(sha, ShieldSource.VirusTotal))
            assertNull(old.get(sha, ShieldSource.MetaDefender))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun bothSourcesAreAlwaysAskedAndEachKeepsItsOwnAnswer() {
        runBlocking {
            val notes = mutableListOf<String>()
            var vtAsked = false
            var mdAsked = false
            val answers = lookupBothSources(
                sha, ReputationCache(null),
                vt = { vtAsked = true; VtLookupResult.RateLimited },
                md = { mdAsked = true; VtLookupResult.Found(0, 0, 38) },
                note = { notes += it },
            )
            assertTrue(vtAsked && mdAsked)
            assertEquals(VtLookupResult.RateLimited, answers.vt.result)
            assertEquals(VtLookupResult.Found(0, 0, 38), answers.md.result)
            assertFalse(answers.md.info.fromCache)
            assertNotNull(answers.md.info.checkedAtMs)
            assertTrue(notes.any { it.contains("VirusTotal") } && notes.any { it.contains("MetaDefender") })
            assertTrue(notes.none { it.contains("apikey", ignoreCase = true) })
            // A clean VirusTotal answer does not stop MetaDefender from being asked (it used to be skipped).
            mdAsked = false
            lookupBothSources(sha, null, vt = { VtLookupResult.Found(0, 0, 70) }, md = { mdAsked = true; VtLookupResult.Found(9, 0, 38) })
            assertTrue(mdAsked)
        }
    }

    @Test fun bothSourcesAreAskedAtTheSameTime() {
        runBlocking {
            val mdStarted = CompletableDeferred<Unit>()
            val answers = lookupBothSources(
                sha, null,
                vt = { mdStarted.await(); VtLookupResult.Found(0, 0, 70) },
                md = { mdStarted.complete(Unit); VtLookupResult.Found(0, 0, 38) },
                timeoutMs = 3_000L,
            )
            // Asked one after the other, VirusTotal would wait for a MetaDefender that never starts and time out.
            assertEquals(VtLookupResult.Found(0, 0, 70), answers.vt.result)
            assertEquals(VtLookupResult.Found(0, 0, 38), answers.md.result)
        }
    }

    @Test fun aSlowOrBrokenSourceFailsAloneAndTheOtherStillAnswers() {
        runBlocking {
            val slow = lookupBothSources(
                sha, null,
                vt = { delay(10_000L); VtLookupResult.Found(0, 0, 70) },
                md = { VtLookupResult.Found(0, 0, 38) },
                timeoutMs = 100L,
            )
            assertEquals(VtLookupResult.Unavailable, slow.vt.result)
            assertEquals(VtLookupResult.Found(0, 0, 38), slow.md.result)
            val broken = lookupBothSources(
                sha, null,
                vt = { throw IllegalStateException("boom") },
                md = { VtLookupResult.UnknownHash },
            )
            assertEquals(VtLookupResult.Unavailable, broken.vt.result)
            assertEquals(VtLookupResult.UnknownHash, broken.md.result)
        }
    }

    @Test fun aCachedAnswerIsMarkedAsCachedAndNobodyIsAskedAgain() {
        runBlocking {
            val cache = ReputationCache(null) { 10_000L }
            val first = lookupBothSources(sha, cache, vt = { VtLookupResult.Found(0, 0, 70, 1L) }, md = { VtLookupResult.UnknownHash }, clock = { 10_000L })
            assertFalse(first.vt.info.fromCache)
            var asked = false
            val again = lookupBothSources(
                sha, cache,
                vt = { asked = true; VtLookupResult.Unavailable },
                md = { asked = true; VtLookupResult.Found(0, 0, 38) },
            )
            // VirusTotal's answer came from the cache; MetaDefender's "unknown" is never cached, so it was asked again.
            assertTrue(again.vt.info.fromCache)
            assertEquals(10_000L, again.vt.info.checkedAtMs)
            assertEquals(VtLookupResult.Found(0, 0, 70, 1L), again.vt.result)
            assertFalse(again.md.info.fromCache)
            assertTrue(asked)
        }
    }

    @Test fun withoutKeysNobodyIsAsked() {
        runBlocking {
            val none = lookupBothSources(sha, ReputationCache(null), vt = null, md = null)
            assertNull(none.vt.result)
            assertNull(none.md.result)
            val mdOnly = lookupBothSources(sha, null, vt = null, md = { VtLookupResult.Found(0, 0, 40) })
            assertNull(mdOnly.vt.result)
            assertEquals(VtLookupResult.Found(0, 0, 40), mdOnly.md.result)
        }
    }
}
