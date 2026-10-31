package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.crypto.KeyGenerator

class SecurityShieldTest {
    private fun makeZip(vararg entries: Pair<String, ByteArray>): ByteArray {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            for ((name, data) in entries) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(data)
                zos.closeEntry()
            }
        }
        return baos.toByteArray()
    }

    // ---- Streaming SHA-256 ----

    @Test fun sha256HexMatchesKnownVectorsAndStreamsMultiChunkFiles() {
        // Empty input vector
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sha256Hex(ByteArrayInputStream(ByteArray(0))),
        )
        // Standard "abc" vector
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            sha256Hex(ByteArrayInputStream("abc".toByteArray(Charsets.US_ASCII))),
        )

        // Multi-chunk (> 64 KiB buffer) file streaming accuracy
        val tempFile = Files.createTempFile("sha256_test_", ".bin").toFile()
        try {
            val largePayload = ByteArray(150_000) { i -> (i * 31 and 0xFF).toByte() }
            tempFile.writeBytes(largePayload)
            val fromStream = sha256Hex(ByteArrayInputStream(largePayload))
            val fromFile = sha256Hex(tempFile)
            assertEquals(64, fromFile.length)
            assertEquals(fromStream, fromFile)
            assertEquals("ba7816bf\u202615ad", truncateSha256("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"))
        } finally {
            tempFile.delete()
        }
    }

    // ---- VirusTotal v3 response parsing ----

    @Test fun parseVirusTotalResponseHandlesCleanMaliciousUnknownInvalidAndRateLimit() {
        val cleanJson = """
            {
              "data": {
                "id": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "type": "file",
                "attributes": {
                  "last_analysis_date": 1700000000,
                  "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 64,
                    "harmless": 2,
                    "timeout": 0,
                    "type-unsupported": 4
                  }
                }
              }
            }
        """.trimIndent()
        assertEquals(
            VtLookupResult.Found(malicious = 0, suspicious = 0, total = 66, lastAnalysisDate = 1700000000L),
            parseVirusTotalResponse(200, cleanJson, sha),
        )

        val maliciousJson = """
            {
              "data": {
                "id": "$sha",
                "attributes": {
                  "last_analysis_date": 1700000000,
                  "last_analysis_stats": {
                    "malicious": 14,
                    "suspicious": 2,
                    "undetected": 50,
                    "harmless": 0
                  }
                }
              }
            }
        """.trimIndent()
        assertEquals(
            VtLookupResult.Found(malicious = 14, suspicious = 2, total = 66, lastAnalysisDate = 1700000000L),
            parseVirusTotalResponse(200, maliciousJson, sha),
        )

        assertEquals(VtLookupResult.UnknownHash, parseVirusTotalResponse(404, """{"error":{"code":"NotFoundError"}}""", sha))
        assertEquals(VtLookupResult.InvalidKey, parseVirusTotalResponse(401, """{"error":{"code":"WrongCredentialsError"}}""", sha))
        assertEquals(VtLookupResult.InvalidKey, parseVirusTotalResponse(403, """{"error":{"code":"ForbiddenError"}}""", sha))
        assertEquals(VtLookupResult.RateLimited, parseVirusTotalResponse(429, """{"error":{"code":"QuotaExceededError"}}""", sha))
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(503, "", sha))
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, """{"unexpected":"payload"}""", sha))
    }

    private fun vtBody(
        id: String = sha,
        stats: String = """{"malicious":0,"suspicious":0,"harmless":2,"undetected":64}""",
        date: String = ""","last_analysis_date":1700000000""",
        before: String = "",
    ) = """{"data":{"id":"$id","attributes":{$before"last_analysis_stats":$stats$date}}}"""

    @Test fun vtResponseWithoutLastAnalysisStatsIsUnavailable() {
        val onlyVotes = """{"data":{"id":"$sha","attributes":{"last_analysis_date":1700000000,"total_votes":{"harmless":90,"malicious":0}}}}"""
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, onlyVotes, sha))
        val otherName = """{"data":{"id":"$sha","attributes":{"last_analysis_date":1700000000,"stats":{"harmless":90,"malicious":0}}}}"""
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, otherName, sha))
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, """{"harmless":90,"undetected":10}""", sha))
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, vtBody(stats = "{}"), sha))
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, vtBody(stats = """{"malicious":"many"}"""), sha))
    }

    @Test fun vtTotalVotesIgnored() {
        val body = vtBody(before = """"total_votes":{"harmless":999,"malicious":888},""")
        assertEquals(
            VtLookupResult.Found(0, 0, 66, lastAnalysisDate = 1700000000L),
            parseVirusTotalResponse(200, body, sha),
        )
    }

    @Test fun vtTruncatedBodyIsUnavailable() {
        assertNull(readVtBody(ByteArrayInputStream(ByteArray(MaxVtResponseBytes + 1) { 'a'.code.toByte() })))
        assertEquals(MaxVtResponseBytes, readVtBody(ByteArrayInputStream(ByteArray(MaxVtResponseBytes) { 'a'.code.toByte() }))?.length)
        val cut = vtBody().substringBefore(""""suspicious"""")
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, cut, sha))
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, "", sha))
    }

    @Test fun vtShaMismatchRejected() {
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, vtBody(id = "ab".repeat(32)), sha))
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, vtBody(id = ""), sha))
        assertTrue(parseVirusTotalResponse(200, vtBody(id = sha.uppercase()), sha) is VtLookupResult.Found)
    }

    @Test fun vtMissingLastAnalysisDateIsUnavailable() {
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, vtBody(date = ""), sha))
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, vtBody(date = ""","last_analysis_date":0"""), sha))
    }

    @Test fun analysisAgeTextDescribesTheAge() {
        val now = 1_700_000_000L + 3 * 86_400L + 100L
        assertEquals("analysed 3 days ago", analysisAgeText(1_700_000_000L, now))
        assertEquals("analysed 1 day ago", analysisAgeText(now - 86_400L - 5L, now))
        assertEquals("analysed today", analysisAgeText(now - 10L, now))
        assertEquals("analysed today", analysisAgeText(now + 10_000L, now))
        assertEquals("analysis date unknown", analysisAgeText(null, now))
        // An old analysis still gives a Found: the verdict engine decides what its age means (isStaleAnalysis).
        assertTrue(parseVirusTotalResponse(200, vtBody(date = ""","last_analysis_date":1000"""), sha) is VtLookupResult.Found)
    }

    // ---- Offline manifest permission scanner (UTF-8 & UTF-16LE binary AXML string tables) ----

    @Test fun scanManifestRiskPermissionsFindsUtf8AndUtf16LePermissions() {
        val utf8Pool = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
            write("android.permission.BIND_ACCESSIBILITY_SERVICE".toByteArray(Charsets.UTF_8))
            write(byteArrayOf(0x00, 0x00))
            write("android.permission.REQUEST_INSTALL_PACKAGES".toByteArray(Charsets.UTF_8))
        }.toByteArray()
        assertEquals(
            setOf("BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES"),
            scanManifestRiskPermissions(utf8Pool),
        )

        val utf16LePool = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
            write("android.permission.BIND_DEVICE_ADMIN".toByteArray(Charsets.UTF_16LE))
            write(byteArrayOf(0x00, 0x00))
            write("android.permission.SEND_SMS".toByteArray(Charsets.UTF_16LE))
            write(byteArrayOf(0x00, 0x00))
            write("android.permission.SYSTEM_ALERT_WINDOW".toByteArray(Charsets.UTF_16LE))
        }.toByteArray()
        assertEquals(
            setOf("BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW", "SEND_SMS"),
            scanManifestRiskPermissions(utf16LePool),
        )

        val benignPool = "android.permission.INTERNET\u0000android.permission.VIBRATE".toByteArray(Charsets.UTF_16LE)
        assertTrue(scanManifestRiskPermissions(benignPool).isEmpty())
    }

    // ---- Offline unsigned vs signed APK, debug cert, version downgrade & signature mismatch ----

    @Test fun analyzePackageOfflineDetectsUnsignedApkAndSignedApk() {
        val tempDir = Files.createTempDirectory("shield_offline_").toFile()
        try {
            // 1. Unsigned single APK
            val unsignedBytes = makeZip(
                "AndroidManifest.xml" to """<manifest package="com.example.unsigned" android:versionCode="10"/>""".toByteArray(),
                "classes.dex" to ByteArray(64) { 1 },
            )
            val unsignedFile = File(tempDir, "unsigned.apk").apply { writeBytes(unsignedBytes) }
            val unsignedBundle = (inspectAndExtractPackage(unsignedFile, tempDir) as PackageInspectResult.Valid).bundle
            val unsignedReport = analyzePackageOffline(unsignedFile, unsignedBundle)
            assertFalse(unsignedReport.signed)
            assertTrue(ShieldWarningReason.UnsignedPackage in unsignedReport.reasons)
            assertEquals(10L, unsignedReport.versionCode)

            // 2. Signed single APK with real X.509 certificate (CN=Android Debug) and high-risk permission
            val debugIdentity = generateAdbIdentity("CN=Android Debug,O=Android,C=US")
            val expectedCertSha256 = sha256Hex(ByteArrayInputStream(debugIdentity.certificate.encoded))
            val signedBytes = makeZip(
                "AndroidManifest.xml" to "versionCode=\"25\" android.permission.READ_SMS".toByteArray(Charsets.UTF_8),
                "META-INF/CERT.RSA" to debugIdentity.certificate.encoded,
                "classes.dex" to ByteArray(64) { 2 },
            )
            val signedFile = File(tempDir, "signed.apk").apply { writeBytes(signedBytes) }
            val signedBundle = (inspectAndExtractPackage(signedFile, tempDir) as PackageInspectResult.Valid).bundle
            val signedReport = analyzePackageOffline(signedFile, signedBundle)
            assertTrue(signedReport.signed)
            assertTrue(signedReport.debugOrTestSigned)
            assertEquals(expectedCertSha256, signedReport.signerSha256)
            assertEquals(25L, signedReport.versionCode)
            assertEquals(setOf("READ_SMS"), signedReport.highRiskPermissions)
            assertEquals(listOf("READ_SMS"), signedReport.allPermissions)
            assertEquals(listOf(ShieldWarningReason.DebugOrTestCertificate), signedReport.reasons)

            // 3. Downgrade + Signature mismatch detection against installed package
            val mismatchAndDowngrade = analyzePackageOffline(
                sourceFile = signedFile,
                bundle = signedBundle,
                installedSigSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                installedVersionCode = 30L,
            )
            assertTrue(mismatchAndDowngrade.signatureMismatch)
            assertTrue(mismatchAndDowngrade.versionDowngrade)
            assertEquals(
                listOf(
                    ShieldWarningReason.DebugOrTestCertificate,
                    ShieldWarningReason.SignatureMismatch,
                    ShieldWarningReason.VersionDowngrade,
                ),
                mismatchAndDowngrade.reasons,
            )

            // 4. Garbage non-X.509 bytes in META-INF/CERT.RSA are rejected as unsigned
            val garbageSigBytes = makeZip(
                "AndroidManifest.xml" to """<manifest package="com.example.garbage" android:versionCode="5"/>""".toByteArray(),
                "META-INF/CERT.RSA" to "not a valid x509 certificate".toByteArray(Charsets.UTF_8),
                "classes.dex" to ByteArray(32) { 3 },
            )
            val garbageSigFile = File(tempDir, "garbage_sig.apk").apply { writeBytes(garbageSigBytes) }
            val garbageSigBundle = (inspectAndExtractPackage(garbageSigFile, tempDir) as PackageInspectResult.Valid).bundle
            val garbageSigReport = analyzePackageOffline(garbageSigFile, garbageSigBundle)
            assertFalse(garbageSigReport.signed)
            assertNull(garbageSigReport.signerSha256)
            assertTrue(ShieldWarningReason.UnsignedPackage in garbageSigReport.reasons)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test fun analyzePackageOfflineDetectsUnsignedSplitInsideBundle() {
        val tempDir = Files.createTempDirectory("shield_bundle_").toFile()
        try {
            val certBytes = generateAdbIdentity("CN=Release Publisher").certificate.encoded
            val signedSplit = makeZip(
                "AndroidManifest.xml" to "manifest".toByteArray(),
                "META-INF/CERT.RSA" to certBytes,
            )
            val unsignedSplit = makeZip(
                "AndroidManifest.xml" to "manifest".toByteArray(),
            )
            val bundleBytes = makeZip(
                "base.apk" to signedSplit,
                "split_config.arm64_v8a.apk" to unsignedSplit,
            )
            val bundleFile = File(tempDir, "bundle.apks").apply { writeBytes(bundleBytes) }
            val bundle = (inspectAndExtractPackage(bundleFile, tempDir) as PackageInspectResult.Valid).bundle
            val report = analyzePackageOffline(bundleFile, bundle)
            assertFalse(report.signed)
            assertEquals(listOf(ShieldWarningReason.UnsignedPackage), report.reasons)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    // ---- Verdict evaluation ----

    private val sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    private val now = 1_700_000_000L + 100L * 86_400L
    private val cleanOffline = OfflineScanReport(
        signed = true,
        debugOrTestSigned = false,
        signerSha256 = "aa".repeat(32),
        versionCode = 10L,
        highRiskPermissions = emptySet(),
        versionDowngrade = false,
        signatureMismatch = false,
        reasons = emptyList(),
    )

    private fun file(
        name: String,
        vt: VtLookupResult?,
        md: VtLookupResult? = null,
        size: Long = 1_000_000L,
        hash: String = name.padEnd(64, '0'),
    ) = ShieldFileEvidence(name, size, hash, vt = vt, md = md)

    private fun verdict(
        files: List<ShieldFileEvidence>,
        offline: OfflineScanReport = cleanOffline,
        hasKey: Boolean = true,
        trusted: Boolean = false,
        canUpload: Boolean = true,
    ) = evaluateShieldVerdict(sha, offline, hasKey, trusted, files, canUpload, nowEpochSeconds = now)

    private fun reasonsOf(v: ShieldVerdict) = (v as ShieldVerdict.Warning).reasons

    /** A verdict from a service, analysed one day ago, with the engines that flagged it. */
    private fun found(flagged: Int, total: Int, vararg names: String, suspicious: Int = 0) = VtLookupResult.Found(
        malicious = flagged,
        suspicious = suspicious,
        total = total,
        lastAnalysisDate = now - 86_400L,
        detections = names.mapIndexed { i, label -> EngineFlag("Engine${'A' + i}", label) },
    )

    private val known = found(0, 62)

    @Test fun offlineYellowPlusFlaggedOnlineIsRedAndTheOnlineResultIsNeverHidden() {
        // Audit F1: an on-device Yellow used to return before the online result was read.
        val offline = cleanOffline.copy(reasons = listOf(ShieldWarningReason.DebugOrTestCertificate))
        val v = verdict(listOf(file("a", found(40, 70))), offline = offline) as ShieldVerdict.Warning
        assertEquals(listOf(ShieldWarningReason.MalwareDetected, ShieldWarningReason.DebugOrTestCertificate), v.reasons)
        assertEquals(SecurityTier.Red, securityTierOf(v))
        assertEquals(40, v.vtMalicious)
        assertEquals(70, v.vtTotal)
        assertFalse(mayInstall(v, userOverridden = true))
    }

    @Test fun offlineYellowWithACleanOnlineResultStaysYellowAndKeepsTheOnlineSummary() {
        // Audit F2: the card used to say "no analysis" because the online result was thrown away.
        val offline = cleanOffline.copy(reasons = listOf(ShieldWarningReason.DebugOrTestCertificate))
        val v = verdict(listOf(file("a", known)), offline = offline) as ShieldVerdict.Warning
        assertEquals(listOf(ShieldWarningReason.DebugOrTestCertificate), v.reasons)
        assertEquals(SecurityTier.Yellow, securityTierOf(v))
        assertEquals("VirusTotal 0/62", v.report?.summary)
        assertEquals(62, v.vtTotal)
    }

    @Test fun offlineYellowStillGetsTheUploadOfferForAnUnknownFile() {
        val offline = cleanOffline.copy(reasons = listOf(ShieldWarningReason.DropperDetected))
        assertTrue(verdict(listOf(file("a", VtLookupResult.UnknownHash)), offline = offline) is ShieldVerdict.NeedsUpload)
        // After the user declines, the same Yellow reasons stay and "not known" joins them.
        val declined = verdict(listOf(file("a", VtLookupResult.UnknownHash)), offline = offline, canUpload = false)
        assertEquals(listOf(ShieldWarningReason.DropperDetected, ShieldWarningReason.NotKnownToVirusTotal), reasonsOf(declined))
    }

    @Test fun offlineRedBlocksAndNeverOffersAnUpload() {
        val offline = cleanOffline.copy(reasons = listOf(ShieldWarningReason.UnsignedPackage))
        val v = verdict(listOf(file("a", VtLookupResult.UnknownHash)), offline = offline) as ShieldVerdict.Warning
        assertTrue(ShieldWarningReason.UnsignedPackage in v.reasons)
        assertEquals(SecurityTier.Red, securityTierOf(v))
        assertTrue(verdict(listOf(file("a", found(3, 60, "Android.Trojan.X"))), offline, hasKey = false, trusted = true) is ShieldVerdict.Warning)
    }

    @Test fun flagsFollowTheOwnersThresholds() {
        // 0 engines: Green.
        assertTrue(verdict(listOf(file("a", known))) is ShieldVerdict.Clean)
        // 1 to 3 light detections: Yellow, the user decides.
        for (n in 1..3) {
            val names = Array(n) { "Android.Riskware.Agent.$it" }
            assertEquals("$n light engines", listOf(ShieldWarningReason.EnginesFlagged), reasonsOf(verdict(listOf(file("a", found(n, 70, *names))))))
        }
        // 4 engines: Red even when every name is light.
        assertEquals(
            listOf(ShieldWarningReason.MalwareDetected),
            reasonsOf(verdict(listOf(file("a", found(4, 70, "Adware.A", "Adware.B", "Riskware.C", "PUA.D"))))),
        )
        // 1 serious name: Red.
        assertEquals(
            listOf(ShieldWarningReason.MalwareDetected),
            reasonsOf(verdict(listOf(file("a", found(1, 70, "Android.Trojan.SMSreg.X"))))),
        )
        // A suspicious verdict counts like a malicious one.
        assertEquals(
            listOf(ShieldWarningReason.EnginesFlagged),
            reasonsOf(verdict(listOf(file("a", found(0, 70, "Android.PUA.Foo", suspicious = 1))))),
        )
    }

    @Test fun countsWithoutNamesAreYellowUpToThreeAndRedFromFour() {
        assertEquals(listOf(ShieldWarningReason.EnginesFlagged), reasonsOf(verdict(listOf(file("a", found(1, 70))))))
        assertEquals(listOf(ShieldWarningReason.EnginesFlagged), reasonsOf(verdict(listOf(file("a", found(3, 70))))))
        assertEquals(listOf(ShieldWarningReason.MalwareDetected), reasonsOf(verdict(listOf(file("a", found(4, 70))))))
    }

    @Test fun twoSourcesCountDistinctEnginesOnly() {
        val vt = found(2, 70, "Adware.A", "Adware.B")
        // The same two engines in MetaDefender: still 2 engines, Yellow.
        val sameEngines = found(2, 38, "Adware.A", "Adware.B")
        assertEquals(listOf(ShieldWarningReason.EnginesFlagged), reasonsOf(verdict(listOf(file("a", vt, sameEngines)))))
        // Two different engines in MetaDefender: 4 distinct engines, Red.
        val otherEngines = VtLookupResult.Found(
            2, 0, 38, now - 86_400L,
            listOf(EngineFlag("EngineX", "Adware.C"), EngineFlag("EngineY", "Adware.D")),
        )
        assertEquals(listOf(ShieldWarningReason.MalwareDetected), reasonsOf(verdict(listOf(file("a", vt, otherEngines)))))
    }

    @Test fun aTrustedUpdateIsCleanWithoutKeyButNeverWhenAnEngineFlagsIt() {
        // Unchanged owner rule: the same signer as the installed app is accepted without an online answer.
        val unknown = verdict(listOf(file("a", VtLookupResult.UnknownHash)), hasKey = false, trusted = true)
        assertTrue(unknown is ShieldVerdict.Clean && unknown.trustedUpdate)
        for (vt in listOf(VtLookupResult.Unavailable, VtLookupResult.RateLimited, VtLookupResult.InvalidKey)) {
            assertTrue(verdict(listOf(file("a", vt)), trusted = true) is ShieldVerdict.Clean)
        }
        val summary = verdict(listOf(file("a", found(0, 5))), trusted = true) as ShieldVerdict.Clean
        assertEquals("VirusTotal 0/5", summary.vtSummary)
        // Flagged: the trust does not help, light or serious.
        assertEquals(listOf(ShieldWarningReason.EnginesFlagged), reasonsOf(verdict(listOf(file("a", found(1, 70, "Riskware.A"))), trusted = true)))
        assertEquals(listOf(ShieldWarningReason.MalwareDetected), reasonsOf(verdict(listOf(file("a", found(1, 70, "Trojan.A"))), trusted = true)))
    }

    @Test fun noKeyIsYellowNeverGreenWhenNotATrustedUpdate() {
        val v = verdict(listOf(file("a", null)), hasKey = false)
        assertEquals(listOf(ShieldWarningReason.VirusTotalKeyMissing), reasonsOf(v))
        assertEquals(SecurityTier.Yellow, securityTierOf(v))
        assertTrue(verdict(listOf(file("a", VtLookupResult.UnknownHash)), hasKey = false) is ShieldVerdict.Warning)
    }

    @Test fun unreachableRateLimitedOrRejectedKeyAreYellowWithTheirOwnReason() {
        // Audit F4: these were Red with no way out, while no key at all was Yellow.
        val expected = mapOf(
            VtLookupResult.Unavailable to ShieldWarningReason.VirusTotalUnreachable,
            VtLookupResult.RateLimited to ShieldWarningReason.OnlineRateLimited,
            VtLookupResult.InvalidKey to ShieldWarningReason.OnlineKeyRejected,
        )
        for ((failure, reason) in expected) {
            val v = verdict(listOf(file("a", known), file("b", failure)))
            assertEquals(listOf(reason), reasonsOf(v))
            assertEquals(SecurityTier.Yellow, securityTierOf(v))
            assertFalse(mayInstall(v, userOverridden = false))
            assertTrue(mayInstall(v, userOverridden = true))
        }
        // The upload is not offered while the service is failing.
        val mixed = verdict(listOf(file("a", VtLookupResult.UnknownHash), file("b", VtLookupResult.Unavailable)))
        assertEquals(listOf(ShieldWarningReason.NotKnownToVirusTotal, ShieldWarningReason.VirusTotalUnreachable), reasonsOf(mixed))
        // Nothing to look at is not proof, but it is not a block either.
        val none = verdict(emptyList())
        assertEquals(listOf(ShieldWarningReason.VirusTotalUnreachable), reasonsOf(none))
        assertEquals(SecurityTier.Yellow, securityTierOf(none))
    }

    @Test fun oneFailingSourceNeverHidesTheOtherOnesAnswer() {
        for (failure in listOf(VtLookupResult.Unavailable, VtLookupResult.RateLimited, VtLookupResult.InvalidKey)) {
            val clean = verdict(listOf(file("a", failure, found(0, 38))))
            assertTrue("MetaDefender answered, $failure", clean is ShieldVerdict.Clean)
            val flagged = verdict(listOf(file("a", failure, found(5, 38))))
            assertEquals(listOf(ShieldWarningReason.MalwareDetected), reasonsOf(flagged))
        }
        // The report says which source failed.
        val v = verdict(listOf(file("a", VtLookupResult.RateLimited, found(0, 38)))) as ShieldVerdict.Clean
        val sources = v.report!!.files.single().sources
        assertEquals(SourceStatus.RateLimited, sources.first { it.source == ShieldSource.VirusTotal }.status)
        assertEquals(SourceStatus.Answered, sources.first { it.source == ShieldSource.MetaDefender }.status)
    }

    @Test fun anUnknownFileIsOnlyUnknownWhenEveryAskedSourceSaidSo() {
        // Audit F5: a rate-limited source plus an "unknown" one is "not checked", not "unknown".
        assertEquals(
            listOf(ShieldWarningReason.OnlineRateLimited),
            reasonsOf(verdict(listOf(file("a", VtLookupResult.RateLimited, VtLookupResult.UnknownHash)))),
        )
        assertEquals(
            listOf(ShieldWarningReason.OnlineKeyRejected),
            reasonsOf(verdict(listOf(file("a", VtLookupResult.InvalidKey, VtLookupResult.UnknownHash)))),
        )
        assertTrue(verdict(listOf(file("a", VtLookupResult.UnknownHash, VtLookupResult.UnknownHash))) is ShieldVerdict.NeedsUpload)
        assertTrue(verdict(listOf(file("a", VtLookupResult.UnknownHash, null))) is ShieldVerdict.NeedsUpload)
    }

    @Test fun fewEnginesAreYellowAndNotBlocking() {
        // Audit F40: MetaDefender may answer with fewer than 20 engines; that must not be a Red block.
        assertEquals(listOf(ShieldWarningReason.TooFewEngines), reasonsOf(verdict(listOf(file("a", found(0, 19))))))
        assertEquals(listOf(ShieldWarningReason.TooFewEngines), reasonsOf(verdict(listOf(file("a", null, found(0, 12))))))
        assertEquals(SecurityTier.Yellow, securityTierOf(verdict(listOf(file("a", found(0, 3))))))
        assertTrue(verdict(listOf(file("a", found(0, MinVtEngines)))) is ShieldVerdict.Clean)
        // Two sources: the bigger engine count is the one that counts.
        assertTrue(verdict(listOf(file("a", found(0, 62), found(0, 12)))) is ShieldVerdict.Clean)
    }

    @Test fun anOldAnalysisIsYellow() {
        // Audit F7: an analysis from years ago says nothing about malware that appeared later.
        fun at(daysAgo: Long) = VtLookupResult.Found(0, 0, 70, now - daysAgo * 86_400L)
        assertTrue(verdict(listOf(file("a", at(29)))) is ShieldVerdict.Clean)
        assertTrue(verdict(listOf(file("a", at(30)))) is ShieldVerdict.Clean)
        assertEquals(listOf(ShieldWarningReason.StaleAnalysis), reasonsOf(verdict(listOf(file("a", at(31))))))
        assertEquals(listOf(ShieldWarningReason.StaleAnalysis), reasonsOf(verdict(listOf(file("a", at(900))))))
        // One fresh dated source is enough; an undated answer does not make an old one fresh.
        assertTrue(verdict(listOf(file("a", at(900), at(2)))) is ShieldVerdict.Clean)
        assertEquals(listOf(ShieldWarningReason.StaleAnalysis), reasonsOf(verdict(listOf(file("a", at(900), VtLookupResult.Found(0, 0, 38))))))
        assertTrue(verdict(listOf(file("a", VtLookupResult.Found(0, 0, 70)))) is ShieldVerdict.Clean)
    }

    @Test fun unknownFilesNeedAnUploadUnlessTooLarge() {
        val v = verdict(listOf(file("a", known), file("b", VtLookupResult.UnknownHash, size = 5_000_000L), file("c", VtLookupResult.UnknownHash)))
        assertTrue(v is ShieldVerdict.NeedsUpload)
        assertEquals(
            listOf(UploadCandidate("b", 5_000_000L, "b".padEnd(64, '0')), UploadCandidate("c", 1_000_000L, "c".padEnd(64, '0'))),
            (v as ShieldVerdict.NeedsUpload).files,
        )
        assertTrue(verdict(listOf(file("a", VtLookupResult.UnknownHash, size = MaxVtUploadBytes))) is ShieldVerdict.NeedsUpload)
        // A file nobody knows and that cannot be uploaded is Yellow (the user decides), not a hard block.
        val tooLarge = reasonsOf(verdict(listOf(file("a", VtLookupResult.UnknownHash, size = MaxVtUploadBytes + 1), file("b", VtLookupResult.UnknownHash))))
        assertEquals(listOf(ShieldWarningReason.NotKnownToVirusTotal), tooLarge)
        assertEquals(SecurityTier.Yellow, securityTierOf(ShieldVerdict.Warning(sha, tooLarge, 0, 0)))
        // No VirusTotal key (only MetaDefender): nothing can be uploaded.
        assertEquals(listOf(ShieldWarningReason.NotKnownToVirusTotal), reasonsOf(verdict(listOf(file("a", null, VtLookupResult.UnknownHash)), canUpload = false)))
    }

    @Test fun allKnownAndCleanIsCleanWithTheSummaryOfEverySource() {
        val single = verdict(listOf(file("a", known))) as ShieldVerdict.Clean
        assertEquals("VirusTotal 0/62", single.vtSummary)
        val both = verdict(listOf(file("a", known, found(0, 38)))) as ShieldVerdict.Clean
        assertEquals("VirusTotal 0/62 \u00b7 MetaDefender 0/38", both.vtSummary)
        val bundle = verdict(listOf(file("a", known), file("b", found(0, 58)), file("c", found(0, 70)))) as ShieldVerdict.Clean
        assertEquals("VirusTotal 0/58 (\u00d73)", bundle.vtSummary)
        assertEquals("a", single.report!!.analysedName)
    }

    @Test fun resourceOnlySplitsAreIgnoredByTheOnlineRules() {
        val files = listOf(
            ShieldFileEvidence("base.apk", 1000L, "a".repeat(64), found(0, 60)),
            ShieldFileEvidence("config.pt.apk", 10L, "b".repeat(64), lookedUp = false),
        )
        assertTrue(verdict(files) is ShieldVerdict.Clean)
    }

    @Test fun afterTheUploadTheSameFunctionDecidesAgain() {
        val before = listOf(file("a", VtLookupResult.UnknownHash))
        assertTrue(verdict(before) is ShieldVerdict.NeedsUpload)
        assertTrue(verdict(listOf(file("a", found(0, 64)))) is ShieldVerdict.Clean)
        assertEquals(listOf(ShieldWarningReason.EnginesFlagged), reasonsOf(verdict(listOf(file("a", found(2, 64, "Adware.A", "Adware.B"))))))
        assertEquals(listOf(ShieldWarningReason.TooFewEngines), reasonsOf(verdict(listOf(file("a", found(0, 8))))))
    }

    @Test fun aLoneSelfUpdaterPermissionIsInformationNotAWarning() {
        // Audit F32: nearly every app with its own updater asks for REQUEST_INSTALL_PACKAGES.
        val offline = cleanOffline.copy(reasons = listOf(ShieldWarningReason.SelfUpdaterPermission))
        assertTrue(verdict(listOf(file("a", known)), offline = offline) is ShieldVerdict.Clean)
        // Together with another finding it is listed.
        val withOther = verdict(listOf(file("a", found(1, 70, "Riskware.A"))), offline = offline)
        assertEquals(listOf(ShieldWarningReason.EnginesFlagged, ShieldWarningReason.SelfUpdaterPermission), reasonsOf(withOther))
        // It does not stop an update of the installed app from being trusted (audit F25, second half).
        val installed = InstalledAppInfo(versionCode = 10L, sigSha256 = "aa".repeat(32))
        assertTrue(isTrustedUpdate(offline, installed))
    }

    @Test fun reasonsAreOrderedByGravity() {
        // Audit F13: the most serious reason leads.
        val offline = cleanOffline.copy(reasons = listOf(ShieldWarningReason.SelfUpdaterPermission, ShieldWarningReason.AdwareDetected))
        val v = verdict(listOf(file("a", found(0, 62, suspicious = 0))), offline = offline)
        assertEquals(listOf(ShieldWarningReason.AdwareDetected, ShieldWarningReason.SelfUpdaterPermission), reasonsOf(v))
    }

    @Test fun trustedUpdateNeedsSameSignerNotOlderVersionAndCleanOfflineReport() {
        val signer = "aa".repeat(32)
        val installed = InstalledAppInfo(versionCode = 10L, sigSha256 = signer)
        assertTrue(isTrustedUpdate(cleanOffline, installed))
        assertTrue(isTrustedUpdate(cleanOffline.copy(versionCode = 11L), installed))
        assertTrue(isTrustedUpdate(cleanOffline.copy(signerSha256 = signer.uppercase()), installed.copy(sigSha256 = signer.chunked(2).joinToString(":"))))
        assertFalse(isTrustedUpdate(cleanOffline.copy(versionCode = 9L), installed))
        assertFalse(isTrustedUpdate(cleanOffline.copy(signerSha256 = "bb".repeat(32)), installed))
        assertFalse(isTrustedUpdate(cleanOffline.copy(reasons = listOf(ShieldWarningReason.UnsignedPackage)), installed))
        assertFalse(isTrustedUpdate(cleanOffline, null))
        assertFalse(isTrustedUpdate(cleanOffline, installed.copy(sigSha256 = null)))
        assertFalse(isTrustedUpdate(cleanOffline, installed.copy(versionCode = null)))
        assertFalse(isTrustedUpdate(cleanOffline.copy(signerSha256 = null), installed))
        assertFalse(isTrustedUpdate(cleanOffline.copy(versionCode = null), installed))
    }

    // ---- VirusTotal analysis, upload parsing and pacer ----

    @Test fun parseVirusTotalAnalysisHandlesCompletedQueuedRateLimitAndGarbage() {
        val completed = """
            {"data":{"attributes":{"date":1,"results":{"E1":{"category":"undetected","result":null}},
            "stats":{"malicious":1,"suspicious":0,"undetected":60,"harmless":2,"timeout":0,"type-unsupported":4},
            "status":"completed"},"id":"abc==","type":"analysis"}}
        """.trimIndent()
        assertEquals(VtAnalysisPoll.Done(VtLookupResult.Found(1, 0, 63, lastAnalysisDate = 1L)), parseVirusTotalAnalysis(200, completed))
        assertEquals(VtAnalysisPoll.Pending, parseVirusTotalAnalysis(200, """{"data":{"attributes":{"stats":{},"status":"queued"}}}"""))
        assertEquals(VtAnalysisPoll.Pending, parseVirusTotalAnalysis(200, """{"data":{"attributes":{"status":"in-progress"}}}"""))
        assertEquals(VtAnalysisPoll.RateLimited, parseVirusTotalAnalysis(429, """{"error":{"code":"QuotaExceededError"}}"""))
        assertEquals(VtAnalysisPoll.InvalidKey, parseVirusTotalAnalysis(401, ""))
        assertEquals(VtAnalysisPoll.InvalidKey, parseVirusTotalAnalysis(403, ""))
        assertEquals(VtAnalysisPoll.Failed, parseVirusTotalAnalysis(500, "oops"))
        assertEquals(VtAnalysisPoll.Failed, parseVirusTotalAnalysis(200, "not json at all"))
        assertEquals(VtAnalysisPoll.Failed, parseVirusTotalAnalysis(200, """{"data":{"attributes":{"status":"completed"}}}"""))
    }

    @Test fun parseVirusTotalUploadResponseAndUrl() {
        assertEquals(
            VtUploadResult.Started("MzEyYQ=="),
            parseVirusTotalUploadResponse(200, """{"data":{"type":"analysis","id":"MzEyYQ=="}}"""),
        )
        assertEquals(VtUploadResult.InvalidKey, parseVirusTotalUploadResponse(401, ""))
        assertEquals(VtUploadResult.RateLimited, parseVirusTotalUploadResponse(429, ""))
        assertEquals(VtUploadResult.Failed, parseVirusTotalUploadResponse(413, ""))
        assertEquals(VtUploadResult.Failed, parseVirusTotalUploadResponse(200, "{}"))

        assertEquals("https://www.virustotal.com/_ah/upload/x", parseVirusTotalUploadUrl("""{"data":"https://www.virustotal.com/_ah/upload/x"}"""))
        assertEquals("https://www.virustotal.com/_ah/upload/x", parseVirusTotalUploadUrl("""{"data":"http://www.virustotal.com/_ah/upload/x"}"""))
        assertEquals("https://www.virustotal.com/a/b", parseVirusTotalUploadUrl("""{"data":"https:\/\/www.virustotal.com\/a\/b"}"""))
        assertNull(parseVirusTotalUploadUrl("""{"data":"ftp://example.com/x"}"""))
        assertNull(parseVirusTotalUploadUrl("{}"))
    }

    @Test fun requestPacerAllowsFourPerMinuteWithAFakeClock() {
        var now = 1_000L
        val pacer = RequestPacer(maxRequests = 4, windowMs = 60_000L, clock = { now })
        repeat(4) { assertEquals(0L, pacer.reserve()) }
        // The fifth waits until the first request leaves the window.
        assertEquals(60_000L, pacer.reserve())
        // The sixth is booked behind the second one (same instant), and so on.
        assertEquals(60_000L, pacer.reserve())
        now += 30_000L
        // Booked slots: 1_000 x2 and 61_000 x2; the next one is free once the oldest leaves the window, at 61_000.
        assertEquals(30_000L, pacer.reserve())
        now += 200_000L
        assertEquals(0L, pacer.reserve())
        assertEquals(0L, pacer.reserve())
    }

    @Test fun formatUploadSizeUsesOneDecimalOfBinaryMegabytes() {
        assertEquals("12.3 MB", formatUploadSize((12.3 * 1024 * 1024).toLong() + 1000))
        assertEquals("0.0 MB", formatUploadSize(0L))
        assertEquals("650.0 MB", formatUploadSize(MaxVtUploadBytes))
    }

    // ---- Dumpsys parser & AES-GCM key encryption ----

    @Test fun parseDumpsysExtractsVersionCodeAndCertSha256() {
        val sample = """
            Packages:
              Package [com.example.app] (123456):
                versionCode=42 minSdk=30 targetSdk=35
                cert-sha256=a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc
        """.trimIndent()
        val info = parseDumpsysInstalledApp(sample)
        assertEquals(42L, info.versionCode)
        assertEquals("a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc", info.sigSha256)
        assertNull(parseDumpsysInstalledApp("Unable to find package: com.missing").versionCode)
    }

    @Test fun aesGcmEncryptsAndDecryptsVirusTotalApiKeyWithoutLeakingPlaintext() {
        val secretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val rawApiKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val encrypted = encryptApiKeyWithSecretKey(rawApiKey, secretKey)
        assertNotEquals(rawApiKey, encrypted)
        assertFalse(encrypted.contains(rawApiKey))
        assertEquals(rawApiKey, decryptApiKeyWithSecretKey(encrypted, secretKey))
    }

    @Test fun shieldStatusKindDistinguishesTrustedUpdateFromVirusTotalProof() {
        assertEquals(ShieldStatusKind.VerifiedWithVt, shieldStatusKind(ShieldVerdict.Clean(sha, "0/72")))
        assertEquals(ShieldStatusKind.TrustedUpdate, shieldStatusKind(ShieldVerdict.Clean(sha, null, trustedUpdate = true)))
        assertEquals(ShieldStatusKind.TrustedUpdate, shieldStatusKind(ShieldVerdict.Clean(sha, "0/72", trustedUpdate = true)))
    }

    @Test fun scanManifestPermissionsReturnsSortedShortNames() {
        val bytes = "android.permission.SEND_SMS\u0000android.permission.INTERNET".toByteArray(Charsets.UTF_8)
        assertEquals(listOf("INTERNET", "SEND_SMS"), scanManifestPermissions(bytes))
    }

    // ---- 3-Color Security Tiers (Green / Yellow / Red) ----

    @Test fun securitySeverityCategorizesRedVsYellowReasons() {
        // Yellow (Caution / Mod Risk / User Decision): a missing proof is never Red.
        val yellowReasons = listOf(
            ShieldWarningReason.DropperDetected,
            ShieldWarningReason.DebugOrTestCertificate,
            ShieldWarningReason.NotKnownToVirusTotal,
            ShieldWarningReason.VirusTotalKeyMissing,
            ShieldWarningReason.EnginesFlagged,
            ShieldWarningReason.VirusTotalUnreachable,
            ShieldWarningReason.OnlineRateLimited,
            ShieldWarningReason.OnlineKeyRejected,
            ShieldWarningReason.TooFewEngines,
            ShieldWarningReason.StaleAnalysis,
            ShieldWarningReason.ScanIncomplete,
            ShieldWarningReason.InvalidNativeLibrary,
            ShieldWarningReason.RiskyPermissionCombo,
            ShieldWarningReason.SuspiciousNativeCode,
            ShieldWarningReason.SelfUpdaterPermission,
        )
        for (reason in yellowReasons) {
            assertEquals("Expected $reason to have Yellow severity", SecuritySeverity.Yellow, reason.severity())
        }

        // Red (Critical / Hard Block): proof of harm or of a forged package.
        val redReasons = listOf(
            ShieldWarningReason.MalwareDetected,
            ShieldWarningReason.AdwareDetected,
            ShieldWarningReason.SignatureMismatch,
            ShieldWarningReason.AbusivePermissions,
            ShieldWarningReason.UnsignedPackage,
            ShieldWarningReason.PackageMismatch,
            ShieldWarningReason.VersionDowngrade,
            ShieldWarningReason.CompromisedKey,
            ShieldWarningReason.LegacySignatureOnly,
            ShieldWarningReason.MalformedArchive,
        )
        for (reason in redReasons) {
            assertEquals("Expected $reason to have Red severity", SecuritySeverity.Red, reason.severity())
        }
        // Every reason is in exactly one of the two lists.
        assertEquals(ShieldWarningReason.entries.toSet(), (yellowReasons + redReasons).toSet())
    }

    @Test fun securityTierEvaluatesVerdictColor() {
        val clean = ShieldVerdict.Clean(sha, "0/70")
        assertEquals(SecurityTier.Green, securityTierOf(clean))

        val trusted = ShieldVerdict.Clean(sha, null, trustedUpdate = true)
        assertEquals(SecurityTier.Green, securityTierOf(trusted))

        val dropperOnly = ShieldVerdict.Warning(sha, listOf(ShieldWarningReason.DropperDetected), 0, 70)
        assertEquals(SecurityTier.Yellow, securityTierOf(dropperOnly))

        val testKeyOnly = ShieldVerdict.Warning(sha, listOf(ShieldWarningReason.DebugOrTestCertificate), 0, 0)
        assertEquals(SecurityTier.Yellow, securityTierOf(testKeyOnly))

        val multipleYellow = ShieldVerdict.Warning(
            sha,
            listOf(ShieldWarningReason.DropperDetected, ShieldWarningReason.DebugOrTestCertificate),
            0,
            60,
        )
        assertEquals(SecurityTier.Yellow, securityTierOf(multipleYellow))

        // Any Red reason makes the overall verdict Red
        val malware = ShieldVerdict.Warning(sha, listOf(ShieldWarningReason.MalwareDetected), 5, 70)
        assertEquals(SecurityTier.Red, securityTierOf(malware))

        val mixedRedAndYellow = ShieldVerdict.Warning(
            sha,
            listOf(ShieldWarningReason.DropperDetected, ShieldWarningReason.MalwareDetected),
            5,
            70,
        )
        assertEquals(SecurityTier.Red, securityTierOf(mixedRedAndYellow))

        val adwareAndDropper = ShieldVerdict.Warning(
            sha,
            listOf(ShieldWarningReason.DropperDetected, ShieldWarningReason.AdwareDetected),
            0,
            70,
        )
        assertEquals(SecurityTier.Red, securityTierOf(adwareAndDropper))
    }

    @Test fun mayInstallEnforces3ColorTierGate() {
        val clean = ShieldVerdict.Clean(sha, "0/70")
        val yellow = ShieldVerdict.Warning(sha, listOf(ShieldWarningReason.DropperDetected), 0, 70)
        val red = ShieldVerdict.Warning(sha, listOf(ShieldWarningReason.MalwareDetected), 3, 70)
        val mixed = ShieldVerdict.Warning(sha, listOf(ShieldWarningReason.DropperDetected, ShieldWarningReason.SignatureMismatch), 0, 0)

        // Null verdict (shield off) is allowed
        assertTrue(mayInstall(null, userOverridden = false))
        assertTrue(mayInstall(null, userOverridden = true))

        // Green is always allowed
        assertTrue(mayInstall(clean, userOverridden = false))
        assertTrue(mayInstall(clean, userOverridden = true))

        // Yellow without override is blocked
        assertFalse(mayInstall(yellow, userOverridden = false))
        // Yellow with override is permitted
        assertTrue(mayInstall(yellow, userOverridden = true))

        // Red without override is blocked
        assertFalse(mayInstall(red, userOverridden = false))
        // Red with override is STILL BLOCKED (Protected fail-closed!)
        assertFalse(mayInstall(red, userOverridden = true))

        // Mixed Red+Yellow is STILL BLOCKED even with override
        assertFalse(mayInstall(mixed, userOverridden = true))
    }
}
