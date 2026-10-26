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
            VtLookupResult.Found(malicious = 0, suspicious = 0, total = 66),
            parseVirusTotalResponse(200, cleanJson),
        )

        val maliciousJson = """
            {
              "data": {
                "attributes": {
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
            VtLookupResult.Found(malicious = 14, suspicious = 2, total = 66),
            parseVirusTotalResponse(200, maliciousJson),
        )

        assertEquals(VtLookupResult.UnknownHash, parseVirusTotalResponse(404, """{"error":{"code":"NotFoundError"}}"""))
        assertEquals(VtLookupResult.InvalidKey, parseVirusTotalResponse(401, """{"error":{"code":"WrongCredentialsError"}}"""))
        assertEquals(VtLookupResult.InvalidKey, parseVirusTotalResponse(403, """{"error":{"code":"ForbiddenError"}}"""))
        assertEquals(VtLookupResult.RateLimited, parseVirusTotalResponse(429, """{"error":{"code":"QuotaExceededError"}}"""))
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(503, ""))
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(200, """{"unexpected":"payload"}"""))
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

    @Test fun evaluateShieldVerdictReturnsCleanOrWarningCorrectly() {
        val sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        val cleanOffline = OfflineScanReport(
            signed = true,
            debugOrTestSigned = false,
            signerSha256 = "aaaa",
            versionCode = 10L,
            highRiskPermissions = emptySet(),
            versionDowngrade = false,
            signatureMismatch = false,
            reasons = emptyList(),
        )

        // Clean offline + Clean VT (0 malicious) -> Clean
        val verdictClean = evaluateShieldVerdict(
            sha256 = sha,
            offline = cleanOffline,
            vt = VtLookupResult.Found(malicious = 0, suspicious = 0, total = 68),
        )
        assertEquals(ShieldVerdict.Clean(sha, "0/68", cleanOffline), verdictClean)

        // Clean offline + Unknown hash with Deep Scan enabled -> Clean (with deep scan note)
        val verdictUnknownDeep = evaluateShieldVerdict(
            sha256 = sha,
            offline = cleanOffline,
            vt = VtLookupResult.UnknownHash,
            deepScanEnabled = true,
            fileSizeBytes = 5_000_000L,
        )
        assertEquals(ShieldVerdict.Clean(sha, "unknown (deep scan eligible)", cleanOffline), verdictUnknownDeep)

        // Clean offline + VT Malware detected -> Warning(MalwareDetected)
        val verdictMalware = evaluateShieldVerdict(
            sha256 = sha,
            offline = cleanOffline,
            vt = VtLookupResult.Found(malicious = 5, suspicious = 1, total = 70),
        )
        assertEquals(
            ShieldVerdict.Warning(
                sha256 = sha,
                reasons = listOf(ShieldWarningReason.MalwareDetected),
                vtMalicious = 6,
                vtTotal = 70,
                offline = cleanOffline,
            ),
            verdictMalware,
        )

        // Unsigned offline + Unavailable VT -> Warning(UnsignedPackage)
        val unsignedOffline = cleanOffline.copy(
            signed = false,
            reasons = listOf(ShieldWarningReason.UnsignedPackage),
        )
        val verdictUnsigned = evaluateShieldVerdict(
            sha256 = sha,
            offline = unsignedOffline,
            vt = VtLookupResult.Unavailable,
        )
        assertEquals(
            ShieldVerdict.Warning(
                sha256 = sha,
                reasons = listOf(ShieldWarningReason.UnsignedPackage),
                vtMalicious = 0,
                vtTotal = 0,
                offline = unsignedOffline,
            ),
            verdictUnsigned,
        )
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

    @Test fun shieldStatusKindMapsVirusTotalSummary() {
        assertEquals(ShieldStatusKind.OfflineNoKey, shieldStatusKind(null))
        assertEquals(ShieldStatusKind.VerifiedWithVt, shieldStatusKind("0/72"))
        assertEquals(ShieldStatusKind.OfflineVtIssue, shieldStatusKind("unknown"))
        assertEquals(ShieldStatusKind.OfflineVtIssue, shieldStatusKind("invalid key"))
    }

    @Test fun scanManifestPermissionsReturnsSortedShortNames() {
        val bytes = "android.permission.SEND_SMS\u0000android.permission.INTERNET".toByteArray(Charsets.UTF_8)
        assertEquals(listOf("INTERNET", "SEND_SMS"), scanManifestPermissions(bytes))
    }
}
