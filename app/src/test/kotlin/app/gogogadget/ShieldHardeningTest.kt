package app.gogogadget

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Tests for the 0.9.1 hardening: install gate, shield-off note, re-hash before streaming, signer facts, VirusTotal hosts, stale prompts. */
class ShieldHardeningTest {
    private val sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    private val offline = OfflineScanReport(
        signed = true,
        debugOrTestSigned = false,
        signerSha256 = "aa".repeat(32),
        versionCode = 1L,
        highRiskPermissions = emptySet(),
        versionDowngrade = false,
        signatureMismatch = false,
        reasons = emptyList(),
    )

    // ---- B. Gate ----

    @Test fun gateAllowsOnlyCleanOrOff() {
        assertTrue(mayInstall(null))
        assertTrue(mayInstall(ShieldVerdict.Clean(sha, "0/70")))
        assertTrue(mayInstall(ShieldVerdict.Clean(sha, null, trustedUpdate = true)))
        assertFalse(mayInstall(ShieldVerdict.Warning(sha, listOf(ShieldWarningReason.MalwareDetected), 3, 70)))
        assertFalse(mayInstall(ShieldVerdict.NeedsUpload(sha, listOf(UploadCandidate("a.apk", 10L, sha)))))
        // ShieldVerdict is sealed, so a test cannot add a subtype; mayInstall allows `is Clean` only, so any future one stops.
    }

    // ---- C. Shield off ----

    @Test fun shieldOffIsShownInResult() {
        assertTrue(shieldOffNote(InstallStatus(working = false, ok = true, shieldOff = true)))
        assertTrue(shieldOffNote(InstallStatus(working = false, ok = false, shieldOff = true)))
        assertFalse(shieldOffNote(InstallStatus(working = false, ok = true)))
        assertFalse(shieldOffNote(InstallStatus(working = false, ok = true, shieldOff = true, shieldVerdict = ShieldVerdict.Clean(sha, "0/70"))))
    }

    // ---- F. Re-hash before streaming ----

    private fun scan(file: File) = ScannedFile(file, file.length(), sha256Hex(file))

    @Test fun singleApkChangedAfterScanIsRejected() {
        val dir = Files.createTempDirectory("toctou_single_").toFile()
        try {
            val apk = File(dir, "source.pkg").apply { writeBytes(ByteArray(1000) { 1 }) }
            val scanned = listOf(scan(apk))
            assertTrue(filesUnchangedSinceScan(scanned, listOf(apk)))
            // Same size, other content.
            apk.writeBytes(ByteArray(1000) { 2 })
            assertFalse(filesUnchangedSinceScan(scanned, listOf(apk)))
            // Other size.
            apk.writeBytes(ByteArray(1001) { 1 })
            assertFalse(filesUnchangedSinceScan(scanned, listOf(apk)))
            // Gone.
            apk.delete()
            assertFalse(filesUnchangedSinceScan(scanned, listOf(apk)))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun splitFileChangedAfterScanIsRejected() {
        val dir = Files.createTempDirectory("toctou_split_").toFile()
        try {
            val base = File(dir, "base.apk").apply { writeBytes(ByteArray(500) { 3 }) }
            val split = File(dir, "split_config.arm64_v8a.apk").apply { writeBytes(ByteArray(300) { 4 }) }
            val scanned = listOf(scan(base), scan(split))
            assertTrue(filesUnchangedSinceScan(scanned, listOf(base, split)))
            split.writeBytes(ByteArray(300) { 5 })
            assertFalse(filesUnchangedSinceScan(scanned, listOf(base, split)))
            // The untouched base alone is still fine; a file that was never scanned is not.
            assertTrue(filesUnchangedSinceScan(scanned, listOf(base)))
            val extra = File(dir, "extra.apk").apply { writeBytes(ByteArray(10)) }
            assertFalse(filesUnchangedSinceScan(scanned, listOf(base, extra)))
            assertFalse(filesUnchangedSinceScan(scanned, listOf(null)))
        } finally {
            dir.deleteRecursively()
        }
    }

    // ---- H. VirusTotal host, redirects, stale prompt ----

    @Test fun uploadUrlOffVirusTotalHostRejected() {
        for (ok in listOf("https://www.virustotal.com/_ah/upload/x", "https://virustotal.com/x", "https://upload.VirusTotal.com/a")) {
            assertTrue(ok, isAllowedVirusTotalHost(ok))
        }
        val bad = listOf(
            "https://evil.com/x",
            "https://virustotal.com.evil.com/x",
            "https://notvirustotal.com/x",
            "http://www.virustotal.com/x",
            "https://www.virustotal.com@evil.com/",
            "https://evil.com@www.virustotal.com/",
            "https://www.virustotal.com:8443/x",
            "ftp://www.virustotal.com/x",
            "https://evil.com\\@www.virustotal.com/",
            "//www.virustotal.com/x",
            "",
        )
        for (url in bad) assertFalse(url, isAllowedVirusTotalHost(url))
        // The http -> https rewrite happens first, then the host is checked.
        assertEquals("https://www.virustotal.com/a", parseVirusTotalUploadUrl("""{"data":"http://www.virustotal.com/a"}"""))
        assertNull(parseVirusTotalUploadUrl("""{"data":"http://evil.com/a"}"""))
        assertNull(parseVirusTotalUploadUrl("""{"data":"https://virustotal.com.evil.com/a"}"""))
        assertNull(parseVirusTotalUploadUrl("""{"data":"https://www.virustotal.com@evil.com/"}"""))
        // A redirect status is never a good answer.
        assertEquals(VtLookupResult.Unavailable, parseVirusTotalResponse(302, "", sha))
        assertEquals(VtAnalysisPoll.Failed, parseVirusTotalAnalysis(301, ""))
        assertEquals(VtUploadResult.Failed, parseVirusTotalUploadResponse(307, ""))
    }

    @Test fun confirmUploadFromStalePromptIgnored() {
        val gate = UploadGate()
        val first = gate.open()
        val second = gate.open()
        // Opening a new question counts the old one as "no".
        assertTrue(first.second.isCompleted)
        assertFalse(runBlocking { first.second.await() })
        assertTrue(first.first != second.first)
        // A late "yes" for the old prompt does nothing to the new one.
        gate.answer(first.first, true)
        assertFalse(second.second.isCompleted)
        gate.answer(second.first, true)
        assertTrue(runBlocking { second.second.await() })
        // Once it is closed, nothing can answer it again.
        val third = gate.open()
        gate.close(third)
        gate.answer(third.first, true)
        assertFalse(third.second.isCompleted)
    }

    // ---- G. Signer facts ----

    private fun cert(dn: String) = generateAdbIdentity(dn).certificate.encoded

    private fun info(der: ByteArray) = parseCertificateBytes(der)!!

    @Test fun secondSignerTestKeyFlagged() {
        val release = cert("CN=Release Publisher")
        val debug = cert("CN=Android Debug,O=Android,C=US")
        assertFalse(anyCertDebugOrTest(listOf(release)))
        assertTrue(anyCertDebugOrTest(listOf(release, debug)))
        assertTrue(anyCertDebugOrTest(listOf(debug, release)))
        assertTrue(mergeSignerFacts(listOf(info(release)), listOf(info(release), info(debug))).debugOrTest)
        assertTrue(mergeSignerFacts(listOf(info(release), info(debug)), emptyList()).debugOrTest)
    }

    @Test fun v1CertDoesNotOverrideV2Signer() {
        val v1 = info(cert("CN=V1 Signer"))
        val v2 = info(cert("CN=V2 Signer"))
        val facts = mergeSignerFacts(listOf(v1), listOf(v2))
        assertEquals(v2.sha256, facts.signerSha256)
        assertEquals(v2.subject, facts.certSubject)
        assertEquals(v1.sha256, mergeSignerFacts(listOf(v1), emptyList()).signerSha256)
        assertNull(mergeSignerFacts(emptyList(), emptyList()).signerSha256)
    }

    private fun le(value: Int): ByteArray = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()
    private fun le(value: Long): ByteArray = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array()
    private fun prefixed(bytes: ByteArray): ByteArray = le(bytes.size) + bytes

    /** Inserts an APK Signing Block with one v2 signer holding [certs] between the entries and the central directory. */
    private fun withV2Block(apk: ByteArray, certs: List<ByteArray>): ByteArray {
        val certSequence = certs.fold(ByteArray(0)) { acc, c -> acc + prefixed(c) }
        val signedData = prefixed(ByteArray(0)) + prefixed(certSequence)
        val value = prefixed(prefixed(prefixed(signedData)))
        val pair = le(4L + value.size) + le(0x7109871a) + value
        val sizeOfBlock = pair.size + 24L
        val block = le(sizeOfBlock) + pair + le(sizeOfBlock) + "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
        val eocd = apk.size - 22
        val cdOffset = ByteBuffer.wrap(apk, eocd + 16, 4).order(ByteOrder.LITTLE_ENDIAN).int
        val out = apk.copyOfRange(0, cdOffset) + block + apk.copyOfRange(cdOffset, apk.size)
        ByteBuffer.wrap(out, out.size - 22 + 16, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(cdOffset + block.size)
        return out
    }

    private fun apkZip(vararg extra: Pair<String, ByteArray>): ByteArray {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            for ((name, data) in listOf("AndroidManifest.xml" to """<manifest versionCode="3"/>""".toByteArray()) + extra) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(data)
                zos.closeEntry()
            }
        }
        return baos.toByteArray()
    }

    private fun analyze(bytes: ByteArray): OfflineScanReport {
        val dir = Files.createTempDirectory("shield_sig_").toFile()
        try {
            val file = File(dir, "app.apk").apply { writeBytes(bytes) }
            val bundle = (inspectAndExtractPackage(file, dir) as PackageInspectResult.Valid).bundle
            return analyzePackageOffline(file, bundle)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun unreadableCertificateDoesNotCountAsSigned() {
        // A v2 block that is present but holds no readable certificate used to count as signed.
        val unreadable = analyze(withV2Block(apkZip(), listOf("not a certificate".toByteArray())))
        assertFalse(unreadable.signed)
        assertNull(unreadable.signerSha256)
        assertTrue(ShieldWarningReason.UnsignedPackage in unreadable.reasons)

        val release = cert("CN=Release Publisher")
        val readable = analyze(withV2Block(apkZip(), listOf(release)))
        assertTrue(readable.signed)
        assertEquals(info(release).sha256, readable.signerSha256)
        assertTrue(readable.reasons.isEmpty())
    }

    @Test fun v2BlockWithTestKeyAsSecondCertIsFlaggedAndV2WinsOverV1() {
        val v1 = cert("CN=V1 Signer")
        val release = cert("CN=Release Publisher")
        val debug = cert("CN=Android Debug,O=Android,C=US")
        val report = analyze(withV2Block(apkZip("META-INF/CERT.RSA" to v1), listOf(release, debug)))
        assertEquals(info(release).sha256, report.signerSha256)
        assertTrue(report.debugOrTestSigned)
        assertNotNull(report.certSubject)
        assertTrue(ShieldWarningReason.DebugOrTestCertificate in report.reasons)
    }
}
