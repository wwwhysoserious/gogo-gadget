package app.gogogadget

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.crypto.KeyGenerator

/** 0.9.50: manifest permissions, Play Protect settings, backup hashes, key storage, installed-version failures, texts. */
class Shield0950Test {
    private val sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    // ---- A compiled (binary) manifest, built the way aapt writes it ----

    /** An attribute of a test element: a string value, or a number when [number] is set. */
    private data class Attr(val name: String, val text: String? = null, val number: Int? = null)

    private fun axml(utf8: Boolean, elements: List<Pair<String, List<Attr>>>): ByteArray {
        // Attribute names with a resource id come first, like in a real manifest: name, versionCode, permission.
        val resIds = intArrayOf(0x01010003, 0x0101021b, 0x01010006)
        val strings = arrayListOf("name", "versionCode", "permission")
        fun index(value: String): Int {
            var i = strings.indexOf(value)
            if (i < 0) {
                strings += value
                i = strings.size - 1
            }
            return i
        }
        for ((element, attrs) in elements) {
            index(element)
            for (attr in attrs) {
                index(attr.name)
                attr.text?.let { index(it) }
            }
        }
        // String pool.
        val pool = ByteArrayOutputStream()
        val offsets = IntArray(strings.size)
        for ((i, value) in strings.withIndex()) {
            offsets[i] = pool.size()
            if (utf8) {
                val bytes = value.toByteArray(Charsets.UTF_8)
                pool.write(value.length)
                pool.write(bytes.size)
                pool.write(bytes)
                pool.write(0)
            } else {
                pool.write(value.length and 0xFF)
                pool.write((value.length shr 8) and 0xFF)
                pool.write(value.toByteArray(Charsets.UTF_16LE))
                pool.write(0)
                pool.write(0)
            }
        }
        while (pool.size() % 4 != 0) pool.write(0)
        val poolHeader = 28
        val stringsStart = poolHeader + strings.size * 4
        val poolSize = stringsStart + pool.size()
        val resSize = 8 + resIds.size * 4
        val elementBytes = elements.map { (element, attrs) ->
            val size = 16 + 20 + attrs.size * 20
            val buf = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
            buf.putShort(0x0102.toShort()); buf.putShort(16); buf.putInt(size)
            buf.putInt(1); buf.putInt(-1)
            buf.putInt(-1); buf.putInt(index(element))
            buf.putShort(20); buf.putShort(20); buf.putShort(attrs.size.toShort())
            buf.putShort(0); buf.putShort(0); buf.putShort(0)
            for (attr in attrs) {
                buf.putInt(-1)
                buf.putInt(index(attr.name))
                buf.putInt(if (attr.text != null) index(attr.text) else -1)
                buf.putShort(8)
                buf.put(0)
                buf.put((if (attr.text != null) 0x03 else 0x10).toByte())
                buf.putInt(if (attr.text != null) index(attr.text) else (attr.number ?: 0))
            }
            buf.array()
        }
        val total = 8 + poolSize + resSize + elementBytes.sumOf { it.size }
        val out = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
        out.putShort(0x0003); out.putShort(8); out.putInt(total)
        out.putShort(0x0001); out.putShort(poolHeader.toShort()); out.putInt(poolSize)
        out.putInt(strings.size); out.putInt(0); out.putInt(if (utf8) 0x100 else 0); out.putInt(stringsStart); out.putInt(0)
        for (offset in offsets) out.putInt(offset)
        out.put(pool.toByteArray())
        out.putShort(0x0180.toShort()); out.putShort(8); out.putInt(resSize)
        for (id in resIds) out.putInt(id)
        for (bytes in elementBytes) out.put(bytes)
        return out.array()
    }

    private fun manifest(vararg children: Pair<String, List<Attr>>, versionCode: Int = 42): List<Pair<String, List<Attr>>> =
        listOf("manifest" to listOf(Attr("versionCode", number = versionCode))) + children.toList()

    private fun permission(name: String) = "uses-permission" to listOf(Attr("name", name))
    private fun guardedService(permission: String) = "service" to listOf(Attr("name", "com.example.Svc"), Attr("permission", permission))

    // ---- Permissions are the declared ones, not every string (audit F15, F34) ----

    @Test fun onlyUsesPermissionElementsAreRequestedPermissions() {
        val elements = manifest(
            permission("android.permission.INTERNET"),
            permission("com.example.permission.READ_SMS"),
            permission("android.permission.SEND_SMS"),
            guardedService("android.permission.BIND_JOB_SERVICE"),
            guardedService("android.permission.READ_SMS"),
        )
        for (utf8 in listOf(false, true)) {
            val bytes = axml(utf8, elements)
            // The platform SMS permission is requested; the custom READ_SMS of another namespace is not the same permission.
            assertEquals(
                "utf8=$utf8",
                listOf("INTERNET", "SEND_SMS", "com.example.permission.READ_SMS"),
                declaredManifestPermissions(bytes),
            )
        }
    }

    @Test fun aServiceGuardIsNotARequestedPermission() {
        val bytes = axml(
            false,
            manifest(permission("android.permission.INTERNET"), guardedService("android.permission.SEND_SMS"), guardedService("android.permission.BIND_QUICK_SETTINGS_TILE")),
        )
        assertEquals(listOf("INTERNET"), declaredManifestPermissions(bytes))
        // The old string scan could not tell the difference, which is the false positive of the audit.
        assertTrue("SEND_SMS" in scanManifestPermissions(bytes))
        assertEquals(setOf("SEND_SMS", "BIND_QUICK_SETTINGS_TILE"), declaredServiceGuards(bytes))
    }

    @Test fun anAccessibilityServiceIsACapabilityOfTheApp() {
        val bytes = axml(true, manifest(permission("android.permission.INTERNET"), guardedService("android.permission.BIND_ACCESSIBILITY_SERVICE")))
        assertTrue("BIND_ACCESSIBILITY_SERVICE" in declaredServiceGuards(bytes).orEmpty())
        assertEquals(listOf("INTERNET"), declaredManifestPermissions(bytes))
    }

    @Test fun aPlainXmlManifestAndOtherBytesAreHandled() {
        val xml = """<manifest xmlns:android="x"><uses-permission android:name="android.permission.CAMERA"/>
            <uses-permission-sdk-23 android:name="android.permission.READ_SMS"/>
            <uses-permission android:name='com.x.permission.Y'/>
            <service android:permission="android.permission.SEND_SMS"/></manifest>""".toByteArray()
        assertEquals(listOf("CAMERA", "READ_SMS", "com.x.permission.Y"), declaredManifestPermissions(xml))
        // Neither binary nor XML: the caller falls back to the string scan.
        assertNull(declaredManifestPermissions("versionCode=\"25\" android.permission.READ_SMS".toByteArray()))
        assertNull(declaredManifestPermissions(ByteArray(0)))
        assertNull(declaredManifestPermissions(ByteArray(64) { 0x55 }))
        assertNull(parseAxmlElements(ByteArray(4)))
    }

    @Test fun theVersionCodeIsReadFromTheBinaryManifest() {
        for (utf8 in listOf(false, true)) {
            assertEquals(42L, axmlVersionCode(axml(utf8, manifest())))
            assertEquals(42L, extractManifestVersionCode(axml(utf8, manifest())))
        }
        assertEquals(2_000_000_000L, extractManifestVersionCode(axml(false, manifest(versionCode = 2_000_000_000))))
        assertNull(axmlVersionCode(axml(false, listOf("application" to emptyList()))))
        // Plain text still works.
        assertEquals(10L, extractManifestVersionCode("""<manifest android:versionCode="10"/>""".toByteArray()))
    }

    @Test fun aTruncatedBinaryManifestDoesNotCrash() {
        val bytes = axml(false, manifest(permission("android.permission.INTERNET")))
        for (cut in listOf(10, 40, bytes.size - 5)) {
            // Whatever comes back, it must not throw.
            declaredManifestPermissions(bytes.copyOf(cut))
            extractManifestVersionCode(bytes.copyOf(cut))
        }
    }

    @Test fun theOfflineReportUsesTheDeclaredPermissionsAndTheAccessibilityCapability() {
        val dir = Files.createTempDirectory("shield0950_").toFile()
        try {
            val manifestBytes = axml(
                false,
                manifest(
                    permission("android.permission.INTERNET"),
                    permission("android.permission.REQUEST_INSTALL_PACKAGES"),
                    guardedService("android.permission.SEND_SMS"),
                    guardedService("android.permission.BIND_ACCESSIBILITY_SERVICE"),
                ),
            )
            val out = ByteArrayOutputStream()
            ZipOutputStream(out).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml")); zip.write(manifestBytes); zip.closeEntry()
                zip.putNextEntry(ZipEntry("classes.dex")); zip.write(ByteArray(8)); zip.closeEntry()
            }
            val file = File(dir, "a.apk").apply { writeBytes(out.toByteArray()) }
            val bundle = (inspectAndExtractPackage(file, dir) as PackageInspectResult.Valid).bundle
            val report = analyzePackageOffline(file, bundle)
            assertEquals(listOf("INTERNET", "REQUEST_INSTALL_PACKAGES"), report.allPermissions)
            assertEquals(setOf("REQUEST_INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE"), report.highRiskPermissions)
            assertEquals(setOf("BIND_ACCESSIBILITY_SERVICE"), report.capabilities)
            assertEquals(42L, report.versionCode)
        } finally {
            dir.deleteRecursively()
        }
    }

    // ---- Certificates (audit F14) ----

    @Test fun onlyTheExactAndroidDebugNameAndModToolsAreTestCertificates() {
        assertTrue(isDebugOrTestCertificateDn("CN=Android Debug,O=Android,C=US"))
        assertTrue(isDebugOrTestCertificateDn("C=US, O=Android, CN=Android Debug"))
        assertTrue(isDebugOrTestCertificateDn("CN=\"Android Debug\", O=Android, C=US"))
        assertTrue(isDebugOrTestCertificateDn("CN=Lucky Patcher"))
        assertTrue(isDebugOrTestCertificateDn("CN=MT Manager,OU=MT Manager"))
        assertTrue(isDebugOrTestCertificateDn("O=APKTool, CN=whatever"))
        // What `keytool` writes when every question is answered with Enter, and common names of real developers.
        for (dn in listOf(
            "CN=Unknown,OU=Unknown,O=Unknown,L=Unknown,ST=Unknown,C=Unknown",
            "CN=Test", "CN=Test Studio,O=Test Studio Ltd", "OU=Android,O=Acme Ltd", "O=Android Studio Labs", "CN=Android Developer",
            "CN=Android Debug,O=Acme,C=US", "CN=Android Debug,O=Android,C=US,OU=Extra", "CN=My MT Managers Inc", "EmailAddress=android@android.com",
            "CN=Octave", "",
        )) {
            assertFalse(dn, isDebugOrTestCertificateDn(dn))
        }
    }

    @Test fun aCertificateIsJudgedByItsOwnSubjectNotByTwoNamesJoined() {
        val debug = generateAdbIdentity("CN=Android Debug,O=Android,C=US").certificate.encoded
        val info = parseCertificateBytes(debug)
        assertTrue(info?.debugOrTest == true)
        val unknown = parseCertificateBytes(generateAdbIdentity("CN=Unknown,OU=Unknown,O=Unknown").certificate.encoded)
        assertFalse(unknown?.debugOrTest == true)
        val developer = parseCertificateBytes(generateAdbIdentity("CN=Octave").certificate.encoded)
        assertFalse(developer?.debugOrTest == true)
    }

    // ---- Play Protect settings are put back (audit F26) ----

    private class RecordingAdb(
        private val answers: Map<String, String> = emptyMap(),
        private val failOnWrite: Boolean = false,
    ) : AdbClient {
        val commands = mutableListOf<String>()
        override val isConnected: Boolean = true
        override fun pair(host: String, port: Int, code: String) = Unit
        override fun connect(host: String, port: Int) = Unit
        override fun disconnect() = Unit
        override fun shell(command: String): String {
            commands += command
            return answers[command] ?: "Success: created install session [9]"
        }

        override fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit): String {
            if (failOnWrite) throw IOException("Stream closed")
            apk.readBytes()
            return "Success"
        }
    }

    @Test fun aSettingIsReadAsNotSetAWholeNumberOrUnknown() {
        assertEquals(SavedSetting("k", null, true), parseSavedSetting("k", "null\n"))
        assertEquals(SavedSetting("k", "1", true), parseSavedSetting("k", "1\n"))
        assertEquals(SavedSetting("k", "-1", true), parseSavedSetting("k", " -1 "))
        for (answer in listOf("", "error: closed", "Failure [x]", "12345678901", "1; rm -rf /")) {
            assertFalse(answer, parseSavedSetting("k", answer).known)
        }
        assertEquals("settings delete global k", restoreSettingCommand(SavedSetting("k", null, true)))
        assertEquals("settings put global k 0", restoreSettingCommand(SavedSetting("k", "0", true)))
        assertNull(restoreSettingCommand(SavedSetting("k", null, false)))
    }

    @Test fun theInstallPutsThePreviousPlayProtectSettingsBackEvenWhenItFails() {
        val answers = mapOf(ReadAdbVerifyCommand to "1\n", ReadVerifierCommand to "null\n")
        val adb = RecordingAdb(answers, failOnWrite = true)
        val split = ExtractedFile("base.apk", "base.apk", 10L, bytes = ByteArray(10))
        try {
            installBundleSession(adb, listOf(split))
        } catch (_: IOException) {
        }
        val disabled = adb.commands.indexOf(DisableVerifierCommand)
        val restoredAdb = adb.commands.indexOf("settings put global verifier_verify_adb_installs 1")
        val restoredConsent = adb.commands.indexOf("settings delete global package_verifier_user_consent")
        assertTrue(disabled >= 0)
        assertTrue("restore comes after the settings were turned off", restoredAdb > disabled && restoredConsent > disabled)
        // The failed session was abandoned before the settings were restored.
        assertTrue(adb.commands.indexOf("pm install-abandon 9") in 0 until restoredAdb)
    }

    @Test fun anUnreadableSettingIsLeftAloneAndAFailingShellDoesNotBreakTheRestore() {
        val adb = RecordingAdb(mapOf(ReadAdbVerifyCommand to "error", ReadVerifierCommand to "0"))
        val saved = readVerifierSettings(adb)
        assertFalse(saved[0].known)
        restoreVerifierSettings(adb, saved)
        assertEquals(listOf(ReadAdbVerifyCommand, ReadVerifierCommand, "settings put global package_verifier_user_consent 0"), adb.commands)
        val throwing = object : AdbClient {
            override val isConnected: Boolean = true
            override fun pair(host: String, port: Int, code: String) = Unit
            override fun connect(host: String, port: Int) = Unit
            override fun disconnect() = Unit
            override fun shell(command: String): String = throw IOException("gone")
            override fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit): String = ""
        }
        val unknown = readVerifierSettings(throwing)
        assertTrue(unknown.none { it.known })
        restoreVerifierSettings(throwing, listOf(SavedSetting("k", "1", true)))
    }

    // ---- Backups keep a hash (audit F31) ----

    private class PullingAdb(private val payloads: Map<String, ByteArray>) : AdbClient {
        override val isConnected: Boolean = true
        override fun pair(host: String, port: Int, code: String) = Unit
        override fun connect(host: String, port: Int) = Unit
        override fun disconnect() = Unit
        override fun shell(command: String): String = payloads.keys.joinToString("\n") { "package:/data/app/$it" }
        override fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit): String = "Success"
        override fun pull(remotePath: String, destFile: File): Boolean {
            destFile.parentFile?.mkdirs()
            destFile.writeBytes(payloads.getValue(remotePath.removePrefix("/data/app/")))
            return true
        }
    }

    @Test fun aBackupRecordsAndVerifiesTheHashOfEveryApk() {
        val dir = Files.createTempDirectory("shield0950_backup_").toFile()
        try {
            val manager = BackupManager(backupsDir = dir)
            val adb = PullingAdb(mapOf("base.apk" to "base content".toByteArray(), "split_a.apk" to "split content".toByteArray()))
            val item = manager.createBackup(adb, "com.example.app", InstalledAppInfo(5L, null, appName = "App", versionName = "1.0"), "dev1", "TV")!!
            assertEquals(setOf("base.apk", "split_a.apk"), item.apkSha256.keys)
            for (file in item.apkFiles) assertEquals(sha256Hex(file), item.apkSha256.getValue(file.name))
            assertEquals(BackupCheck.Verified, verifyBackupFiles(item))
            // The hashes are in the metadata, so a listing after a restart still has them.
            val listed = manager.listBackups().single()
            assertEquals(item.apkSha256, listed.apkSha256)
            assertEquals(BackupCheck.Verified, verifyBackupFiles(listed))
            // Another program swaps the file: the revert is refused.
            listed.apkFiles.first { it.name == "base.apk" }.writeText("evil")
            assertEquals(BackupCheck.Changed(listOf("base.apk")), verifyBackupFiles(listed))
            // A file that was never part of the backup is refused too.
            val extra = File(listed.apkFiles.first().parentFile, "extra.apk").apply { writeText("x") }
            assertEquals(BackupCheck.Changed(listOf("extra.apk")), verifyBackupFiles(listed.copy(apkFiles = listOf(extra), apkSha256 = item.apkSha256)))
            // A backup of an older version has no hash: it cannot be compared, and says so.
            assertEquals(BackupCheck.NoHash, verifyBackupFiles(listed.copy(apkSha256 = emptyMap())))
        } finally {
            dir.deleteRecursively()
        }
    }

    // ---- API keys are never lost to a temporary failure (audit F27) ----

    private class MemoryPrefs : SharedPreferences {
        val map = HashMap<String, Any?>()

        override fun getAll(): MutableMap<String, *> = HashMap(map)
        override fun getString(key: String?, defValue: String?): String? = (map[key.orEmpty()] as? String) ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
        override fun getInt(key: String?, defValue: Int): Int = (map[key.orEmpty()] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (map[key.orEmpty()] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (map[key.orEmpty()] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = (map[key.orEmpty()] as? Boolean) ?: defValue
        override fun contains(key: String?): Boolean = map.containsKey(key.orEmpty())
        override fun edit(): SharedPreferences.Editor = Editor()
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit

        inner class Editor : SharedPreferences.Editor {
            private fun put(key: String?, value: Any?): SharedPreferences.Editor {
                map[key.orEmpty()] = value
                return this
            }

            override fun putString(key: String?, value: String?): SharedPreferences.Editor = put(key, value)
            override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor = this
            override fun putInt(key: String?, value: Int): SharedPreferences.Editor = put(key, value)
            override fun putLong(key: String?, value: Long): SharedPreferences.Editor = put(key, value)
            override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = put(key, value)
            override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = put(key, value)

            override fun remove(key: String?): SharedPreferences.Editor {
                map.remove(key.orEmpty())
                return this
            }

            override fun clear(): SharedPreferences.Editor {
                map.clear()
                return this
            }

            override fun commit(): Boolean = true
            override fun apply() = Unit
        }
    }

    @Test fun onlyAKeyThatCanNeverBeDecryptedAgainIsForgotten() {
        val prefs = MemoryPrefs()
        val aes = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val other = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        assertTrue(ShieldSettingsStore(prefs) { aes }.saveVirusTotalApiKey("my-secret-key"))
        assertEquals("my-secret-key", ShieldSettingsStore(prefs) { aes }.loadVirusTotalApiKey())
        assertNotEquals("my-secret-key", prefs.getString("vt_api_key_enc", null))

        // The Keystore is busy (boot, locked screen): no key now, but it is still stored for the next try.
        val busy = ShieldSettingsStore(prefs) { throw IllegalStateException("keystore busy") }
        assertNull(busy.loadVirusTotalApiKey())
        assertTrue(busy.hasVirusTotalApiKey())
        assertEquals("my-secret-key", ShieldSettingsStore(prefs) { aes }.loadVirusTotalApiKey())

        // The Keystore key was replaced: the stored text can never be decrypted again, so it is forgotten.
        val replaced = ShieldSettingsStore(prefs) { other }
        assertNull(replaced.loadVirusTotalApiKey())
        assertFalse(replaced.hasVirusTotalApiKey())
    }

    @Test fun permanentKeyFailuresAreTellApartFromTemporaryOnes() {
        assertTrue(isPermanentKeyFailure(javax.crypto.AEADBadTagException()))
        assertTrue(isPermanentKeyFailure(java.security.UnrecoverableKeyException()))
        assertTrue(isPermanentKeyFailure(IllegalArgumentException("bad base64")))
        assertFalse(isPermanentKeyFailure(IllegalStateException("busy")))
        assertFalse(isPermanentKeyFailure(IOException("io")))
        assertFalse(isPermanentKeyFailure(java.security.KeyStoreException("temporary")))
    }

    // ---- The installed version could not be read (audit F24, decision 8) ----

    @Test fun aDeviceThatCannotBeAskedIsNotTheSameAsAppNotInstalled() {
        val failing = object : AdbClient {
            override val isConnected: Boolean = true
            override fun pair(host: String, port: Int, code: String) = Unit
            override fun connect(host: String, port: Int) = Unit
            override fun disconnect() = Unit
            override fun shell(command: String): String = throw IOException("device gone")
            override fun install(command: String, size: Long, apk: InputStream, onProgress: (Long) -> Unit): String = ""
        }
        val failed = queryInstalledAppInfo(failing, "com.example.app")
        assertTrue(failed.queryFailed)
        assertNull(failed.versionCode)
        val notInstalled = queryInstalledAppInfo(RecordingAdb(mapOf("dumpsys package com.example.app" to "Unable to find package: com.example.app")), "com.example.app")
        assertFalse(notInstalled.queryFailed)
        assertNull(notInstalled.versionCode)
        val installed = queryInstalledAppInfo(RecordingAdb(mapOf("dumpsys package com.example.app" to "versionCode=42 minSdk=30\n")), "com.example.app")
        assertFalse(installed.queryFailed)
        assertEquals(42L, installed.versionCode)
    }

    // ---- Texts: every reason, finding and source status has text in every language ----

    private val locales = listOf("values", "values-pt", "values-pt-rPT", "values-es")

    private fun resDir(): File =
        listOf("src/main/res", "app/src/main/res").map(::File).firstOrNull { it.isDirectory } ?: error("res directory not found")

    private fun kotlinSource(name: String): String {
        val file = listOf("src/main/kotlin/app/gogogadget/$name", "app/src/main/kotlin/app/gogogadget/$name").map(::File).firstOrNull { it.isFile }
            ?: error("$name not found")
        return file.readText()
    }

    private fun stringsOf(locale: String): Map<String, String> {
        val text = File(resDir(), "$locale/strings.xml").readText()
        return Regex("""<string name="([^"]+)">(.*?)</string>""", RegexOption.DOT_MATCHES_ALL).findAll(text).associate { it.groupValues[1] to it.groupValues[2] }
    }

    @Test fun everyStringTheShieldScreensUseExistsAndIsFilledInEveryLanguage() {
        val used = listOf("ShieldText.kt", "HomeScreen.kt").flatMap { name ->
            Regex("""R\.string\.([a-z0-9_]+)""").findAll(kotlinSource(name)).map { it.groupValues[1] }.toList()
        }.toSet()
        assertTrue(used.size > 80)
        for (locale in locales) {
            val strings = stringsOf(locale)
            for (name in used) assertTrue("$locale / $name is missing or empty", strings[name]?.isNotBlank() == true)
        }
    }

    @Test fun everyReasonFindingAndStatusHasItsOwnText() {
        for (reason in ShieldWarningReason.entries) {
            val text = reasonText(reason)
            assertTrue(reason.name, text.titleRes != 0 && text.whatRes != 0)
            assertNotEquals(reason.name, text.titleRes, text.whatRes)
            assertTrue(reason.name, shortReasonRes(reason) != 0)
        }
        // Every title is different, so the card tells the reasons apart.
        val titles = ShieldWarningReason.entries.map { reasonText(it).titleRes }
        assertEquals(titles.size, titles.toSet().size)
        for (code in IssueCode.entries) {
            val spec = issueTextSpec(StaticAnalysisIssue(ShieldWarningReason.DropperDetected, "x", code, "p1", "p2"))
            assertTrue(code.name, spec.resId != 0)
        }
        for (status in SourceStatus.entries) {
            val spec = sourceStatusSpec(SourceReport(ShieldSource.MetaDefender, status, 1, 2))
            assertTrue(status.name, spec.resId != 0 && spec.args.first() == "MetaDefender")
        }
        // The engine counts reach the sentence of the two engine reasons.
        assertEquals(listOf("3", "70"), reasonWhatSpec(ShieldWarningReason.EnginesFlagged, 3, 70).args)
        assertEquals(listOf("5", "5"), reasonWhatSpec(ShieldWarningReason.MalwareDetected, 5, 0).args)
        assertTrue(reasonWhatSpec(ShieldWarningReason.DropperDetected, 3, 70).args.isEmpty())
    }

    @Test fun noEnglishTechnicalLineReachesATranslatedScreen() {
        // These literals used to be shown on the card (audit F9); they belong to the terminal log only.
        val forbidden = listOf(
            "Dynamic class loader", "REQUEST_INSTALL_PACKAGES requested by", "Signed with test/mod", "File hash is not known",
            "Potential mod or dynamic code risk", "Not checked by online antivirus engines (no API key",
        )
        for (name in listOf("HomeScreen.kt", "ShieldText.kt")) {
            val source = kotlinSource(name)
            for (literal in forbidden) assertFalse("$name still has \"$literal\"", literal in source)
        }
        assertFalse("the card must not show the English detail", "prompt.detail" in kotlinSource("HomeScreen.kt"))
        // The terminal line of a finding stays English, and the card uses the code instead.
        val issue = StaticAnalysisIssue(ShieldWarningReason.DropperDetected, "Hidden DEX file (x) found in assets or resources", IssueCode.HiddenDex, "x")
        assertEquals(listOf("x"), issueTextSpec(issue).args)
    }

    @Test fun theDropperTextNoLongerClaimsALoadFromTheInternet() {
        // Audit F3: nothing proves the code comes from the Internet, so the text must not say it.
        for (locale in locales) {
            val strings = stringsOf(locale)
            for (key in listOf("caution_dropper_risk", "shield_warn_dropper")) {
                assertFalse("$locale / $key", Regex("(?i)internet").containsMatchIn(strings.getValue(key)))
            }
        }
    }

    @Test fun everyLanguageHasTheSameStringNamesAsEnglish() {
        val english = stringsOf("values").keys
        for (locale in locales.drop(1)) assertEquals(locale, english, stringsOf(locale).keys)
    }
}
