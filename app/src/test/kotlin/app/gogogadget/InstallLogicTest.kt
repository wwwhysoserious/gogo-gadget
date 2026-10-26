package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlinx.coroutines.CancellationException
import java.io.EOFException
import java.io.IOException
import java.net.SocketException
import java.net.SocketTimeoutException

class InstallLogicTest {
    // ---- installPercent ----

    @Test fun percentIsBytesOverTotal() {
        assertEquals(0, installPercent(0, 1000, false))
        assertEquals(50, installPercent(500, 1000, false))
        assertEquals(12, installPercent(125, 1000, false))
    }

    @Test fun percentStaysAt99UntilDone() {
        assertEquals(99, installPercent(1000, 1000, false))
        assertEquals(99, installPercent(2000, 1000, false))
        assertEquals(99, installPercent(999, 1000, false))
    }

    @Test fun percentIs100OnlyWhenDone() {
        assertEquals(100, installPercent(1000, 1000, true))
        assertEquals(100, installPercent(0, 0, true))
    }

    @Test fun percentHandlesOddInput() {
        assertEquals(0, installPercent(10, 0, false))
        assertEquals(0, installPercent(-5, 100, false))
    }

    // ---- installPhase ----

    @Test fun phaseSendingShowsRealPercent() {
        assertEquals(PhaseState(InstallPhase.Sending, 0), installPhase(0, 1000, false))
        assertEquals(PhaseState(InstallPhase.Sending, 42), installPhase(420, 1000, false))
        assertEquals(PhaseState(InstallPhase.Sending, 99), installPhase(999, 1000, false))
    }

    @Test fun phaseInstallingWhenAllBytesSentAndNoAnswer() {
        assertEquals(PhaseState(InstallPhase.Installing, 99), installPhase(1000, 1000, false))
        assertEquals(PhaseState(InstallPhase.Installing, 99), installPhase(2000, 1000, false))
    }

    @Test fun phaseDoneOnlyWhenAnswered() {
        assertEquals(PhaseState(InstallPhase.Done, 100), installPhase(1000, 1000, true))
        assertEquals(PhaseState(InstallPhase.Done, 100), installPhase(0, 0, true))
    }

    @Test fun phaseUnknownTotalStaysSendingAtZero() {
        assertEquals(PhaseState(InstallPhase.Sending, 0), installPhase(10, 0, false))
        assertEquals(PhaseState(InstallPhase.Sending, 0), installPhase(-5, 100, false))
    }

    // ---- ProgressThrottle ----

    @Test fun throttleLetsFirstAndLastThrough() {
        val t = ProgressThrottle(100)
        assertTrue(t.shouldReport(0, 10, 1000))
        assertFalse(t.shouldReport(10, 20, 1000))
        assertTrue(t.shouldReport(11, 1000, 1000))
    }

    @Test fun throttleAllowsAboutTenPerSecond() {
        val t = ProgressThrottle(100)
        var passed = 0
        for (ms in 0L until 1000L step 5L) if (t.shouldReport(ms, ms, 1_000_000)) passed++
        assertEquals(10, passed)
    }

    // ---- installLabel ----

    @Test fun labelPrefersPackageName() {
        assertEquals("com.example.app", installLabel("com.example.app", "app.apk", "Package"))
    }

    @Test fun labelFallsBackToFileName() {
        assertEquals("app.apk", installLabel(null, "app.apk", "Package"))
        assertEquals("app.apk", installLabel("not a package", " app.apk ", "Package"))
        assertEquals("Package", installLabel(null, "  ", "Package"))
        assertEquals("Package", installLabel(null, null, "Package"))
    }

    // ---- decodeFileName ----

    @Test fun fileNameIsDecodedForDisplay() {
        assertEquals("my app.apk", decodeFileName("my%20app.apk"))
        assertEquals("Caf\u00e9.apk", decodeFileName("Caf%C3%A9.apk"))
        assertEquals("x.apk", decodeFileName("primary%3ADownload%2Fx.apk"))
        assertEquals("a b.apk", decodeFileName("a+b.apk"))
        assertEquals(
            "Downloader by AFTVnews_2.0.4-ForGoogleAndroidDevices_APKPure.apk",
            decodeFileName("Downloader+by+AFTVnews_2.0.4-ForGoogleAndroidDevices_APKPure.apk"),
        )
        assertEquals(
            "Downloader by AFTVnews_2.0.4-ForGoogleAndroidDevices_APKPure.apk",
            installLabel(null, "Downloader+by+AFTVnews_2.0.4-ForGoogleAndroidDevices_APKPure.apk", "Package"),
        )
        assertEquals("a+b.apk", decodeFileName("a%2Bb.apk"))
        assertEquals("100%.apk", decodeFileName("100%.apk"))
        assertEquals("bad%FF.apk", decodeFileName("bad%FF.apk"))
        assertEquals("my app.apk", installLabel(null, "my%20app.apk", "Package"))
    }

    // ---- pmFailure: one test per mapped case ----

    private fun reasonOf(line: String) = pmFailure(line).reason

    @Test fun downgrade() = assertEquals(R.string.reason_downgrade, reasonOf("Failure [INSTALL_FAILED_VERSION_DOWNGRADE: Downgrade detected]"))
    @Test fun updateIncompatible() = assertEquals(R.string.reason_signature, reasonOf("Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Package signatures do not match]"))
    @Test fun inconsistentCertificates() = assertEquals(R.string.reason_signature, reasonOf("Failure [INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES]"))
    @Test fun storage() = assertEquals(R.string.reason_storage, reasonOf("Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]"))
    @Test fun olderSdk() = assertEquals(R.string.reason_older_sdk, reasonOf("Failure [INSTALL_FAILED_OLDER_SDK]"))
    @Test fun noMatchingAbis() = assertEquals(R.string.reason_abis, reasonOf("Failure [INSTALL_FAILED_NO_MATCHING_ABIS: x]"))
    @Test fun userRestricted() = assertEquals(R.string.reason_restricted, reasonOf("Failure [INSTALL_FAILED_USER_RESTRICTED: Install canceled by user]"))
    @Test fun alreadyExists() = assertEquals(R.string.reason_exists, reasonOf("Failure [INSTALL_FAILED_ALREADY_EXISTS]"))
    @Test fun parseNotApk() = assertEquals(R.string.reason_parse, reasonOf("Failure [INSTALL_PARSE_FAILED_NOT_APK: not an apk]"))
    @Test fun parseManifest() = assertEquals(R.string.reason_parse, reasonOf("Failure [INSTALL_PARSE_FAILED_MANIFEST_MALFORMED]"))
    @Test fun parseUnexpected() = assertEquals(R.string.reason_parse, reasonOf("Failure [INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION]"))
    @Test fun parseNoCertificates() = assertEquals(R.string.reason_parse, reasonOf("Failure [INSTALL_PARSE_FAILED_NO_CERTIFICATES]"))

    @Test fun unknownPmCodeIsUnknown() {
        assertEquals(R.string.reason_unknown, reasonOf("Failure [INSTALL_FAILED_SOMETHING_NEW: x]"))
        assertEquals(R.string.reason_unknown, reasonOf("No output from pm"))
        assertEquals(R.string.reason_unknown, reasonOf("Failure [weird]"))
    }

    @Test fun pmFailureKeepsRawLine() {
        assertEquals("Failure [INSTALL_FAILED_OLDER_SDK]", pmFailure("Failure [INSTALL_FAILED_OLDER_SDK]").raw)
    }

    // ---- transferFailure ----

    @Test fun connectionLostWhenSessionGone() {
        assertEquals(R.string.reason_connection_lost, transferFailure(IOException("boom"), "d", sessionConnected = false).reason)
    }

    @Test fun connectionLostFromClosedSocketOrStream() {
        assertEquals(R.string.reason_connection_lost, transferFailure(SocketException("Socket closed"), null).reason)
        assertEquals(R.string.reason_connection_lost, transferFailure(IOException("Stream closed"), null).reason)
        assertEquals(R.string.reason_connection_lost, transferFailure(IOException("w", EOFException()), null).reason)
    }

    @Test fun timeout() {
        assertEquals(R.string.reason_timeout, transferFailure(SocketTimeoutException("x"), "d").reason)
        assertEquals(R.string.reason_timeout, transferFailure(WatchdogTimeoutException(), null).reason)
    }

    @Test fun cancelled() {
        assertEquals(R.string.reason_cancelled, transferFailure(CancellationException("x"), null).reason)
    }

    @Test fun unreadableFile() {
        assertEquals(R.string.err_read_file, transferFailure(FileEndedException(10), null).reason)
        assertEquals(R.string.err_read_file, transferFailure(IOException("w", FileEndedException(10)), null).reason)
    }

    @Test fun unidentifiedFailureIsUnknown() {
        assertEquals(R.string.reason_unknown, transferFailure(IOException("boom"), "IOException: boom").reason)
        assertEquals(R.string.reason_unknown, transferFailure(IllegalStateException("x"), null).reason)
        assertEquals("IOException: boom", transferFailure(IOException("boom"), "IOException: boom").raw)
    }

    @Test fun connectionLossNeverGivesTheBundleText() {
        val errors = listOf(IOException("Stream closed"), SocketException("Socket closed"), EOFException(), IOException("x"))
        for (e in errors) for (up in listOf(true, false)) {
            assertNotEquals(R.string.reason_parse, transferFailure(e, null, up).reason)
        }
        assertEquals(R.string.reason_connection_lost, transferFailure(IOException("x"), null, false).reason)
    }

    // ---- fillWidthPx ----

    @Test fun fillWidthAtKeyPercents() {
        assertEquals(0, fillWidthPx(1000, 0))
        assertEquals(10, fillWidthPx(1000, 1))
        assertEquals(500, fillWidthPx(1000, 50))
        assertEquals(990, fillWidthPx(1000, 99))
        assertEquals(1000, fillWidthPx(1000, 100))
    }

    @Test fun fillWidthEndsExactlyAtTheInnerEdgeForAnyWidth() {
        for (w in listOf(1, 7, 238, 777, 1001, 1080, 1439)) {
            assertEquals(w, fillWidthPx(w, 100))
            assertEquals(0, fillWidthPx(w, 0))
            assertTrue(fillWidthPx(w, 99) < w || w < 100)
        }
    }

    @Test fun fillWidthIsClampedAndMonotonic() {
        assertEquals(0, fillWidthPx(1000, -5))
        assertEquals(1000, fillWidthPx(1000, 250))
        assertEquals(0, fillWidthPx(-10, 50))
        assertEquals(Int.MAX_VALUE, fillWidthPx(Int.MAX_VALUE, 100))
        for (p in 0 until 100) assertTrue(fillWidthPx(777, p) <= fillWidthPx(777, p + 1))
    }

    @Test fun barFillPercentIsProgressWhileWorkingAndFullWhenFinished() {
        assertEquals(0, barFillPercent(working = true, percent = 0))
        assertEquals(42, barFillPercent(working = true, percent = 42))
        assertEquals(99, barFillPercent(working = true, percent = 99))
        assertEquals(100, barFillPercent(working = false, percent = 0))
        assertEquals(100, barFillPercent(working = false, percent = 42))
        assertEquals(100, barFillPercent(working = false, percent = 100))
    }
}
