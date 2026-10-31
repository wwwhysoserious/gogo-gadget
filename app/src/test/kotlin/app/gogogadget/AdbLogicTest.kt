package app.gogogadget

import io.github.muntashirakon.adb.AdbPairingRequiredException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.EOFException
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.lang.reflect.InvocationTargetException
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException

class AdbLogicTest {
    private val own = setOf("192.168.1.20", "fe80::1%wlan0", "10.0.0.5")

    // ---- isLocalHost ----

    @Test fun loopbackIsLocal() {
        for (h in listOf("127.0.0.1", "127.1.2.3", "::1", "[::1]", "localhost", "LOCALHOST", "::ffff:127.0.0.1")) {
            assertTrue(h, isLocalHost(h, emptySet()))
        }
    }

    @Test fun ownInterfaceAddressesAreLocal() {
        assertTrue(isLocalHost("192.168.1.20", own))
        assertTrue(isLocalHost("10.0.0.5", own))
        assertTrue(isLocalHost("fe80::1", own))
        assertTrue(isLocalHost("FE80::1%wlan0", own))
    }

    @Test fun otherAddressesAreNetwork() {
        assertFalse(isLocalHost("192.168.1.21", own))
        assertFalse(isLocalHost("128.0.0.1", own))
        assertFalse(isLocalHost("12.7.0.1", own))
        assertFalse(isLocalHost("192.168.1.20", emptySet()))
        assertFalse(isLocalHost("phone.local", own))
    }

    // ---- validation ----

    @Test fun portsMustBeInRange() {
        assertEquals(5555, parsePort(" 5555 "))
        assertEquals(1, parsePort("1"))
        assertEquals(65535, parsePort("65535"))
        for (bad in listOf("", "0", "65536", "-1", "abc", "12 34")) assertNull(bad, parsePort(bad))
    }

    @Test fun hostsAreValidated() {
        for (ok in listOf("192.168.1.20", "10.0.0.1", "phone.local", "my-phone", "fe80::1", "fe80::1%wlan0", "[fe80::1]")) {
            assertTrue(ok, isValidHost(ok))
        }
        for (bad in listOf("", " ", "999.1.1.1", "1.2.3", "bad_host", "-a.local", "a..b", "host name", "1.2.3.4.5")) {
            assertFalse(bad, isValidHost(bad))
        }
    }

    @Test fun onlyLocalNetworkAddressesAreAccepted() {
        for (ok in listOf("192.168.0.9", "10.1.2.3", "172.16.0.1", "172.31.255.1", "169.254.1.1", "fe80::2", "fd12::1", "phone.local")) {
            assertTrue(ok, isLanHost(ok))
        }
        for (bad in listOf("8.8.8.8", "172.32.0.1", "172.15.0.1", "192.169.0.1", "example.com", "2001:db8::1")) {
            assertFalse(bad, isLanHost(bad))
        }
    }

    @Test fun tailscaleAddressesAreAccepted() {
        for (ok in listOf("100.64.0.1", "100.100.1.2", "100.127.255.254", "fd7a:115c:a1e0::1", "my-tv.tail1234.ts.net")) {
            assertTrue(ok, isLanHost(ok))
            assertTrue(ok, isValidHost(ok))
        }
        for (bad in listOf("100.63.255.255", "100.128.0.1")) assertFalse(bad, isLanHost(bad))
        assertEquals(Endpoint("100.101.102.103", 5555), parseEndpoint("100.101.102.103", "5555"))
        assertTrue(isLocalHost("100.64.0.9", setOf("100.64.0.9")))
    }

    @Test fun endpointNeedsAHostAndAValidOrBlankPort() {
        assertEquals(Endpoint("192.168.1.30", 40123), parseEndpoint(" 192.168.1.30 ", "40123"))
        assertEquals(Endpoint("192.168.1.30", 0), parseEndpoint("192.168.1.30", " "))
        assertNull(parseEndpoint("192.168.1.30", "0"))
        assertNull(parseEndpoint("192.168.1.30", "70000"))
        assertNull(parseEndpoint("8.8.8.8", "5555"))
        assertNull(parseEndpoint("", "5555"))
    }

    @Test fun hostPortBracketsIpv6() {
        assertEquals("192.168.1.2:5555", hostPort("192.168.1.2", 5555))
        assertEquals("[fe80::1]:5555", hostPort("fe80::1", 5555))
    }

    // ---- mDNS matching ----

    private val found = listOf(
        Found("adb-self", "192.168.1.20", 41000, FoundKind.Connect),
        Found("adb-self", "192.168.1.20", 41001, FoundKind.Pairing),
        Found("adb-tv", "192.168.1.50", 42000, FoundKind.Connect),
        Found("adb-tv", "192.168.1.50", 42001, FoundKind.Pairing),
    )

    @Test fun thisDevicePicksItsOwnServices() {
        val self = Target("Pixel", "127.0.0.1", 0)
        assertEquals(41000, resolveConnectPort(self, found, own))
        assertEquals(41001, resolvePairingPort(self, found, own))
    }

    @Test fun networkDevicePicksServicesOfItsHost() {
        val tv = Target("TV", "192.168.1.50", 0)
        assertEquals(42000, resolveConnectPort(tv, found, own))
        assertEquals(42001, resolvePairingPort(tv, found, own))
        assertNull(resolveConnectPort(Target("x", "192.168.1.99", 0), found, own))
    }

    @Test fun explicitPortWinsAndNothingFoundIsNull() {
        assertEquals(5555, resolveConnectPort(Target("x", "192.168.1.50", 5555), found, own))
        assertNull(resolveConnectPort(Target("Pixel", "127.0.0.1", 0), emptyList(), own))
    }

    // ---- errors ----

    @Test fun refusedConnectionMeansWirelessDebuggingIsOffOnlyForThisDevice() {
        val refused = ConnectException("Connection refused")
        assertEquals(AdbError.WirelessDebuggingOff, classifyError(IOException(refused), Phase.Connect, local = true))
        assertEquals(AdbError.Unreachable, classifyError(refused, Phase.Connect, local = false))
    }

    @Test fun unpairedKeyAsksForPairing() {
        assertEquals(AdbError.PairingRequired, classifyError(AdbPairingRequiredException("x"), Phase.Connect, local = true))
        assertEquals(
            AdbError.PairingRequired,
            classifyError(IOException(AdbPairingRequiredException("x")), Phase.Connect, local = false),
        )
    }

    @Test fun onlyARefusedExchangeIsCalledAWrongCode() {
        assertEquals(AdbError.WrongCode, classifyError(IOException("Exchanging message wasn't successful."), Phase.Pair, local = true))
        assertEquals(AdbError.WrongCode, classifyError(IOException("Could not exchange peer info."), Phase.Pair, local = true))
        assertEquals(AdbError.WrongCode, classifyError(EOFException(), Phase.Pair, local = false))
    }

    @Test fun otherPairingFailuresKeepTheirOwnMessage() {
        // exportKeyingMaterial unavailable: the library wraps the reflection failure in an SSLException.
        val tls = SSLException(ClassNotFoundException("com.android.org.conscrypt.Conscrypt"))
        assertEquals(AdbError.TlsFailed, classifyError(tls, Phase.Pair, local = true))
        assertEquals(AdbError.TlsFailed, classifyError(SSLHandshakeException("x"), Phase.Pair, local = true))
        assertEquals(AdbError.PairingUnreachable, classifyError(ConnectException("refused"), Phase.Pair, local = true))
        assertEquals(AdbError.PairingUnreachable, classifyError(SocketTimeoutException(), Phase.Pair, local = false))
        assertEquals(AdbError.Failed, classifyError(IOException("Broken pipe"), Phase.Pair, local = true))
        assertEquals(AdbError.Failed, classifyError(IllegalStateException(), Phase.Pair, local = true))
    }

    @Test fun diagnosticNamesTheClassAndCauses() {
        val e = SSLException(InvocationTargetException(NoSuchMethodException("exportKeyingMaterial")))
        assertEquals(
            "SSLException: java.lang.reflect.InvocationTargetException < InvocationTargetException < " +
                "NoSuchMethodException: exportKeyingMaterial",
            diagnostic(e),
        )
        assertEquals("EOFException", diagnostic(EOFException()))
    }

    @Test fun diagnosticMasksCodesKeysAndControlCharacters() {
        assertEquals("IOException: bad ****** and 1234567 x", diagnostic(IOException("bad 123456 and 1234567\nx")))
        val key = "A".repeat(40)
        assertEquals("IOException: key ...", diagnostic(IOException("key $key")))
        assertEquals(160, diagnostic(IOException("ab ".repeat(200))).length)
    }

    @Test fun pairingHostsTryTheWifiAddressThenLoopback() {
        val seen = Found("adb", "192.168.1.135", 37639, FoundKind.Pairing)
        val me = Target("Me", "127.0.0.1", 0)
        assertEquals(listOf("192.168.1.135", "127.0.0.1"), pairingHosts(me, seen, local = true, loopback = "127.0.0.1"))
        assertEquals(listOf("127.0.0.1"), pairingHosts(me, null, local = true, loopback = "127.0.0.1"))
        assertEquals(listOf("127.0.0.1"), pairingHosts(me, seen.copy(host = "127.0.0.1"), local = true, loopback = "127.0.0.1"))
        val tv = Target("TV", "192.168.1.50", 0)
        assertEquals(listOf("192.168.1.50"), pairingHosts(tv, null, local = false, loopback = "127.0.0.1"))
    }

    @Test fun resolvePairingReturnsTheMatchingServiceHost() {
        val list = listOf(
            Found("a", "192.168.1.50", 1111, FoundKind.Pairing),
            Found("b", "192.168.1.20", 37639, FoundKind.Pairing),
            Found("c", "192.168.1.20", 40000, FoundKind.Connect),
        )
        assertEquals(37639, resolvePairing(Target("Me", "127.0.0.1", 0), list, own)?.port)
        assertEquals(1111, resolvePairingPort(Target("TV", "192.168.1.50", 0), list, own))
        assertNull(resolvePairing(Target("TV", "192.168.1.60", 0), list, own))
    }

    @Test fun timeoutsAreUnreachableAndSessionDropsAreLostConnections() {
        assertEquals(AdbError.Unreachable, classifyError(SocketTimeoutException(), Phase.Connect, local = false))
        assertEquals(AdbError.Unreachable, classifyError(InterruptedException("Timed out"), Phase.Connect, local = true))
        assertEquals(AdbError.ConnectionLost, classifyError(IOException("Stream closed"), Phase.Session, local = true))
        assertEquals(AdbError.Failed, classifyError(IllegalStateException(), Phase.Connect, local = true))
    }

    // ---- pm output ----

    @Test fun successNeedsASuccessLine() {
        assertEquals(PmResult(true, "Success"), parsePmOutput("Success\n"))
        assertEquals(PmResult(true, "Success"), parsePmOutput("Performing Streamed Install\r\nSuccess\r\n"))
    }

    @Test fun failuresKeepTheFailureLine() {
        assertEquals(
            PmResult(false, "Failure [INSTALL_FAILED_VERSION_DOWNGRADE]"),
            parsePmOutput("Performing Streamed Install\nFailure [INSTALL_FAILED_VERSION_DOWNGRADE]\n"),
        )
        assertEquals(PmResult(false, "Error: Unknown option: --bogus"), parsePmOutput("Error: Unknown option: --bogus"))
        assertEquals(PmResult(false, "something odd"), parsePmOutput("\nsomething odd\n"))
        assertEquals(PmResult(false, "No output from pm"), parsePmOutput(" \n"))
    }

    @Test fun successIsNeverInferredFromSubstrings() {
        assertFalse(parsePmOutput("Failure [NOT Success]").success)
    }

    @Test fun bypassFlagIsDroppedOnlyWhenTheDeviceRejectsIt() {
        assertTrue(shouldRetryWithoutBypass("Error: Unknown option: --bypass-low-target-sdk-block"))
        assertTrue(shouldRetryWithoutBypass("java.lang.IllegalArgumentException: Unknown argument: --bypass-low-target-sdk-block"))
        assertFalse(shouldRetryWithoutBypass("Failure [INSTALL_FAILED_VERSION_DOWNGRADE]"))
        assertFalse(shouldRetryWithoutBypass("Success"))
    }

    @Test fun installCommandUsesTheDocumentedFlags() {
        assertEquals("cmd package install -S 1234 -r -d --bypass-low-target-sdk-block", streamInstallCommand(1234, bypass = true))
        assertEquals("cmd package install -S 1234 -r -d", streamInstallCommand(1234, bypass = false))
        assertEquals("cmd package install -S 1234 -r -d -t --bypass-low-target-sdk-block", streamInstallCommand(1234, bypass = true, testOnly = true))
    }

    @Test fun testOnlyFailureIsDetected() {
        assertEquals(true, isTestOnlyFailure("Failure [INSTALL_FAILED_TEST_ONLY: install -t flag is required]"))
        assertEquals(false, isTestOnlyFailure("Failure [INSTALL_FAILED_ALREADY_EXISTS]"))
    }

    @Test fun installCommandAppendsTheUserInstallReasonOnlyWhenAsked() {
        assertEquals(4, InstallReasonUser)
        assertEquals(
            "cmd package install -S 1234 -r -d --bypass-low-target-sdk-block --install-reason 4",
            streamInstallCommand(1234, bypass = true, userInstall = true),
        )
        assertEquals("cmd package install -S 1234 -r -d --install-reason 4", streamInstallCommand(1234, bypass = false, userInstall = true))
        assertEquals("cmd package install -S 1234 -r -d --bypass-low-target-sdk-block", streamInstallCommand(1234, bypass = true, userInstall = false))
        assertEquals("cmd package install -S 1234 -r -d", streamInstallCommand(1234, bypass = false, userInstall = false))
    }

    @Test fun installWriteSuccessLineCountsAsSuccess() {
        assertEquals(PmResult(true, "Success"), parsePmOutput("Success: streamed 4096 bytes\n"))
        assertEquals(PmResult(true, "Success"), parsePmOutput("Success: created install session [123456]\n"))
    }

    // ---- recent devices ----

    @Test fun recentsRoundTripAndDropBrokenLines() {
        val list = listOf(Target("Pixel 8", "127.0.0.1", 0), Target("TV", "192.168.1.50", 42000))
        assertEquals(list, decodeRecents(encodeRecents(list)))
        assertEquals(emptyList<Target>(), decodeRecents(null))
        assertEquals(listOf(list[1]), decodeRecents("garbage\nTV\t192.168.1.50\t42000\nx\t\t1\nx\ty\tz"))
    }

    @Test fun recentsKeepTheirSubnetAndOldLinesDecodeWithoutOne() {
        val list = listOf(Target("TV", "192.168.1.50", 0, "192.168.1"), Target("Box", "10.0.0.7", 0))
        assertEquals(list, decodeRecents(encodeRecents(list)))
        // Lines written by older versions have three fields.
        assertEquals(listOf(Target("TV", "192.168.1.50", 42000)), decodeRecents("TV\t192.168.1.50\t42000"))
        assertEquals(emptyList<Target>(), decodeRecents("a\tb\t1\tc\td\te"))
    }

    @Test fun recentsKeepTheDeviceIdAndOldLinesDecodeWithoutOne() {
        val withId = Target("TV", "192.168.1.50", 0, "192.168.1", "a1b2c3")
        val legacy = Target("Box", "10.0.0.7", 0, "10.0.0")
        val list = listOf(withId, legacy)
        assertEquals(list, decodeRecents(encodeRecents(list)))
        // No id: the line is the one 0.9.24 wrote, so an older app still reads it.
        assertEquals("Box\t10.0.0.7\t0\t10.0.0", encodeRecents(listOf(legacy)))
        assertEquals(listOf(legacy.copy(subnet = null)), decodeRecents("Box\t10.0.0.7\t0"))
        assertEquals(listOf(legacy), decodeRecents("Box\t10.0.0.7\t0\t10.0.0"))
        // An id with no subnet keeps its column.
        val noSubnet = Target("TV", "192.168.1.50", 0, null, "a1b2c3")
        assertEquals(listOf(noSubnet), decodeRecents(encodeRecents(listOf(noSubnet))))
        // An id that could not be a file name is dropped, never used in a path.
        assertEquals(listOf(Target("TV", "192.168.1.50", 0, "192.168.1")), decodeRecents("TV\t192.168.1.50\t0\t192.168.1\t../x"))
    }

    @Test fun recentsStripSeparatorsFromNames() {
        val decoded = decodeRecents(encodeRecents(listOf(Target("a\tb\nc", "10.0.0.2", 1))))
        assertEquals(listOf(Target("a b c", "10.0.0.2", 1)), decoded)
    }

    @Test fun removeRecentDropsTheDeviceByHostAndKeepsTheOrderOfTheRest() {
        val a = Target("A", "192.168.1.50", 0)
        val b = Target("B", "192.168.1.51", 0)
        val c = Target("C", "192.168.1.52", 0)
        assertEquals(listOf(a, c), removeRecent(listOf(a, b, c), b))
        // Same host with another name or port is the same device.
        assertEquals(listOf(a, c), removeRecent(listOf(a, b, c), Target("other", "192.168.1.51", 5555)))
        assertEquals(listOf(a, b, c), removeRecent(listOf(a, b, c), Target("D", "192.168.1.60", 0)))
        assertEquals(emptyList<Target>(), removeRecent(emptyList(), a))
    }

    @Test fun removeRecentOfThisPhoneDropsEveryEntryForIt() {
        val own = listOf("192.168.1.20")
        val phone = Target("Phone", "192.168.1.20", 0)
        val loopback = Target("Phone", "127.0.0.1", 0)
        val other = Target("B", "192.168.1.51", 0)
        assertEquals(listOf(other), removeRecent(listOf(phone, other, loopback), phone, own))
        assertEquals(listOf(other), removeRecent(listOf(phone, other, loopback), loopback, own))
        // Forgetting another device never touches this phone.
        assertEquals(listOf(phone, loopback), removeRecent(listOf(phone, other, loopback), other, own))
    }

    @Test fun forgettingTheConnectedPhoneEndsItsSession() {
        val own = listOf("192.168.1.20")
        val phone = Target("Phone", "127.0.0.1", 0)
        val connected = Connection(ConnectionState.Connected, Device("Phone", "127.0.0.1", 41000, true))
        assertEquals(Connection(), connectionAfterForget(connected, phone, own))
        // Whatever address the phone was saved with.
        assertEquals(Connection(), connectionAfterForget(connected, Target("Phone", "192.168.1.20", 0), own))
        val pairing = Connection(ConnectionState.Pairing, Device("Phone", "127.0.0.1", 0, true))
        assertEquals(Connection(), connectionAfterForget(pairing, phone, own))
        // Another device's session, or no session, is left alone.
        val tv = Connection(ConnectionState.Connected, Device("TV", "192.168.1.50", 5555, false))
        assertEquals(tv, connectionAfterForget(tv, phone, own))
        assertEquals(Connection(), connectionAfterForget(Connection(), phone, own))
    }

    @Test fun firstRunResetHappensOnlyWhenNoSavedDeviceIsLeft() {
        val a = Target("A", "192.168.1.50", 0)
        val b = Target("B", "192.168.1.51", 0)
        assertTrue(shouldResetToFirstRun(emptyList()))
        assertFalse(shouldResetToFirstRun(listOf(a)))
        assertTrue(shouldResetToFirstRun(removeRecent(listOf(a), a)))
        assertFalse(shouldResetToFirstRun(removeRecent(listOf(a, b), a)))
    }

    @Test fun recentsPutTheLatestFirstWithoutDuplicatesAndKeepEverything() {
        val self = Target("Pixel", "127.0.0.1", 0)
        val tv = Target("TV", "192.168.1.50", 42000)
        assertEquals(listOf(tv, self), addRecent(listOf(self, tv), tv, own))
        // The port changes on every Wireless debugging restart: same host replaces the old entry.
        assertEquals(listOf(tv.copy(port = 1), self), addRecent(listOf(self, tv), tv.copy(port = 1), own))
        // This device under any of its own addresses is one entry.
        assertEquals(listOf(self), addRecent(listOf(self.copy(host = "192.168.1.20")), self, own))
        val many = (1..9).fold(emptyList<Target>()) { acc, i -> addRecent(acc, Target("d$i", "10.0.0.$i", i), own) }
        assertEquals(9, many.size)
        assertEquals("d9", many.first().name)
    }

    @Test fun pendingCodeWaitsForThePortThenSubmits() {
        assertEquals(PairingStep.WaitingForDialog, pairingStep("123456", null))
        assertEquals(PairingStep.Submit, pairingStep("123456", 37639))
    }

    @Test fun incompleteOrNonNumericCodeIsNeverPending() {
        for (code in listOf("", "1", "12345", "1234567", "12345a", "١٢٣٤٥٦")) {
            assertEquals(code, PairingStep.EnterCode, pairingStep(code, null))
            assertEquals(code, PairingStep.EnterCode, pairingStep(code, 37639))
        }
    }

    @Test fun portChangeWithCompleteCodeStaysSubmittable() {
        assertEquals(PairingStep.Submit, pairingStep("000000", 1))
        assertEquals(PairingStep.Submit, pairingStep("000000", 65535))
    }

    @Test fun localPairingStatusFollowsThePairingPort() {
        assertEquals(LocalPairingStatus.WaitingForDialog, localPairingStatus(null))
        assertEquals(LocalPairingStatus.DialogFound, localPairingStatus(37639))
    }

    @Test fun wirelessButtonPulsesOnlyUntilTheDialogIsFound() {
        assertEquals(true, shouldPulseWirelessButton(LocalPairingStatus.WaitingForDialog))
        assertEquals(false, shouldPulseWirelessButton(LocalPairingStatus.DialogFound))
    }

    @Test fun recentsForgetTheirPorts() {
        val list = listOf(Target("TV", "192.168.1.50", 42000), Target("Me", "127.0.0.1", 0))
        assertEquals(listOf(0, 0), forgetPorts(list).map { it.port })
        assertEquals(list.map { it.host }, forgetPorts(list).map { it.host })
    }

    @Test
    fun noPortActionDecidesByKindOfConnect() {
        assertEquals(NoPortAction.StartPairing, noPortAction(silent = false, paired = false))
        assertEquals(NoPortAction.GoIdle, noPortAction(silent = true, paired = false))
        assertEquals(NoPortAction.ReportMissing, noPortAction(silent = false, paired = true))
        assertEquals(NoPortAction.GoIdle, noPortAction(silent = true, paired = true))
    }

    @Test
    fun theConnectPortIsAwaitedLongerAfterPairing() {
        assertEquals(5_000L, connectPortWaitMs(paired = false))
        assertEquals(15_000L, connectPortWaitMs(paired = true))
    }
}
