package app.gogogadget

import io.github.muntashirakon.adb.AdbPairingRequiredException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException

class NetworkAndLocalPairingTest {
    private val own = setOf("192.168.1.20", "127.0.0.1", "fe80::1%wlan0")

    // ---- this phone's own pairing service (Shizuku's rule) ----

    @Test fun portBoundCheckSaysBoundWhenBindingFails() {
        assertTrue(isPortBoundLocally(4000) { throw IOException("Address already in use") })
        assertFalse(isPortBoundLocally(4000) { })
    }

    @Test fun ownServiceNeedsOwnAddressAndABoundPort() {
        val mine = Found("adb-me", "192.168.1.20", 40001, FoundKind.Pairing)
        assertEquals(mine, acceptOwnPairing(listOf(mine), own) { true })
        // Own address but nothing listens on the port: another phone's stale record, or a lie.
        assertNull(acceptOwnPairing(listOf(mine), own) { false })
    }

    @Test fun anotherDevicesDialogIsRejectedEvenIfAPortIsBound() {
        val other = Found("adb-tv", "192.168.1.50", 40001, FoundKind.Pairing)
        assertNull(acceptOwnPairing(listOf(other), own) { true })
    }

    @Test fun onlyPairingServicesCount() {
        val connect = Found("adb-me", "192.168.1.20", 40002, FoundKind.Connect)
        val remote = Found("tv", "192.168.1.20", 40003, FoundKind.Remote)
        assertNull(acceptOwnPairing(listOf(connect, remote), own) { true })
    }

    @Test fun ownAddressMatchIgnoresCaseScopeAndMappedPrefix() {
        assertEquals(40004, acceptOwnPairing(listOf(Found("a", "FE80::1%wlan0", 40004, FoundKind.Pairing)), own) { true }?.port)
        assertEquals(40005, acceptOwnPairing(listOf(Found("a", "::ffff:192.168.1.20", 40005, FoundKind.Pairing)), own) { true }?.port)
    }

    @Test fun firstAcceptedServiceWinsAndThePortCheckRunsPerPort() {
        val list = listOf(
            Found("a", "192.168.1.20", 1111, FoundKind.Pairing),
            Found("b", "192.168.1.20", 2222, FoundKind.Pairing),
        )
        assertEquals(2222, acceptOwnPairing(list, own) { it == 2222 }?.port)
    }

    // ---- merging discovered services per host ----

    @Test fun servicesOfOneHostAreMergedAndNamedByTheRemoteService() {
        val found = listOf(
            Found("adb-X-abc", "192.168.1.50", 42000, FoundKind.Connect),
            Found("Living room TV", "192.168.1.50", 6466, FoundKind.Remote),
            Found("adb-X-abc", "192.168.1.50", 42001, FoundKind.Pairing),
        )
        assertEquals(listOf(NetDevice("192.168.1.50", "Living room TV", 42000, 42001)), mergeByHost(found, own))
    }

    @Test fun adbOnlyDevicesHaveNoFriendlyName() {
        val merged = mergeByHost(listOf(Found("adb-X-abc", "192.168.1.51", 42000, FoundKind.Connect)), own)
        assertNull(merged.single().name)
        assertEquals(42000, merged.single().connectPort)
        assertNull(merged.single().pairPort)
    }

    @Test fun thisPhonesServicesAndIpv6HostsAreLeftOut() {
        val found = listOf(
            Found("adb-me", "192.168.1.20", 41000, FoundKind.Connect),
            Found("adb-me", "127.0.0.1", 41001, FoundKind.Pairing),
            Found("v6", "fe80::abcd", 1, FoundKind.Remote),
            Found("tv", "192.168.1.50", 6466, FoundKind.Remote),
        )
        assertEquals(listOf("192.168.1.50"), mergeByHost(found, own).map { it.host })
    }

    @Test fun devicesKeepTheOrderTheyWereFirstSeenIn() {
        val found = listOf(
            Found("b", "192.168.1.60", 6466, FoundKind.Remote),
            Found("a", "192.168.1.50", 6466, FoundKind.Remote),
            Found("adb", "192.168.1.60", 42000, FoundKind.Connect),
        )
        assertEquals(listOf("192.168.1.60", "192.168.1.50"), mergeByHost(found, own).map { it.host })
    }

    @Test fun mdnsConnectPortLooksUpByHost() {
        val found = listOf(
            Found("adb-tv", "192.168.1.50", 42000, FoundKind.Connect),
            Found("tv", "192.168.1.50", 6466, FoundKind.Remote),
        )
        assertEquals(42000, mdnsConnectPort("192.168.1.50", found))
        assertNull(mdnsConnectPort("192.168.1.51", found))
    }

    // ---- network ports and names ----

    @Test fun networkPortCandidatesAreMdnsThenLastGoodThenFiveFiveFiveFive() {
        assertEquals(listOf(42000, 37000, 5555), connectPortCandidates(42000, 37000))
        assertEquals(listOf(42000, 5555), connectPortCandidates(42000, null))
        assertEquals(listOf(5555), connectPortCandidates(null, null))
        assertEquals(5555, ClassicAdbPort)
    }

    @Test fun tappingADeviceConnectsUnlessOnlyItsPairingDialogIsOpen() {
        assertEquals(TapAction.Connect(42000), tapAction(NetDevice("h", null, 42000, 42001)))
        assertEquals(TapAction.Connect(5555), tapAction(NetDevice("h", "TV", null, null)))
        assertEquals(TapAction.Pair(42001), tapAction(NetDevice("h", null, null, 42001)))
    }

    @Test fun displayNamePrefersFriendlyNameThenModelThenHost() {
        assertEquals("Living room TV", networkDisplayName("Living room TV", "192.168.1.50", "Shield"))
        assertEquals("Shield", networkDisplayName("", "192.168.1.50", "Shield"))
        assertEquals("Shield", networkDisplayName("192.168.1.50", "192.168.1.50", "Shield"))
        assertEquals("192.168.1.50", networkDisplayName(null, "192.168.1.50", null))
    }

    // ---- local -> notification, network -> direct connect ----

    @Test fun thisPhonePairsByNotificationAndOthersByCodeInTheApp() {
        assertEquals(PairingMethod.Notification, pairingMethod(local = true))
        assertEquals(PairingMethod.InAppCode, pairingMethod(local = false))
    }

    @Test fun networkDevicesAreAlwaysConnectedToFirst() {
        assertEquals(FirstStep.DirectConnect, firstStep(local = false, connectPort = null))
        assertEquals(FirstStep.DirectConnect, firstStep(local = false, connectPort = 5555))
    }

    @Test fun thisPhoneTriesTheAllowPromptOnlyWhenAConnectPortIsKnown() {
        assertEquals(FirstStep.DirectConnect, firstStep(local = true, connectPort = 40000))
        assertEquals(FirstStep.PairNow, firstStep(local = true, connectPort = null))
    }

    @Test fun onlyPairingRequiredLeadsToPairingAndMethodFollowsTheTarget() {
        assertEquals(Next.PairWithNotification, nextAfterConnectFailure(AdbError.PairingRequired, local = true, silent = false))
        assertEquals(Next.PairWithCodeInApp, nextAfterConnectFailure(AdbError.PairingRequired, local = false, silent = false))
        assertEquals(Next.Fail, nextAfterConnectFailure(AdbError.Unreachable, local = false, silent = false))
        assertEquals(Next.Fail, nextAfterConnectFailure(AdbError.AllowTimeout, local = true, silent = false))
        assertEquals(Next.GoIdle, nextAfterConnectFailure(AdbError.PairingRequired, local = true, silent = true))
    }

    @Test fun refusedKeyAndMissingPairingBothMeanPairingRequired() {
        assertEquals(AdbError.PairingRequired, classifyError(AdbPairingRequiredException("x"), Phase.Connect, local = true))
    }

    // ---- Allow waiting ----

    @Test fun allowWaitIsFortyFiveSecondsAndSilentReconnectsAreShorter() {
        assertEquals(45_000L, connectTimeoutMs(silent = false))
        assertTrue(connectTimeoutMs(silent = true) < connectTimeoutMs(silent = false))
    }

    @Test fun allowNoteTellsWhereToTapAndIsQuietWhenSilent() {
        assertEquals(R.string.allow_note_network, allowNoteFor(local = false, silent = false))
        assertEquals(R.string.allow_note_local, allowNoteFor(local = true, silent = false))
        assertNull(allowNoteFor(local = false, silent = true))
    }

    @Test fun onlyTheWatchdogTurnsATimeoutIntoTheAllowMessage() {
        assertEquals(AdbError.AllowTimeout, connectFailure(WatchdogTimeoutException(), local = false, silent = false))
        assertEquals(AdbError.Unreachable, connectFailure(WatchdogTimeoutException(), local = false, silent = true))
        assertEquals(AdbError.Unreachable, connectFailure(SocketTimeoutException("x"), local = false, silent = false))
        assertEquals(AdbError.Unreachable, connectFailure(ConnectException("refused"), local = false, silent = false))
    }

    // ---- pairing failures reported by the notification ----

    @Test fun keyProblemsHaveTheirOwnMessage() {
        assertEquals(AdbError.KeyError, classifyError(AdbKeyException(IOException("x")), Phase.Pair, local = true))
        assertEquals(AdbError.KeyError, classifyError(IOException(AdbKeyException(IOException("x"))), Phase.Pair, local = true))
    }

    @Test fun pairingFailuresAreDistinct() {
        assertEquals(AdbError.PairingUnreachable, classifyError(ConnectException("refused"), Phase.Pair, local = true))
        assertEquals(AdbError.WrongCode, classifyError(java.io.EOFException(), Phase.Pair, local = true))
        assertEquals(AdbError.Failed, classifyError(IllegalStateException(), Phase.Pair, local = true))
    }
}
