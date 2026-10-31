package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ForgetTest {
    private val own = setOf("192.168.1.20", "100.98.120.20")
    private val phone = Target("Moto", "127.0.0.1", 0)
    private val phoneByIp = Target("Moto (old)", "192.168.1.20", 0, "192.168.1")
    private val phoneByName = Target("Moto (name)", "localhost", 0)
    private val tv = Target("TV", "192.168.1.50", 0, "192.168.1")
    private val tablet = Target("Tablet", "192.168.1.60", 0, "192.168.1")

    // Saved after 0.9.25: each has a key of its own. The ones above were saved before and share one key.
    private val box = Target("Box", "192.168.1.70", 0, "192.168.1", "b0b0")
    private val stick = Target("Stick", "192.168.1.80", 0, "192.168.1", "57c4")

    private fun connected(t: Target) = Connection(ConnectionState.Connected, Device(t.name, t.host, 0, t.host == "127.0.0.1"))

    // ---- BUG: deleting this phone's key disconnected the session of a network device ----

    @Test fun forgettingThisPhoneWhileConnectedToATvKeepsTheTvSession() {
        val connection = connected(tv)
        val plan = planForget(connection, listOf(phone, tv), phone, own)
        assertFalse(plan.endSession)
        assertSame(connection, plan.connection)
        assertEquals(setOf(IdentityName.Local), plan.doomed)
        assertEquals(listOf(tv), plan.recent)
    }

    @Test fun forgettingThisPhoneWhileConnectedToItEndsTheSessionAndDeletesItsKey() {
        val plan = planForget(connected(phone), listOf(phone, tv), phone, own)
        assertTrue(plan.endSession)
        assertEquals(Connection(), plan.connection)
        assertEquals(setOf(IdentityName.Local), plan.doomed)
    }

    @Test fun theNotificationServiceStopsBeforeThisPhonesKeyIsDeleted() {
        // Idle, connected to a TV, pairing a TV: the service must be stopped whenever the Local key goes.
        assertTrue(planForget(Connection(), listOf(phone, tv), phone, own).stopPairing)
        assertTrue(planForget(connected(tv), listOf(phone, tv), phone, own).stopPairing)
        val pairingTv = Connection(ConnectionState.Pairing, Device("TV", "192.168.1.50", 0, false))
        assertTrue(planForget(pairingTv, listOf(phone, tv), phone, own).stopPairing)
    }

    @Test fun forgettingThisPhoneWhilePairingItEndsThePairing() {
        val pairing = Connection(ConnectionState.Pairing, Device("Moto", "127.0.0.1", 0, true))
        val plan = planForget(pairing, listOf(phone, tv), phone, own)
        assertTrue(plan.endSession)
        assertTrue(plan.stopPairing)
        assertEquals(Connection(), plan.connection)
    }

    @Test fun forgettingThisPhoneWhileConnectingToItEndsTheAttempt() {
        val connecting = Connection(ConnectionState.Connecting, Device("Moto", "127.0.0.1", 0, true))
        assertTrue(planForget(connecting, listOf(phone, tv), phone, own).endSession)
    }

    // ---- network devices ----

    @Test fun forgettingTheConnectedSharedKeyDeviceEndsTheSessionButKeepsEveryKey() {
        val plan = planForget(connected(tv), listOf(phone, tv, tablet), tv, own)
        assertTrue(plan.endSession)
        assertEquals(emptySet<IdentityName>(), plan.doomed)
        assertTrue(plan.stopPairing)
    }

    @Test fun forgettingAnotherNetworkDeviceChangesNothingButTheList() {
        val connection = connected(tv)
        val plan = planForget(connection, listOf(phone, tv, tablet), tablet, own)
        assertFalse(plan.endSession)
        assertSame(connection, plan.connection)
        assertEquals(emptySet<IdentityName>(), plan.doomed)
        assertFalse(plan.stopPairing)
        assertEquals(listOf(phone, tv), plan.recent)
    }

    @Test fun forgettingAnIdleNetworkDeviceLeavesAPairingOfThisPhoneRunning() {
        val pairing = Connection(ConnectionState.Pairing, Device("Moto", "127.0.0.1", 0, true))
        val plan = planForget(pairing, listOf(phone, tv), tv, own)
        assertFalse(plan.endSession)
        assertFalse(plan.stopPairing)
    }

    // ---- last device ----

    @Test fun forgettingTheLastDeviceResetsAndDeletesEveryKey() {
        val plan = planForget(Connection(), listOf(tv), tv, own)
        assertTrue(plan.resetToFirstRun)
        assertEquals(setOf(IdentityName.Everything), plan.doomed)
        val phoneOnly = planForget(Connection(), listOf(phone), phone, own)
        assertTrue(phoneOnly.resetToFirstRun)
        assertEquals(setOf(IdentityName.Everything), phoneOnly.doomed)
        val boxOnly = planForget(Connection(), listOf(box), box, own)
        assertEquals(setOf(IdentityName.Everything), boxOnly.doomed)
        // The notification service stops first: this phone's key goes with the rest.
        assertTrue(plan.stopPairing)
    }

    // ---- BUG: forgetting a network device did not revoke it, every TV shared one key ----

    @Test fun forgettingADeviceWithItsOwnKeyDeletesThatKeyAndEndsItsSession() {
        val plan = planForget(connected(box), listOf(phone, tv, box), box, own)
        assertTrue(plan.endSession)
        assertEquals(Connection(), plan.connection)
        assertEquals(setOf(IdentityName.Network("b0b0")), plan.doomed)
        assertEquals(listOf(phone, tv), plan.recent)
    }

    @Test fun theSavedEntryDecidesTheKeyEvenWhenTheScreenPassesATargetWithoutTheId() {
        val fromTheList = Target("Box", "192.168.1.70", 0)
        assertEquals(setOf(IdentityName.Network("b0b0")), planForget(Connection(), listOf(phone, tv, box), fromTheList, own).doomed)
    }

    @Test fun forgettingADeviceWithItsOwnKeyLeavesTheSessionOfAnotherDeviceAlone() {
        val connection = connected(tv)
        val plan = planForget(connection, listOf(phone, tv, box, stick), box, own)
        assertFalse(plan.endSession)
        assertSame(connection, plan.connection)
        assertEquals(setOf(IdentityName.Network("b0b0")), plan.doomed)
    }

    @Test fun forgettingADeviceOnTheSharedKeyDeletesNoKeyButClosesItsSession() {
        val plan = planForget(connected(tv), listOf(phone, tv, tablet, box), tv, own)
        assertTrue(plan.endSession)
        assertEquals(emptySet<IdentityName>(), plan.doomed)
        assertEquals(listOf(phone, tablet, box), plan.recent)
    }

    @Test fun aForgottenSharedKeyDeviceIsAddedAgainWithANewOwnKeyNeverTheSharedOne() {
        val plan = planForget(Connection(), listOf(phone, tv, tablet), tv, own)
        // Found again on the network: no id, and no longer saved.
        val again = withDeviceId(Target("TV", tv.host, 0), plan.recent, own) { "ne01" }
        assertEquals("ne01", again.deviceId)
        assertEquals(IdentityName.Network("ne01"), identityFor(again.host, own, again.deviceId))
        // The other device on the shared key is untouched.
        val other = withDeviceId(Target("Tablet", tablet.host, 0), plan.recent, own) { "unused" }
        assertEquals(IdentityName.Shared, identityFor(other.host, own, other.deviceId))
    }

    @Test fun aForgottenDeviceWithItsOwnKeyIsAddedAgainWithAnotherKey() {
        val plan = planForget(Connection(), listOf(phone, box, stick), box, own)
        val again = withDeviceId(Target("Box", box.host, 0), plan.recent, own) { "ne02" }
        assertEquals(IdentityName.Network("ne02"), identityFor(again.host, own, again.deviceId))
    }

    @Test fun anotherDeviceLeftMeansNoReset() {
        assertFalse(planForget(Connection(), listOf(phone, tv), phone, own).resetToFirstRun)
    }

    // ---- duplicate local entries ----

    @Test fun everyEntryForThisPhoneGoesWhicheverAddressItWasSavedWith() {
        val recent = listOf(phoneByIp, tv, phone, phoneByName)
        assertEquals(listOf(tv), planForget(Connection(), recent, phone, own).recent)
        // Forgetting the entry saved with the phone's own IP removes the loopback ones too.
        assertEquals(listOf(tv), planForget(Connection(), recent, phoneByIp, own).recent)
        assertEquals(IdentityName.Local, identityFor(phoneByIp.host, own))
    }

    @Test fun theTailscaleStyleAddressOfThisPhoneIsThisPhone() {
        val viaVpn = Target("Moto (VPN)", "100.98.120.20", 0)
        assertEquals(IdentityName.Local, identityFor(viaVpn.host, own))
        assertEquals(listOf(tv), planForget(Connection(), listOf(viaVpn, tv), phone, own).recent)
    }

    // ---- BUG: a forgotten device stayed "available" from an older probe ----

    @Test fun aForgottenDeviceIsNoLongerAvailable() {
        val reachable = setOf("192.168.1.50", "192.168.1.60")
        assertEquals(setOf("192.168.1.60"), keepSavedHosts(reachable, listOf(phone, tablet)))
        // A probe that finishes after the device was forgotten publishes the same filtered result.
        assertEquals(emptySet<String>(), keepSavedHosts(reachable, emptyList()))
        assertEquals(setOf("192.168.1.60"), keepSavedHosts(setOf(" 192.168.1.60 "), listOf(tablet)).map { it.trim() }.toSet())
    }

    // ---- BUG: a deletion the app was killed in the middle of was never finished ----

    @Test fun markedIdentitiesSurviveTheirEncoding() {
        val all = setOf(IdentityName.Local, IdentityName.Shared, IdentityName.Network("a1b2"), IdentityName.Everything)
        assertEquals(all, decodeIdentities(encodeIdentities(all)))
        assertEquals(setOf(IdentityName.Local), decodeIdentities(encodeIdentities(setOf(IdentityName.Local))))
        assertEquals(setOf(IdentityName.Network("b0b0")), decodeIdentities(encodeIdentities(setOf(IdentityName.Network("b0b0")))))
        assertEquals(emptySet<IdentityName>(), decodeIdentities(encodeIdentities(emptySet())))
        assertEquals(emptySet<IdentityName>(), decodeIdentities(null))
        assertEquals(setOf(IdentityName.Shared), decodeIdentities("network,bogus,"))
    }
}
