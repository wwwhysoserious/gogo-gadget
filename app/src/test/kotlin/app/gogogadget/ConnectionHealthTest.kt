package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The pure rules of the connection health: session liveness, availability hysteresis, probe targets and ports. */
class ConnectionHealthTest {
    private val tv = Device("TV", "192.168.1.20", 41234, false)
    private val net = setOf("192.168.1")

    // ---- Session liveness ----

    @Test fun oneFailedPingIsSuspectTwoLoseTheSession() {
        val tracker = LivenessTracker()
        assertEquals(LivenessTracker.Verdict.Suspect, tracker.onPing(false))
        assertTrue(tracker.suspect)
        assertEquals(LivenessTracker.Verdict.Lost, tracker.onPing(false))
    }

    @Test fun anAnswerInBetweenStartsTheCountAgain() {
        val tracker = LivenessTracker()
        tracker.onPing(false)
        assertEquals(LivenessTracker.Verdict.Healthy, tracker.onPing(true))
        assertFalse(tracker.suspect)
        assertEquals(LivenessTracker.Verdict.Suspect, tracker.onPing(false))
    }

    @Test fun aConnectionTheLibraryReportsAsEndedIsLostAtOnce() {
        val tracker = LivenessTracker()
        assertEquals(LivenessTracker.Verdict.Lost, tracker.onFlagsDead())
    }

    @Test fun resetForgetsEarlierFailures() {
        val tracker = LivenessTracker()
        tracker.onPing(false)
        tracker.reset()
        assertEquals(LivenessTracker.Verdict.Suspect, tracker.onPing(false))
    }

    // ---- A verdict only applies to the session it was found for ----

    @Test fun aLossAppliesOnlyToTheSameConnectedSession() {
        fun apply(gen: Int = 3, sid: Long = 7, dev: Device? = tv, state: ConnectionState = ConnectionState.Connected) =
            shouldApplyLoss(3, gen, 7, sid, tv, dev, state)
        assertTrue(apply())
        assertFalse("another operation began", apply(gen = 4))
        assertFalse("a newer session", apply(sid = 8))
        assertFalse("another device", apply(dev = tv.copy(host = "192.168.1.21")))
        assertFalse("no device", apply(dev = null))
        assertFalse("already an error", apply(state = ConnectionState.Error))
        assertFalse("connecting again", apply(state = ConnectionState.Connecting))
    }

    @Test fun theKeepaliveRunsOnlyInFrontOnANetworkDeviceWithNothingWorking() {
        assertTrue(keepaliveAllowed(foreground = true, local = false, busy = false))
        assertFalse(keepaliveAllowed(foreground = false, local = false, busy = false))
        assertFalse(keepaliveAllowed(foreground = true, local = true, busy = false))
        assertFalse("an install or a backup is working", keepaliveAllowed(foreground = true, local = false, busy = true))
    }

    // ---- Availability of the devices that are not connected ----

    @Test fun aDeviceStartsUnknownAndBecomesAvailableOnTheFirstAnswer() {
        val tracker = AvailabilityTracker()
        assertEquals(Availability.Unknown, tracker.stateOf("192.168.1.20"))
        assertTrue(tracker.available().isEmpty())
        assertEquals(Availability.Available, tracker.record("192.168.1.20", true))
        assertEquals(setOf("192.168.1.20"), tracker.available())
    }

    @Test fun anAvailableDeviceNeedsTwoMissesInARowToGoGrey() {
        val tracker = AvailabilityTracker()
        tracker.record("h", true)
        assertEquals(Availability.Available, tracker.record("h", false))
        assertEquals(Availability.Unavailable, tracker.record("h", false))
        assertEquals(Availability.Available, tracker.record("h", true))
    }

    @Test fun anAnswerBetweenTwoMissesStartsTheCountAgain() {
        val tracker = AvailabilityTracker()
        tracker.record("h", true)
        tracker.record("h", false)
        tracker.record("h", true)
        assertEquals(Availability.Available, tracker.record("h", false))
    }

    @Test fun aDeviceThatNeverAnsweredStaysGrey() {
        val tracker = AvailabilityTracker()
        assertEquals(Availability.Unavailable, tracker.record("h", false))
        assertTrue(tracker.available().isEmpty())
    }

    @Test fun aHostThatLeavesTheProbeStartsUnknownAgain() {
        val tracker = AvailabilityTracker()
        tracker.record("h", true)
        tracker.retain(emptyList())
        assertEquals(Availability.Unknown, tracker.stateOf("h"))
    }

    // ---- What is probed ----

    @Test fun theConnectedDeviceThisPhoneAndOtherNetworksAreNeverProbed() {
        val own = setOf("192.168.1.10")
        val recent = listOf(
            Target("TV", "192.168.1.20", 0, "192.168.1"),
            Target("Tablet", "192.168.1.30", 0, "192.168.1"),
            Target("Me", "192.168.1.10", 0, "192.168.1"),
            Target("Loop", "127.0.0.1", 0),
            Target("Office", "10.0.5.9", 0, "10.0.5"),
            Target("Tablet again", " 192.168.1.30 ", 0, "192.168.1"),
        )
        assertEquals(listOf("TV", "Tablet"), probeTargets(recent, own, net, null).map { it.name })
        assertEquals(listOf("Tablet"), probeTargets(recent, own, net, "192.168.1.20").map { it.name })
        assertTrue(probeTargets(recent, own, emptySet(), null).isEmpty())
    }

    @Test fun anOldEntryWithoutASubnetFollowsItsHost() {
        assertEquals(1, probeTargets(listOf(Target("Old", "192.168.1.77", 0)), emptySet(), net, null).size)
    }

    // ---- Ports ----

    @Test fun probePortsPutTheLastGoodPortFirstWithoutRepeats() {
        assertEquals(listOf(41234, 37001, 5555), probePorts(0, listOf(37001, 41234, 0, 70000), 41234))
        assertEquals(listOf(5555), probePorts(0, emptyList(), null))
        assertEquals(listOf(40123, 41234, 37001, 5555), probePorts(40123, listOf(37001), 41234))
        assertEquals(listOf(5555), probePorts(0, listOf(5555), 5555))
    }

    @Test fun anMdnsPortNotTriedBeforeCallsForANewProbe() {
        val found = listOf(Found("adb-x", "192.168.1.20", 41234, FoundKind.Connect), Found("tv", "192.168.1.20", 6466, FoundKind.Remote))
        assertTrue(hasNewConnectPorts(emptyMap(), listOf("192.168.1.20"), found))
        assertFalse(hasNewConnectPorts(mapOf("192.168.1.20" to setOf(41234)), listOf("192.168.1.20"), found))
        assertFalse("a device that is not probed", hasNewConnectPorts(emptyMap(), listOf("192.168.1.99"), found))
        assertFalse(hasNewConnectPorts(emptyMap(), listOf("192.168.1.20"), emptyList()))
    }

    // ---- Start ----

    @Test fun onlyTheLastDeviceOfThisNetworkIsReconnectedAtStart() {
        val here = Target("TV", "192.168.1.20", 0, "192.168.1")
        val far = Target("Office", "10.0.5.9", 0, "10.0.5")
        val me = Target("Pixel", "127.0.0.1", 0)
        assertEquals(here, startupReconnect(listOf(here, far), emptySet(), net))
        assertNull("last device is on another network", startupReconnect(listOf(far, here), emptySet(), net))
        assertEquals(me, startupReconnect(listOf(me, far), emptySet(), net))
        assertNull(startupReconnect(listOf(here), emptySet(), emptySet()))
        assertNull(startupReconnect(emptyList(), emptySet(), net))
    }
}
