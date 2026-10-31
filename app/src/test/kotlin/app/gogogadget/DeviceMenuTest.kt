package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DeviceMenuTest {
    private val me = Target("Pixel", "127.0.0.1", 0)
    private val net = "192.168.1"
    private val tv = Target("TV", "192.168.1.20", 0, net)
    private val tab = Target("Tablet", "192.168.1.30", 0, net)
    private val far = Target("Office", "10.0.5.9", 0, "10.0.5")

    private fun menu(recent: List<Target>, up: Set<String> = emptySet(), connected: String? = null, own: Set<String> = emptySet()) =
        deviceMenuEntries(me, recent, setOf(net), up, connected, own)

    private fun List<DeviceMenuEntry>.summary() = map { it.target.name to it.status }

    @Test
    fun subnetIsTheFirstThreeOctets() {
        assertEquals("192.168.1", subnetOf("192.168.1.20"))
        assertEquals("10.0.5", subnetOf(" 10.0.5.9 "))
        assertNull(subnetOf("127.0.0.1"))
        assertNull(subnetOf("fe80::1"))
        assertNull(subnetOf("192.168.1"))
        assertNull(subnetOf("192.168.1.300"))
        assertNull(subnetOf("localhost"))
    }

    @Test
    fun zoneScopeIsStrippedFromOwnAddresses() {
        assertEquals(setOf("192.168.1"), currentSubnets(setOf("fe80::1%wlan0", "192.168.1.10%wlan0")))
    }

    @Test
    fun tailscaleNodesShareOneNetworkAcrossSlash24s() {
        val node = Target("Node", "100.101.7.9", 0)
        val result = deviceMenuEntries(me, listOf(node), setOf(net), emptySet(), null, setOf("100.80.1.5", "192.168.1.10"))
        assertEquals(listOf("100.101.7.9"), result.thisNetwork.filter { !it.local }.map { it.target.host })
        val without = deviceMenuEntries(me, listOf(node), setOf(net), emptySet(), null, setOf("192.168.1.10"))
        assertEquals(listOf("100.101.7.9"), without.otherNetworks.map { it.target.host })
    }

    @Test
    fun tailscaleTargetsAreProbedWhenPhoneIsOnTailnet() {
        val node = Target("Node", "100.101.7.9", 0)
        assertEquals(listOf(node), probeTargets(listOf(node), setOf("100.80.1.5"), emptySet(), null))
        assertEquals(emptyList<Target>(), probeTargets(listOf(node), setOf("192.168.1.10"), setOf(net), null))
    }

    @Test
    fun emptyCurrentSubnetsFallBackToOwnAddresses() {
        val tv = Target("TV", "100.64.1.20", 5555)
        val result = deviceMenuEntries(me, listOf(tv), emptySet(), emptySet(), null, setOf("100.64.1.5"))
        assertEquals(listOf("100.64.1.20"), result.thisNetwork.filter { !it.local }.map { it.target.host })
    }

    @Test
    fun currentSubnetsAreEveryPrivateAddress() {
        assertEquals(setOf("192.168.1"), currentSubnets(setOf("fe80::1", "127.0.0.1", "8.8.8.8", "192.168.1.10")))
        assertEquals(emptySet<String>(), currentSubnets(setOf("127.0.0.1", "8.8.8.8")))
        assertEquals(emptySet<String>(), currentSubnets(emptySet()))
    }

    @Test
    fun mobileDataOrVpnDoesNotHideTheWifiNetwork() {
        // "10.20.0.5" sorts before "192.168.1.10": the old single-subnet pick chose the mobile network.
        val subnets = currentSubnets(setOf("10.20.0.5", "192.168.1.10", "172.20.3.4", "100.64.1.2"))
        assertEquals(setOf("10.20.0", "192.168.1", "172.20.3", "100.64.1"), subnets)
        val result = deviceMenuEntries(me, listOf(tv), subnets, setOf("192.168.1.20"), null)
        assertEquals(listOf("Pixel" to DeviceStatus.AVAILABLE, "TV" to DeviceStatus.AVAILABLE), result.thisNetwork.summary())
    }

    @Test
    fun thisDeviceIsAlwaysFirstAndAvailableUntilConnected() {
        assertEquals(listOf("Pixel" to DeviceStatus.AVAILABLE), menu(emptyList()).thisNetwork.summary())
        assertEquals(DeviceStatus.CONNECTED, menu(emptyList(), connected = "127.0.0.1").thisNetwork.first().status)
        assertEquals(true, menu(emptyList()).thisNetwork.first().local)
        assertEquals(true, menu(emptyList()).otherNetworks.isEmpty())
    }

    @Test
    fun currentNetworkConnectedThenAvailableThenUnavailable() {
        val result = menu(listOf(far, tv, tab), up = setOf("192.168.1.30"))
        assertEquals(
            listOf("Pixel" to DeviceStatus.AVAILABLE, "Tablet" to DeviceStatus.AVAILABLE, "TV" to DeviceStatus.UNAVAILABLE),
            result.thisNetwork.summary(),
        )
        assertEquals(listOf("Office" to DeviceStatus.OTHER_NETWORK), result.otherNetworks.summary())
    }

    @Test
    fun theConnectedDeviceIsMarkedWithoutAProbeAndSortedFirst() {
        assertEquals(
            listOf("Pixel" to DeviceStatus.AVAILABLE, "TV" to DeviceStatus.CONNECTED, "Tablet" to DeviceStatus.UNAVAILABLE),
            menu(listOf(tab, tv), connected = "192.168.1.20").thisNetwork.summary(),
        )
        assertEquals(DeviceStatus.AVAILABLE, menu(listOf(tab, tv), connected = "192.168.1.20").thisNetwork.first().status)
    }

    @Test
    fun oldEntriesWithoutASubnetFollowTheirHost() {
        val oldHere = Target("Old here", "192.168.1.77", 0)
        val oldFar = Target("Old far", "172.16.4.2", 0)
        val result = menu(listOf(oldFar, oldHere))
        assertEquals(listOf("Pixel" to DeviceStatus.AVAILABLE, "Old here" to DeviceStatus.UNAVAILABLE), result.thisNetwork.summary())
        assertEquals(listOf("Old far" to DeviceStatus.OTHER_NETWORK), result.otherNetworks.summary())
    }

    @Test
    fun theHostBeatsAStaleSavedSubnet() {
        val moved = Target("Moved", "192.168.1.99", 0, "10.9.9")
        assertEquals(listOf("Pixel" to DeviceStatus.AVAILABLE, "Moved" to DeviceStatus.UNAVAILABLE), menu(listOf(moved)).thisNetwork.summary())
        val farHost = Target("Far", "10.9.9.4", 0, net)
        assertEquals(listOf("Far" to DeviceStatus.OTHER_NETWORK), menu(listOf(farHost)).otherNetworks.summary())
    }

    @Test
    fun deviceSubnetPrefersAnIpv4Host() {
        assertEquals("192.168.1", deviceSubnet(Target("TV", "192.168.1.64", 0, "100.81.81")))
    }

    @Test
    fun deviceSubnetUsesTheStoredSubnetForAHostname() {
        assertEquals("10.9.9", deviceSubnet(Target("TV", "tv.local", 0, "10.9.9")))
    }

    @Test
    fun deviceSubnetIsNullForAHostnameWithAnInvalidStoredSubnet() {
        assertNull(deviceSubnet(Target("TV", "tv.local", 0, "banana")))
        assertNull(deviceSubnet(Target("TV", "tv.local", 0, null)))
    }

    @Test
    fun aDeviceWithAStaleTailscaleSubnetIsOnThisWifi() {
        val tv = Target("Vodafone TV", "192.168.1.64", 0, "100.81.81")
        val result = deviceMenuEntries(me, listOf(tv), setOf(net), emptySet(), null, setOf("192.168.1.126"))
        assertEquals(listOf("Vodafone TV"), result.thisNetwork.filter { !it.local }.map { it.target.name })
        assertEquals(emptyList<DeviceMenuEntry>(), result.otherNetworks)
    }

    @Test
    fun aManuallySavedTailscaleDeviceStaysOnThisNetworkWithATailnetAddress() {
        val node = Target("Node", "100.101.7.9", 5555, "100.101.7")
        val result = deviceMenuEntries(me, listOf(node), setOf(net), emptySet(), null, setOf("192.168.1.126", "100.80.1.5"))
        assertEquals(listOf("Node"), result.thisNetwork.filter { !it.local }.map { it.target.name })
    }

    @Test
    fun withoutANetworkEveryOtherDeviceIsOnAnotherNetwork() {
        val result = deviceMenuEntries(me, listOf(tv, far), emptySet(), emptySet(), null)
        assertEquals(listOf("Pixel"), result.thisNetwork.map { it.target.name })
        assertEquals(listOf("TV", "Office"), result.otherNetworks.map { it.target.name })
        assertEquals(listOf(DeviceStatus.OTHER_NETWORK, DeviceStatus.OTHER_NETWORK), result.otherNetworks.map { it.status })
    }

    @Test
    fun entriesThatAreThisDeviceAreSkipped() {
        val self = Target("Pixel (Wi-Fi)", "192.168.1.10", 0, net)
        val loop = Target("Pixel", "localhost", 0)
        assertEquals(listOf("Pixel", "TV"), menu(listOf(self, loop, tv), own = setOf("192.168.1.10")).thisNetwork.map { it.target.name })
    }

    @Test
    fun repeatedHostsAppearOnce() {
        assertEquals(
            listOf("Pixel", "TV"),
            menu(listOf(tv, tv.copy(name = "TV again"), tv.copy(host = " 192.168.1.20 "))).thisNetwork.map { it.target.name },
        )
    }

    @Test
    fun availableHostsMatchIgnoringCaseAndSpaces() {
        assertEquals(DeviceStatus.AVAILABLE, menu(listOf(tv), up = setOf(" 192.168.1.20")).thisNetwork.last().status)
    }

    @Test
    fun hostPortLabelOmitsAnUnknownPort() {
        assertEquals("192.168.1.20:5555", hostPortLabel(" 192.168.1.20 ", 5555))
        assertEquals("192.168.1.20", hostPortLabel("192.168.1.20", 0))
    }

    @Test
    fun onlyTheConnectedDeviceShowsAdbAndOtherNetworksAreUnavailable() {
        assertEquals(DeviceStateLabel.ADB, deviceStateLabel(DeviceStatus.CONNECTED))
        assertEquals(DeviceStateLabel.AVAILABLE, deviceStateLabel(DeviceStatus.AVAILABLE))
        assertEquals(DeviceStateLabel.UNAVAILABLE, deviceStateLabel(DeviceStatus.UNAVAILABLE))
        assertEquals(DeviceStateLabel.UNAVAILABLE, deviceStateLabel(DeviceStatus.OTHER_NETWORK))
    }

    @Test
    fun thisPhoneIsOfferedButNotSavedOrConnectedOnceForgotten() {
        val forgotten = menu(emptyList()).thisNetwork.first()
        assertEquals(false, forgotten.saved)
        assertEquals(DeviceStatus.AVAILABLE, forgotten.status)
        assertEquals(true, menu(listOf(me)).thisNetwork.first().saved)
        assertEquals(true, menu(listOf(Target("Pixel", "192.168.1.9", 0)), own = setOf("192.168.1.9")).thisNetwork.first().saved)
        assertEquals(false, menu(listOf(tv)).thisNetwork.first().saved)
    }

    @Test
    fun aLostDeviceIsGreyAndInertUntilAProbeSeesItAgain() {
        val lostRow = menu(listOf(tv)).thisNetwork.first { !it.local }
        assertEquals(DeviceStatus.UNAVAILABLE, lostRow.status)
        assertEquals(false, isDeviceSelectable(lostRow.status))
        val backRow = menu(listOf(tv), up = setOf("192.168.1.20")).thisNetwork.first { !it.local }
        assertEquals(DeviceStatus.AVAILABLE, backRow.status)
        assertEquals(true, isDeviceSelectable(backRow.status))
    }
}
