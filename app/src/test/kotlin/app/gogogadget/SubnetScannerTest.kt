package app.gogogadget

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SubnetScannerTest {
    @Test fun sweepsTheLanSubnetWithoutThisPhone() {
        val hosts = SubnetScanner.candidates(setOf("192.168.1.20", "fe80::1"))
        assertEquals(253, hosts.size)
        assertFalse("192.168.1.20" in hosts)
        assertTrue("192.168.1.1" in hosts && "192.168.1.254" in hosts)
    }

    @Test fun aTailnetAddressProducesNoTailnetCandidates() {
        val hosts = SubnetScanner.candidates(setOf("192.168.1.20", "100.80.1.5"))
        assertTrue(hosts.none { it.startsWith("100.") })
        assertEquals(253, hosts.size)
    }

    @Test fun onlyATailnetAddressMeansNothingToSweep() {
        assertTrue(SubnetScanner.candidates(setOf("100.80.1.5")).isEmpty())
    }

    @Test fun noLanAddressMeansNothingToSweep() {
        assertTrue(SubnetScanner.candidates(setOf("8.8.8.8", "fe80::1")).isEmpty())
        assertTrue(SubnetScanner.candidates(emptySet()).isEmpty())
    }

    @Test fun answeringHostsBecomeConnectEntriesWithNameOrIp() = runBlocking {
        val found = SubnetScanner.scan(
            listOf("192.168.1.5", "192.168.1.6", "192.168.1.7"),
            mapOf("192.168.1.5" to "TV"),
            reachable = { host, port, _ -> port == 5555 && host != "192.168.1.6" },
        )
        assertEquals(listOf("192.168.1.5", "192.168.1.7"), found.map { it.host })
        assertEquals("TV", found[0].name)
        assertTrue(found.all { it.kind == FoundKind.Connect && it.port == 5555 })
    }
}
