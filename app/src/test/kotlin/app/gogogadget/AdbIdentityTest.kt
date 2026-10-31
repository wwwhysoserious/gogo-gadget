package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AdbIdentityTest {
    private val own = setOf("192.168.1.20")

    private val tv = Target("TV", "192.168.1.50", 0, "192.168.1")

    @Test fun thisPhoneUsesTheLocalIdentityAndEveryOtherHostItsDeviceKeyOrTheSharedOne() {
        assertEquals(IdentityName.Local, identityFor("127.0.0.1", own))
        assertEquals(IdentityName.Local, identityFor("192.168.1.20", own))
        // This phone ignores any id.
        assertEquals(IdentityName.Local, identityFor("192.168.1.20", own, "abc"))
        assertEquals(IdentityName.Shared, identityFor("192.168.1.50", own))
        assertEquals(IdentityName.Shared, identityFor("tv.local", own))
        assertEquals(IdentityName.Network("abc"), identityFor("192.168.1.50", own, "abc"))
        assertNotEquals(IdentityName.Network("abc"), IdentityName.Network("abd"))
    }

    @Test fun eachIdentityHasItsOwnFilesAndKeystoreAlias() {
        assertEquals("adb_key_local.enc", identityKeyFileName(IdentityName.Local))
        assertEquals("adb_cert_network.der", identityCertFileName(IdentityName.Shared))
        assertNotEquals(identityKeyFileName(IdentityName.Local), identityKeyFileName(IdentityName.Shared))
        assertNotEquals(identityAlias(IdentityName.Local), identityAlias(IdentityName.Shared))
        // The shared key (0.9.22) must keep opening with the file names and alias it was written with.
        assertEquals("adb_key_network.enc", identityKeyFileName(IdentityName.Shared))
        assertEquals("gogo_adb_wrap", identityAlias(IdentityName.Shared))
        assertEquals("gogo_adb_wrap_local", identityAlias(IdentityName.Local))
        val device = IdentityName.Network("a1b2")
        assertEquals("adb_key_dev_a1b2.enc", identityKeyFileName(device))
        assertEquals("adb_cert_dev_a1b2.der", identityCertFileName(device))
        assertEquals("gogo_adb_wrap_dev_a1b2", identityAlias(device))
        assertNotEquals(identityKeyFileName(device), identityKeyFileName(IdentityName.Network("a1b3")))
        assertNotEquals(identityAlias(device), identityAlias(IdentityName.Network("a1b3")))
    }

    @Test fun aDeviceIdCanNeverBeAPath() {
        listOf("", "../x", "a/b", "a.b", "a b", "a".repeat(65)).forEach {
            assertFalse(it, isValidDeviceId(it))
            assertThrows(IllegalArgumentException::class.java) { IdentityName.Network(it) }
        }
        assertTrue(isValidDeviceId(newDeviceId()))
        assertNotEquals(newDeviceId(), newDeviceId())
        assertThrows(IllegalArgumentException::class.java) { identityKeyFileName(IdentityName.Everything) }
    }

    @Test fun legacyKeyMovesOnlyOnceAndNeverOverANewerIdentity() {
        assertTrue(legacyMigration(existsOld = true, existsNew = false))
        assertFalse(legacyMigration(existsOld = true, existsNew = true))
        assertFalse(legacyMigration(existsOld = false, existsNew = false))
        assertFalse(legacyMigration(existsOld = false, existsNew = true))
    }

    @Test fun forgettingThisPhoneDeletesOnlyTheLocalKey() {
        assertEquals(setOf(IdentityName.Local), identitiesToDelete(IdentityName.Local, noDeviceLeft = false))
    }

    @Test fun forgettingADeviceWithItsOwnKeyDeletesThatKeyOnly() {
        val key = IdentityName.Network("a1b2")
        assertEquals(setOf(key), identitiesToDelete(key, noDeviceLeft = false))
    }

    @Test fun forgettingADeviceOnTheSharedKeyKeepsEveryKey() {
        assertEquals(emptySet<IdentityName>(), identitiesToDelete(IdentityName.Shared, noDeviceLeft = false))
    }

    @Test fun forgettingTheLastDeviceDeletesEverything() {
        val all = setOf(IdentityName.Everything)
        assertEquals(all, identitiesToDelete(IdentityName.Shared, noDeviceLeft = true))
        assertEquals(all, identitiesToDelete(IdentityName.Local, noDeviceLeft = true))
        assertEquals(all, identitiesToDelete(IdentityName.Network("a1b2"), noDeviceLeft = true))
    }

    @Test fun everythingCoversLocalSharedAndEveryDeviceKeyFoundByItsFilesOrAlias() {
        val files = listOf(
            "adb_key_local.enc", "adb_key_network.enc", "adb_key_dev_aa11.enc", "adb_cert_dev_aa11.der",
            "adb_cert_dev_bb22.der.tmp", "adb_key_dev_../x.enc", "notes.txt", "adb_key_devx.enc",
        )
        val aliases = listOf("gogo_adb_wrap", "gogo_adb_wrap_local", "gogo_adb_wrap_dev_aa11", "gogo_adb_wrap_dev_cc33", "other")
        val expected = setOf(
            IdentityName.Local, IdentityName.Shared,
            IdentityName.Network("aa11"), IdentityName.Network("bb22"), IdentityName.Network("cc33"),
        )
        assertEquals(expected, expandIdentities(setOf(IdentityName.Everything), files, aliases))
        // Nothing stored: still this phone and the shared key.
        assertEquals(setOf(IdentityName.Local, IdentityName.Shared), expandIdentities(setOf(IdentityName.Everything), emptyList(), emptyList()))
        // Without the sweep marker the set is left as it is.
        val one = setOf(IdentityName.Network("aa11"))
        assertEquals(one, expandIdentities(one, files, aliases))
    }

    @Test fun anEntrySavedBeforeTheUpdateStaysOnTheSharedKey() {
        val recent = listOf(tv)
        val again = withDeviceId(tv.copy(subnet = null), recent, own) { "unused" }
        assertNull(again.deviceId)
        assertEquals(IdentityName.Shared, identityFor(again.host, own, again.deviceId))
    }

    @Test fun aNewNetworkDeviceGetsItsOwnIdAndOneAlreadyFixedIsKept() {
        val fresh = withDeviceId(Target("New", "192.168.1.77", 0), listOf(tv), own) { "n3w1" }
        assertEquals("n3w1", fresh.deviceId)
        assertEquals(IdentityName.Network("n3w1"), identityFor(fresh.host, own, fresh.deviceId))
        // The id is kept once it is set (a pairing followed by a connect), and a saved id wins over a new one.
        assertEquals("n3w1", withDeviceId(fresh, emptyList(), own) { "other" }.deviceId)
        val saved = tv.copy(deviceId = "sv01")
        assertEquals("sv01", withDeviceId(Target("TV", "192.168.1.50", 0), listOf(saved), own) { "other" }.deviceId)
        // This phone never gets one.
        assertNull(withDeviceId(Target("Me", "127.0.0.1", 0), emptyList(), own) { "other" }.deviceId)
    }

    @Test fun markedIdentitiesSurviveTheirEncodingAndNothingElseDecodes() {
        val all = setOf(IdentityName.Local, IdentityName.Shared, IdentityName.Network("a1b2"), IdentityName.Everything)
        assertEquals(all, decodeIdentities(encodeIdentities(all)))
        // The marks 0.9.24 wrote keep their meaning.
        assertEquals(setOf(IdentityName.Local, IdentityName.Shared), decodeIdentities("local,network"))
        assertEquals(emptySet<IdentityName>(), decodeIdentities("dev_../x,dev_,dev_a b,bogus,"))
    }
}
