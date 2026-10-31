package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallPolicyTest {
    @Test fun offNeverDeletesAndNeverOffersTheButton() {
        assertEquals(DeleteSourceAction.None, deleteSourceAction(DeleteSourceMode.Off, installOk = true))
        assertEquals(DeleteSourceAction.None, deleteSourceAction(DeleteSourceMode.Off, installOk = false))
    }

    @Test fun onOffersTheButtonAfterAnyInstall() {
        assertEquals(DeleteSourceAction.OfferButton, deleteSourceAction(DeleteSourceMode.On, installOk = true))
        assertEquals(DeleteSourceAction.OfferButton, deleteSourceAction(DeleteSourceMode.On, installOk = false))
    }

    @Test fun automaticDeletesOnlyAfterASuccessfulInstall() {
        assertEquals(DeleteSourceAction.DeleteNow, deleteSourceAction(DeleteSourceMode.Automatic, installOk = true))
        assertEquals(DeleteSourceAction.None, deleteSourceAction(DeleteSourceMode.Automatic, installOk = false))
    }

    @Test fun storedModeWinsOverTheOldBoolean() {
        assertEquals(DeleteSourceMode.Automatic, deleteSourceModeFrom("Automatic", legacy = false))
        assertEquals(DeleteSourceMode.Off, deleteSourceModeFrom("Off", legacy = true))
        assertEquals(DeleteSourceMode.On, deleteSourceModeFrom("On", legacy = null))
    }

    @Test fun oldBooleanMigratesTrueToOnAndFalseToOff() {
        assertEquals(DeleteSourceMode.On, deleteSourceModeFrom(null, legacy = true))
        assertEquals(DeleteSourceMode.Off, deleteSourceModeFrom(null, legacy = false))
    }

    @Test fun nothingStoredOrAnUnknownNameIsOff() {
        assertEquals(DeleteSourceMode.Off, deleteSourceModeFrom(null, legacy = null))
        assertEquals(DeleteSourceMode.Off, deleteSourceModeFrom("Maybe", legacy = null))
        assertEquals(DeleteSourceMode.On, deleteSourceModeFrom("Maybe", legacy = true))
    }

    @Test fun tappingCyclesOffOnAutomaticOff() {
        assertEquals(DeleteSourceMode.On, nextDeleteSourceMode(DeleteSourceMode.Off))
        assertEquals(DeleteSourceMode.Automatic, nextDeleteSourceMode(DeleteSourceMode.On))
        assertEquals(DeleteSourceMode.Off, nextDeleteSourceMode(DeleteSourceMode.Automatic))
    }

    @Test fun backupHappensOnlyWhenEnabledAndAnOlderVersionIsInstalled() {
        assertTrue(shouldBackupBeforeUpdate(true, "com.example.app", 12L))
        assertFalse("setting off", shouldBackupBeforeUpdate(false, "com.example.app", 12L))
        assertFalse("new install", shouldBackupBeforeUpdate(true, "com.example.app", null))
        assertFalse("unknown package", shouldBackupBeforeUpdate(true, null, 12L))
        assertFalse("blank package", shouldBackupBeforeUpdate(true, "  ", 12L))
    }
}
