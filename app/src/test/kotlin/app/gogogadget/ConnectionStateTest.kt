package app.gogogadget

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ConnectionStateTest {
    private fun connection(state: ConnectionState, local: Boolean? = null) =
        Connection(state, local?.let { Device("Pixel", "127.0.0.1", 37215, it) })

    @Test fun buttonFollowsState() {
        assertEquals(ButtonSpec(R.string.choose_device, ButtonAction.ChooseDevice), buttonFor(ConnectionState.NotConnected))
        assertEquals(ButtonSpec(R.string.choose_device, ButtonAction.ChooseDevice), buttonFor(ConnectionState.Error))
        assertEquals(ButtonSpec(R.string.cancel, ButtonAction.Cancel), buttonFor(ConnectionState.Pairing))
        assertEquals(ButtonSpec(R.string.cancel, ButtonAction.Cancel), buttonFor(ConnectionState.Connecting))
        assertEquals(ButtonSpec(R.string.choose_package, ButtonAction.ChoosePackage), buttonFor(ConnectionState.Connected))
    }

    @Test fun lineLabelOnlyOnceConnected() {
        assertNull(lineLabelFor(connection(ConnectionState.NotConnected)))
        assertNull(lineLabelFor(connection(ConnectionState.Pairing, local = true)))
        assertNull(lineLabelFor(connection(ConnectionState.Error, local = true)))
        assertNull(lineLabelFor(connection(ConnectionState.Connecting, local = true)))
        assertEquals(R.string.local, lineLabelFor(connection(ConnectionState.Connected, local = true)))
        assertEquals(R.string.network, lineLabelFor(connection(ConnectionState.Connected, local = false)))
    }

    @Test fun infoIsPerMethodUntilConnected() {
        for (state in listOf(ConnectionState.NotConnected, ConnectionState.Pairing, ConnectionState.Connecting, ConnectionState.Error)) {
            assertEquals(R.string.info_connect_title, infoFor(connection(state)).title)
        }
        val none = infoFor(connection(ConnectionState.NotConnected))
        assertEquals(R.string.info_connect_intro, none.intro)
        assertEquals(5, none.steps.size)
        val local = infoFor(connection(ConnectionState.Pairing, local = true))
        assertEquals(R.string.info_connect_local, local.intro)
        assertEquals(5, local.steps.size)
        val network = infoFor(connection(ConnectionState.Connecting, local = false))
        assertEquals(R.string.info_connect_network, network.intro)
        assertEquals(4, network.steps.size)
    }

    @Test fun infoShowsInstallStepsAndTellsLocalFromNetwork() {
        val local = infoFor(connection(ConnectionState.Connected, local = true))
        assertEquals(R.string.info_install_title, local.title)
        assertEquals(R.string.info_install_local, local.intro)
        assertEquals(5, local.steps.size)
        assertEquals(R.string.info_install_network, infoFor(connection(ConnectionState.Connected, local = false)).intro)
    }
}
