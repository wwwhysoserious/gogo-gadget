package app.gogogadget

enum class ConnectionState { NotConnected, Pairing, Connecting, Connected, Error }

/** The device the app is connected (or connecting) to. [local] is decided by [isLocalHost]. */
data class Device(val name: String, val host: String, val port: Int, val local: Boolean)

data class Connection(
    val state: ConnectionState = ConnectionState.NotConnected,
    val device: Device? = null,
    val error: AdbError? = null,
    /** Exception class and sanitised message, shown under the error (see [diagnostic]). */
    val detail: String? = null,
    /** Short line under "Connecting…": where to tap Allow (a string resource). */
    val note: Int? = null,
)

enum class ButtonAction { ChooseDevice, Cancel, ChoosePackage }

data class ButtonSpec(val label: Int, val action: ButtonAction)

fun buttonFor(state: ConnectionState): ButtonSpec = when (state) {
    ConnectionState.NotConnected, ConnectionState.Error -> ButtonSpec(R.string.choose_device, ButtonAction.ChooseDevice)
    ConnectionState.Pairing, ConnectionState.Connecting -> ButtonSpec(R.string.cancel, ButtonAction.Cancel)
    ConnectionState.Connected -> ButtonSpec(R.string.choose_package, ButtonAction.ChoosePackage)
}

/** Label on the panel line; only once the connection exists. */
fun lineLabelFor(connection: Connection): Int? = connection.device?.takeIf {
    connection.state == ConnectionState.Connected
}?.let { if (it.local) R.string.local else R.string.network }

/** What the "i" balloon shows: a title, an optional intro line and numbered steps (string resources). */
data class InfoContent(val title: Int, val intro: Int?, val steps: List<Int>)

/** Before a device is chosen: both methods in short. */
private val GeneralConnectInfo = InfoContent(
    R.string.info_connect_title,
    R.string.info_connect_intro,
    listOf(R.string.connect_step_1, R.string.general_step_2, R.string.general_step_3, R.string.general_step_4,
        R.string.general_step_5),
)

/** This device: Wireless debugging of this phone, the code typed in a notification. */
private val LocalConnectInfo = InfoContent(
    R.string.info_connect_title,
    R.string.info_connect_local,
    listOf(R.string.connect_step_1, R.string.connect_step_2, R.string.local_step_3, R.string.local_step_4,
        R.string.local_step_5),
)

/** Another device on the network: connect first, the other device asks to Allow. */
private val NetworkConnectInfo = InfoContent(
    R.string.info_connect_title,
    R.string.info_connect_network,
    listOf(R.string.network_step_1, R.string.network_step_2, R.string.network_step_3, R.string.network_step_4),
)

private fun installInfo(local: Boolean) = InfoContent(
    R.string.info_install_title,
    if (local) R.string.info_install_local else R.string.info_install_network,
    listOf(
        R.string.install_step_1, R.string.install_step_2, R.string.install_step_3,
        R.string.install_step_4, R.string.install_step_5,
    ),
)

fun infoFor(connection: Connection): InfoContent = when {
    connection.state == ConnectionState.Connected -> installInfo(connection.device?.local ?: true)
    connection.device == null -> GeneralConnectInfo
    connection.device.local -> LocalConnectInfo
    else -> NetworkConnectInfo
}
