package app.gogogadget

import android.content.Context
import kotlinx.coroutines.sync.Mutex

/**
 * The few objects that must exist once per process: the pairing service and the connection model share the ADB
 * client (one key, one session), the lock that serialises every call that uses or deletes a key, the terminal log, and
 * the mDNS discovery (which counts its users).
 */
object Graph {
    @Volatile private var client: AdbClient? = null
    @Volatile private var nsd: DeviceDiscovery? = null

    /**
     * ADB calls run one at a time, whoever makes them: the model (connect, install, delete a key) and the pairing
     * service. A key is never deleted while a pairing or a connect is using it, or being made.
     */
    val adbLock = Mutex()

    /** Connecting, pairing and forgetting, oldest line first; also written by the pairing service. */
    val log = TerminalLog()

    fun adb(context: Context): AdbClient = client ?: synchronized(this) {
        client ?: LibAdbClient(context.applicationContext, log::add).also { client = it }
    }

    fun discovery(context: Context): DeviceDiscovery = nsd ?: synchronized(this) {
        nsd ?: NsdDiscovery(context.applicationContext).also { nsd = it }
    }
}
