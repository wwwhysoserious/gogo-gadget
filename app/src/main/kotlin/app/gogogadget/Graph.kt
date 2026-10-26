package app.gogogadget

import android.content.Context

/**
 * The few objects that must exist once per process: the pairing service and the connection model share the ADB
 * client (one key, one session) and the mDNS discovery (which counts its users).
 */
object Graph {
    @Volatile private var client: AdbClient? = null
    @Volatile private var nsd: DeviceDiscovery? = null

    fun adb(context: Context): AdbClient = client ?: synchronized(this) {
        client ?: LibAdbClient(context.applicationContext).also { client = it }
    }

    fun discovery(context: Context): DeviceDiscovery = nsd ?: synchronized(this) {
        nsd ?: NsdDiscovery(context.applicationContext).also { nsd = it }
    }
}
