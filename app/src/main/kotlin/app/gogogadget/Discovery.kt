package app.gogogadget

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import androidx.annotation.RequiresApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.concurrent.Executor

/** Wireless Debugging and TV remote services on the network, found by mDNS. */
interface DeviceDiscovery {
    val found: StateFlow<List<Found>>

    /** Discovery runs while at least one caller has acquired it. */
    fun acquire()
    fun release()

    /** Starts the discovery over, to catch a service that appeared while it was running. */
    fun restart()
}

/** Every address of this device's own network interfaces. */
fun ownAddresses(): Set<String> = runCatching {
    NetworkInterface.getNetworkInterfaces().toList()
        .flatMap { it.inetAddresses.toList() }
        .mapNotNull { it.hostAddress }
        .toSet()
}.getOrDefault(emptySet())

/** One instance for the whole app: the pairing service and the model share it, and it counts its users. */
class NsdDiscovery(context: Context) : DeviceDiscovery {
    private val appContext = context.applicationContext
    private val nsd = appContext.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val state = MutableStateFlow<List<Found>>(emptyList())
    override val found = state.asStateFlow()

    private var users = 0
    private var lock: WifiManager.MulticastLock? = null
    private val listeners = mutableListOf<NsdManager.DiscoveryListener>()

    // Android 12-13 resolve one service at a time, so those go through a queue.
    private val queue = ArrayDeque<Pair<NsdServiceInfo, FoundKind>>()
    private var resolving = false

    // Android 14+: one callback per service keeps its address and port up to date.
    private val callbacks = HashMap<String, Any>()

    // Callbacks run inline on NSD's own thread: a private executor that was shut down would reject late callbacks.
    private val inline = Executor(Runnable::run)

    @Synchronized
    override fun acquire() {
        if (users++ > 0) return
        startListeners()
    }

    @Synchronized
    override fun restart() {
        if (users == 0) return
        stopListeners()
        startListeners()
    }

    @Synchronized
    override fun release() {
        if (users == 0 || --users > 0) return
        stopListeners()
        state.value = emptyList()
    }

    private fun startListeners() {
        // NSD drops multicast packets unless the app holds this lock.
        lock = runCatching {
            appContext.getSystemService(WifiManager::class.java).createMulticastLock("gogogadget").apply {
                setReferenceCounted(false)
                acquire()
            }
        }.getOrNull()
        FoundKind.entries.forEach { kind ->
            val listener = listenerFor(kind)
            listeners += listener
            runCatching { nsd.discoverServices(type(kind), NsdManager.PROTOCOL_DNS_SD, listener) }
        }
    }

    private fun stopListeners() {
        listeners.forEach { runCatching { nsd.stopServiceDiscovery(it) } }
        listeners.clear()
        queue.clear()
        if (Build.VERSION.SDK_INT >= 34) unregisterAll()
        callbacks.clear()
        runCatching { lock?.release() }
        lock = null
    }

    @RequiresApi(34)
    private fun unregisterAll() {
        callbacks.values.forEach { runCatching { nsd.unregisterServiceInfoCallback(it as NsdManager.ServiceInfoCallback) } }
    }

    private fun type(kind: FoundKind) = when (kind) {
        FoundKind.Connect -> "_adb-tls-connect._tcp"
        FoundKind.Pairing -> "_adb-tls-pairing._tcp"
        FoundKind.Remote -> "_androidtvremote2._tcp"
    }

    private fun listenerFor(kind: FoundKind) = object : NsdManager.DiscoveryListener {
        override fun onServiceFound(info: NsdServiceInfo) = watch(info, kind)
        override fun onServiceLost(info: NsdServiceInfo) = forget(info.serviceName, kind)
        override fun onDiscoveryStarted(serviceType: String) {}
        override fun onDiscoveryStopped(serviceType: String) {}
        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {}
        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
    }

    private fun forget(name: String, kind: FoundKind) {
        state.update { list -> list.filterNot { it.name == name && it.kind == kind } }
        if (Build.VERSION.SDK_INT >= 34) unregister(name, kind)
    }

    @RequiresApi(34)
    @Synchronized
    private fun unregister(name: String, kind: FoundKind) {
        val cb = callbacks.remove(name + "|" + kind) as NsdManager.ServiceInfoCallback? ?: return
        runCatching { nsd.unregisterServiceInfoCallback(cb) }
    }

    @Synchronized
    private fun watch(info: NsdServiceInfo, kind: FoundKind) {
        if (Build.VERSION.SDK_INT >= 34) {
            // NSD announces the same service again on every refresh; one callback per service is enough.
            val key = info.serviceName + "|" + kind
            if (key in callbacks) return
            callbacks[key] = register(info, kind)
        } else {
            queue.addLast(info to kind)
            resolveNext()
        }
    }

    @RequiresApi(34)
    private fun register(info: NsdServiceInfo, kind: FoundKind): NsdManager.ServiceInfoCallback {
        val cb = object : NsdManager.ServiceInfoCallback {
            override fun onServiceUpdated(resolved: NsdServiceInfo) = publish(resolved, kind)
            override fun onServiceLost() = forget(info.serviceName, kind)
            override fun onServiceInfoCallbackRegistrationFailed(errorCode: Int) {}
            override fun onServiceInfoCallbackUnregistered() {}
        }
        nsd.registerServiceInfoCallback(info, inline, cb)
        return cb
    }

    @Synchronized
    private fun resolveNext() {
        if (resolving) return
        val (info, kind) = queue.removeFirstOrNull() ?: return
        resolving = true
        @Suppress("DEPRECATION") // The replacement needs API 34; minSdk is 30.
        nsd.resolveService(info, object : NsdManager.ResolveListener {
            override fun onServiceResolved(resolved: NsdServiceInfo) {
                publish(resolved, kind)
                done()
            }

            override fun onResolveFailed(failed: NsdServiceInfo, errorCode: Int) = done()
        })
    }

    @Synchronized
    private fun done() {
        resolving = false
        resolveNext()
    }

    /** IPv4 first: that is what other devices on a home network answer on. */
    @Suppress("DEPRECATION")
    private fun hostOf(info: NsdServiceInfo): String? {
        val address = if (Build.VERSION.SDK_INT >= 34) {
            info.hostAddresses.let { all -> all.firstOrNull { it is Inet4Address } ?: all.firstOrNull() }
        } else {
            info.host
        }
        return address?.hostAddress
    }

    private fun publish(resolved: NsdServiceInfo, kind: FoundKind) {
        val host = hostOf(resolved) ?: return
        if (resolved.port <= 0) return
        val item = Found(resolved.serviceName, host, resolved.port, kind)
        state.update { list -> list.filterNot { it.name == item.name && it.kind == kind } + item }
    }
}
