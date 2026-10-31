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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
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

    /** Adds the hosts a subnet scan found answering on their ADB port; the previous scan's results are replaced. */
    fun publishProbed(items: List<Found>)
}

/** Active sweep of the /24 of this phone's private LAN addresses. Tailscale or other VPN devices are never discovered, only added by hand. */
object SubnetScanner {
    const val PORT = 5555
    const val TIMEOUT_MS = 600
    const val PARALLEL = 48
    private const val MAX_SUBNETS = 4

    /** Hosts worth a probe: .1-.254 of each /24 of this phone's private LAN addresses (never 100.64.0.0/10). Never this phone. */
    fun candidates(own: Collection<String>): List<String> {
        val ownNorm = own.map(::normalise).toSet()
        val lan = own.map { it.trim().substringBefore('%') }.filter(::isPrivateLanV4).mapNotNull(::subnetOf).distinct()
        return lan.take(MAX_SUBNETS).flatMap { subnet -> (1..254).map { "$subnet.$it" } }
            .map(::normalise).filter { it !in ownNorm }.distinct()
    }

    /** Probes [hosts] on [PORT] at most [PARALLEL] at a time and returns those that accept a connection, as Connect entries. */
    suspend fun scan(
        hosts: List<String>,
        names: Map<String, String> = emptyMap(),
        reachable: (String, Int, Int) -> Boolean = ::tcpOpen,
    ): List<Found> = withContext(Dispatchers.IO) {
        val gate = Semaphore(PARALLEL)
        hosts.map { host -> async { gate.withPermit { host.takeIf { reachable(it, PORT, TIMEOUT_MS) } } } }
            .awaitAll().filterNotNull()
            .map { host -> Found(names[normalise(host)] ?: resolveName(host), host, PORT, FoundKind.Connect) }
    }

    private fun tcpOpen(host: String, port: Int, timeoutMs: Int): Boolean = try {
        Socket().use { it.connect(InetSocketAddress(host, port), timeoutMs) }
        true
    } catch (e: IOException) {
        false
    }

    /** The reverse-DNS name when the network has one, otherwise the IP. */
    private suspend fun resolveName(host: String): String {
        val name = withTimeoutOrNull(1_000) {
            withContext(Dispatchers.IO) { runCatching { InetAddress.getByName(host).canonicalHostName }.getOrNull() }
        }
        return name?.takeIf { it.isNotBlank() && it != host } ?: host
    }
}

/** Every address of this device's own network interfaces. */
fun ownAddresses(): Set<String> = runCatching {
    // One broken interface (a tun or tailscale one coming up or down) must not hide the others.
    NetworkInterface.getNetworkInterfaces().toList()
        .flatMap { runCatching { it.inetAddresses.toList() }.getOrDefault(emptyList()) }
        .mapNotNull { it.hostAddress?.substringBefore('%') }
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
        probed = emptyList()
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

    private var probed: List<Found> = emptyList()

    @Synchronized
    override fun publishProbed(items: List<Found>) {
        if (users == 0) return
        val old = probed.toSet()
        probed = items
        state.update { list ->
            val kept = list.filterNot { it in old }
            // An mDNS entry for the same host is better (real port and name): the sweep only fills the gaps.
            kept + items.filter { i -> kept.none { it.kind == FoundKind.Connect && normalise(it.host) == normalise(i.host) } }
        }
    }

    private fun publish(resolved: NsdServiceInfo, kind: FoundKind) {
        val host = hostOf(resolved) ?: return
        if (resolved.port <= 0) return
        val item = Found(resolved.serviceName, host, resolved.port, kind)
        state.update { list -> list.filterNot { it.name == item.name && it.kind == kind } + item }
    }
}
