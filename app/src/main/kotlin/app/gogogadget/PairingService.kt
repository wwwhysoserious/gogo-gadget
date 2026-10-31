package app.gogogadget

import android.annotation.SuppressLint
import android.app.Notification
import android.app.RemoteInput
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * Pairs with this phone's own Wireless debugging, following Shizuku's design: a short foreground service shows a
 * "searching" notification, accepts only a pairing service that belongs to this phone ([acceptOwnPairing]), asks for
 * the code in the notification's inline reply (so the system pairing dialog can stay on screen), pairs to 127.0.0.1
 * (then to the dialog's own address if that is refused) and reports the result. The pairing runs under the shared ADB
 * lock ([Graph.adbLock]), so this phone's key is never deleted while it is in use. The code lives only in the reply's
 * result Intent and a local variable: it is never persisted, logged or put in a notification.
 *
 * All state below is touched on the main thread only.
 */
class PairingService : Service() {
    companion object {
        const val KEY_CODE = "pairing_code"
        private const val KEY_PORT = "pairing_port"
        private const val KEY_HOST = "pairing_host"
        private const val ACTION_START = "app.gogogadget.action.PAIRING_START"
        private const val ACTION_STOP = "app.gogogadget.action.PAIRING_STOP"
        private const val ACTION_REPLY = "app.gogogadget.action.PAIRING_REPLY"

        fun startIntent(context: Context): Intent =
            Intent(context, PairingService::class.java).setAction(ACTION_START)

        fun stopIntent(context: Context): Intent =
            Intent(context, PairingService::class.java).setAction(ACTION_STOP)

        fun replyIntent(context: Context, port: Int, host: String?): Intent =
            Intent(context, PairingService::class.java).setAction(ACTION_REPLY).putExtra(KEY_PORT, port).putExtra(KEY_HOST, host)
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var notifier: PairingNotifier
    private var search: Job? = null
    private var discovery: DeviceDiscovery? = null

    /** The pairing service of this phone's dialog (its own address and port); null while it is not on screen. */
    private var dialog: Endpoint? = null

    private var busy = false

    override fun onCreate() {
        super.onCreate()
        notifier = PairingNotifier(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                if (search == null) {
                    show(notifier.searching(), foreground = true)
                    startSearch()
                }
            }
            ACTION_REPLY -> reply(intent)
            ACTION_STOP -> shutdown()
            else -> stopSelf()
        }
        return START_NOT_STICKY
    }

    /** A short service has a time limit (Android 14+): stop cleanly when the system says so. */
    @SuppressLint("NewApi", "Override")
    override fun onTimeout(startId: Int) = shutdown()

    override fun onDestroy() {
        stopSearch()
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startSearch() {
        if (search != null) return
        val nsd = Graph.discovery(this).also { it.acquire() }
        discovery = nsd
        search = scope.launch {
            nsd.found
                .map { acceptOwnPairing(it, ownAddresses(), ::portInUse)?.let { f -> Endpoint(f.host, f.port) } }
                .distinctUntilChanged()
                .collect { seen -> withContext(Dispatchers.Main) { onPort(seen) } }
        }
    }

    private fun stopSearch() {
        search?.cancel()
        search = null
        discovery?.release()
        discovery = null
    }

    // Binding fails only when a service of this phone already listens on the port.
    private fun portInUse(port: Int): Boolean = isPortBoundLocally(port) {
        ServerSocket().use { socket -> socket.bind(InetSocketAddress(LoopbackHost, it), 1) }
    }

    private fun onPort(seen: Endpoint?) {
        val lost = dialog != null && seen == null
        dialog = seen
        if (seen != null && !busy) show(notifier.found(seen.port, seen.host), foreground = false)
        // The dialog was closed: the guide comes back.
        else if (lost && !busy) show(notifier.searching(), foreground = false)
    }

    private fun shutdown() {
        stopSearch()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun reply(intent: Intent) {
        // One pairing at a time.
        if (busy) return
        val raw = RemoteInput.getResultsFromIntent(intent)?.getCharSequence(KEY_CODE)
        val port = intent.getIntExtra(KEY_PORT, -1)
        val host = intent.getStringExtra(KEY_HOST)
        when (val decision = decideReply(raw, port)) {
            ReplyDecision.NoPort -> {
                // Nothing to pair with: look for the dialog again.
                show(notifier.searching(), foreground = true)
                startSearch()
            }
            ReplyDecision.BadCode -> {
                show(notifier.found(port, host, R.string.notif_bad_code), foreground = true)
                startSearch()
            }
            is ReplyDecision.Submit -> {
                show(notifier.working(), foreground = true)
                pair(decision.code, decision.port, host)
            }
        }
    }

    private fun pair(code: String, port: Int, seenHost: String?) {
        busy = true
        val hosts = servicePairingHosts(seenHost, ownAddresses())
        scope.launch(Dispatchers.IO) {
            // Under the shared ADB lock; every failure is classified, logged and returned, never thrown.
            val outcome = runLocalPairing(Graph.adb(this@PairingService), Graph.adbLock, hosts, port, code, Graph.log::add)
            withContext(Dispatchers.Main) { finish(outcome) }
        }
    }

    private fun finish(outcome: PairOutcome) {
        busy = false
        val failure = outcome as? PairOutcome.Failed
        val message = if (failure == null) {
            // The app connects by itself when it is running; otherwise the user opens it.
            if (PairingBridge.paired()) R.string.notif_paired_connecting else R.string.notif_paired_open_app
        } else {
            PairingBridge.failed(failure.error, failure.detail)
            failure.error.message
        }
        stopSearch()
        stopForeground(STOP_FOREGROUND_REMOVE)
        notifier.post(notifier.result(message, failure?.exceptionName))
        // Back to the app after a successful pairing, where the OS allows it; the notification's tap opens it otherwise.
        if (failure == null) openApp()
        stopSelf()
    }

    private fun openApp() {
        runCatching {
            startActivity(
                Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            )
        }
    }

    private fun show(notification: Notification, foreground: Boolean) {
        if (foreground) {
            try {
                startForeground(PairingNotificationId, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST)
                return
            } catch (e: Exception) {
                // ForegroundServiceStartNotAllowedException (Android 12+): a plain notification instead.
            }
        }
        notifier.post(notification)
    }
}
