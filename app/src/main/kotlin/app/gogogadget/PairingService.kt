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

private const val LOOPBACK_HOST = "127.0.0.1"

/**
 * Pairs with this phone's own Wireless debugging, following Shizuku's design: a short foreground service shows a
 * "searching" notification, accepts only a pairing service that belongs to this phone ([acceptOwnPairing]), asks for
 * the code in the notification's inline reply (so the system pairing dialog can stay on screen), pairs to 127.0.0.1
 * and reports the result. The code lives only in the reply's result Intent and a local variable: it is never
 * persisted, logged or put in a notification.
 *
 * All state below is touched on the main thread only.
 */
class PairingService : Service() {
    companion object {
        const val KEY_CODE = "pairing_code"
        private const val KEY_PORT = "pairing_port"
        private const val ACTION_START = "app.gogogadget.action.PAIRING_START"
        private const val ACTION_STOP = "app.gogogadget.action.PAIRING_STOP"
        private const val ACTION_REPLY = "app.gogogadget.action.PAIRING_REPLY"

        fun startIntent(context: Context): Intent =
            Intent(context, PairingService::class.java).setAction(ACTION_START)

        fun stopIntent(context: Context): Intent =
            Intent(context, PairingService::class.java).setAction(ACTION_STOP)

        fun replyIntent(context: Context, port: Int): Intent =
            Intent(context, PairingService::class.java).setAction(ACTION_REPLY).putExtra(KEY_PORT, port)
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var notifier: PairingNotifier
    private var search: Job? = null
    private var discovery: DeviceDiscovery? = null

    /** The pairing port of this phone's dialog; null while it is not on screen. */
    private var port: Int? = null

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
                .map { acceptOwnPairing(it, ownAddresses(), ::portInUse)?.port }
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
        ServerSocket().use { socket -> socket.bind(InetSocketAddress(LOOPBACK_HOST, it), 1) }
    }

    private fun onPort(seen: Int?) {
        port = seen
        if (seen != null && !busy) show(notifier.found(seen), foreground = false)
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
        when (val decision = decideReply(raw, port)) {
            ReplyDecision.NoPort -> {
                // Nothing to pair with: look for the dialog again.
                show(notifier.searching(), foreground = true)
                startSearch()
            }
            ReplyDecision.BadCode -> {
                show(notifier.found(port, R.string.notif_bad_code), foreground = true)
                startSearch()
            }
            is ReplyDecision.Submit -> {
                show(notifier.working(), foreground = true)
                pair(decision.code, decision.port)
            }
        }
    }

    private fun pair(code: String, port: Int) {
        busy = true
        scope.launch(Dispatchers.IO) {
            val error = try {
                Graph.adb(this@PairingService).pair(LOOPBACK_HOST, port, code)
                null
            } catch (e: Exception) {
                e
            }
            withContext(Dispatchers.Main) { finish(error) }
        }
    }

    private fun finish(error: Exception?) {
        busy = false
        val message = if (error == null) {
            // The app connects by itself when it is running; otherwise the user opens it.
            if (PairingBridge.paired()) R.string.notif_paired_connecting else R.string.notif_paired_open_app
        } else {
            classifyError(error, Phase.Pair, local = true).message
        }
        stopSearch()
        stopForeground(STOP_FOREGROUND_REMOVE)
        notifier.post(notifier.result(message))
        stopSelf()
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
