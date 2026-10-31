package app.gogogadget

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Person
import android.app.RemoteInput
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

const val PairingNotificationId = 1
private const val CHANNEL_ID = "pairing"

/**
 * Lets the pairing service tell the running app that this phone is paired, so the app connects by itself. Null
 * while no [ConnectionModel] is alive.
 */
object PairingBridge {
    @Volatile
    var onPaired: (() -> Unit)? = null

    /** Told when the service's pairing failed, with the classified error and its [diagnostic] line (no code in it). */
    @Volatile
    var onFailed: ((AdbError, String) -> Unit)? = null

    /** True if an app model took the hand-over (and will connect). */
    fun paired(): Boolean {
        val listener = onPaired ?: return false
        listener()
        return true
    }

    fun failed(error: AdbError, detail: String) {
        onFailed?.invoke(error, detail)
    }
}

/**
 * The notifications of the "This device" pairing flow (the design of Shizuku's pairing service): searching, found
 * with the code input, working, and the result. None of them ever contains the code.
 */
class PairingNotifier(context: Context) {
    private val context = context.applicationContext
    private val manager = this.context.getSystemService(NotificationManager::class.java)

    /** False when the user has not granted POST_NOTIFICATIONS (Android 13+) or turned the app's notifications off. */
    fun canPost(): Boolean =
        (Build.VERSION.SDK_INT < 33 ||
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) &&
            manager.areNotificationsEnabled()

    /**
     * While the pairing dialog of this phone is not on screen yet: tells which menu item to choose, with a Stop action.
     * It switches to [found] by itself once the dialog appears.
     */
    fun searching(): Notification =
        base(context.getString(R.string.notif_guide_text))
            .setContentTitle(context.getString(R.string.notif_guide_title))
            .setStyle(Notification.BigTextStyle().bigText(context.getString(R.string.notif_guide_text)))
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, context.getString(R.string.notif_stop), stopIntent()).build())
            .build()

    /**
     * The pairing dialog of this phone was found: asks for the code. The [port] and the dialog's [host] travel in the
     * PendingIntent's extras, because the service can be killed before the user has typed anything. [message] replaces
     * the default text.
     *
     * Android has no public flag that keeps an inline reply field open. The closest thing is what messaging apps use:
     * a high-importance, public, ongoing MessagingStyle notification whose only action is a reply action (semantic
     * action REPLY, RemoteInput). The system then offers its reply field right on that action, and the heads-up
     * shows it too; on some versions/OEMs one tap on the action is still needed to open the keyboard.
     */
    fun found(port: Int, host: String? = null, message: Int? = null): Notification {
        val hint = context.getString(R.string.notif_hint)
        val input = RemoteInput.Builder(PairingService.KEY_CODE).setLabel(hint).build()
        val action = Notification.Action.Builder(null, hint, replyIntent(port, host))
            .addRemoteInput(input)
            .setAllowGeneratedReplies(false)
            .setSemanticAction(Notification.Action.SEMANTIC_ACTION_REPLY)
            .build()
        val system = Person.Builder().setName(context.getString(R.string.notif_sender)).build()
        val me = Person.Builder().setName(context.getString(R.string.notif_me)).build()
        val style = Notification.MessagingStyle(me)
            .setConversationTitle(context.getString(R.string.notif_title))
            .addMessage(context.getString(message ?: R.string.notif_prompt), System.currentTimeMillis(), system)
        return base(context.getString(message ?: R.string.notif_prompt))
            .setStyle(style)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setOngoing(true)
            .setOnlyAlertOnce(false)
            .addAction(action)
            .build()
    }

    /** Shown while pairing; also clears the reply spinner left by the inline input. */
    fun working(): Notification =
        base(context.getString(R.string.notif_working)).setOngoing(true).setProgress(0, 0, true).build()

    /**
     * Final state: a short [message] (a string resource), dismissible. [details] is the simple name of the exception
     * of a failure (never its message, never the code): it gets a "Details" line.
     */
    fun result(message: Int, details: String? = null): Notification {
        val text = failureText(context.getString(message), details?.let { context.getString(R.string.notif_details, it) })
        return base(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .setOnlyAlertOnce(false)
            .build()
    }

    fun post(notification: Notification) {
        if (canPost()) runCatching { manager.notify(PairingNotificationId, notification) }
    }

    /** Removes the pairing notification, e.g. once the code was typed in the app instead. */
    fun dismiss() {
        runCatching { manager.cancel(PairingNotificationId) }
    }

    private fun stopIntent(): PendingIntent = PendingIntent.getService(
        context, STOP_REQUEST, PairingService.stopIntent(context), PendingIntent.FLAG_IMMUTABLE,
    )

    // RemoteInput needs a mutable PendingIntent. It is explicit (our own service class), and its flags make a later
    // call with another port update the extras of this one.
    private fun replyIntent(port: Int, host: String?): PendingIntent = PendingIntent.getForegroundService(
        context, REPLY_REQUEST, PairingService.replyIntent(context, port, host),
        if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        else PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun base(text: String): Notification.Builder {
        // No sound, no badge, no bubbles: the notification is a form, not an alert.
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, context.getString(R.string.notif_channel), NotificationManager.IMPORTANCE_HIGH)
                .apply {
                    setSound(null, null)
                    setShowBadge(false)
                    setAllowBubbles(false)
                    lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                },
        )
        val open = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java).setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_pair)
            .setContentTitle(context.getString(R.string.notif_title))
            .setContentText(text)
            .setContentIntent(open)
            .setCategory(Notification.CATEGORY_STATUS)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .setOnlyAlertOnce(true)
            .apply { if (Build.VERSION.SDK_INT >= 31) setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE) }
    }

    private companion object {
        const val REPLY_REQUEST = 1
        const val STOP_REQUEST = 2
    }
}

/** What the connection model needs from the pairing service; faked in tests. */
interface PairingLauncher {
    fun canPost(): Boolean

    /** Starts searching for this phone's pairing dialog (a notification asks for the code). */
    fun start()

    /** Posts the pairing notification again from scratch (the user lost or dismissed it). */
    fun restart() {
        stop()
        start()
    }

    /** Stops the service (and with it the search and its notification). */
    fun stop()

    /** Removes the pairing notification (the pairing was done from the app). */
    fun dismiss()

    /** Final line in the notification once the connect that followed the pairing is over; [details] as in [PairingNotifier.result]. */
    fun report(message: Int, details: String? = null)
}

class ServicePairingLauncher(context: Context) : PairingLauncher {
    private val context = context.applicationContext
    private val notifier = PairingNotifier(this.context)

    override fun canPost() = notifier.canPost()

    override fun start() {
        // Refused when the app is not in the foreground (Android 12+): the in-app code field still works then.
        runCatching { context.startForegroundService(PairingService.startIntent(context)) }
    }

    override fun stop() {
        runCatching { context.stopService(Intent(context, PairingService::class.java)) }
    }

    override fun dismiss() = notifier.dismiss()

    override fun report(message: Int, details: String?) = notifier.post(notifier.result(message, details))
}
