package app.gogogadget

import android.Manifest
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.content.ActivityNotFoundException
import android.content.res.Configuration
import android.net.Uri
import android.graphics.Color.TRANSPARENT
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color

private const val PREFS = "settings"
private const val KEY_THEME = "theme"
const val SUPPORTED_FORMATS = "APK · APKS · XAPK · APKM · ZIP"

class MainActivity : ComponentActivity() {
    private val model: ConnectionModel by viewModels()
    private var appliedBars: Pair<Boolean, Long>? = null

    /** Whether the pairing notification can be shown; refreshed on resume (e.g. back from the system settings). */
    private var notificationsOk by mutableStateOf(true)
    private var askedForNotifications = false

    private fun refreshNotifications() {
        val before = notificationsOk
        notificationsOk = model.notificationsAllowed()
        if (notificationsOk && !before) model.notificationsChanged()
    }

    override fun onResume() {
        super.onResume()
        refreshNotifications()
        // In front again: the saved devices are probed at once and the connected session is looked after (pings only in front).
        model.appVisible(true)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        receiveIncoming(intent)
    }

    /** A package opened with GoGo ("Open with") or shared to it: copied at once, because the grant is temporary. */
    private fun receiveIncoming(intent: Intent) {
        val uri = when (intent.action) {
            Intent.ACTION_VIEW -> intent.data
            Intent.ACTION_SEND ->
                if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                else @Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_STREAM)
            else -> null
        } ?: return
        model.receiveFile(uri)
    }

    override fun onPause() {
        model.appVisible(false)
        super.onPause()
    }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { refreshNotifications() }

    /** First tap shows the system prompt (Android 13+); if it was refused, later taps open the app's notification settings. */
    private fun allowNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && !askedForNotifications) {
            askedForNotifications = true
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            startActivity(
                Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName),
            )
        }
    }

    /** Opens Developer options at the Wireless debugging switch (as Shizuku does); older screens just open the list. */
    private fun openDeveloperOptions() {
        try {
            startActivity(
                Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS).putExtra(":settings:fragment_args_key", "toggle_adb_wireless"),
            )
        } catch (e: ActivityNotFoundException) {
            // No Developer options screen on this device: nothing to open.
        }
    }

    /** Re-applies system bar styles and window background only when the palette's look changes. */
    private fun applyPalette(palette: Palette) {
        val key = palette.isDark to palette.background
        if (key == appliedBars) return
        appliedBars = key
        val bars = if (palette.isDark) {
            SystemBarStyle.dark(TRANSPARENT)
        } else {
            SystemBarStyle.light(TRANSPARENT, TRANSPARENT)
        }
        enableEdgeToEdge(statusBarStyle = bars, navigationBarStyle = bars)
        window.isNavigationBarContrastEnforced = false
        window.setBackgroundDrawable(ColorDrawable(palette.background.toInt()))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // After a rotation or process restart the same intent comes back; its file was already taken.
        if (savedInstanceState == null) receiveIncoming(intent)
        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        var setting by mutableStateOf(themeSettingFromName(prefs.getString(KEY_THEME, null)))
        val systemDark = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES
        // Before the first frame, so the window never shows the system theme's colours.
        applyPalette(resolvePalette(setting, systemDark))
        setContent {
            val palette = resolvePalette(setting, isSystemInDarkTheme())
            LaunchedEffect(palette.isDark, palette.background) { applyPalette(palette) }
            GoGoTheme(palette) {
                var tab by rememberSaveable { mutableStateOf(Tab.Install) }
                var themeOpen by rememberSaveable { mutableStateOf(false) }
                var vtKeyOpen by rememberSaveable { mutableStateOf(false) }
                var vtKeyFromHome by rememberSaveable { mutableStateOf(false) }
                var infoOpen by rememberSaveable { mutableStateOf(false) }
                var howOpen by rememberSaveable { mutableStateOf(false) }
                var keysVersion by rememberSaveable { mutableStateOf(0) }
                val shieldStore = remember { ShieldSettingsStore(this@MainActivity) }
                val installStore = remember { InstallSettingsStore(this@MainActivity) }
                // First launch only, and never for someone who already has a key: recommend the API keys once.
                var welcomeOpen by rememberSaveable { mutableStateOf(!installStore.welcomeSeen && !shieldStore.hasAnyApiKey()) }
                var devicesOpen by rememberSaveable { mutableStateOf(false) }
                val connection = model.connection
                val found by model.found.collectAsState()
                val terminal by model.terminal.collectAsState()
                // Pairing this phone: ask for the notification permission once, right when it is needed.
                val pairingThisDevice = connection.state == ConnectionState.Pairing && connection.device?.local == true
                LaunchedEffect(pairingThisDevice, notificationsOk) {
                    if (Build.VERSION.SDK_INT >= 33 && pairingThisDevice && !notificationsOk && !askedForNotifications) allowNotifications()
                }
                // A null Uri means the picker was cancelled; no picker app at all is reported too.
                val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
                    model.installFrom(uri)
                }
                // A file waiting for a device or for the running install starts as soon as both allow it.
                LaunchedEffect(model.pendingFile, connection.state, model.install?.working) { model.startPendingFile() }
                DisposableEffect(devicesOpen) {
                    model.scanForPicker(devicesOpen)
                    onDispose { model.scanForPicker(false) }
                }
                // Back closes the info balloon, then the device list, then the Settings sub-screens, then returns to Install.
                BackHandler(infoOpen || devicesOpen || howOpen || tab != Tab.Install) {
                    if (infoOpen) infoOpen = false
                    else if (howOpen) howOpen = false
                    else if (devicesOpen) devicesOpen = false
                    else if (tab == Tab.Settings && themeOpen) themeOpen = false
                    else if (tab == Tab.Settings && vtKeyOpen) {
                        vtKeyOpen = false
                        if (vtKeyFromHome) {
                            vtKeyFromHome = false
                            tab = Tab.Install
                        }
                    }
                    else tab = Tab.Install
                }
                val menu = remember(model.recent, model.reachable, model.subnets, connection) {
                    val own = ownAddresses()
                    deviceMenuEntries(
                        model.thisDevice(), model.recent, model.subnets, model.reachable,
                        connection.device?.takeIf { connection.state == ConnectionState.Connected }?.host, own,
                    )
                }
                // Maximum protection means the Shield is enabled, an online key is set and the deep scan is on: without the
                // deep scan the dropper, adware, permission and native-library rules do not run.
                var shieldVersion by rememberSaveable { mutableStateOf(0) }
                val isMaximum = remember(tab, keysVersion, shieldVersion, welcomeOpen) {
                    shieldStore.shieldEnabled && shieldStore.hasAnyApiKey() && shieldStore.deepScanEnabled
                }
                Column(Modifier.fillMaxSize().background(Color(palette.background)).windowInsetsPadding(WindowInsets.safeDrawing)) {
                    if (welcomeOpen) {
                        Box(Modifier.weight(1f).fillMaxWidth()) {
                            WelcomeScreen(
                                palette,
                                onSetUp = { installStore.welcomeSeen = true; welcomeOpen = false; tab = Tab.Settings; vtKeyOpen = true; vtKeyFromHome = true },
                                onSkip = { installStore.welcomeSeen = true; welcomeOpen = false },
                            )
                        }
                        return@Column
                    }
                    Box(Modifier.weight(1f).fillMaxWidth()) {
                        when (tab) {
                            Tab.Install -> if (howOpen) {
                                HowItWorksScreen(palette, onBack = { howOpen = false })
                            } else if (devicesOpen) {
                                val own = remember(found) { ownAddresses() }
                                DevicesScreen(
                                    palette = palette,
                                    sections = menu,
                                    found = found,
                                    ownAddresses = own,
                                    onOpen = { model.probeDevices() },
                                    onRefresh = { model.probeDevices() },
                                    onBack = { devicesOpen = false },
                                    onSelect = { devicesOpen = false; model.connect(it) },
                                    onFound = {
                                        devicesOpen = false
                                        val target = Target(it.name.orEmpty(), it.host, 0)
                                        when (val tap = tapAction(it)) {
                                            is TapAction.Connect -> model.connect(target.copy(port = tap.port))
                                            is TapAction.Pair -> model.startPairing(target, tap.pairPort)
                                        }
                                    },
                                    onManual = { endpoint, pair, customName ->
                                        devicesOpen = false
                                        val devName = customName ?: endpoint.host
                                        if (pair) model.startPairing(Target(devName, endpoint.host, 0), endpoint.port)
                                        else model.connect(Target(devName, endpoint.host, endpoint.port))
                                    },
                                    onForget = model::forget,
                                )
                            } else HomeScreen(
                                palette = palette,
                                connection = connection,
                                install = model.install.takeIf { connection.state == ConnectionState.Connected },
                                infoOpen = infoOpen,
                                pairPort = model.pairPort,
                                onCode = { model.submitCode(it) },
                                onRepost = model::repostNotification,
                                onOpenDeveloperOptions = ::openDeveloperOptions,
                                onInfoToggle = { infoOpen = !infoOpen },
                                onConfirmUpload = model::confirmUpload,
                                onCancelUpload = model::cancelUpload,
                                onConfirmCaution = model::confirmCaution,
                                onCancelCaution = model::cancelCaution,
                                onDeleteSource = model::deleteSourcePackage,
                                pendingName = model.pendingFile?.name,
                                onCancelPending = model::cancelPendingFile,
                                log = terminal,
                                menu = menu,
                                onSelectDevice = { model.connect(it) },
                                onAddDevice = { devicesOpen = true },
                                onMenuOpen = { model.probeDevices() },
                                onMenuRefresh = { model.probeDevices() },
                                maximumProtection = isMaximum,
                                hasSecurityKeys = shieldStore.hasAnyApiKey(),
                                onStartActivation = {
                                    shieldStore.shieldEnabled = true
                                    // Maximum protection includes the deep scan.
                                    shieldStore.deepScanEnabled = true
                                    shieldVersion++
                                },
                                onStartDeactivation = {
                                    shieldStore.shieldEnabled = false
                                    shieldVersion++
                                },
                                onOpenSecurityApis = {
                                    if (shieldStore.hasAnyApiKey()) {
                                        shieldStore.shieldEnabled = !shieldStore.shieldEnabled
                                        shieldVersion++
                                    } else {
                                        tab = Tab.Settings
                                        vtKeyOpen = true
                                        vtKeyFromHome = true
                                    }
                                },
                                onHowItWorks = { howOpen = true },
                                onButton = { action ->
                                    when (action) {
                                        ButtonAction.ChooseDevice -> devicesOpen = true
                                        ButtonAction.Cancel -> model.cancel()
                                        ButtonAction.ChoosePackage -> if (model.install?.working != true) try {
                                            picker.launch(arrayOf("*/*"))
                                        } catch (e: ActivityNotFoundException) {
                                            model.installUnavailable()
                                        }
                                    }
                                },
                            )
                            Tab.Backups -> BackupsScreen(
                                palette = palette,
                                backups = model.backups,
                                isWorking = model.install?.working == true,
                                onRevert = { backup ->
                                    model.revertBackup(backup)
                                    tab = Tab.Install
                                },
                                onDelete = { backup ->
                                    model.deleteBackup(backup)
                                },
                                connectedDeviceId = model.connection.device?.takeIf { model.connection.state == ConnectionState.Connected }?.backupId(),
                                connectedDeviceName = model.connection.device?.name,
                                onRevertMany = { list ->
                                    model.revertBackups(list)
                                    tab = Tab.Install
                                },
                                onDeleteMany = { list -> model.deleteBackups(list) },
                                onGoToInstall = { tab = Tab.Install },
                            )
                            Tab.Settings -> SettingsScreen(
                                palette = palette,
                                selected = setting,
                                themeOpen = themeOpen,
                                onThemeOpen = { themeOpen = it },
                                onSelect = {
                                    setting = it
                                    prefs.edit().putString(KEY_THEME, it.name).apply()
                                },
                                vtKeyOpen = vtKeyOpen,
                                onVtKeyOpen = { open ->
                                    vtKeyOpen = open
                                    if (!open && vtKeyFromHome) {
                                        vtKeyFromHome = false
                                        tab = Tab.Install
                                    }
                                },
                                onKeysChanged = {
                                    keysVersion++
                                    // Verdicts stored for a key that was just changed or removed are not trusted any more.
                                    model.clearReputationCache()
                                },
                            )
                        }
                    }
                    BottomBar(palette, tab) { tab = it; themeOpen = false; vtKeyOpen = false; howOpen = false; vtKeyFromHome = false }
                }
            }
        }
    }
}

