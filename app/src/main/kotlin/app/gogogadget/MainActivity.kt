package app.gogogadget

import android.Manifest
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.content.ActivityNotFoundException
import android.content.res.Configuration
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
                var infoOpen by rememberSaveable { mutableStateOf(false) }
                var devicesOpen by rememberSaveable { mutableStateOf(false) }
                val connection = model.connection
                val found by model.found.collectAsState()
                // Pairing this phone: ask for the notification permission once, right when it is needed.
                val pairingThisDevice = connection.state == ConnectionState.Pairing && connection.device?.local == true
                LaunchedEffect(pairingThisDevice, notificationsOk) {
                    if (Build.VERSION.SDK_INT >= 33 && pairingThisDevice && !notificationsOk && !askedForNotifications) allowNotifications()
                }
                // A null Uri means the picker was cancelled; no picker app at all is reported too.
                val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
                    model.installFrom(uri)
                }
                DisposableEffect(devicesOpen) {
                    model.scanForPicker(devicesOpen)
                    onDispose { model.scanForPicker(false) }
                }
                // Back closes the info balloon, then the device list, then the Settings sub-screens, then returns to Install.
                BackHandler(infoOpen || devicesOpen || tab != Tab.Install) {
                    if (infoOpen) infoOpen = false
                    else if (devicesOpen) devicesOpen = false
                    else if (tab == Tab.Settings && themeOpen) themeOpen = false
                    else if (tab == Tab.Settings && vtKeyOpen) vtKeyOpen = false
                    else tab = Tab.Install
                }
                Column(Modifier.fillMaxSize().background(Color(palette.background)).windowInsetsPadding(WindowInsets.safeDrawing)) {
                    Box(Modifier.weight(1f).fillMaxWidth()) {
                        when (tab) {
                            Tab.Install -> if (devicesOpen) {
                                val own = remember(found) { ownAddresses() }
                                DevicesScreen(
                                    palette = palette,
                                    thisDevice = model.thisDevice(),
                                    found = found,
                                    ownAddresses = own,
                                    recent = model.recent,
                                    connected = connection.state == ConnectionState.Connected,
                                    onBack = { devicesOpen = false },
                                    onThisDevice = { devicesOpen = false; model.connect(model.thisDevice()) },
                                    onFound = {
                                        devicesOpen = false
                                        val target = Target(it.name.orEmpty(), it.host, 0)
                                        when (val tap = tapAction(it)) {
                                            is TapAction.Connect -> model.connect(target.copy(port = tap.port))
                                            is TapAction.Pair -> model.startPairing(target, tap.pairPort)
                                        }
                                    },
                                    onManual = { endpoint, pair ->
                                        devicesOpen = false
                                        if (pair) model.startPairing(Target(endpoint.host, endpoint.host, 0), endpoint.port)
                                        else model.connect(Target(endpoint.host, endpoint.host, endpoint.port))
                                    },
                                    onRecent = { devicesOpen = false; model.connect(it) },
                                    onDisconnect = { devicesOpen = false; model.cancel() },
                                )
                            } else HomeScreen(
                                palette = palette,
                                connection = connection,
                                install = model.install.takeIf { connection.state == ConnectionState.Connected },
                                infoOpen = infoOpen,
                                pairPort = model.pairPort,
                                onCode = { model.submitCode(it) },
                                onRepost = model::repostNotification,
                                notificationsOk = notificationsOk,
                                onAllowNotifications = ::allowNotifications,
                                onOpenDeveloperOptions = ::openDeveloperOptions,
                                onInfoToggle = { infoOpen = !infoOpen },
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
                            Tab.Backups -> BackupsScreen(palette)
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
                                onVtKeyOpen = { vtKeyOpen = it },
                            )
                        }
                    }
                    BottomBar(palette, tab) { tab = it; themeOpen = false; vtKeyOpen = false }
                }
            }
        }
    }
}

