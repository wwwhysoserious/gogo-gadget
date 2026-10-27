package app.gogogadget

import android.content.Context
import android.content.SharedPreferences

private const val HomePrefsName = "install_settings"
private const val KeyHomeShortcut = "home_shortcut"
private const val KeyDeleteApk = "delete_apk"

/** Persists the "Home screen shortcut" and "Delete APK after install" settings. */
class InstallSettingsStore(private val prefs: SharedPreferences) {
    constructor(context: Context) : this(
        context.applicationContext.getSharedPreferences(HomePrefsName, Context.MODE_PRIVATE),
    )

    var homeShortcut: Boolean
        get() = runCatching { prefs.getBoolean(KeyHomeShortcut, false) }.getOrDefault(false)
        set(value) {
            runCatching { prefs.edit().putBoolean(KeyHomeShortcut, value).apply() }
        }

    var deleteApk: Boolean
        get() = runCatching { prefs.getBoolean(KeyDeleteApk, false) }.getOrDefault(false)
        set(value) {
            runCatching { prefs.edit().putBoolean(KeyDeleteApk, value).apply() }
        }
}
