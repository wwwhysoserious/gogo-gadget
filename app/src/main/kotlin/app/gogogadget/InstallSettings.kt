package app.gogogadget

import android.content.Context
import android.content.SharedPreferences

private const val HomePrefsName = "install_settings"
private const val KeyHomeShortcut = "home_shortcut"

/** Persists the "Home screen shortcut" switch (default off). */
class InstallSettingsStore(private val prefs: SharedPreferences) {
    constructor(context: Context) : this(
        context.applicationContext.getSharedPreferences(HomePrefsName, Context.MODE_PRIVATE),
    )

    var homeShortcut: Boolean
        get() = runCatching { prefs.getBoolean(KeyHomeShortcut, false) }.getOrDefault(false)
        set(value) {
            runCatching { prefs.edit().putBoolean(KeyHomeShortcut, value).apply() }
        }
}
