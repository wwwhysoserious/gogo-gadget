package app.gogogadget

import android.content.Context
import android.content.SharedPreferences

private const val HomePrefsName = "install_settings"
private const val KeyHomeShortcut = "home_shortcut"
private const val KeyDeleteApk = "delete_apk"
private const val KeyDeleteMode = "delete_source_mode"
private const val KeyBackupBeforeUpdate = "backup_before_update"
private const val KeyWelcomeSeen = "welcome_seen"

/** Persists the "Home screen shortcut", "Delete APK after install" and "Backup before update" settings. */
class InstallSettingsStore(private val prefs: SharedPreferences) {
    constructor(context: Context) : this(
        context.applicationContext.getSharedPreferences(HomePrefsName, Context.MODE_PRIVATE),
    )

    var homeShortcut: Boolean
        get() = runCatching { prefs.getBoolean(KeyHomeShortcut, false) }.getOrDefault(false)
        set(value) {
            runCatching { prefs.edit().putBoolean(KeyHomeShortcut, value).apply() }
        }

    /** Off, On or Automatic; the old on/off boolean (key `delete_apk`) is read until the mode is first written. */
    var deleteSourceMode: DeleteSourceMode
        get() = runCatching {
            val legacy = if (prefs.contains(KeyDeleteApk)) prefs.getBoolean(KeyDeleteApk, false) else null
            deleteSourceModeFrom(prefs.getString(KeyDeleteMode, null), legacy)
        }.getOrDefault(DeleteSourceMode.Off)
        set(value) {
            runCatching { prefs.edit().putString(KeyDeleteMode, value.name).remove(KeyDeleteApk).apply() }
        }

    /** True once the first-launch welcome step (recommending the API keys) was shown and answered; it never shows again. */
    var welcomeSeen: Boolean
        get() = runCatching { prefs.getBoolean(KeyWelcomeSeen, false) }.getOrDefault(false)
        set(value) {
            runCatching { prefs.edit().putBoolean(KeyWelcomeSeen, value).apply() }
        }

    var backupBeforeUpdate: Boolean
        get() = runCatching { prefs.getBoolean(KeyBackupBeforeUpdate, true) }.getOrDefault(true)
        set(value) {
            runCatching { prefs.edit().putBoolean(KeyBackupBeforeUpdate, value).apply() }
        }
}
