package app.gogogadget

import android.app.LocaleManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import java.util.Locale

// Per-app language needs the system picker, which exists from Android 13 (API 33).
fun appLanguageSupported(sdkInt: Int): Boolean = sdkInt >= 33

// Label for the Language row. An empty tag means the app follows the phone language,
// so [systemLabel] is shown. Otherwise the language is named in its own language.
fun languageRowLabel(appLocaleTag: String?, systemLabel: String): String {
    val tag = appLocaleTag?.trim().orEmpty()
    if (tag.isEmpty()) return systemLabel
    val locale = Locale.forLanguageTag(tag)
    if (locale.language.isEmpty()) return systemLabel
    return locale.getDisplayName(locale).replaceFirstChar { it.titlecase(locale) }
}

// First application locale tag chosen in the system settings, or empty for "System".
fun currentAppLocaleTag(context: Context): String {
    if (!appLanguageSupported(Build.VERSION.SDK_INT)) return ""
    val locales = context.getSystemService(LocaleManager::class.java)?.applicationLocales ?: return ""
    return if (locales.isEmpty) "" else locales.toLanguageTags().substringBefore(',')
}

// Opens the system per-app language screen; the caller must check [appLanguageSupported] first.
fun openAppLanguageSettings(context: Context) {
    val intent = Intent(Settings.ACTION_APP_LOCALE_SETTINGS, Uri.fromParts("package", context.packageName, null))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(intent)
    } catch (_: android.content.ActivityNotFoundException) {
    }
}
