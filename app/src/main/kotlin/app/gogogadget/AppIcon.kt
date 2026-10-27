package app.gogogadget

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager

/** The launcher icon variants: each one is an activity-alias in the manifest, exactly one enabled at a time. */
enum class AppIcon(val alias: String, val label: Int) {
    Blue(".IconB", R.string.theme_blue),
    Light(".IconA", R.string.theme_light),
    Dark(".IconC", R.string.theme_dark),
}

private fun component(context: Context, icon: AppIcon) =
    ComponentName(context.packageName, "app.gogogadget" + icon.alias)

fun currentAppIcon(context: Context): AppIcon {
    val pm = context.packageManager
    return AppIcon.entries.firstOrNull { icon ->
        when (pm.getComponentEnabledSetting(component(context, icon))) {
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED -> true
            PackageManager.COMPONENT_ENABLED_STATE_DEFAULT -> icon == AppIcon.Blue
            else -> false
        }
    } ?: AppIcon.Blue
}

/** Enables the chosen alias before disabling the others, so the app never has zero launcher entries. */
fun setAppIcon(context: Context, icon: AppIcon) {
    val pm = context.packageManager
    pm.setComponentEnabledSetting(component(context, icon), PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
    AppIcon.entries.filter { it != icon }.forEach {
        pm.setComponentEnabledSetting(component(context, it), PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
    }
}
