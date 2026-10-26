package app.gogogadget

import android.content.Context
import android.content.res.Configuration
import android.graphics.Color.TRANSPARENT
import android.graphics.drawable.ColorDrawable
import android.net.Uri
import android.provider.OpenableColumns
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private const val PREFS = "settings"
private const val KEY_THEME = "theme"

class MainActivity : ComponentActivity() {
    private var appliedBars: Pair<Boolean, Long>? = null

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
                var showSettings by rememberSaveable { mutableStateOf(false) }
                var fileUri by rememberSaveable { mutableStateOf<Uri?>(null) }
                var fileName by rememberSaveable { mutableStateOf<String?>(null) }
                val context = LocalContext.current
                val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
                    if (uri != null) {
                        fileUri = uri
                        fileName = displayName(context, uri)
                    }
                }
                BackHandler(showSettings) { showSettings = false }
                Box(Modifier.fillMaxSize().background(Color(palette.background))) {
                    if (showSettings) {
                        SettingsScreen(
                            palette = palette,
                            selected = setting,
                            onSelect = {
                                setting = it
                                prefs.edit().putString(KEY_THEME, it.name).apply()
                            },
                            onBack = { showSettings = false },
                        )
                    } else {
                        HomeScreen(
                            palette = palette,
                            fileName = fileName,
                            onChoose = { picker.launch(arrayOf("*/*")) },
                            onSettings = { showSettings = true },
                        )
                    }
                }
            }
        }
    }
}

private fun displayName(context: Context, uri: Uri): String =
    runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            val column = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (column >= 0 && c.moveToFirst()) c.getString(column) else null
        }
    }.getOrNull()?.takeIf { it.isNotBlank() } ?: context.getString(R.string.unnamed_file)
