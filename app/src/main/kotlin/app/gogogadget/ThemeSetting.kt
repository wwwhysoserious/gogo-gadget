package app.gogogadget

enum class ThemeSetting { System, Light, Blue, Dark }

/** Reads a stored theme name; null or an unknown value falls back to [ThemeSetting.System]. */
fun themeSettingFromName(name: String?): ThemeSetting =
    ThemeSetting.entries.firstOrNull { it.name == name } ?: ThemeSetting.System

enum class Banner { A, B, C }

/** Colours as 0xAARRGGBB so this file stays free of Android/Compose types. */
data class Palette(
    val background: Long,
    val text: Long,
    val secondary: Long,
    val divider: Long,
    val surface: Long,
    val accent: Long,
    val buttonContainer: Long,
    val buttonContent: Long,
    val indicator: Long,
    val navInactive: Long,
    val success: Long,
    val error: Long,
    val isDark: Boolean,
    val banner: Banner,
)

val LightPalette = Palette(
    background = 0xFFFFFFFF,
    text = 0xFF0B1220,
    secondary = 0xFF5B6675,
    divider = 0xFFE3E8EF,
    surface = 0xFFF5F7FA,
    accent = 0xFF1976D2,
    buttonContainer = 0xFF2196F3,
    buttonContent = 0xFFFFFFFF,
    indicator = 0xFF9AA6B5,
    navInactive = 0xFF5B6675,
    success = 0xFF12A150,
    error = 0xFFD92D20,
    isDark = false,
    banner = Banner.A,
)

val BluePalette = Palette(
    background = 0xFF2196F3,
    text = 0xFFFFFFFF,
    secondary = 0xFFFFFFFF,
    divider = 0x3DFFFFFF,
    surface = 0x1FFFFFFF,
    accent = 0xFFFFFFFF,
    buttonContainer = 0xFFFFFFFF,
    buttonContent = 0xFF2196F3,
    indicator = 0xFF9AA6B5,
    // White on this blue is only 3.1:1; dark navy gives 6:1.
    navInactive = 0xFF0B1220,
    success = 0xFFFFFFFF,
    error = 0xFFFFFFFF,
    isDark = true,
    banner = Banner.B,
)

val DarkPalette = Palette(
    background = 0xFF000000,
    text = 0xFFFFFFFF,
    secondary = 0xFF9AA6B5,
    divider = 0xFF1F2933,
    surface = 0xFF0A0A0A,
    accent = 0xFF2196F3,
    buttonContainer = 0xFF2196F3,
    buttonContent = 0xFFFFFFFF,
    indicator = 0xFF9AA6B5,
    navInactive = 0xFF9AA6B5,
    success = 0xFF12A150,
    error = 0xFFF04438,
    isDark = true,
    banner = Banner.C,
)

fun resolvePalette(setting: ThemeSetting, isSystemDark: Boolean): Palette = when (setting) {
    ThemeSetting.Light -> LightPalette
    ThemeSetting.Blue -> BluePalette
    ThemeSetting.Dark -> DarkPalette
    ThemeSetting.System -> if (isSystemDark) DarkPalette else LightPalette
}
