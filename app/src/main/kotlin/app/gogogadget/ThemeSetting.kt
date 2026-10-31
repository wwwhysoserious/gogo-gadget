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
    // Install button while it shows progress: its background, and its 1 px border / unlit segments.
    val track: Long,
    val trackLine: Long,
    val isDark: Boolean,
    val banner: Banner,
)

// Every Light and Blue colour is opaque; their text pairs are checked by ContrastTest (WCAG ratio).
val LightPalette = Palette(
    background = 0xFFFFFFFF,
    text = 0xFF0B1220,
    secondary = 0xFF4A5565,
    divider = 0xFFD5DCE5,
    surface = 0xFFF2F5F9,
    accent = 0xFF1976D2,
    buttonContainer = 0xFF2196F3,
    buttonContent = 0xFFFFFFFF,
    indicator = 0xFF8A96A6,
    navInactive = 0xFF4A5565,
    success = 0xFF0B7D3C,
    error = 0xFFC62828,
    track = 0xFFE6EBF1,
    trackLine = 0xFFC3CCD8,
    isDark = false,
    banner = Banner.A,
)

val BluePalette = Palette(
    background = 0xFF1565C0,
    text = 0xFFFFFFFF,
    secondary = 0xFFDCEBFA,
    divider = 0xFF4D8FD6,
    // One blue for the whole theme: background, banner_b.png and launcher icon B are all 1565C0 (white text 5.1:1).
    surface = 0xFF1259AB,
    accent = 0xFFFFFFFF,
    buttonContainer = 0xFFFFFFFF,
    buttonContent = 0xFF0D47A1,
    indicator = 0xFF90CAF9,
    navInactive = 0xFFD6E8FB,
    success = 0xFFB9F6CA,
    error = 0xFFFFE0E0,
    track = 0xFF0D47A1,
    trackLine = 0xFF64A0E0,
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
    track = 0xFF0A0A0A,
    trackLine = 0x40FFFFFF,
    isDark = true,
    banner = Banner.C,
)

fun resolvePalette(setting: ThemeSetting, isSystemDark: Boolean): Palette = when (setting) {
    ThemeSetting.Light -> LightPalette
    ThemeSetting.Blue -> BluePalette
    ThemeSetting.Dark -> DarkPalette
    ThemeSetting.System -> if (isSystemDark) DarkPalette else LightPalette
}

/** [argb] with the alpha forced to 0xFF, for surfaces that float over other content (menus, popups). */
fun opaque(argb: Long): Long = argb or 0xFF000000L

private fun linear(channel: Long): Double {
    val c = channel / 255.0
    return if (c <= 0.03928) c / 12.92 else Math.pow((c + 0.055) / 1.055, 2.4)
}

/** WCAG relative luminance of an opaque 0xAARRGGBB colour (the alpha byte is ignored). */
fun relativeLuminance(argb: Long): Double =
    0.2126 * linear((argb shr 16) and 0xFF) + 0.7152 * linear((argb shr 8) and 0xFF) + 0.0722 * linear(argb and 0xFF)

/** WCAG contrast ratio of two opaque colours, from 1.0 (identical) to 21.0 (black on white). */
fun contrastRatio(a: Long, b: Long): Double {
    val la = relativeLuminance(a)
    val lb = relativeLuminance(b)
    return (maxOf(la, lb) + 0.05) / (minOf(la, lb) + 0.05)
}
