package app.gogogadget

import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val Square = CutCornerShape(0.dp)

private val Flat = Shapes(Square, Square, Square, Square, Square)

private val Type = Typography(
    headlineMedium = TextStyle(fontSize = 32.sp, lineHeight = 40.sp, fontWeight = FontWeight.Bold),
    bodyLarge = TextStyle(fontSize = 16.sp, lineHeight = 24.sp),
    bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 24.sp),
    titleMedium = TextStyle(fontSize = 18.sp, lineHeight = 24.sp, fontWeight = FontWeight.Medium),
    bodySmall = TextStyle(fontSize = 12.sp, lineHeight = 18.sp),
    labelMedium = TextStyle(fontSize = 12.sp, lineHeight = 16.sp, fontWeight = FontWeight.Bold),
    labelSmall = TextStyle(fontSize = 11.sp, lineHeight = 16.sp, fontWeight = FontWeight.Bold),
    labelLarge = TextStyle(fontSize = 16.sp, lineHeight = 24.sp, fontWeight = FontWeight.Bold),
)

@Composable
fun GoGoTheme(palette: Palette, content: @Composable () -> Unit) {
    val background = Color(palette.background)
    val text = Color(palette.text)
    val scheme = if (palette.isDark) {
        darkColorScheme(
            primary = Color(palette.buttonContainer),
            onPrimary = Color(palette.buttonContent),
            primaryContainer = Color(palette.buttonContainer),
            onPrimaryContainer = Color(palette.buttonContent),
            secondary = Color(palette.accent),
            onSecondary = background,
            secondaryContainer = background,
            onSecondaryContainer = text,
            tertiary = Color(palette.accent),
            onTertiary = background,
            background = background,
            onBackground = text,
            surface = background,
            onSurface = text,
            surfaceVariant = background,
            onSurfaceVariant = Color(palette.secondary),
            surfaceTint = Color(palette.buttonContainer),
            error = Color(palette.error),
            onError = background,
            outline = Color(palette.divider),
            outlineVariant = Color(palette.divider),
        )
    } else {
        lightColorScheme(
            primary = Color(palette.buttonContainer),
            onPrimary = Color(palette.buttonContent),
            primaryContainer = Color(palette.buttonContainer),
            onPrimaryContainer = Color(palette.buttonContent),
            secondary = Color(palette.accent),
            onSecondary = background,
            secondaryContainer = background,
            onSecondaryContainer = text,
            tertiary = Color(palette.accent),
            onTertiary = background,
            background = background,
            onBackground = text,
            surface = background,
            onSurface = text,
            surfaceVariant = background,
            onSurfaceVariant = Color(palette.secondary),
            surfaceTint = Color(palette.buttonContainer),
            error = Color(palette.error),
            onError = background,
            outline = Color(palette.divider),
            outlineVariant = Color(palette.divider),
        )
    }
    MaterialTheme(colorScheme = scheme, shapes = Flat, typography = Type, content = content)
}
