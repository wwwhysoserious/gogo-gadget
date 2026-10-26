package app.gogogadget

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

private fun label(setting: ThemeSetting): Int = when (setting) {
    ThemeSetting.System -> R.string.theme_system
    ThemeSetting.Light -> R.string.theme_light
    ThemeSetting.Blue -> R.string.theme_blue
    ThemeSetting.Dark -> R.string.theme_dark
}

@Composable
fun SettingsScreen(
    palette: Palette,
    selected: ThemeSetting,
    onSelect: (ThemeSetting) -> Unit,
    onBack: () -> Unit,
) {
    Column(
        Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)
            .verticalScroll(rememberScrollState()),
    ) {
        Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(
                stringResource(R.string.back),
                style = MaterialTheme.typography.bodyMedium,
                color = Color(palette.accent),
                modifier = Modifier.clickable(onClick = onBack).height(56.dp).padding(horizontal = Margin)
                    .padding(vertical = 16.dp),
            )
        }
        Divider(palette)
        Text(
            stringResource(R.string.theme),
            style = MaterialTheme.typography.bodyMedium,
            color = Color(palette.secondary),
            modifier = Modifier.padding(horizontal = Margin, vertical = 16.dp),
        )
        ThemeSetting.entries.forEach { option ->
            Divider(palette)
            Row(
                Modifier.fillMaxWidth().height(56.dp)
                    .selectable(option == selected, role = Role.RadioButton) { onSelect(option) }
                    .padding(horizontal = Margin),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    stringResource(label(option)),
                    style = MaterialTheme.typography.bodyLarge,
                    color = Color(if (option == selected) palette.accent else palette.text),
                    modifier = Modifier.weight(1f),
                )
                if (option == selected) Box(Modifier.size(8.dp).background(Color(palette.accent)))
            }
        }
        Divider(palette)
    }
}
