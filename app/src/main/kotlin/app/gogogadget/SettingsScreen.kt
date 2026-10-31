package app.gogogadget

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

private fun label(setting: ThemeSetting): Int = when (setting) {
    ThemeSetting.System -> R.string.theme_system
    ThemeSetting.Light -> R.string.theme_light
    ThemeSetting.Blue -> R.string.theme_blue
    ThemeSetting.Dark -> R.string.theme_dark
}

private fun deleteModeLabel(mode: DeleteSourceMode): Int = when (mode) {
    DeleteSourceMode.Off -> R.string.delete_apk_off
    DeleteSourceMode.On -> R.string.delete_apk_on
    DeleteSourceMode.Automatic -> R.string.delete_apk_auto
}

/** A settings row; [onClick] null means display-only placeholder. */
@Composable
private fun SettingRow(
    palette: Palette,
    name: Int,
    value: String,
    onClick: (() -> Unit)? = null,
) {
    Divider(palette)
    val secondary = Color(palette.secondary)
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp)
            .then(if (onClick != null) Modifier.clickable(role = Role.Button, onClick = onClick) else Modifier)
            .padding(horizontal = Margin, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            stringResource(name),
            style = MaterialTheme.typography.bodyLarge,
            color = Color(palette.text),
            modifier = Modifier.weight(1f),
        )
        Spacer(Modifier.width(16.dp))
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = secondary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            textAlign = androidx.compose.ui.text.style.TextAlign.End,
        )
        if (onClick != null) {
            Spacer(Modifier.width(8.dp))
            // Straight ">" chevron, only on rows that do something.
            Canvas(Modifier.size(8.dp, 12.dp)) {
                val w = 1.5.dp.toPx()
                drawLine(secondary, Offset(0f, 0f), Offset(size.width, size.height / 2), w)
                drawLine(secondary, Offset(size.width, size.height / 2), Offset(0f, size.height), w)
            }
        }
    }
}

@Composable
internal fun GroupHeader(palette: Palette, title: Int) {
    Text(
        stringResource(title).uppercase(),
        style = MaterialTheme.typography.labelSmall,
        color = Color(palette.secondary),
        modifier = Modifier.padding(start = Margin, end = Margin, top = 24.dp, bottom = 8.dp),
    )
}

@Composable
fun SettingsScreen(
    palette: Palette,
    selected: ThemeSetting,
    themeOpen: Boolean,
    onThemeOpen: (Boolean) -> Unit,
    onSelect: (ThemeSetting) -> Unit,
    vtKeyOpen: Boolean = false,
    onVtKeyOpen: (Boolean) -> Unit = {},
    onKeysChanged: () -> Unit = {},
) {
    if (themeOpen) {
        ThemePicker(palette, selected, onSelect, onBack = { onThemeOpen(false) })
        return
    }
    val context = LocalContext.current
    var iconOpen by rememberSaveable { mutableStateOf(false) }
    var appIcon by remember { mutableStateOf(currentAppIcon(context)) }
    if (iconOpen) {
        IconPicker(palette, appIcon, onSelect = { setAppIcon(context, it); appIcon = it }, onBack = { iconOpen = false })
        return
    }
    val shieldStore = remember(context) { ShieldSettingsStore(context) }
    val installStore = remember(context) { InstallSettingsStore(context) }
    var homeShortcut by rememberSaveable { mutableStateOf(installStore.homeShortcut) }
    var deleteMode by rememberSaveable { mutableStateOf(installStore.deleteSourceMode) }
    var backupBeforeUpdate by rememberSaveable { mutableStateOf(installStore.backupBeforeUpdate) }
    var shieldEnabled by rememberSaveable { mutableStateOf(shieldStore.shieldEnabled) }
    var hasApiKey by rememberSaveable { mutableStateOf(shieldStore.hasAnyApiKey()) }
    var deepScanEnabled by rememberSaveable { mutableStateOf(shieldStore.deepScanEnabled) }

    if (vtKeyOpen) {
        SecurityApisScreen(palette, shieldStore, onChanged = { hasApiKey = shieldStore.hasAnyApiKey(); shieldEnabled = shieldStore.shieldEnabled; onKeysChanged() }, onBack = { onVtKeyOpen(false) })
        return
    }

    val version = remember(context) { context.packageManager.getPackageInfo(context.packageName, 0).versionName.orEmpty() }
    fun s(id: Int) = context.getString(id)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Text(
            stringResource(R.string.settings),
            style = MaterialTheme.typography.headlineMedium,
            color = Color(palette.text),
            modifier = Modifier.padding(horizontal = Margin, vertical = 16.dp).semantics { heading() },
        )
        GroupHeader(palette, R.string.group_appearance)
        SettingRow(palette, R.string.theme, s(label(selected)), onClick = { onThemeOpen(true) })
        SettingRow(palette, R.string.app_icon, s(appIcon.label), onClick = { iconOpen = true })
        GroupHeader(palette, R.string.group_security)
        SettingRow(
            palette = palette,
            name = R.string.antivirus_shield,
            value = s(if (shieldEnabled) R.string.on else R.string.off),
            onClick = {
                val next = !shieldEnabled
                shieldEnabled = next
                shieldStore.shieldEnabled = next
                onKeysChanged()
            },
        )
        SettingRow(
            palette = palette,
            name = R.string.security_apis,
            value = if (!shieldEnabled) s(R.string.disabled_by_shield) else s(if (hasApiKey) R.string.on else R.string.api_status_none),
            onClick = { onVtKeyOpen(true) },
        )
        SettingRow(
            palette = palette,
            name = R.string.deep_scan,
            value = if (!shieldEnabled) s(R.string.disabled_by_shield) else s(if (deepScanEnabled) R.string.on else R.string.off),
            onClick = {
                if (shieldEnabled) {
                    val next = !deepScanEnabled
                    deepScanEnabled = next
                    shieldStore.deepScanEnabled = next
                    onKeysChanged()
                }
            },
        )
        GroupHeader(palette, R.string.group_installation)
        SettingRow(
            palette = palette,
            name = R.string.home_shortcut,
            value = s(if (homeShortcut) R.string.on else R.string.off),
            onClick = {
                val next = !homeShortcut
                homeShortcut = next
                installStore.homeShortcut = next
            },
        )
        SettingRow(
            palette = palette,
            name = R.string.delete_apk,
            value = s(deleteModeLabel(deleteMode)),
            onClick = {
                val next = nextDeleteSourceMode(deleteMode)
                deleteMode = next
                installStore.deleteSourceMode = next
            },
        )
        SettingRow(
            palette = palette,
            name = R.string.backup_before_update,
            value = s(if (backupBeforeUpdate) R.string.on else R.string.off),
            onClick = {
                val next = !backupBeforeUpdate
                backupBeforeUpdate = next
                installStore.backupBeforeUpdate = next
            },
        )
        GroupHeader(palette, R.string.group_language)
        SettingRow(
            palette = palette,
            name = R.string.language,
            value = languageRowLabel(currentAppLocaleTag(context), s(R.string.language_value)),
            onClick = if (appLanguageSupported(android.os.Build.VERSION.SDK_INT)) {
                { openAppLanguageSettings(context) }
            } else null,
        )
        GroupHeader(palette, R.string.group_about)
        SettingRow(palette, R.string.version, version)
        SettingRow(palette, R.string.source_code, s(R.string.github))
        SettingRow(palette, R.string.licence, s(R.string.licence_value))
        Divider(palette)
    }
}

@Composable
private fun ThemePicker(palette: Palette, selected: ThemeSetting, onSelect: (ThemeSetting) -> Unit, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
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
            modifier = Modifier.padding(horizontal = Margin, vertical = 16.dp).semantics { heading() },
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

@Composable
private fun IconPicker(palette: Palette, selected: AppIcon, onSelect: (AppIcon) -> Unit, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(
                stringResource(R.string.back),
                style = MaterialTheme.typography.bodyMedium,
                color = Color(palette.accent),
                modifier = Modifier.clickable(role = Role.Button, onClick = onBack).height(56.dp)
                    .padding(horizontal = Margin).padding(vertical = 16.dp),
            )
        }
        Divider(palette)
        Text(
            stringResource(R.string.app_icon),
            style = MaterialTheme.typography.bodyMedium,
            color = Color(palette.secondary),
            modifier = Modifier.padding(horizontal = Margin, vertical = 16.dp).semantics { heading() },
        )
        AppIcon.entries.forEach { option ->
            Divider(palette)
            Row(
                Modifier.fillMaxWidth().height(56.dp)
                    .selectable(option == selected, role = Role.RadioButton) { onSelect(option) }
                    .padding(horizontal = Margin),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    stringResource(option.label),
                    style = MaterialTheme.typography.bodyLarge,
                    color = Color(if (option == selected) palette.accent else palette.text),
                    modifier = Modifier.weight(1f),
                )
                if (option == selected) Box(Modifier.size(8.dp).background(Color(palette.accent)))
            }
        }
        Divider(palette)
        Text(
            stringResource(R.string.app_icon_note),
            style = MaterialTheme.typography.bodySmall,
            color = Color(palette.secondary),
            modifier = Modifier.padding(horizontal = Margin, vertical = 16.dp),
        )
    }
}
