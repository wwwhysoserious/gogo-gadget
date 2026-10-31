package app.gogogadget

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun BackupsScreen(
    palette: Palette,
    backups: List<AppBackupItem> = emptyList(),
    isWorking: Boolean = false,
    onRevert: (AppBackupItem) -> Unit = {},
    onDelete: (AppBackupItem) -> Unit = {},
    connectedDeviceId: String? = null,
    connectedDeviceName: String? = null,
    onRevertMany: (List<AppBackupItem>) -> Unit = {},
    onDeleteMany: (List<AppBackupItem>) -> Unit = {},
    onGoToInstall: () -> Unit = {},
) {
    // Only the connected device's backups; with no device connected there is nothing to list.
    val visible = visibleBackups(backups, connectedDeviceId)
    val canRevert = connectedDeviceId != null
    if (visible.isEmpty()) {
        Box(
            Modifier.fillMaxSize().padding(Margin),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    stringResource(if (connectedDeviceId != null) R.string.backups_empty_device else R.string.backups_no_device),
                    style = MaterialTheme.typography.bodyLarge,
                    color = Color(palette.secondary),
                    textAlign = TextAlign.Center,
                )
                if (connectedDeviceId != null) {
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = onGoToInstall,
                    shape = RectangleShape,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(palette.buttonContainer),
                        contentColor = Color(palette.buttonContent),
                    ),
                    elevation = null,
                ) {
                    Text(
                        stringResource(R.string.backup_empty_action),
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Bold,
                    )
                }
                }
            }
        }
    } else {
        var searchOpen by rememberSaveable { mutableStateOf(false) }
        var query by rememberSaveable { mutableStateOf("") }
        var selectMode by rememberSaveable { mutableStateOf(false) }
        var selected by remember { mutableStateOf(emptySet<String>()) }
        var pending by remember { mutableStateOf<String?>(null) }
        val shown = remember(visible, query) { filterBackups(visible, query) }
        selected = pruneSelection(selected, visible)
        val chosen = visible.filter { it.key in selected }
        fun exitSelect() { selectMode = false; selected = emptySet(); pending = null }
        Column(
            Modifier.fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = Margin, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                stringResource(R.string.nav_backups),
                style = MaterialTheme.typography.titleMedium,
                color = Color(palette.text),
                fontWeight = FontWeight.Bold,
                modifier = Modifier.semantics { heading() },
            )
            if (connectedDeviceId != null) {
                Text(
                    stringResource(R.string.backups_device, connectedDeviceName ?: connectedDeviceId),
                    style = MaterialTheme.typography.titleSmall,
                    color = Color(palette.text),
                    fontWeight = FontWeight.Bold,
                )
            }
            Text(
                stringResource(R.string.backups_info),
                style = MaterialTheme.typography.bodySmall,
                color = Color(palette.secondary),
            )
            // One row for search and everything about selecting.
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                BarButton(palette, R.string.backup_search, active = searchOpen, modifier = Modifier.weight(1f)) {
                    searchOpen = !searchOpen
                    if (!searchOpen) query = ""
                }
                if (!selectMode) {
                    BarButton(palette, R.string.backup_select, active = false, modifier = Modifier.weight(1f)) { selectMode = true }
                } else {
                    BarButton(palette, if (allVisibleSelected(selected, shown)) R.string.backup_none else R.string.backup_all, active = false, modifier = Modifier.weight(1f)) {
                        selected = if (allVisibleSelected(selected, shown)) emptySet() else selectAllVisible(shown)
                    }
                    BarButton(palette, R.string.backup_revert, active = false, enabled = chosen.isNotEmpty() && canRevert && !isWorking, modifier = Modifier.weight(1f)) { pending = "revert" }
                    BarButton(palette, R.string.backup_delete, active = false, enabled = chosen.isNotEmpty() && !isWorking, danger = true, modifier = Modifier.weight(1f)) { pending = "delete" }
                    BarButton(palette, R.string.cancel, active = false, modifier = Modifier.weight(1f)) { exitSelect() }
                }
            }
            if (selectMode) {
                Text(
                    stringResource(R.string.backup_selected_count, chosen.size) + if (!canRevert) " · " + stringResource(R.string.backup_revert_needs_device) else "",
                    style = MaterialTheme.typography.labelSmall,
                    color = Color(palette.secondary),
                )
            }
            val action = pending
            if (selectMode && action != null && chosen.isNotEmpty()) {
                Column(Modifier.fillMaxWidth().border(1.dp, Color(palette.accent)).padding(10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        stringResource(if (action == "revert") R.string.backup_confirm_revert else R.string.backup_confirm_delete, chosen.size),
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(palette.text),
                    )
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = {
                                val list = chosen
                                if (action == "revert") onRevertMany(list) else onDeleteMany(list)
                                exitSelect()
                            },
                            modifier = Modifier.weight(1f).height(48.dp),
                            shape = RectangleShape,
                            colors = ButtonDefaults.buttonColors(containerColor = Color(palette.buttonContainer), contentColor = Color(palette.buttonContent)),
                            elevation = null,
                        ) { Text(stringResource(R.string.backup_confirm), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold) }
                        OutlinedButton(
                            onClick = { pending = null },
                            modifier = Modifier.weight(1f).height(48.dp),
                            shape = RectangleShape,
                            border = BorderStroke(1.dp, Color(palette.divider)),
                        ) { Text(stringResource(R.string.cancel), style = MaterialTheme.typography.labelLarge, color = Color(palette.text)) }
                    }
                }
            }
            if (searchOpen) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = RectangleShape,
                    placeholder = { Text(stringResource(R.string.backup_search_hint)) },
                )
            }
            if (shown.isEmpty()) {
                Text(
                    stringResource(R.string.backup_no_results),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(palette.secondary),
                    modifier = Modifier.padding(vertical = 16.dp),
                )
            }
            for (backup in shown) {
                BackupCard(
                    palette = palette,
                    backup = backup,
                    isWorking = isWorking,
                    canRevert = canRevertBackup(backup.deviceId, connectedDeviceId),
                    selectMode = selectMode,
                    isSelected = backup.key in selected,
                    onToggle = { selected = toggleSelection(selected, backup.key) },
                    onRevert = { onRevert(backup) },
                    onDelete = { onDelete(backup) },
                )
            }
        }
    }
}

@Composable
private fun BarButton(
    palette: Palette,
    label: Int,
    active: Boolean,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    danger: Boolean = false,
    onClick: () -> Unit,
) {
    val color = when {
        !enabled -> Color(palette.indicator)
        danger -> Color(palette.error)
        active -> Color(palette.accent)
        else -> Color(palette.text)
    }
    Box(
        modifier.height(48.dp)
            .border(1.dp, Color(if (active && enabled) palette.accent else palette.divider))
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Text(stringResource(label), style = MaterialTheme.typography.labelMedium, color = color, maxLines = 1)
    }
}

/** Case-insensitive match on app name or package name; a blank query keeps everything. */
internal fun filterBackups(backups: List<AppBackupItem>, query: String): List<AppBackupItem> {
    val q = query.trim()
    if (q.isEmpty()) return backups
    return backups.filter { it.appName.contains(q, ignoreCase = true) || it.packageName.contains(q, ignoreCase = true) }
}

@Composable
private fun BackupCard(
    palette: Palette,
    backup: AppBackupItem,
    isWorking: Boolean,
    canRevert: Boolean,
    selectMode: Boolean = false,
    isSelected: Boolean = false,
    onToggle: () -> Unit = {},
    onRevert: () -> Unit,
    onDelete: () -> Unit,
) {
    val dateFormat = remember { SimpleDateFormat("MMM d, HH:mm", Locale.US) }
    val dateStr = remember(backup.timestamp) { dateFormat.format(Date(backup.timestamp)) }
    val sizeStr = remember(backup.totalSizeBytes) { formatByteSize(backup.totalSizeBytes) }

    Row(
        Modifier.fillMaxWidth()
            .background(Color(palette.surface))
            .border(1.dp, Color(if (isSelected) palette.accent else palette.divider))
            .then(if (selectMode) Modifier.clickable(role = Role.Checkbox, onClick = onToggle) else Modifier)
            .padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (selectMode) {
            Box(
                Modifier.size(24.dp).border(1.dp, Color(if (isSelected) palette.accent else palette.secondary)),
                contentAlignment = Alignment.Center,
            ) {
                if (isSelected) Box(Modifier.size(14.dp).background(Color(palette.accent)))
            }
            Spacer(Modifier.width(10.dp))
        }
        Column(Modifier.weight(1f)) {
            Text(
                text = backup.appName,
                style = MaterialTheme.typography.titleSmall,
                color = Color(palette.text),
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = backup.packageName,
                style = MaterialTheme.typography.labelSmall,
                fontFamily = FontFamily.Monospace,
                color = Color(palette.secondary),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = "v${backup.versionName ?: backup.versionCode} · $sizeStr",
                style = MaterialTheme.typography.labelSmall,
                color = Color(palette.secondary),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = dateStr,
                style = MaterialTheme.typography.labelSmall,
                color = Color(palette.secondary),
                maxLines = 1,
            )
            val deviceLabel = if (backup.deviceId == UNASSIGNED_DEVICE) stringResource(R.string.backups_unassigned) else backup.deviceName ?: backup.deviceId
            Text(
                text = deviceLabel,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = Color(palette.accent),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(top = 2.dp).border(1.dp, Color(palette.accent)).padding(horizontal = 4.dp, vertical = 1.dp),
            )
        }
        if (!selectMode) {
        Spacer(Modifier.width(8.dp))
        Button(
            onClick = onRevert,
            enabled = !isWorking && canRevert,
            modifier = Modifier.width(84.dp).height(48.dp),
            contentPadding = PaddingValues(horizontal = 4.dp),
            shape = RectangleShape,
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(palette.buttonContainer),
                contentColor = Color(palette.buttonContent),
            ),
            elevation = null,
        ) {
            Text(
                stringResource(R.string.backup_revert),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
            )
        }
        Spacer(Modifier.width(6.dp))
        OutlinedButton(
            onClick = onDelete,
            enabled = !isWorking,
            modifier = Modifier.width(84.dp).height(48.dp),
            contentPadding = PaddingValues(horizontal = 4.dp),
            shape = RectangleShape,
            border = BorderStroke(1.dp, Color(palette.divider)),
        ) {
            Text(
                stringResource(R.string.backup_delete),
                style = MaterialTheme.typography.labelMedium,
                color = Color(palette.error),
                maxLines = 1,
            )
        }
        }
    }
}

internal fun formatByteSize(bytes: Long): String = when {
    bytes >= 1024L * 1024L -> String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
    bytes >= 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
    else -> "$bytes B"
}
