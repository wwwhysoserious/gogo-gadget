package app.gogogadget

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.res.stringResource
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
) {
    if (backups.isEmpty()) {
        Box(
            Modifier.fillMaxSize().padding(Margin),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                stringResource(R.string.backups_empty),
                style = MaterialTheme.typography.bodyLarge,
                color = Color(palette.secondary),
                textAlign = TextAlign.Center,
            )
        }
    } else {
        Column(
            Modifier.fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = Margin, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                stringResource(R.string.nav_backups),
                style = MaterialTheme.typography.titleMedium,
                color = Color(palette.text),
                fontWeight = FontWeight.Bold,
                modifier = Modifier.semantics { heading() },
            )
            for (backup in backups) {
                BackupCard(
                    palette = palette,
                    backup = backup,
                    isWorking = isWorking,
                    onRevert = { onRevert(backup) },
                    onDelete = { onDelete(backup) },
                )
            }
        }
    }
}

@Composable
private fun BackupCard(
    palette: Palette,
    backup: AppBackupItem,
    isWorking: Boolean,
    onRevert: () -> Unit,
    onDelete: () -> Unit,
) {
    val dateFormat = remember { SimpleDateFormat("MMM d, yyyy HH:mm", Locale.US) }
    val dateStr = remember(backup.timestamp) { dateFormat.format(Date(backup.timestamp)) }
    val sizeStr = remember(backup.totalSizeBytes) { formatByteSize(backup.totalSizeBytes) }

    Column(
        Modifier.fillMaxWidth()
            .background(Color(palette.surface))
            .border(1.dp, Color(palette.divider))
            .padding(14.dp),
    ) {
        Text(
            text = backup.appName,
            style = MaterialTheme.typography.titleMedium,
            color = Color(palette.text),
            fontWeight = FontWeight.Bold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = backup.packageName,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = Color(palette.secondary),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(8.dp))
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = "v${backup.versionName ?: backup.versionCode} (${backup.versionCode})",
                style = MaterialTheme.typography.bodySmall,
                color = Color(palette.text),
                fontWeight = FontWeight.Medium,
            )
            Text(
                text = sizeStr,
                style = MaterialTheme.typography.bodySmall,
                color = Color(palette.secondary),
            )
        }
        Text(
            text = "Saved $dateStr",
            style = MaterialTheme.typography.labelSmall,
            color = Color(palette.secondary),
        )
        Spacer(Modifier.height(12.dp))
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Button(
                onClick = onRevert,
                enabled = !isWorking,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                shape = RectangleShape,
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(palette.buttonContainer),
                    contentColor = Color(palette.buttonContent),
                ),
                elevation = null,
            ) {
                Text(
                    stringResource(R.string.backup_revert),
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                )
            }
            OutlinedButton(
                onClick = onDelete,
                enabled = !isWorking,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                shape = RectangleShape,
                border = BorderStroke(1.dp, Color(palette.divider)),
            ) {
                Text(
                    stringResource(R.string.backup_delete),
                    style = MaterialTheme.typography.labelLarge,
                    color = Color(palette.error),
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
