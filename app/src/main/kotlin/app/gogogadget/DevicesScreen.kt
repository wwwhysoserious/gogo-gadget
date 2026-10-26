package app.gogogadget

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/** "Choose device": this phone first, then devices found on the network, manual entry and recent devices. */
@Composable
fun DevicesScreen(
    palette: Palette,
    thisDevice: Target,
    found: List<Found>,
    ownAddresses: Set<String>,
    recent: List<Target>,
    connected: Boolean,
    onBack: () -> Unit,
    onThisDevice: () -> Unit,
    onFound: (NetDevice) -> Unit,
    onManual: (Endpoint, pair: Boolean) -> Unit,
    onRecent: (Target) -> Unit,
    onDisconnect: () -> Unit,
) {
    val network = mergeByHost(found, ownAddresses)
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Text(
            stringResource(R.string.back),
            style = MaterialTheme.typography.bodyMedium,
            color = Color(palette.accent),
            modifier = Modifier.clickable(role = Role.Button, onClick = onBack).heightIn(min = 56.dp)
                .padding(horizontal = Margin).padding(vertical = 16.dp),
        )
        Divider(palette)
        Text(
            stringResource(R.string.choose_device),
            style = MaterialTheme.typography.headlineMedium,
            color = Color(palette.text),
            modifier = Modifier.padding(horizontal = Margin, vertical = 16.dp).semantics { heading() },
        )

        GroupHeader(palette, R.string.this_device)
        DeviceRow(palette, thisDevice.name, stringResource(R.string.subtitle_this_device), onClick = onThisDevice)

        GroupHeader(palette, R.string.devices_on_network)
        if (network.isEmpty()) {
            Divider(palette)
            Text(
                stringResource(R.string.no_devices),
                style = MaterialTheme.typography.bodyMedium,
                color = Color(palette.secondary),
                modifier = Modifier.padding(horizontal = Margin, vertical = 16.dp),
            )
        }
        network.forEach { item ->
            DeviceRow(
                palette, item.name ?: stringResource(R.string.subtitle_network),
                item.connectPort?.let { hostPort(item.host, it) } ?: item.host,
                onClick = { onFound(item) },
            )
        }

        GroupHeader(palette, R.string.add_manually)
        Divider(palette)
        ManualForm(palette, onManual)

        if (recent.isNotEmpty()) {
            GroupHeader(palette, R.string.recent)
            recent.forEach { target ->
                DeviceRow(
                    palette, target.name.ifBlank { target.host },
                    if (target.port > 0) hostPort(target.host, target.port) else target.host,
                    onClick = { onRecent(target) },
                )
            }
        }
        if (connected) {
            GroupHeader(palette, R.string.group_connection)
            DeviceRow(palette, stringResource(R.string.disconnect), null, onClick = onDisconnect)
        }
        Divider(palette)
    }
}

@Composable
private fun DeviceRow(palette: Palette, title: String, subtitle: String?, trailing: String? = null, onClick: () -> Unit) {
    Divider(palette)
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = Margin, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                title,
                style = MaterialTheme.typography.bodyLarge,
                color = Color(palette.text),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            subtitle?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = Color(palette.secondary),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        trailing?.let {
            Spacer(Modifier.width(16.dp))
            Text(it, style = MaterialTheme.typography.labelMedium, color = Color(palette.accent))
        }
    }
}

@Composable
private fun ManualForm(palette: Palette, onManual: (Endpoint, pair: Boolean) -> Unit) {
    var host by rememberSaveable { mutableStateOf("") }
    var port by rememberSaveable { mutableStateOf("") }
    var invalid by rememberSaveable { mutableStateOf(false) }
    fun submit(pair: Boolean) {
        val endpoint = parseEndpoint(host, port)
        invalid = endpoint == null
        if (endpoint != null) onManual(endpoint, pair)
    }
    Column(Modifier.padding(horizontal = Margin, vertical = 16.dp)) {
        Field(palette, host, { host = it.trim(); invalid = false }, R.string.host_hint, KeyboardType.Uri, mono = true)
        Spacer(Modifier.height(8.dp))
        Field(palette, port, { if (it.length <= 5 && it.all(Char::isDigit)) { port = it; invalid = false } }, R.string.port_hint,
            KeyboardType.Number, mono = true)
        Text(
            stringResource(if (invalid) R.string.invalid_endpoint else R.string.manual_help),
            style = MaterialTheme.typography.bodySmall,
            color = Color(if (invalid) palette.error else palette.secondary),
            modifier = Modifier.padding(vertical = 8.dp),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { submit(pair = false) },
                modifier = Modifier.weight(1f).height(48.dp),
                shape = RectangleShape,
                colors = ButtonDefaults.buttonColors(),
                elevation = null,
            ) { Text(stringResource(R.string.connect), style = MaterialTheme.typography.labelLarge) }
            OutlinedButton(
                onClick = { submit(pair = true) },
                modifier = Modifier.weight(1f).height(48.dp),
                shape = RectangleShape,
                border = BorderStroke(1.dp, Color(palette.accent)),
            ) { Text(stringResource(R.string.pair), style = MaterialTheme.typography.labelLarge, color = Color(palette.accent)) }
        }
    }
}
