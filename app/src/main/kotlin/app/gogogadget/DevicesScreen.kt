package app.gogogadget

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

private val StartSlot = 56.dp
private val LabelWidth = 80.dp
private val ForgetSize = 48.dp
private val EndSlot = LabelWidth + ForgetSize

/**
 * Device management: the saved devices (this phone first, grouped like the dropdown, with state and a forget button),
 * then the devices found on the network that are not saved yet and the manual address form. [onOpen] runs when the page opens.
 */
@Composable
fun DevicesScreen(
    palette: Palette,
    sections: DeviceMenuSections,
    found: List<Found>,
    ownAddresses: Set<String>,
    onOpen: () -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    onSelect: (Target) -> Unit,
    onFound: (NetDevice) -> Unit,
    onManual: (Endpoint, pair: Boolean, name: String?) -> Unit,
    onForget: (Target) -> Unit,
) {
    var forgetting by remember { mutableStateOf<Target?>(null) }
    forgetting?.let { ForgetDialog(palette, it, { forgetting = null }, onForget) }
    // The page opens with a probe and repeats it while it stays open, so a device switched on or off shows up by itself.
    LaunchedEffect(Unit) {
        onOpen()
        while (true) {
            delay(RefreshWhileOpenMs)
            onRefresh()
        }
    }
    val saved = (sections.thisNetwork + sections.otherNetworks).map { it.target.host.trim().lowercase() }.toSet()
    val network = mergeByHost(found, ownAddresses).filter { it.host.trim().lowercase() !in saved }
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
        Text(
            stringResource(R.string.devices_info),
            style = MaterialTheme.typography.bodySmall,
            color = Color(palette.secondary),
            modifier = Modifier.fillMaxWidth().padding(start = Margin, end = Margin, bottom = 16.dp),
        )

        Divider(palette)
        SectionHeader(palette, stringResource(R.string.section_saved_devices), Margin, strong = true)
        listOf(
            R.string.section_this_network to sections.thisNetwork,
            R.string.section_other_networks to sections.otherNetworks,
        ).filter { it.second.isNotEmpty() }.forEach { (header, entries) ->
            SectionHeader(palette, stringResource(header), Margin)
            entries.forEach { entry ->
                Divider(palette)
                DeviceEntryRow(
                    palette, entry, { onSelect(entry.target) }, StartSlot, EndSlot, Margin,
                    end = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            DeviceStateText(palette, entry.status, Modifier.width(LabelWidth))
                            if (entry.saved) ForgetButton(palette) { forgetting = entry.target }
                            else Spacer(Modifier.size(ForgetSize))
                        }
                    },
                )
            }
        }
        Divider(palette)

        Spacer(Modifier.height(16.dp))
        Divider(palette)
        SectionHeader(palette, stringResource(R.string.section_add_device), Margin, strong = true)
        Text(
            stringResource(R.string.tv_first_connect_hint),
            style = MaterialTheme.typography.labelSmall,
            color = Color(palette.accent),
            modifier = Modifier.padding(horizontal = Margin, vertical = 4.dp),
        )
        SectionHeader(palette, stringResource(R.string.devices_on_network), Margin)
        if (network.isEmpty()) {
            Divider(palette)
            Text(
                stringResource(R.string.no_devices),
                style = MaterialTheme.typography.bodySmall,
                color = Color(palette.secondary),
                modifier = Modifier.fillMaxWidth().padding(horizontal = Margin, vertical = 16.dp),
            )
        }
        network.forEach { item ->
            Divider(palette)
            val lines = stringResource(R.string.subtitle_network) to (item.connectPort?.let { hostPort(item.host, it) } ?: item.host)
            DeviceListRow(
                item.name ?: item.host, lines, Color(palette.text), Color(palette.secondary), { onFound(item) },
                StartSlot, EndSlot, Margin,
                start = { PlusMark(palette) },
            )
        }
        Divider(palette)
        SectionHeader(palette, stringResource(R.string.add_manually), Margin)
        Text(
            stringResource(R.string.manual_add_hint),
            style = MaterialTheme.typography.labelSmall,
            color = Color(palette.secondary),
            modifier = Modifier.fillMaxWidth().padding(start = Margin, end = Margin, bottom = 8.dp),
        )
        Divider(palette)
        ManualForm(palette, onManual)
        Divider(palette)
    }
}

@Composable
private fun ForgetButton(palette: Palette, onClick: () -> Unit) =
    TrashButton(palette, stringResource(R.string.forget_device), onClick)

/** Red trash-can icon (48 dp touch target, 20 dp drawing) made of straight lines only; [label] is read by screen readers. */
@Composable
internal fun TrashButton(palette: Palette, label: String, onClick: () -> Unit) {
    val color = Color(palette.error)
    Box(
        Modifier.size(ForgetSize).clickable(role = Role.Button, onClick = onClick).semantics { contentDescription = label },
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(20.dp).clearAndSetSemantics {}) {
            val w = size.width
            val h = size.height
            val lid = Path().apply { moveTo(w * 0.1f, h * 0.2f); lineTo(w * 0.9f, h * 0.2f) }
            val handle = Path().apply {
                moveTo(w * 0.35f, h * 0.2f); lineTo(w * 0.35f, h * 0.05f); lineTo(w * 0.65f, h * 0.05f); lineTo(w * 0.65f, h * 0.2f)
            }
            val body = Path().apply {
                moveTo(w * 0.2f, h * 0.2f); lineTo(w * 0.25f, h * 0.95f); lineTo(w * 0.75f, h * 0.95f); lineTo(w * 0.8f, h * 0.2f)
            }
            val inner1 = Path().apply { moveTo(w * 0.42f, h * 0.4f); lineTo(w * 0.42f, h * 0.75f) }
            val inner2 = Path().apply { moveTo(w * 0.58f, h * 0.4f); lineTo(w * 0.58f, h * 0.75f) }
            val stroke = Stroke(width = 1.5.dp.toPx())
            listOf(lid, handle, body, inner1, inner2).forEach { drawPath(it, color, style = stroke) }
        }
    }
}

/** Asks before [target] is removed from the saved devices; [onDismiss] closes the question either way. */
@Composable
fun ForgetDialog(palette: Palette, target: Target, onDismiss: () -> Unit, onForget: (Target) -> Unit) {
    val name = target.name.ifBlank { target.host }
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RectangleShape,
        containerColor = Color(palette.surface),
        titleContentColor = Color(palette.text),
        textContentColor = Color(palette.secondary),
        title = { Text(stringResource(R.string.forget_device_title, name)) },
        text = { Text(stringResource(R.string.forget_device_body)) },
        dismissButton = {
            TextButton(onClick = onDismiss, shape = RectangleShape) {
                Text(stringResource(R.string.cancel), style = MaterialTheme.typography.labelLarge, color = Color(palette.accent))
            }
        },
        confirmButton = {
            TextButton(onClick = { onDismiss(); onForget(target) }, shape = RectangleShape) {
                Text(stringResource(R.string.forget_device), style = MaterialTheme.typography.labelLarge, color = Color(palette.error))
            }
        },
    )
}

@Composable
private fun ManualForm(palette: Palette, onManual: (Endpoint, pair: Boolean, name: String?) -> Unit) {
    var deviceName by rememberSaveable { mutableStateOf("") }
    var host by rememberSaveable { mutableStateOf("") }
    var port by rememberSaveable { mutableStateOf("") }
    var invalid by rememberSaveable { mutableStateOf(false) }
    fun submit(pair: Boolean) {
        val endpoint = parseEndpoint(host, port)
        invalid = endpoint == null
        if (endpoint != null) onManual(endpoint, pair, deviceName.trim().takeIf { it.isNotEmpty() })
    }
    Column(Modifier.padding(horizontal = Margin, vertical = 16.dp)) {
        Field(palette, deviceName, { deviceName = it }, R.string.device_name_hint, KeyboardType.Text)
        Spacer(Modifier.height(8.dp))
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
