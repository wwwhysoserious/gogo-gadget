package app.gogogadget

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupProperties
import kotlinx.coroutines.delay

/**
 * State of a device in the list: connected over ADB now, reachable on this network, not reachable on this network, or
 * saved for another network.
 */
enum class DeviceStatus { CONNECTED, AVAILABLE, UNAVAILABLE, OTHER_NETWORK }

/** What the right side of a list item shows: the "ADB" label, or a reachability text. */
enum class DeviceStateLabel { ADB, AVAILABLE, UNAVAILABLE }

/** Only the device connected over ADB or proven reachable can be chosen; unreachable and other-network devices are inert. */
fun isDeviceSelectable(status: DeviceStatus): Boolean = status == DeviceStatus.CONNECTED || status == DeviceStatus.AVAILABLE

/**
 * Ports to try for a saved device, without repeats: its saved port, the port of its last good connection (only a hint:
 * Wireless debugging picks a new one when it is toggled), every connect port mDNS announced for the same host, and
 * 5555 always (static ADB devices and TVs keep it even if an old wireless debugging port was saved). A stale mDNS entry alone never makes a device available; one of these must accept a TCP connection.
 */
fun probePorts(savedPort: Int, announced: Collection<Int>, lastGoodPort: Int? = null, defaultPort: Int = 5555): List<Int> =
    (listOfNotNull(savedPort, lastGoodPort) + announced + listOf(defaultPort))
        .filter { it in 1..65535 }.distinct()

/** Only the device connected over ADB shows "ADB"; devices on other networks are not reachable from here. */
fun deviceStateLabel(status: DeviceStatus): DeviceStateLabel = when (status) {
    DeviceStatus.CONNECTED -> DeviceStateLabel.ADB
    DeviceStatus.AVAILABLE -> DeviceStateLabel.AVAILABLE
    DeviceStatus.UNAVAILABLE, DeviceStatus.OTHER_NETWORK -> DeviceStateLabel.UNAVAILABLE
}

/**
 * One row of the connection card's device list; [local] is this phone. [saved] is false only for this phone when it is
 * offered as a choice but not in the saved devices (nothing to forget).
 */
data class DeviceMenuEntry(val target: Target, val status: DeviceStatus, val local: Boolean, val saved: Boolean = true)

/** The device list in its two sections; [thisNetwork] starts with this phone. */
data class DeviceMenuSections(val thisNetwork: List<DeviceMenuEntry>, val otherNetworks: List<DeviceMenuEntry>) {
    val isEmpty get() = thisNetwork.isEmpty() && otherNetworks.isEmpty()
}

/** "host:port", or only the host while the port is unknown (0). */
fun hostPortLabel(host: String, port: Int): String = if (port > 0) "${host.trim()}:$port" else host.trim()

private fun hostKey(host: String) = host.trim().lowercase()

/** The /24 network of an IPv4 address ("192.168.1.20" gives "192.168.1"); null for anything else or for loopback. */
fun isValidSubnet(s: String?): Boolean {
    if (s == null) return false
    val parts = s.split('.')
    return parts.size == 3 && parts.all { it.isNotEmpty() && it.length <= 3 && it.all(Char::isDigit) && (it.toIntOrNull() ?: 256) in 0..255 }
}

fun subnetOf(ip: String): String? {
    val parts = ip.trim().split('.')
    if (parts.size != 4) return null
    val octets = parts.map { p -> p.takeIf { it.length in 1..3 && it.all(Char::isDigit) }?.toInt()?.takeIf { it <= 255 } }
    if (octets.any { it == null }) return null
    if (octets[0] == 127 || octets[0] == 0) return null
    return octets.take(3).joinToString(".")
}

/**
 * The /24 subnets of every private (LAN) IPv4 address of this phone: Wi-Fi, but also the mobile data or VPN interface
 * that may be up at the same time, so a device on the Wi-Fi is never left out because another interface sorts first.
 */
fun currentSubnets(own: Collection<String>): Set<String> = own.map { it.trim().substringBefore('%') }.filter { ip ->
    isPrivateLanV4(ip) || isTailscaleV4(ip)
}.mapNotNull(::subnetOf).toSet()

/** True for an IPv4 address in 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16. */
fun isPrivateLanV4(ip: String): Boolean {
    val o = ip.split('.').mapNotNull { it.toIntOrNull() }
    return o.size == 4 && (o[0] == 10 || (o[0] == 192 && o[1] == 168) || (o[0] == 172 && o[1] in 16..31))
}

/**
 * The network of a saved device. An IPv4 host is always judged by its current address, because the subnet stored when it was
 * saved can be stale; only a hostname falls back to the stored subnet, if valid.
 */
fun deviceSubnet(t: Target): String? = subnetOf(t.host) ?: t.subnet?.takeIf(::isValidSubnet).takeUnless { isIpv4Literal(t.host) }

private fun isIpv4Literal(host: String): Boolean = host.trim().split('.').let { p ->
    p.size == 4 && p.all { it.length in 1..3 && it.all(Char::isDigit) && it.toInt() <= 255 }
}

/**
 * "This network": this device first (connected, otherwise available), then the devices of the current network
 * (connected, available, or unavailable, in that order). "Other networks": every device saved for another network.
 * Hosts that are this device, or repeat, are skipped. A device saved without a subnet counts as current when its host
 * lies in one of [currentSubnets]. [available] holds hosts proven reachable; [connectedHost] is the host of the device connected
 * over ADB right now.
 */
fun deviceMenuEntries(
    thisDevice: Target,
    recent: List<Target>,
    currentSubnets: Set<String>,
    available: Set<String>,
    connectedHost: String?,
    own: Collection<String> = emptySet(),
): DeviceMenuSections {
    val connected = connectedHost?.let(::hostKey)
    val up = available.map(::hostKey).toSet()
    val thisConnected = connectedHost != null && isLocalHost(connectedHost, own)
    val seen = mutableSetOf<String>()
    val others = recent.filter { target ->
        !isLocalHost(target.host, own) && seen.add(hostKey(target.host))
    }
    fun onCurrentNetwork(t: Target): Boolean {
        val subnet = deviceSubnet(t)
        if (hostKey(t.host) == connected) return true
        // One tailnet spans all of 100.64.0.0/10, whatever the /24 of each node.
        if (isTailscaleV4(t.host) && hasTailscaleAddress(own)) return true
        if (subnet == null) return false
        if (currentSubnets.isNotEmpty()) return subnet in currentSubnets
        // No private subnet known (VPN or interface naming quirk): fall back to any IPv4 address of this phone.
        return own.any { subnetOf(it.trim().substringBefore('%')) == subnet }
    }
    val (here, elsewhere) = others.partition(::onCurrentNetwork)
    fun statusOf(t: Target) = when {
        hostKey(t.host) == connected -> DeviceStatus.CONNECTED
        hostKey(t.host) in up -> DeviceStatus.AVAILABLE
        else -> DeviceStatus.UNAVAILABLE
    }
    val rank = listOf(DeviceStatus.CONNECTED, DeviceStatus.AVAILABLE, DeviceStatus.UNAVAILABLE)
    val sorted = here.map { DeviceMenuEntry(it, statusOf(it), false) }.sortedBy { rank.indexOf(it.status) }
    val self = DeviceMenuEntry(
        thisDevice, if (thisConnected) DeviceStatus.CONNECTED else DeviceStatus.AVAILABLE, true,
        saved = thisConnected || recent.any { isLocalHost(it.host, own) },
    )
    return DeviceMenuSections(
        listOf(self) + sorted,
        elsewhere.map { DeviceMenuEntry(it, DeviceStatus.OTHER_NETWORK, false) },
    )
}

private val MenuRowHeight = 72.dp
private val MenuMaxHeight = 280.dp
private val MarkSize = 10.dp
private val SideSlot = 72.dp
private val RowPadding = 16.dp
const val RefreshWhileOpenMs = 5_000L

/** Lines 2 and 3 of a device: its type, then "host:port" (network device) or "Local connection" (this phone). */
@Composable
fun deviceLines(local: Boolean, host: String, port: Int): Pair<String, String> =
    if (local) stringResource(R.string.this_device) to stringResource(R.string.local_connection)
    else stringResource(R.string.subtitle_network) to hostPortLabel(host, port)

/** Name, type and address on one centre axis, one line each. */
@Composable
private fun NameBlock(title: String, lines: Pair<String, String>?, titleColor: Color, subtitleColor: Color, modifier: Modifier = Modifier) {
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        Text(
            title,
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Medium,
            color = titleColor,
            textAlign = TextAlign.Center,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        if (lines != null) listOf(lines.first, lines.second).forEach { line ->
            Text(
                line,
                style = MaterialTheme.typography.bodySmall,
                color = subtitleColor,
                textAlign = TextAlign.Center,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/** The shared row layout: a slot on each side ([startWidth], [endWidth]) and the name block centred between them. */
@Composable
private fun DeviceRowLayout(
    startWidth: Dp,
    endWidth: Dp,
    edge: Dp,
    nameBlock: @Composable (Modifier) -> Unit,
    start: @Composable () -> Unit = {},
    end: @Composable () -> Unit = {},
) {
    Row(Modifier.fillMaxSize().padding(horizontal = edge), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.width(startWidth), contentAlignment = Alignment.CenterStart) { start() }
        nameBlock(Modifier.weight(1f))
        Box(Modifier.width(endWidth), contentAlignment = Alignment.CenterEnd) { end() }
    }
}

/**
 * The one 72 dp device row of the dropdown and of the Devices page: [start] slot, name block (name, type, address) and
 * [end] slot. A 4 dp green bar marks the row when [barColor] is set. Whole row taps to [onClick]; a null [onClick] makes
 * the row inert (no ripple, no action).
 */
@Composable
fun DeviceListRow(
    title: String,
    lines: Pair<String, String>?,
    titleColor: Color,
    subtitleColor: Color,
    onClick: (() -> Unit)?,
    startWidth: Dp = SideSlot,
    endWidth: Dp = SideSlot,
    edge: Dp = RowPadding,
    barColor: Color? = null,
    start: @Composable () -> Unit = {},
    end: @Composable () -> Unit = {},
) {
    val tap = if (onClick != null) Modifier.clickable(role = Role.Button, onClick = onClick) else Modifier
    Box(Modifier.fillMaxWidth().height(MenuRowHeight).then(tap)) {
        DeviceRowLayout(
            startWidth, endWidth, edge,
            nameBlock = { NameBlock(title, lines, titleColor, subtitleColor, it) },
            start = start,
            end = end,
        )
        if (barColor != null) ConnectedBar(barColor, Modifier.align(Alignment.CenterStart))
    }
}

/** Small caps section header; [strong] uses the text colour (page sections), otherwise secondary (sub-sections). */
@Composable
fun SectionHeader(palette: Palette, text: String, edge: Dp = RowPadding, strong: Boolean = false) {
    Text(
        text,
        style = MaterialTheme.typography.labelSmall,
        color = Color(if (strong) palette.text else palette.secondary),
        modifier = Modifier.fillMaxWidth().padding(horizontal = edge, vertical = 8.dp).semantics { if (strong) heading() },
    )
}

/** The right-hand state text of a device: "ADB" or "Available" in green, "Unavailable" in secondary. */
@Composable
fun DeviceStateText(palette: Palette, status: DeviceStatus, modifier: Modifier = Modifier) {
    val (text, color) = when (deviceStateLabel(status)) {
        DeviceStateLabel.ADB -> R.string.adb to Color(palette.success)
        DeviceStateLabel.AVAILABLE -> R.string.device_available to Color(palette.success)
        DeviceStateLabel.UNAVAILABLE -> R.string.device_unavailable to Color(palette.secondary)
    }
    Text(
        stringResource(text),
        style = MaterialTheme.typography.labelSmall,
        color = color,
        textAlign = TextAlign.End,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
        modifier = modifier,
    )
}

/** A saved device as a row; [end] replaces the default state text, [startWidth]/[endWidth]/[edge] set the geometry. */
@Composable
fun DeviceEntryRow(
    palette: Palette,
    entry: DeviceMenuEntry,
    onClick: () -> Unit,
    startWidth: Dp = SideSlot,
    endWidth: Dp = SideSlot,
    edge: Dp = RowPadding,
    end: (@Composable () -> Unit)? = null,
) {
    val title = entry.target.name.ifBlank { if (entry.local) "" else entry.target.host }.ifBlank { stringResource(R.string.this_device) }
    val lines = deviceLines(entry.local, entry.target.host, entry.target.port)
    val success = Color(palette.success)
    val secondary = Color(palette.secondary)
    val connected = entry.status == DeviceStatus.CONNECTED
    val selectable = isDeviceSelectable(entry.status)
    // An unreachable device is greyed out whole (opaque secondary colour) and does nothing when tapped.
    DeviceListRow(
        title, lines, if (selectable) Color(palette.text) else secondary, secondary, if (selectable) onClick else null,
        startWidth, endWidth, edge,
        barColor = if (connected) success else null,
        start = { if (connected) Box(Modifier.size(MarkSize).background(success)) },
        end = end ?: { DeviceStateText(palette, entry.status) },
    )
}

/** The 4 dp green bar on the left edge of the connected device's row, over the full row height. */
@Composable
private fun ConnectedBar(color: Color, modifier: Modifier = Modifier) {
    Box(modifier.width(4.dp).fillMaxHeight().background(color))
}

/** A line-drawn blue "+" for the left slot of an add row. */
@Composable
fun PlusMark(palette: Palette) {
    val accent = Color(palette.accent)
    Canvas(Modifier.size(MarkSize + 4.dp)) {
        val c = size.width / 2
        drawLine(accent, Offset(0f, c), Offset(size.width, c), strokeWidth = 2.dp.toPx())
        drawLine(accent, Offset(c, 0f), Offset(c, size.height), strokeWidth = 2.dp.toPx())
    }
}

/** First row of the open list: a line-drawn "+" in the left slot and the "Add / remove device" text centred. */
@Composable
private fun AddDeviceItem(palette: Palette, onClick: () -> Unit) {
    Box(Modifier.fillMaxWidth().height(MenuRowHeight).clickable(role = Role.Button, onClick = onClick)) {
        DeviceRowLayout(
            SideSlot, SideSlot, RowPadding,
            nameBlock = {
                Text(
                    stringResource(R.string.add_device),
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    color = Color(palette.text),
                    textAlign = TextAlign.Center,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = it,
                )
            },
            start = { PlusMark(palette) },
        )
    }
}

/**
 * Full-width 72 dp row with the name, type and address of the device connected over ADB (three centred lines) and a
 * flat chevron. Opens a flat square list in two sections, "this network" and "other networks", as wide as the row. Inert
 * when not [enabled]; [onOpen] runs each time the list opens.
 */
@Composable
fun DeviceDropdown(
    palette: Palette,
    connected: Device?,
    sections: DeviceMenuSections,
    enabled: Boolean,
    onSelect: (Target) -> Unit,
    onAddDevice: () -> Unit,
    onOpen: () -> Unit,
    modifier: Modifier = Modifier,
    onRefresh: () -> Unit = {},
) {
    var open by remember { mutableStateOf(false) }
    // While the list is open the devices are probed again, so one that is switched off (or on) shows up without reopening.
    LaunchedEffect(open) {
        while (open) {
            delay(RefreshWhileOpenMs)
            onRefresh()
        }
    }
    var widthPx by remember { mutableIntStateOf(0) }
    var heightPx by remember { mutableIntStateOf(0) }
    val text = Color(palette.text)
    val ink = if (enabled) text else Color(palette.secondary)
    val chooseLabel = stringResource(R.string.target_device_select)
    val title = connected?.name?.ifBlank { connected.host } ?: chooseLabel
    val lines = connected?.let { deviceLines(it.local, it.host, it.port) }
    val edgePx = with(LocalDensity.current) { 1.dp.roundToPx() }
    Box(modifier.fillMaxWidth().onSizeChanged { widthPx = it.width; heightPx = it.height }) {
        run {
            Box(
                Modifier.fillMaxWidth().height(MenuRowHeight)
                    .border(1.dp, Color(palette.divider))
                    .then(
                        if (enabled) Modifier.clickable(role = Role.DropdownList, onClickLabel = chooseLabel) {
                            open = !open
                            if (open) onOpen()
                        } else Modifier,
                    ),
            ) {
                DeviceRowLayout(
                    SideSlot, SideSlot, RowPadding,
                    nameBlock = { NameBlock(title, lines, ink, Color(palette.secondary), it) },
                    end = { Chevron(ink, up = open, modifier = Modifier.size(24.dp)) },
                )
                if (connected != null) ConnectedBar(Color(palette.success), Modifier.align(Alignment.CenterStart))
            }
            if (open && enabled) {
                val width = with(LocalDensity.current) { widthPx.toDp() }
                Popup(
                    alignment = Alignment.TopStart,
                    offset = IntOffset(0, heightPx - edgePx),
                    onDismissRequest = { open = false },
                    properties = PopupProperties(focusable = true),
                ) {
                    Column(
                        Modifier.width(width).heightIn(max = MenuMaxHeight)
                            .background(Color(opaque(palette.surface)))
                            .border(1.dp, Color(palette.divider))
                            .verticalScroll(rememberScrollState()),
                    ) {
                        AddDeviceItem(palette) {
                            open = false
                            onAddDevice()
                        }
                        Divider(palette)
                        val groups = listOf(
                            R.string.section_this_network to sections.thisNetwork,
                            R.string.section_other_networks to sections.otherNetworks,
                        ).filter { it.second.isNotEmpty() }
                        var first = true
                        groups.forEach { (header, entries) ->
                            SectionHeader(palette, stringResource(header))
                            entries.forEach { entry ->
                                if (!first) Divider(palette)
                                first = false
                                DeviceEntryRow(palette, entry, {
                                    open = false
                                    onSelect(entry.target)
                                })
                            }
                        }
                    }
                }
            }
        }
    }
}

/** A flat chevron made of two straight lines. */
@Composable
private fun Chevron(color: Color, up: Boolean, modifier: Modifier = Modifier) {
    Canvas(modifier) {
        val w = size.width
        val h = size.height
        val top = h * 0.4f
        val bottom = h * 0.6f
        val path = Path().apply {
            moveTo(w * 0.25f, if (up) bottom else top)
            lineTo(w * 0.5f, if (up) top else bottom)
            lineTo(w * 0.75f, if (up) bottom else top)
        }
        drawPath(path, color, style = Stroke(width = 2.dp.toPx()))
    }
}
