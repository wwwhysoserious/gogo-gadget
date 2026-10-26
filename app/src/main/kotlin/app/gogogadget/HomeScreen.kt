package app.gogogadget

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.drawscope.clipRect
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlin.math.roundToInt

val Margin = 24.dp
private val PanelHeight = 260.dp
private val NodeSize = 72.dp
private val ProgressInset = 4.dp
private const val ResultHoldMs = 4_000L

@Composable
fun Divider(palette: Palette) =
    HorizontalDivider(thickness = Dp.Hairline, color = Color(palette.divider))

@Composable
fun HomeScreen(
    palette: Palette,
    connection: Connection,
    install: InstallStatus?,
    infoOpen: Boolean,
    pairPort: Int?,
    onCode: (String) -> Unit,
    onRepost: () -> Unit,
    notificationsOk: Boolean,
    onAllowNotifications: () -> Unit,
    onOpenDeveloperOptions: () -> Unit,
    onInfoToggle: () -> Unit,
    onButton: (ButtonAction) -> Unit,
) {
    val banner = when (palette.banner) {
        Banner.A -> R.drawable.banner_a
        Banner.B -> R.drawable.banner_b
        Banner.C -> R.drawable.banner_c
    }
    val density = LocalDensity.current
    var bannerHeight by rememberSaveable { mutableIntStateOf(0) }
    val accent = Color(palette.accent)
    val button = buttonFor(connection.state)
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val viewport = maxHeight
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).heightIn(min = viewport)) {
            Column(Modifier.onSizeChanged { bannerHeight = it.height }) {
                Image(
                    painter = painterResource(banner),
                    contentDescription = stringResource(R.string.banner_description),
                    contentScale = ContentScale.FillWidth,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = Margin, vertical = 48.dp),
                )
                Divider(palette)
            }
            // The composition is centred in the space left under the banner.
            Box(
                Modifier.fillMaxWidth().heightIn(min = viewport - with(density) { bannerHeight.toDp() }),
                contentAlignment = Alignment.Center,
            ) {
                Column(Modifier.fillMaxWidth().padding(horizontal = Margin)) {
                    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            stringResource(R.string.wireless_debugging),
                            style = MaterialTheme.typography.titleMedium,
                            color = Color(palette.text),
                            maxLines = 2,
                            modifier = Modifier.weight(1f).semantics { heading() },
                        )
                        // 48 dp touch target around a 24 dp visible square, flush with the right margin.
                        val infoLabel = stringResource(R.string.info_button)
                        val infoState = stringResource(if (infoOpen) R.string.info_expanded else R.string.info_collapsed)
                        Box(
                            Modifier.size(48.dp).offset(x = 12.dp)
                                .clickable(role = Role.Button, onClick = onInfoToggle)
                                .semantics { contentDescription = infoLabel; stateDescription = infoState },
                            contentAlignment = Alignment.Center,
                        ) {
                            Box(
                                Modifier.size(24.dp).border(1.dp, accent).clearAndSetSemantics {},
                                contentAlignment = Alignment.Center,
                            ) {
                                Text(stringResource(R.string.info_glyph), style = MaterialTheme.typography.labelSmall, color = accent)
                            }
                        }
                    }
                    // The balloon takes the panel's place and is exactly as tall as its content.
                    if (infoOpen) {
                        InfoBalloon(palette, infoFor(connection), onInfoToggle)
                    } else {
                        ConnectionPanel(
                            palette, connection, pairPort, onCode, onRepost, notificationsOk, onAllowNotifications,
                            onOpenDeveloperOptions,
                            onOpenPicker = { onButton(ButtonAction.ChooseDevice) },
                            modifier = Modifier.heightIn(min = PanelHeight),
                        )
                    }
                    Spacer(Modifier.height(16.dp))
                    // The button shows the install progress while it runs and holds the result for ~4 s (or until tapped).
                    var holding by remember { mutableStateOf(false) }
                    val working = install?.working == true
                    LaunchedEffect(working) {
                        if (working) holding = true
                        else if (holding) {
                            delay(ResultHoldMs)
                            holding = false
                        }
                    }
                    if ((working || holding) && install != null) {
                        ProgressButton(palette, install, onDismiss = { holding = false })
                    } else {
                        Button(
                            onClick = { onButton(button.action) },
                            modifier = Modifier.fillMaxWidth().height(56.dp),
                            shape = RectangleShape,
                            colors = ButtonDefaults.buttonColors(),
                            elevation = null,
                        ) { Text(stringResource(button.label), style = MaterialTheme.typography.labelLarge) }
                    }
                    // Minimum-height slot so the button does not move when the install block appears; wraps if needed.
                    Box(Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(top = 12.dp)) {
                        when {
                            install != null -> InstallBlock(palette, install)
                            connection.state == ConnectionState.Connected ->
                                Text(stringResource(R.string.formats), style = MaterialTheme.typography.bodyMedium, color = Color(palette.secondary))
                        }
                    }
                }
            }
        }
    }
}

/** Package name (or file name), plus the plain failure reason and the collapsible raw diagnostic line. */
@Composable
private fun InstallBlock(palette: Palette, install: InstallStatus) {
    Column(Modifier.fillMaxWidth()) {
        if (install.name.isNotEmpty()) {
            Text(
                install.name,
                style = MaterialTheme.typography.bodyMedium,
                color = Color(palette.text),
            )
        }
        if (!install.working && !install.ok) {
            // Only the plain sentence on the main screen; the raw line stays behind "Details" (diagnostic until v1.0).
            Text(
                stringResource(install.reason ?: R.string.reason_unknown),
                style = MaterialTheme.typography.bodyMedium,
                color = Color(palette.text),
            )
            install.raw?.let { raw ->
                var open by remember(raw) { mutableStateOf(false) }
                Text(
                    stringResource(R.string.details),
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(palette.secondary),
                    modifier = Modifier.clickable(role = Role.Button) { open = !open }
                        .heightIn(min = 48.dp).padding(top = 14.dp),
                )
                if (open) Text(raw, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = Color(palette.secondary))
            }
        }
    }
}

/**
 * The main button while an install runs and for ~4 s after: a flat track with ONE solid fill (success colour, error
 * colour after a failure). While running, its width is [fillWidthPx] of the inner width and the running caption is
 * centred in [MaterialTheme.typography.labelMedium]. When finished, the fill covers the full bar and the result
 * ("Success" or "Not installed") is centred in bold 20 sp; tapping the bar returns immediately to the normal button.
 */
@Composable
private fun ProgressButton(palette: Palette, install: InstallStatus, onDismiss: () -> Unit) {
    val track = Color(palette.track)
    val fill = Color(if (install.working || install.ok) palette.success else palette.error)
    val onFill = if (fill.luminance() > 0.4f) Color.Black else Color.White
    val fillPercent = barFillPercent(install.working, install.percent)
    val caption = when {
        !install.working && install.ok -> stringResource(R.string.status_success)
        !install.working -> stringResource(R.string.status_not_installed)
        install.phase == InstallPhase.Installing -> stringResource(R.string.phase_installing)
        else -> stringResource(R.string.phase_sending, install.percent)
    }
    val textStyle = if (install.working) {
        MaterialTheme.typography.labelMedium
    } else {
        MaterialTheme.typography.labelLarge.copy(fontSize = 20.sp, lineHeight = 24.sp, fontWeight = FontWeight.Bold)
    }
    Box(
        Modifier.fillMaxWidth().height(56.dp).background(track).border(1.dp, Color(palette.trackLine))
            .then(if (!install.working) Modifier.clickable(role = Role.Button, onClick = onDismiss) else Modifier)
            .padding(ProgressInset)
            .semantics(mergeDescendants = true) {
                contentDescription = caption
                if (install.working) progressBarRangeInfo = ProgressBarRangeInfo(install.percent / 100f, 0f..1f)
            },
    ) {
        Canvas(Modifier.fillMaxSize()) {
            drawRect(fill, Offset.Zero, androidx.compose.ui.geometry.Size(fillWidthPx(size.width.roundToInt(), fillPercent).toFloat(), size.height))
        }
        Box(Modifier.fillMaxSize().clearAndSetSemantics {}, contentAlignment = Alignment.Center) {
            Text(caption, style = textStyle, color = Color(palette.text), maxLines = 1)
        }
        Box(
            Modifier.fillMaxSize().clearAndSetSemantics {}.drawWithContent {
                val w = fillWidthPx(size.width.roundToInt(), fillPercent).toFloat()
                clipRect(0f, 0f, w, size.height) { this@drawWithContent.drawContent() }
            },
            contentAlignment = Alignment.Center,
        ) {
            Text(caption, style = textStyle, color = onFill, maxLines = 1)
        }
    }
}

@Composable
private fun ConnectionPanel(
    palette: Palette,
    connection: Connection,
    pairPort: Int?,
    onCode: (String) -> Unit,
    onRepost: () -> Unit,
    notificationsOk: Boolean,
    onAllowNotifications: () -> Unit,
    onOpenDeveloperOptions: () -> Unit,
    onOpenPicker: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state = connection.state
    val text = Color(palette.text)
    val secondary = Color(palette.secondary)
    val line = Color(if (state == ConnectionState.NotConnected || state == ConnectionState.Error) palette.indicator else palette.accent)
    val tappable = state != ConnectionState.Pairing && state != ConnectionState.Connecting
    val pickLabel = stringResource(R.string.choose_device)
    Column(
        modifier.fillMaxWidth().background(Color(palette.surface))
            .then(if (tappable) Modifier.clickable(role = Role.Button, onClickLabel = pickLabel, onClick = onOpenPicker) else Modifier)
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Row(Modifier.fillMaxWidth()) {
            Node(palette, R.string.phone, Glyph.Phone)
            Box(Modifier.weight(1f).height(NodeSize)) {
                Canvas(Modifier.fillMaxSize()) {
                    val y = size.height / 2
                    val (stroke, effect) = when (state) {
                        ConnectionState.NotConnected, ConnectionState.Error ->
                            1.dp.toPx() to PathEffect.dashPathEffect(floatArrayOf(8.dp.toPx(), 6.dp.toPx()))
                        ConnectionState.Pairing, ConnectionState.Connecting ->
                            2.dp.toPx() to PathEffect.dashPathEffect(floatArrayOf(16.dp.toPx(), 6.dp.toPx()))
                        ConnectionState.Connected -> 2.dp.toPx() to null
                    }
                    drawLine(line, Offset(0f, y), Offset(size.width, y), strokeWidth = stroke, pathEffect = effect)
                }
                lineLabelFor(connection)?.let {
                    Text(
                        stringResource(it),
                        style = MaterialTheme.typography.labelSmall,
                        color = secondary,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth().padding(top = NodeSize / 2 - 20.dp),
                    )
                }
            }
            Node(palette, R.string.adb, Glyph.Terminal)
        }
        // The state text is centred, both ways, in the space left under the diagram.
        Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                connection.error?.let {
                    Text(
                        stringResource(it.message),
                        style = MaterialTheme.typography.bodyMedium,
                        color = Color(palette.error),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(bottom = if (connection.detail == null) 8.dp else 2.dp),
                    )
                    // Temporary (remove before v1.0): the real cause, so a failure on a device can be diagnosed.
                    connection.detail?.let { detail ->
                        Text(
                            detail,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = secondary,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )
                    }
                }
                when (state) {
                    ConnectionState.Pairing -> PairingForm(
                        palette, connection.device?.local != false, pairPort, onCode, onRepost, notificationsOk, onAllowNotifications,
                        onOpenDeveloperOptions,
                    )
                    ConnectionState.Connected -> connection.device?.let { device ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(Modifier.size(12.dp).background(Color(palette.success)))
                            Spacer(Modifier.width(8.dp))
                            Text(
                                device.name,
                                style = MaterialTheme.typography.bodyLarge,
                                fontWeight = FontWeight.Medium,
                                color = text,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        Text(
                            stringResource(if (device.local) R.string.subtitle_this_device else R.string.subtitle_network),
                            style = MaterialTheme.typography.bodyMedium,
                            color = secondary,
                        )
                        Text(
                            hostPort(device.host, device.port),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = secondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    ConnectionState.Connecting -> {
                        Text(
                            stringResource(R.string.connecting),
                            style = MaterialTheme.typography.bodyLarge,
                            fontWeight = FontWeight.Medium,
                            color = text,
                        )
                        // Where to tap Allow: the other device (or Android on this phone) shows the prompt, not this app.
                        connection.note?.let {
                            Text(
                                stringResource(it),
                                style = MaterialTheme.typography.bodyMedium,
                                color = secondary,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.padding(top = 8.dp),
                            )
                        }
                    }
                    ConnectionState.NotConnected -> Text(
                        stringResource(R.string.not_connected),
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                        color = text,
                    )
                    ConnectionState.Error -> {}
                }
            }
        }
    }
}

/**
 * "This device": the code is typed in the notification (so the system pairing dialog stays on screen), the app only
 * guides and shows the state. Another device: the six-digit code is typed here and submitted by itself as soon as the
 * pairing port has been detected; a code typed earlier waits in memory until then and is never stored.
 */
@Composable
private fun PairingForm(
    palette: Palette,
    local: Boolean,
    port: Int?,
    onCode: (String) -> Unit,
    onRepost: () -> Unit,
    notificationsOk: Boolean,
    onAllowNotifications: () -> Unit,
    onOpenDeveloperOptions: () -> Unit,
) {
    if (local) {
        LocalPairing(palette, port, onRepost, notificationsOk, onAllowNotifications, onOpenDeveloperOptions)
    }
    else NetworkPairing(palette, port, onCode)
}

@Composable
private fun LocalPairing(
    palette: Palette,
    port: Int?,
    onRepost: () -> Unit,
    notificationsOk: Boolean,
    onAllowNotifications: () -> Unit,
    onOpenDeveloperOptions: () -> Unit,
) {
    val accent = Color(palette.accent)
    Text(
        stringResource(R.string.pairing_steps),
        style = MaterialTheme.typography.bodyMedium,
        color = Color(palette.secondary),
    )
    Spacer(Modifier.height(8.dp))
    OutlinedButton(
        onClick = onOpenDeveloperOptions,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        shape = RectangleShape,
        border = BorderStroke(1.dp, accent),
    ) { Text(stringResource(R.string.open_wireless_debugging), style = MaterialTheme.typography.labelLarge, color = accent) }
    Spacer(Modifier.height(12.dp))
    Text(
        stringResource(R.string.type_code_in_notification),
        style = MaterialTheme.typography.bodyLarge,
        fontWeight = FontWeight.Medium,
        color = Color(palette.text),
        textAlign = TextAlign.Center,
    )
    Text(
        stringResource(
            when (localPairingStatus(port)) {
                LocalPairingStatus.WaitingForDialog -> R.string.pairing_status_waiting
                LocalPairingStatus.DialogFound -> R.string.pairing_status_found
            },
        ),
        style = MaterialTheme.typography.bodyMedium,
        color = Color(palette.secondary),
        textAlign = TextAlign.Center,
        modifier = Modifier.padding(top = 4.dp),
    )
    Spacer(Modifier.height(8.dp))
    OutlinedButton(
        onClick = if (notificationsOk) onRepost else onAllowNotifications,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        shape = RectangleShape,
        border = BorderStroke(1.dp, accent),
    ) {
        Text(
            stringResource(if (notificationsOk) R.string.notif_repost else R.string.notif_allow),
            style = MaterialTheme.typography.labelLarge,
            color = accent,
        )
    }
}

@Composable
private fun NetworkPairing(palette: Palette, port: Int?, onCode: (String) -> Unit) {
    var code by remember { mutableStateOf("") }
    val focus = remember { FocusRequester() }
    val step = pairingStep(code, port)
    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }
    // Also runs when the port shows up after the sixth digit was typed (the pending code, kept in memory only).
    LaunchedEffect(code, port) { if (step == PairingStep.Submit) onCode(code) }
    Text(
        stringResource(R.string.pairing_hint_network),
        style = MaterialTheme.typography.bodyMedium,
        color = Color(palette.secondary),
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(8.dp))
    // NumberPassword keeps the keyboard from learning the code.
    Field(palette, code, { if (it.length <= PairingCodeLength && it.all { c -> c in '0'..'9' }) code = it },
        R.string.pairing_code_hint, KeyboardType.NumberPassword, mono = true,
        modifier = Modifier.focusRequester(focus))
    if (step == PairingStep.WaitingForDialog) {
        Text(
            stringResource(R.string.pairing_status_waiting),
            style = MaterialTheme.typography.bodyMedium,
            color = Color(palette.secondary),
            modifier = Modifier.padding(top = 8.dp),
        )
    }
}

/** A flat, square text field with a 1 px border; [hint] is both placeholder and accessibility label. */
@Composable
fun Field(
    palette: Palette,
    value: String,
    onValue: (String) -> Unit,
    hint: Int,
    keyboard: KeyboardType,
    mono: Boolean = false,
    imeAction: ImeAction = ImeAction.Default,
    onDone: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val label = stringResource(hint)
    val style = MaterialTheme.typography.bodyLarge.copy(
        color = Color(palette.text),
        fontFamily = if (mono) FontFamily.Monospace else null,
    )
    BasicTextField(
        value = value,
        onValueChange = onValue,
        singleLine = true,
        textStyle = style,
        cursorBrush = SolidColor(Color(palette.accent)),
        keyboardOptions = KeyboardOptions(keyboardType = keyboard, autoCorrectEnabled = false, imeAction = imeAction),
        keyboardActions = KeyboardActions(onDone = onDone?.let { go -> { go() } }),
        modifier = modifier.fillMaxWidth().height(48.dp).border(1.dp, Color(palette.text)).semantics { contentDescription = label },
        decorationBox = { inner ->
            Box(Modifier.padding(horizontal = 12.dp), contentAlignment = Alignment.CenterStart) {
                if (value.isEmpty()) Text(label, style = style.copy(color = Color(palette.secondary)))
                inner()
            }
        },
    )
}

private enum class Glyph { Phone, Terminal }

@Composable
private fun Node(palette: Palette, label: Int, glyph: Glyph) {
    val text = Color(palette.text)
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Canvas(Modifier.size(NodeSize).background(Color(palette.background)).border(1.dp, text)) {
            val w = 2.dp.toPx()
            val c = Offset(size.width / 2, size.height / 2)
            when (glyph) {
                Glyph.Phone -> {
                    val half = Offset(11.dp.toPx(), 18.dp.toPx())
                    drawRect(text, c - half, androidx.compose.ui.geometry.Size(half.x * 2, half.y * 2), style = androidx.compose.ui.graphics.drawscope.Stroke(w))
                    drawLine(text, Offset(c.x - 3.dp.toPx(), c.y - 12.dp.toPx()), Offset(c.x + 3.dp.toPx(), c.y - 12.dp.toPx()), w)
                    drawRect(text, Offset(c.x - 1.5.dp.toPx(), c.y + 10.dp.toPx()), androidx.compose.ui.geometry.Size(3.dp.toPx(), 3.dp.toPx()))
                }
                Glyph.Terminal -> {
                    val x = c.x - 10.dp.toPx()
                    drawLine(text, Offset(x, c.y - 9.dp.toPx()), Offset(x + 9.dp.toPx(), c.y), w)
                    drawLine(text, Offset(x + 9.dp.toPx(), c.y), Offset(x, c.y + 9.dp.toPx()), w)
                    drawLine(text, Offset(c.x + 2.dp.toPx(), c.y + 9.dp.toPx()), Offset(c.x + 14.dp.toPx(), c.y + 9.dp.toPx()), w)
                }
            }
        }
        Text(
            stringResource(label),
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            color = text,
            modifier = Modifier.padding(top = 4.dp),
        )
    }
}

@Composable
private fun InfoBalloon(palette: Palette, info: InfoContent, onClose: () -> Unit, modifier: Modifier = Modifier) {
    val text = Color(palette.text)
    Column(
        modifier.fillMaxWidth().background(Color(palette.surface))
            .border(1.dp, Color(palette.accent))
            .padding(horizontal = 12.dp).padding(top = 12.dp),
    ) {
        Text(
            stringResource(info.title),
            style = MaterialTheme.typography.labelLarge,
            color = text,
            modifier = Modifier.semantics { heading() },
        )
        info.intro?.let {
            Text(stringResource(it), style = MaterialTheme.typography.bodySmall, color = text,
                modifier = Modifier.padding(top = 4.dp))
        }
        Spacer(Modifier.height(4.dp))
        info.steps.forEachIndexed { i, step ->
            Row(Modifier.padding(top = 4.dp)) {
                Text(stringResource(R.string.step_number, i + 1), style = MaterialTheme.typography.bodySmall, color = Color(palette.secondary),
                    modifier = Modifier.width(20.dp))
                Text(stringResource(step), style = MaterialTheme.typography.bodySmall, color = text)
            }
        }
        Box(
            Modifier.fillMaxWidth().height(48.dp).clickable(role = Role.Button, onClick = onClose),
            contentAlignment = Alignment.CenterEnd,
        ) {
            Text(
                stringResource(R.string.close),
                style = MaterialTheme.typography.labelMedium,
                color = Color(palette.accent),
            )
        }
    }
}
