package app.gogogadget

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipRect
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.VisualTransformation
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
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlin.math.roundToInt

val Margin = 24.dp
private val PanelHeight = 234.dp
private val CardHeight = 420.dp
private val NodeSize = 64.dp
private val ProgressInset = 4.dp
private const val ResultHoldMs = 4_000L

@Composable
fun Divider(palette: Palette) =
    HorizontalDivider(thickness = Dp.Hairline, color = Color(palette.divider))

enum class HomeSlide { Connection, Terminal, Shield }

@Composable
fun HomeScreen(
    palette: Palette,
    connection: Connection,
    install: InstallStatus?,
    infoOpen: Boolean,
    pairPort: Int?,
    onCode: (String) -> Unit,
    onRepost: () -> Unit,
    onOpenDeveloperOptions: () -> Unit,
    onInfoToggle: () -> Unit,
    onButton: (ButtonAction) -> Unit,
    menu: DeviceMenuSections,
    onSelectDevice: (Target) -> Unit,
    onAddDevice: () -> Unit,
    onMenuOpen: () -> Unit,
    onMenuRefresh: () -> Unit = {},
    /** Maximum protection: the Shield is on and an online key is set. Otherwise the protection is limited. */
    maximumProtection: Boolean = false,
    hasSecurityKeys: Boolean = false,
    onOpenSecurityApis: () -> Unit = {},
    onStartActivation: () -> Unit = {},
    onStartDeactivation: () -> Unit = {},
    onHowItWorks: () -> Unit = {},
    onConfirmUpload: (Int) -> Unit,
    onCancelUpload: (Int) -> Unit,
    onConfirmCaution: (Int) -> Unit = {},
    onCancelCaution: (Int) -> Unit = {},
    onDeleteSource: () -> Unit = {},
    /** A package opened from another app that waits for a device or for the running install. */
    pendingName: String? = null,
    onCancelPending: () -> Unit = {},
    /** Connecting and pairing lines (see [TerminalLog]); the terminal slide shows them before the install lines. */
    log: List<String> = emptyList(),
) {
    val banner = when (palette.banner) {
        Banner.A -> R.drawable.banner_a
        Banner.B -> R.drawable.banner_b
        Banner.C -> R.drawable.banner_c
    }
    val density = LocalDensity.current
    var bannerHeight by rememberSaveable { mutableIntStateOf(0) }

    val hasLog = log.isNotEmpty()
    val pages = remember(install, connection.state, hasLog) {
        buildList {
            add(HomeSlide.Connection)
            if (install != null || hasLog) add(HomeSlide.Terminal)
            if (install != null && (install.cautionPrompt != null || install.uploadPrompt != null)) add(HomeSlide.Shield)
        }
    }

    val pagerState = rememberPagerState(pageCount = { pages.size })

    LaunchedEffect(install?.working) {
        if (install?.working == true) {
            val termIdx = pages.indexOf(HomeSlide.Terminal)
            if (termIdx >= 0) pagerState.animateScrollToPage(termIdx)
        }
    }

    LaunchedEffect(install?.cautionPrompt, install?.uploadPrompt) {
        if (install?.cautionPrompt != null || install?.uploadPrompt != null) {
            val shieldIdx = pages.indexOf(HomeSlide.Shield)
            if (shieldIdx >= 0) pagerState.animateScrollToPage(shieldIdx)
        } else if (pagerState.currentPage >= pages.size) {
            pagerState.animateScrollToPage((pages.size - 1).coerceAtLeast(0))
        }
    }

    LaunchedEffect(install?.working, install?.ok) {
        if (install != null && !install.working && install.ok) {
            delay(3500L)
            if (pagerState.currentPage == pages.indexOf(HomeSlide.Terminal)) {
                pagerState.animateScrollToPage(0)
            }
        }
    }

    Column(Modifier.fillMaxSize()) {
        HomeBanner(
            palette = palette,
            banner = banner,
            isMaximum = maximumProtection,
            hasSecurityKeys = hasSecurityKeys,
            onStartActivation = onStartActivation,
            onStartDeactivation = onStartDeactivation,
            onOpenSecurityApis = onOpenSecurityApis,
            modifier = Modifier.onSizeChanged { bannerHeight = it.height },
        )

        Box(
            modifier = Modifier.fillMaxWidth().weight(1f).padding(bottom = 12.dp),
            contentAlignment = Alignment.Center,
        ) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                if (pendingName != null) {
                    Row(
                        Modifier.fillMaxWidth().height(48.dp).padding(horizontal = Margin),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            stringResource(R.string.pending_file, pendingName),
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color(palette.secondary),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                        Text(
                            stringResource(R.string.cancel),
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color(palette.accent),
                            modifier = Modifier.clickable(role = Role.Button, onClick = onCancelPending).padding(start = 12.dp),
                        )
                    }
                }
                if (pages.size > 1) {
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = Margin, vertical = 8.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        pages.forEachIndexed { idx, _ ->
                            val isCurrent = pagerState.currentPage == idx
                            Box(
                                Modifier
                                    .size(width = 24.dp, height = 4.dp)
                                    .background(Color(if (isCurrent) palette.accent else palette.divider))
                            )
                            if (idx < pages.size - 1) Spacer(Modifier.width(6.dp))
                        }
                    }
                }

                HorizontalPager(
                    state = pagerState,
                    modifier = Modifier.fillMaxWidth().height(CardHeight),
                    verticalAlignment = Alignment.CenterVertically,
                ) { pageIndex ->
                    val slide = pages.getOrElse(pageIndex) { HomeSlide.Connection }
                    Box(
                        Modifier
                            .fillMaxWidth()
                            .height(CardHeight)
                            .padding(horizontal = Margin)
                            .border(1.dp, Color(palette.divider))
                            .background(Color(palette.surface))
                            .padding(14.dp),
                        contentAlignment = Alignment.TopCenter,
                    ) {
                        when (slide) {
                            HomeSlide.Connection -> {
                                Column(
                                    Modifier.fillMaxSize()
                                        .verticalScroll(rememberScrollState())
                                ) {
                                    HomeControls(
                                        palette, connection, install, infoOpen, pairPort, onCode, onRepost,
                                        onOpenDeveloperOptions, onInfoToggle,
                                        onButton, menu, onSelectDevice, onAddDevice, onMenuOpen, onMenuRefresh, fixedPanel = true,
                                    )
                                    Box(Modifier.fillMaxWidth().padding(top = 8.dp)) {
                                        if (connection.state == ConnectionState.Connected) {
                                            Text(
                                                stringResource(R.string.formats),
                                                style = MaterialTheme.typography.bodyMedium,
                                                color = Color(palette.secondary),
                                                maxLines = 2,
                                            )
                                        }
                                    }
                                }
                            }
                            HomeSlide.Terminal -> {
                                Column(
                                    Modifier.fillMaxSize()
                                ) {
                                    if (install != null) {
                                        InstallSummary(
                                            palette = palette,
                                            install = install,
                                            onConfirmUpload = onConfirmUpload,
                                            onCancelUpload = onCancelUpload,
                                            onConfirmCaution = onConfirmCaution,
                                            onCancelCaution = onCancelCaution,
                                            onDeleteSource = onDeleteSource,
                                        )
                                        Spacer(Modifier.height(8.dp))
                                    }
                                    TerminalLogBox(
                                        palette = palette,
                                        logs = log + install?.logs.orEmpty(),
                                        modifier = Modifier.weight(1f).fillMaxWidth()
                                    )
                                }
                            }
                            HomeSlide.Shield -> {
                                if (install?.cautionPrompt != null) {
                                    CautionPromptCard(
                                        palette = palette,
                                        prompt = install.cautionPrompt,
                                        verdict = install.shieldVerdict,
                                        onConfirm = onConfirmCaution,
                                        onCancel = onCancelCaution,
                                    )
                                } else if (install?.uploadPrompt != null) {
                                    UploadPromptCard(
                                        palette = palette,
                                        prompt = install.uploadPrompt,
                                        onConfirm = onConfirmUpload,
                                        onCancel = onCancelUpload,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
        // Takes the place of the 48 dp that the carousel box used to leave empty (its bottom padding went 60 dp -> 12 dp).
        // Same 24 dp "i" square as the wireless debugging card, then the label; one 48 dp touch row.
        Row(
            Modifier.fillMaxWidth().height(48.dp).clickable(role = Role.Button, onClick = onHowItWorks)
                .padding(horizontal = Margin),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier.size(24.dp).border(1.dp, Color(palette.accent)).clearAndSetSemantics {},
                contentAlignment = Alignment.Center,
            ) {
                Text(stringResource(R.string.info_glyph), style = MaterialTheme.typography.labelSmall, color = Color(palette.accent))
            }
            Spacer(Modifier.width(8.dp))
            Text(
                stringResource(R.string.how_it_works),
                style = MaterialTheme.typography.bodySmall,
                color = Color(palette.secondary),
            )
        }
    }
}

/**
 * The banner. One line under it always shows the protection level behind a flat toggle: on and green with maximum
 * protection (the Shield is on and an API key is set), off and grey otherwise. Tapping the row opens the Security APIs
 * screen. Where the tagline used to be, so the carousel card (420 dp) and the connection panel (234 dp) keep their size.
 */
@Composable
private fun HomeBanner(
    palette: Palette,
    banner: Int,
    isMaximum: Boolean,
    hasSecurityKeys: Boolean,
    onStartActivation: () -> Unit,
    onStartDeactivation: () -> Unit,
    onOpenSecurityApis: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val animProgress = remember { Animatable(if (isMaximum) 1f else 0f) }
    var isTransitioning by remember { mutableStateOf(false) }

    LaunchedEffect(isMaximum) {
        if (!isTransitioning) {
            animProgress.snapTo(if (isMaximum) 1f else 0f)
        }
    }

    val currentFraction = animProgress.value
    val toggleColor = when {
        isTransitioning && !isMaximum -> {
            // Transição a ativar (cinzento -> verde)
            lerp(Color(palette.secondary), Color(palette.success), currentFraction)
        }
        isTransitioning && isMaximum -> {
            // Transição a desativar (vermelho -> cinzento)
            lerp(Color(palette.error), Color(palette.secondary), 1f - currentFraction)
        }
        isMaximum -> Color(palette.success)
        else -> Color(palette.secondary)
    }

    val statusText = when {
        isTransitioning && !isMaximum -> stringResource(R.string.protection_activating)
        isTransitioning && isMaximum -> stringResource(R.string.protection_deactivating)
        isMaximum -> stringResource(R.string.protection_maximum)
        else -> stringResource(R.string.protection_limited)
    }

    Column(modifier) {
        Image(
            painter = painterResource(banner),
            contentDescription = stringResource(R.string.banner_description),
            contentScale = ContentScale.FillWidth,
            modifier = Modifier.fillMaxWidth().padding(start = Margin, end = Margin, top = 12.dp),
        )
        Row(
            Modifier.fillMaxWidth()
                .clickable(role = Role.Switch) {
                    if (isTransitioning) return@clickable
                    if (isMaximum) {
                        // Desativar: vermelho para cinzento em 4s
                        isTransitioning = true
                        scope.launch {
                            animProgress.snapTo(1f)
                            animProgress.animateTo(0f, tween(durationMillis = 4000, easing = LinearEasing))
                            isTransitioning = false
                            onStartDeactivation()
                        }
                    } else if (hasSecurityKeys) {
                        // Ativar: cinzento para verde em 4s
                        isTransitioning = true
                        scope.launch {
                            animProgress.snapTo(0f)
                            animProgress.animateTo(1f, tween(durationMillis = 4000, easing = LinearEasing))
                            isTransitioning = false
                            onStartActivation()
                        }
                    } else {
                        onOpenSecurityApis()
                    }
                }
                .heightIn(min = 48.dp).padding(horizontal = Margin),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FlatToggle(checked = isMaximum, color = toggleColor, progress = currentFraction)
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    statusText,
                    style = MaterialTheme.typography.bodySmall,
                    color = toggleColor,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    stringResource(if (isMaximum) R.string.protection_info_hint else R.string.protection_info_hint_off),
                    style = MaterialTheme.typography.labelSmall,
                    color = Color(palette.secondary),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Divider(palette)
    }
}

/** A read-only square toggle (36 x 20 dp): the thumb sits at the end when [checked], and is filled with [color]. */
@Composable
private fun FlatToggle(
    checked: Boolean,
    color: Color,
    progress: Float = if (checked) 1f else 0f,
) {
    Box(
        Modifier.size(width = 36.dp, height = 20.dp).border(1.dp, color).padding(2.dp).clearAndSetSemantics {},
    ) {
        val offsetDp = (18.dp * progress.coerceIn(0f, 1f))
        Box(
            Modifier
                .align(Alignment.CenterStart)
                .offset(x = offsetDp)
                .size(14.dp)
                .background(color),
        )
    }
}

/** Title row, connection panel (or info balloon) and the main button, shared by both Home layouts. */
@Composable
private fun HomeControls(
    palette: Palette,
    connection: Connection,
    install: InstallStatus?,
    infoOpen: Boolean,
    pairPort: Int?,
    onCode: (String) -> Unit,
    onRepost: () -> Unit,
    onOpenDeveloperOptions: () -> Unit,
    onInfoToggle: () -> Unit,
    onButton: (ButtonAction) -> Unit,
    menu: DeviceMenuSections,
    onSelectDevice: (Target) -> Unit,
    onAddDevice: () -> Unit,
    onMenuOpen: () -> Unit,
    onMenuRefresh: () -> Unit = {},
    fixedPanel: Boolean,
) {
    val accent = Color(palette.accent)
    val button = buttonFor(connection.state)
    Column(Modifier.fillMaxWidth()) {
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
                palette, connection, pairPort, onCode, onRepost,
                onOpenDeveloperOptions,
                menu, onSelectDevice, onAddDevice, onMenuOpen, onMenuRefresh,
                // Terminal mode is measured with a bounded height: the panel's weighted text area would fill it all.
                modifier = if (fixedPanel) Modifier.height(PanelHeight) else Modifier.heightIn(min = PanelHeight),
            )
        }
        Spacer(Modifier.height(12.dp))
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
    }
}

/** True when the result must say that the shield was off: nothing was checked, and no verdict exists. */
internal fun shieldOffNote(install: InstallStatus): Boolean = install.shieldOff && install.shieldVerdict == null

/** Package name (or file name) with its result mark, persistent Security Shield status, and any failure reason. */
@Composable
private fun InstallSummary(
    palette: Palette,
    install: InstallStatus,
    onConfirmUpload: (Int) -> Unit,
    onCancelUpload: (Int) -> Unit,
    onConfirmCaution: (Int) -> Unit = {},
    onCancelCaution: (Int) -> Unit = {},
    onDeleteSource: () -> Unit = {},
) {
    Column(Modifier.fillMaxWidth()) {
        if (install.name.isNotEmpty()) {
            val mark = packageResultMark(install.working, install.ok)
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (mark != PackageResultMark.None) {
                    val markColor = Color(if (mark == PackageResultMark.Check) palette.success else palette.error)
                    Canvas(Modifier.size(12.dp)) {
                        val w = 2.dp.toPx()
                        when (mark) {
                            PackageResultMark.Check -> {
                                val p1 = Offset(size.width * 0.12f, size.height * 0.55f)
                                val p2 = Offset(size.width * 0.42f, size.height * 0.85f)
                                val p3 = Offset(size.width * 0.90f, size.height * 0.18f)
                                drawLine(markColor, p1, p2, strokeWidth = w)
                                drawLine(markColor, p2, p3, strokeWidth = w)
                            }
                            PackageResultMark.Cross -> {
                                drawLine(
                                    markColor,
                                    Offset(size.width * 0.15f, size.height * 0.15f),
                                    Offset(size.width * 0.85f, size.height * 0.85f),
                                    strokeWidth = w,
                                )
                                drawLine(
                                    markColor,
                                    Offset(size.width * 0.85f, size.height * 0.15f),
                                    Offset(size.width * 0.15f, size.height * 0.85f),
                                    strokeWidth = w,
                                )
                            }
                            PackageResultMark.None -> {}
                        }
                    }
                    Spacer(Modifier.width(8.dp))
                }
                Text(
                    install.name,
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(palette.text),
                )
            }
        }
        val prompt = install.uploadPrompt
        val caution = install.cautionPrompt
        val showShield = (install.shieldChecking && prompt == null && caution == null) || (install.shieldVerdict != null && caution == null)
        if (showShield) {
            if (install.name.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
            }
            ShieldStatusBlock(
                palette = palette,
                checking = install.shieldChecking && prompt == null && caution == null,
                verdict = install.shieldVerdict,
                userAuthorized = install.userAuthorized,
            )
        }
        if (shieldOffNote(install)) {
            if (install.name.isNotEmpty()) Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                SecurityShieldIcon(color = Color(palette.secondary), modifier = Modifier.size(16.dp), check = false)
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(R.string.shield_off_note),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(palette.secondary),
                )
            }
        }
        if (!install.working && !install.ok && (install.userAuthorized || install.shieldVerdict !is ShieldVerdict.Warning)) {
            if (showShield || shieldOffNote(install) || install.name.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
            }
            // Only the plain sentence on the main screen; the raw line stays behind "Details" (diagnostic until v1.0).
            Text(
                stringResource(install.reason ?: R.string.reason_unknown),
                style = MaterialTheme.typography.bodyMedium,
                color = Color(palette.error),
                fontWeight = FontWeight.Bold,
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
        if (!install.working && install.sourceUri != null) {
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = onDeleteSource,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RectangleShape,
                border = BorderStroke(1.dp, Color(palette.divider)),
            ) {
                Text(
                    stringResource(R.string.delete_source_file),
                    style = MaterialTheme.typography.labelMedium,
                    color = Color(palette.error),
                )
            }
        }
    }
}

/** True when the terminal should keep following the newest line: the view is at, or within [thresholdPx] of, the bottom. */
internal fun shouldFollowTail(value: Int, maxValue: Int, thresholdPx: Int): Boolean =
    maxValue - value <= thresholdPx

/** The log box: the header stays fixed, the lines scroll and follow the tail unless the user scrolled up to read. */
@Composable
private fun TerminalLogBox(
    palette: Palette,
    logs: List<String>,
    modifier: Modifier = Modifier,
) {
    val scrollState = rememberScrollState()
    val thresholdPx = with(LocalDensity.current) { 24.dp.roundToPx() }
    var atBottom by remember { mutableStateOf(true) }
    var lastSize by remember { mutableIntStateOf(logs.size) }
    // Only the user (or the jump below) changes the scroll value; new content changes maxValue, so this keeps the intent.
    LaunchedEffect(scrollState) {
        snapshotFlow { scrollState.value }.collect { atBottom = shouldFollowTail(it, scrollState.maxValue, thresholdPx) }
    }
    LaunchedEffect(logs.size) {
        if (logs.size < lastSize) atBottom = true
        lastSize = logs.size
    }
    // Always follow the newest line: every new line (and every size change) jumps to the bottom.
    LaunchedEffect(logs.size) {
        snapshotFlow { scrollState.maxValue }.collect { scrollState.scrollTo(it) }
    }
    Column(
        modifier.fillMaxWidth()
            .background(Color(palette.surface))
            .border(1.dp, Color(palette.divider))
            .padding(12.dp),
    ) {
        Text(
            stringResource(R.string.terminal_header),
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
            color = Color(palette.secondary),
        )
        Spacer(Modifier.height(6.dp))
        Divider(palette)
        Spacer(Modifier.height(6.dp))
        Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(scrollState)) {
        for ((index, line) in logs.withIndex()) {
            val lineColor = when {
                line.contains("BLOCKED") ||
                    line.contains("ABORT") ||
                    line.contains("UNSIGNED") ||
                    line.contains("UNTRUSTED") ||
                    line.contains("MISMATCH") ||
                    line.contains("Failure") ||
                    line.startsWith("> error:") -> Color(palette.error)
                line.contains("PASS") || line.contains("pm: Success") -> Color(palette.success)
                else -> Color(palette.text)
            }
            Text(
                text = String.format(java.util.Locale.US, "%02d %s", index + 1, line),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = lineColor,
                modifier = Modifier.padding(vertical = 1.dp),
            )
        }
        }
    }
}

@Composable
internal fun SecurityShieldIcon(
    color: Color,
    modifier: Modifier = Modifier.size(18.dp),
    check: Boolean = true,
) {
    Canvas(modifier) {
        val sx = size.width / 24f
        val sy = size.height / 24f
        val strokeWidth = (size.minDimension * (2.2f / 24f)).coerceAtLeast(1.5.dp.toPx())
        val shieldPath = Path().apply {
            moveTo(12f * sx, 2f * sy)
            lineTo(20f * sx, 5.5f * sy)
            lineTo(20f * sx, 11.5f * sy)
            lineTo(18.6f * sx, 15.6f * sy)
            lineTo(15.8f * sx, 19.2f * sy)
            lineTo(12f * sx, 22f * sy)
            lineTo(8.2f * sx, 19.2f * sy)
            lineTo(5.4f * sx, 15.6f * sy)
            lineTo(4f * sx, 11.5f * sy)
            lineTo(4f * sx, 5.5f * sy)
            close()
        }
        drawPath(shieldPath, color = color, style = Stroke(width = strokeWidth))
        if (check) {
            val checkPath = Path().apply {
                moveTo(8.2f * sx, 12.2f * sy)
                lineTo(11.0f * sx, 15.0f * sy)
                lineTo(16.2f * sx, 9.2f * sy)
            }
            drawPath(checkPath, color = color, style = Stroke(width = strokeWidth))
        }
    }
}

/** The question before a file is sent to VirusTotal: compact, flat, buttons 48 dp tall. */
@Composable
private fun UploadPromptCard(palette: Palette, prompt: UploadPrompt, onConfirm: (Int) -> Unit, onCancel: (Int) -> Unit) {
    val accent = Color(palette.accent)
    val body = LocalContext.current.resources.getQuantityString(
        R.plurals.shield_upload_body, prompt.fileCount, prompt.fileCount, formatUploadSize(prompt.totalBytes),
    )
    Column(
        Modifier.fillMaxSize()
            .background(Color(palette.surface))
            .padding(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SecurityShieldIcon(color = accent, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(8.dp))
            Text(
                stringResource(R.string.shield_upload_title),
                style = MaterialTheme.typography.labelLarge,
                color = Color(palette.text),
                modifier = Modifier.semantics { heading() },
            )
        }
        Spacer(Modifier.height(12.dp))
        Box(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState())) {
            Text(
                body,
                style = MaterialTheme.typography.bodyMedium,
                color = Color(palette.text),
            )
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { onConfirm(prompt.id) },
                modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                shape = RectangleShape,
                colors = ButtonDefaults.buttonColors(),
                elevation = null,
            ) { Text(stringResource(R.string.shield_upload_send), style = MaterialTheme.typography.labelLarge) }
            OutlinedButton(
                onClick = { onCancel(prompt.id) },
                modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                shape = RectangleShape,
                border = BorderStroke(1.dp, Color(palette.text)),
            ) { Text(stringResource(R.string.cancel), style = MaterialTheme.typography.labelLarge, color = Color(palette.text)) }
        }
    }
}

/**
 * Interactive Caution Prompt Card (Yellow Tier):
 * Yellow/amber accent border, flat, 0 dp radius.
 * Shows which file was checked, EVERY reason (each with its own title, what was found and what it means), what the online
 * engines said, and two action buttons: Cancel (Recommended) and Install Anyway (I Trust This Source).
 */
@Composable
private fun CautionPromptCard(
    palette: Palette,
    prompt: CautionPrompt,
    verdict: ShieldVerdict?,
    onConfirm: (Int) -> Unit,
    onCancel: (Int) -> Unit,
) {
    val cautionColor = if (palette.isDark) Color(0xFFF59E0B) else Color(0xFFD97706)
    val warning = verdict as? ShieldVerdict.Warning
    Column(
        Modifier.fillMaxSize()
            .background(Color(palette.surface))
            .padding(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SecurityShieldIcon(color = cautionColor, modifier = Modifier.size(18.dp), check = false)
            Spacer(Modifier.width(8.dp))
            Text(
                stringResource(R.string.caution_title),
                style = MaterialTheme.typography.titleMedium,
                color = cautionColor,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.semantics { heading() },
            )
        }
        Spacer(Modifier.height(10.dp))
        Column(
            Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState())
        ) {
            if (verdict != null) {
                ShieldFileLine(palette, verdict)
                Spacer(Modifier.height(10.dp))
            }
            val reasons = warning?.reasons ?: listOf(prompt.reason)
            for (reason in reasons) {
                ReasonBlock(palette, reason, warning, cautionColor)
                Spacer(Modifier.height(10.dp))
            }
            Text(
                text = onlineNote(verdict),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = Color(palette.text),
            )
        }
        Spacer(Modifier.height(12.dp))
        // Two buttons: [ Cancel (Recommended) ] and [ Install Anyway (I Trust This Source) ]
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { onCancel(prompt.id) },
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                shape = RectangleShape,
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(palette.buttonContainer),
                    contentColor = Color(palette.buttonContent),
                ),
                elevation = null,
            ) {
                Text(
                    stringResource(R.string.caution_cancel_recommended),
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                )
            }
            OutlinedButton(
                onClick = { onConfirm(prompt.id) },
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                shape = RectangleShape,
                border = BorderStroke(1.dp, cautionColor),
            ) {
                Text(
                    stringResource(R.string.caution_install_anyway),
                    style = MaterialTheme.typography.labelLarge,
                    color = cautionColor,
                )
            }
        }
    }
}

private const val MaxIssueLines = 5

/** The SHA-256 of what the user picked, whatever the verdict. */
internal fun verdictSha(verdict: ShieldVerdict): String = when (verdict) {
    is ShieldVerdict.Clean -> verdict.sha256
    is ShieldVerdict.Warning -> verdict.sha256
    is ShieldVerdict.NeedsUpload -> verdict.sha256
}

/** `File: name.apk (abcd1234…ef90)`: which file was checked. */
@Composable
private fun ShieldFileLine(palette: Palette, verdict: ShieldVerdict, modifier: Modifier = Modifier) {
    val name = verdict.report?.analysedName.orEmpty()
    val sha = truncateSha256(verdict.report?.analysedSha256?.takeIf { it.isNotBlank() } ?: verdictSha(verdict))
    Text(
        text = if (name.isNotBlank()) stringResource(R.string.shield_file_line, name, sha) else stringResource(R.string.shield_sha256, sha),
        style = MaterialTheme.typography.bodySmall,
        fontFamily = FontFamily.Monospace,
        color = Color(palette.secondary),
        modifier = modifier,
    )
}

/** What the online engines said in one line, or that nothing was checked online. */
@Composable
private fun onlineNote(verdict: ShieldVerdict?): String {
    val summary = verdict?.report?.summary
    return if (summary != null) stringResource(R.string.report_online_summary, summary) else stringResource(R.string.report_not_checked_online)
}

@Composable
private fun resolveTextSpec(spec: TextSpec): String {
    val args = spec.args.map { arg ->
        arg.toIntOrNull() ?: arg
    }
    return stringResource(spec.resId, *args.toTypedArray())
}

/** One finding of the deep scan in the user's language, with the APK it was found in when the package has several. */
@Composable
private fun issueLine(issue: StaticAnalysisIssue): String {
    val spec = issueTextSpec(issue)
    val base = resolveTextSpec(spec)
    val apk = issue.apk
    return if (apk != null) base + " " + stringResource(R.string.issue_in_apk, apk) else base
}

/** One reason: its title, what was found, what it means, and the findings behind it. */
@Composable
private fun ReasonBlock(palette: Palette, reason: ShieldWarningReason, warning: ShieldVerdict.Warning?, accent: Color) {
    val text = reasonText(reason)
    val what = reasonWhatSpec(reason, warning?.vtMalicious ?: 0, warning?.vtTotal ?: 0)
    Column(Modifier.fillMaxWidth()) {
        Text(
            stringResource(text.titleRes),
            style = MaterialTheme.typography.titleSmall,
            color = accent,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            text = resolveTextSpec(what),
            style = MaterialTheme.typography.bodyMedium,
            color = Color(palette.text),
            fontWeight = FontWeight.Medium,
        )
        text.meaningRes?.let { meaning ->
            Text(
                text = stringResource(meaning),
                style = MaterialTheme.typography.bodySmall,
                color = Color(palette.secondary),
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        val issues = warning?.offline?.issues.orEmpty().filter { it.reason == reason }
        for (issue in issues.take(MaxIssueLines)) {
            Text(
                text = "\u2022 " + issueLine(issue),
                style = MaterialTheme.typography.bodySmall,
                color = Color(palette.text),
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        if (issues.size > MaxIssueLines) {
            Text(
                text = stringResource(R.string.issue_more, issues.size - MaxIssueLines),
                style = MaterialTheme.typography.bodySmall,
                color = Color(palette.secondary),
            )
        }
        if (reason == ShieldWarningReason.DebugOrTestCertificate) {
            warning?.offline?.certSubject?.let { subject ->
                Text(
                    text = stringResource(R.string.issue_cert_subject, subject),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = Color(palette.secondary),
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
    }
}

@Composable
private fun ShieldStatusBlock(
    palette: Palette,
    checking: Boolean,
    verdict: ShieldVerdict?,
    userAuthorized: Boolean = false,
) {
    when {
        checking -> {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SecurityShieldIcon(color = Color(palette.accent), modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(R.string.shield_status_checking),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(palette.secondary),
                )
            }
        }
        verdict is ShieldVerdict.Clean -> {
            Column(Modifier.fillMaxWidth()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SecurityShieldIcon(color = Color(palette.success), modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(8.dp))
                    val cleanText = when (shieldStatusKind(verdict)) {
                        ShieldStatusKind.VerifiedWithVt -> stringResource(R.string.shield_status_clean_vt, verdict.vtSummary.orEmpty())
                        ShieldStatusKind.TrustedUpdate -> stringResource(R.string.shield_status_trusted_update)
                    }
                    Text(
                        cleanText,
                        style = MaterialTheme.typography.bodyMedium,
                        color = Color(palette.success),
                        modifier = Modifier.weight(1f),
                    )
                    ShieldInfoButton(palette, verdict)
                }
                if (verdict.trustedUpdate && verdict.vtSummary != null) {
                    Text(
                        stringResource(R.string.shield_status_vt_detail, verdict.vtSummary),
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(palette.secondary),
                        modifier = Modifier.padding(top = 2.dp),
                    )
                }
                Text(
                    stringResource(R.string.shield_sha256, truncateSha256(verdict.sha256)),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = Color(palette.secondary),
                    modifier = Modifier.padding(top = 2.dp),
                )
                Text(
                    stringResource(R.string.shield_permissions_summary, verdict.offline?.allPermissions?.size ?: 0),
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(palette.secondary),
                    modifier = Modifier.padding(top = 2.dp),
                )
                TrackersLine(palette, verdict.offline?.trackers)
            }
        }
        verdict is ShieldVerdict.Warning -> {
            // The colour comes from the tier and the user's decision: a refused Yellow is a caution, not a block.
            val tone = shieldCardTone(verdict, userAuthorized)
            val cautionColor = if (palette.isDark) Color(0xFFF59E0B) else Color(0xFFD97706)
            val statusColor = when (tone) {
                ShieldCardTone.Blocked -> Color(palette.error)
                ShieldCardTone.CautionAuthorized -> Color(palette.accent)
                else -> cautionColor
            }
            val statusTitle = when (tone) {
                ShieldCardTone.Blocked -> R.string.shield_status_blocked
                ShieldCardTone.CautionAuthorized -> R.string.shield_status_authorized
                else -> R.string.shield_status_caution_declined
            }
            val textColor = Color(palette.text)
            Column(
                Modifier.fillMaxWidth()
                    .background(Color(palette.surface))
                    .border(1.dp, statusColor)
                    .padding(12.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SecurityShieldIcon(color = statusColor, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(
                        stringResource(statusTitle),
                        style = MaterialTheme.typography.labelLarge,
                        color = statusColor,
                        modifier = Modifier.weight(1f).semantics { heading() },
                    )
                    ShieldInfoButton(palette, verdict, userAuthorized)
                }
                Spacer(Modifier.height(6.dp))
                for (reason in verdict.reasons) {
                    val what = reasonWhatSpec(reason, verdict.vtMalicious, verdict.vtTotal)
                    Text(
                        resolveTextSpec(what),
                        style = MaterialTheme.typography.bodyMedium,
                        color = textColor,
                        modifier = Modifier.padding(top = 2.dp),
                    )
                }
                ShieldFileLine(palette, verdict, Modifier.padding(top = 6.dp))
                TrackersLine(palette, verdict.offline?.trackers)
            }
        }
    }
}

/**
 * The "i" square next to the Shield result: opens GoGo's own report (which file, what each source said, the detections, the
 * reasons and the colour). The links to the external services are secondary and only for sources that answered.
 */
@Composable
private fun ShieldInfoButton(palette: Palette, verdict: ShieldVerdict, userAuthorized: Boolean = false) {
    val sha = verdictSha(verdict)
    var open by remember(sha) { mutableStateOf(false) }
    Box(
        Modifier.size(48.dp).clickable(role = Role.Button, onClickLabel = stringResource(R.string.shield_info_description)) { open = true },
        contentAlignment = Alignment.Center,
    ) {
        Box(Modifier.size(24.dp).border(1.dp, Color(palette.accent)).clearAndSetSemantics {}, contentAlignment = Alignment.Center) {
            Text(stringResource(R.string.info_glyph), style = MaterialTheme.typography.labelSmall, color = Color(palette.accent))
        }
    }
    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            shape = RectangleShape,
            containerColor = Color(palette.surface),
            title = { Text(stringResource(R.string.shield_info_description), color = Color(palette.text)) },
            text = { ShieldReportBody(palette, verdict, userAuthorized) },
            confirmButton = {
                TextButton(onClick = { open = false }, shape = RectangleShape) {
                    Text(stringResource(R.string.close), color = Color(palette.accent))
                }
            },
        )
    }
}

private fun reportDate(epochMs: Long, withTime: Boolean): String {
    val format = if (withTime) java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT)
    else java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM)
    return format.format(java.util.Date(epochMs))
}

/** GoGo's report: the file, the colour and why, what each source answered for each APK, the detections, and the source links. */
@Composable
private fun ShieldReportBody(palette: Palette, verdict: ShieldVerdict, userAuthorized: Boolean) {
    val context = LocalContext.current
    val report = verdict.report
    val tier = securityTierOf(verdict)
    val tierColor = when (tier) {
        SecurityTier.Green -> Color(palette.success)
        SecurityTier.Yellow -> if (palette.isDark) Color(0xFFF59E0B) else Color(0xFFD97706)
        SecurityTier.Red -> Color(palette.error)
    }
    Column(
        Modifier.fillMaxWidth().heightIn(max = 440.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        ShieldFileLine(palette, verdict)
        Text(
            stringResource(
                when (tier) {
                    SecurityTier.Green -> R.string.report_result_green
                    SecurityTier.Yellow -> if (userAuthorized) R.string.report_result_yellow_authorized else R.string.report_result_yellow
                    SecurityTier.Red -> R.string.report_result_red
                },
            ),
            style = MaterialTheme.typography.titleSmall,
            color = tierColor,
            fontWeight = FontWeight.Bold,
        )
        when (verdict) {
            is ShieldVerdict.Warning -> for (reason in verdict.reasons) ReasonBlock(palette, reason, verdict, tierColor)
            is ShieldVerdict.Clean -> Text(
                stringResource(if (verdict.trustedUpdate) R.string.report_reason_trusted else R.string.report_reason_clean),
                style = MaterialTheme.typography.bodyMedium,
                color = Color(palette.text),
            )
            is ShieldVerdict.NeedsUpload -> Text(
                stringResource(R.string.shield_warn_not_known),
                style = MaterialTheme.typography.bodyMedium,
                color = Color(palette.text),
            )
        }
        val looked = report?.files.orEmpty().filter { it.lookedUp }
        Text(
            stringResource(R.string.report_sources_title),
            style = MaterialTheme.typography.labelLarge,
            color = Color(palette.secondary),
        )
        if (looked.isEmpty()) {
            Text(stringResource(R.string.report_not_checked_online), style = MaterialTheme.typography.bodyMedium, color = Color(palette.text))
        }
        for (file in looked) {
            if (looked.size > 1) {
                Text(
                    stringResource(R.string.shield_file_line, file.name, truncateSha256(file.sha256)),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = Color(palette.secondary),
                )
            }
            for (source in file.sources) {
                val spec = sourceStatusSpec(source)
                Text(
                    resolveTextSpec(spec),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(palette.text),
                )
                source.analysisDate?.let { seconds ->
                    Text(
                        stringResource(R.string.report_analysis_date, reportDate(seconds * 1000L, withTime = false)),
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(palette.secondary),
                    )
                }
                val cachedAt = source.checkedAtMs
                if (source.fromCache && cachedAt != null) {
                    Text(
                        stringResource(R.string.report_cached_at, reportDate(cachedAt, withTime = true)),
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(palette.secondary),
                    )
                }
            }
        }
        val detections = report?.detections.orEmpty()
        if (detections.isNotEmpty()) {
            Text(
                stringResource(R.string.report_detections_title),
                style = MaterialTheme.typography.labelLarge,
                color = Color(palette.secondary),
            )
            for (detection in detections) {
                Text(
                    stringResource(
                        if (detection.severity == DetectionSeverity.Serious) R.string.report_detection_serious else R.string.report_detection_light,
                        detection.name,
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(palette.text),
                )
                Text(
                    stringResource(R.string.report_detection_engines, detection.engines.joinToString(", "), detection.sources.joinToString(", ") { it.displayName }),
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(palette.secondary),
                )
                if (looked.size > 1) {
                    Text(
                        stringResource(R.string.issue_in_apk, detection.files.joinToString(", ")),
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(palette.secondary),
                    )
                }
            }
        }
        val links = if (report != null) reportLinks(report) else emptyList()
        if (links.isNotEmpty()) {
            Text(
                stringResource(R.string.shield_info_report),
                style = MaterialTheme.typography.labelLarge,
                color = Color(palette.secondary),
            )
            for (link in links) {
                TextButton(
                    onClick = {
                        runCatching {
                            context.startActivity(
                                Intent(Intent.ACTION_VIEW, Uri.parse(link.url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                            )
                        }
                    },
                    shape = RectangleShape,
                ) {
                    Text(
                        if (looked.size > 1) stringResource(R.string.report_link_open_file, link.source.displayName, link.fileName)
                        else stringResource(R.string.report_link_open, link.source.displayName),
                        color = Color(palette.accent),
                    )
                }
            }
        }
    }
}

/** The tracker SDKs the deep scan found, informational (never blocks); nothing when there are none. */
@Composable
private fun TrackersLine(palette: Palette, trackers: List<String>?) {
    if (trackers.isNullOrEmpty()) return
    Text(
        stringResource(R.string.shield_trackers_found, trackers.joinToString(", ")),
        style = MaterialTheme.typography.bodySmall,
        color = Color(palette.secondary),
        modifier = Modifier.padding(top = 2.dp),
    )
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
        install.phase == InstallPhase.Checking -> stringResource(R.string.phase_checking)
        install.phase == InstallPhase.Uploading -> stringResource(R.string.phase_uploading, install.percent)
        install.phase == InstallPhase.Analysing -> stringResource(R.string.phase_analysing)
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
        val checking = install.working && install.phase == InstallPhase.Checking
        Box(Modifier.fillMaxSize().clearAndSetSemantics {}, contentAlignment = Alignment.Center) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (checking) {
                    SecurityShieldIcon(color = Color(palette.text), modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                }
                Text(caption, style = textStyle, color = Color(palette.text), maxLines = 1)
            }
        }
        Box(
            Modifier.fillMaxSize().clearAndSetSemantics {}.drawWithContent {
                val w = fillWidthPx(size.width.roundToInt(), fillPercent).toFloat()
                clipRect(0f, 0f, w, size.height) { this@drawWithContent.drawContent() }
            },
            contentAlignment = Alignment.Center,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (checking) {
                    SecurityShieldIcon(color = onFill, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                }
                Text(caption, style = textStyle, color = onFill, maxLines = 1)
            }
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
    onOpenDeveloperOptions: () -> Unit,
    menu: DeviceMenuSections,
    onSelectDevice: (Target) -> Unit,
    onAddDevice: () -> Unit,
    onMenuOpen: () -> Unit,
    onMenuRefresh: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val state = connection.state
    val text = Color(palette.text)
    val secondary = Color(palette.secondary)
    val line = Color(if (state == ConnectionState.NotConnected || state == ConnectionState.Error) palette.indicator else palette.accent)
    val pickable = state != ConnectionState.Pairing && state != ConnectionState.Connecting
    Column(
        modifier.fillMaxWidth().background(Color(palette.surface)).padding(vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
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
        Box(Modifier.weight(1f).fillMaxWidth().padding(horizontal = 12.dp), contentAlignment = Alignment.Center) {
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                connection.error?.let {
                    Text(
                        stringResource(it.message),
                        style = MaterialTheme.typography.bodyMedium,
                        color = Color(palette.error),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(bottom = 2.dp),
                    )
                    // Why it failed: exception class and masked message, so an error can be told from the screen alone.
                    connection.detail?.let { detail ->
                        Text(
                            detail,
                            style = MaterialTheme.typography.labelSmall,
                            color = secondary,
                            textAlign = TextAlign.Center,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.padding(bottom = 2.dp),
                        )
                    }
                    if (connection.device?.local != false || it == AdbError.WirelessDebuggingOff) {
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = {
                                onRepost()
                                onOpenDeveloperOptions()
                            },
                            modifier = Modifier.fillMaxWidth().height(44.dp),
                            shape = RectangleShape,
                            border = BorderStroke(1.dp, Color(palette.accent)),
                            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 0.dp),
                        ) {
                            Text(
                                stringResource(R.string.open_wireless_debugging),
                                style = MaterialTheme.typography.labelLarge,
                                color = Color(palette.accent),
                                maxLines = 1,
                                textAlign = TextAlign.Center,
                            )
                        }
                        Spacer(Modifier.height(4.dp))
                    }
                }
                when (state) {
                    ConnectionState.Pairing -> PairingForm(
                        palette, connection.device?.local != false, pairPort, onCode, onRepost,
                        onOpenDeveloperOptions,
                    )
                    // The dropdown below shows the connected device, with its type and address.
                    ConnectionState.Connected -> {}
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
                                modifier = Modifier.padding(top = 2.dp),
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
        if (state != ConnectionState.Pairing) DeviceDropdown(palette, connection.device?.takeIf { state == ConnectionState.Connected }, menu, pickable, onSelectDevice, onAddDevice, onMenuOpen, onRefresh = onMenuRefresh)
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
    onOpenDeveloperOptions: () -> Unit,
) {
    if (local) {
        LocalPairing(palette, port, onRepost, onOpenDeveloperOptions)
    }
    else NetworkPairing(palette, port, onCode)
}

@Composable
private fun LocalPairing(
    palette: Palette,
    port: Int?,
    onRepost: () -> Unit,
    onOpenDeveloperOptions: () -> Unit,
) {
    val accent = Color(palette.accent)
    val status = localPairingStatus(port)
    val pulse = if (shouldPulseWirelessButton(status)) {
        rememberInfiniteTransition(label = "wirelessButtonPulse").animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(700), RepeatMode.Reverse),
            label = "wirelessButtonPulseValue",
        ).value
    } else 0f
    val borderColor = lerp(accent, Color(palette.divider), pulse)
    Column(
        Modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
    Spacer(Modifier.height(8.dp))
    Text(
        stringResource(R.string.pairing_instruction),
        style = MaterialTheme.typography.bodyMedium,
        color = Color(palette.text),
        textAlign = TextAlign.Center,
        maxLines = 2,
    )
    Spacer(Modifier.height(8.dp))
    OutlinedButton(
        onClick = {
            // Fresh on top of the settings screen the button opens.
            onRepost()
            onOpenDeveloperOptions()
        },
        modifier = Modifier.fillMaxWidth().height(48.dp),
        shape = RectangleShape,
        border = BorderStroke(1.dp + 2.dp * pulse, borderColor),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 0.dp),
    ) {
        Text(
            stringResource(R.string.open_wireless_debugging),
            style = MaterialTheme.typography.labelLarge,
            color = accent,
            maxLines = 1,
            textAlign = TextAlign.Center,
        )
    }
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
    visualTransformation: VisualTransformation = VisualTransformation.None,
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
        visualTransformation = visualTransformation,
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
            // The glyph was drawn for a 72 dp node; scale every measure with the canvas.
            val k = size.width / 72.dp.toPx()
            fun u(v: Float) = v.dp.toPx() * k
            when (glyph) {
                Glyph.Phone -> {
                    val half = Offset(u(11f), u(18f))
                    drawRect(text, c - half, androidx.compose.ui.geometry.Size(half.x * 2, half.y * 2), style = androidx.compose.ui.graphics.drawscope.Stroke(w))
                    drawLine(text, Offset(c.x - u(3f), c.y - u(12f)), Offset(c.x + u(3f), c.y - u(12f)), w)
                    drawRect(text, Offset(c.x - u(1.5f), c.y + u(10f)), androidx.compose.ui.geometry.Size(u(3f), u(3f)))
                }
                Glyph.Terminal -> {
                    val x = c.x - u(10f)
                    drawLine(text, Offset(x, c.y - u(9f)), Offset(x + u(9f), c.y), w)
                    drawLine(text, Offset(x + u(9f), c.y), Offset(x, c.y + u(9f)), w)
                    drawLine(text, Offset(c.x + u(2f), c.y + u(9f)), Offset(c.x + u(14f), c.y + u(9f)), w)
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
