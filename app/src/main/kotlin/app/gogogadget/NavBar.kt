package app.gogogadget

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

enum class Tab(val label: Int) {
    Install(R.string.nav_install),
    Backups(R.string.nav_backups),
    Settings(R.string.settings),
}

@Composable
fun BottomBar(palette: Palette, selected: Tab, onSelect: (Tab) -> Unit) {
    Column(Modifier.fillMaxWidth()) {
        Divider(palette)
        Row(Modifier.fillMaxWidth().heightIn(min = 72.dp).height(IntrinsicSize.Min).selectableGroup()) {
            Tab.entries.forEach { tab ->
                val active = tab == selected
                val color = if (active) Color(palette.accent) else Color(palette.navInactive)
                Box(
                    Modifier.weight(1f).fillMaxHeight()
                        .selectable(active, role = Role.Tab) { onSelect(tab) },
                    contentAlignment = Alignment.Center,
                ) {
                    if (active) Box(Modifier.fillMaxWidth().height(2.dp).background(color).align(Alignment.TopCenter))
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Canvas(Modifier.size(24.dp)) { drawGlyph(tab, color) }
                        Text(
                            stringResource(tab.label),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = if (active) FontWeight.Bold else FontWeight.Normal,
                            color = color,
                        )
                    }
                }
            }
        }
    }
}

/** Straight-line glyphs on a 24 dp grid. */
private fun DrawScope.drawGlyph(tab: Tab, color: Color) {
    val w = 2.dp.toPx()
    fun p(x: Float, y: Float) = Offset(x.dp.toPx(), y.dp.toPx())
    when (tab) {
        Tab.Install -> {
            drawLine(color, p(12f, 3f), p(12f, 15f), w)
            drawLine(color, p(6f, 9f), p(12f, 15f), w)
            drawLine(color, p(18f, 9f), p(12f, 15f), w)
            drawLine(color, p(4f, 21f), p(20f, 21f), w)
        }
        Tab.Backups -> {
            drawRect(color, p(4f, 4f), Size(16.dp.toPx(), 6.dp.toPx()), style = Stroke(w))
            drawRect(color, p(4f, 14f), Size(16.dp.toPx(), 6.dp.toPx()), style = Stroke(w))
        }
        Tab.Settings -> {
            drawLine(color, p(4f, 7f), p(20f, 7f), w)
            drawLine(color, p(4f, 12f), p(20f, 12f), w)
            drawLine(color, p(4f, 17f), p(20f, 17f), w)
            // Slider knobs break each line.
            drawRect(color, p(14f, 4.5f), Size(3.dp.toPx(), 5.dp.toPx()))
            drawRect(color, p(7f, 9.5f), Size(3.dp.toPx(), 5.dp.toPx()))
            drawRect(color, p(12f, 14.5f), Size(3.dp.toPx(), 5.dp.toPx()))
        }
    }
}
