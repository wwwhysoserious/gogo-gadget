package app.gogogadget

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

val Margin = 24.dp

@Composable
fun Divider(palette: Palette) =
    HorizontalDivider(thickness = Dp.Hairline, color = Color(palette.divider))

@Composable
fun HomeScreen(
    palette: Palette,
    fileName: String?,
    onChoose: () -> Unit,
    onSettings: () -> Unit,
) {
    val banner = when (palette.banner) {
        Banner.A -> R.drawable.banner_a
        Banner.B -> R.drawable.banner_b
        Banner.C -> R.drawable.banner_c
    }
    BoxWithConstraints(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)) {
    Column(
        Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).heightIn(min = maxHeight),
        verticalArrangement = Arrangement.SpaceBetween,
    ) {
        Column {
        Image(
            painter = painterResource(banner),
            contentDescription = stringResource(R.string.banner_description),
            contentScale = ContentScale.FillWidth,
            modifier = Modifier.fillMaxWidth().padding(horizontal = Margin, vertical = 48.dp),
        )
        Divider(palette)
        }
        Column {
        Column(
            Modifier.fillMaxWidth().padding(horizontal = Margin),
            verticalArrangement = Arrangement.Bottom,
        ) {
            Text(
                stringResource(R.string.home_title),
                style = MaterialTheme.typography.headlineMedium,
                color = Color(palette.text),
            )
            Spacer(Modifier.height(24.dp))
            Button(
                onClick = onChoose,
                modifier = Modifier.fillMaxWidth().height(56.dp),
                shape = RectangleShape,
                colors = ButtonDefaults.buttonColors(),
                elevation = null,
            ) { Text(stringResource(R.string.choose_file), style = MaterialTheme.typography.labelLarge) }
            Spacer(Modifier.height(16.dp))
            Text(
                stringResource(R.string.formats),
                style = MaterialTheme.typography.bodyMedium,
                color = Color(palette.secondary),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                fileName.orEmpty(),
                style = MaterialTheme.typography.bodyLarge,
                color = Color(palette.text),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.heightIn(min = 24.dp),
            )
            Spacer(Modifier.height(96.dp))
        }
        Divider(palette)
        Row(
            Modifier.fillMaxWidth().height(56.dp).padding(horizontal = Margin),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(8.dp).background(Color(palette.indicator)))
            Spacer(Modifier.size(8.dp))
            Text(
                stringResource(R.string.wireless_not_connected),
                style = MaterialTheme.typography.bodyMedium,
                color = Color(palette.secondary),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            Box(
                Modifier.fillMaxHeight().clickable(onClick = onSettings).padding(start = 16.dp),
                contentAlignment = Alignment.CenterEnd,
            ) {
                Text(
                    stringResource(R.string.settings),
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(palette.accent),
                )
            }
        }
    }
    }
    }
}
