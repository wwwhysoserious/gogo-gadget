package app.gogogadget

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource

@Composable
fun BackupsScreen(palette: Palette) {
    Box(Modifier.fillMaxSize().padding(Margin), contentAlignment = Alignment.Center) {
        Text(stringResource(R.string.backups_empty), style = MaterialTheme.typography.bodyLarge, color = Color(palette.secondary))
    }
}
