package app.gogogadget

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

private const val VtSignUpUrl = "https://www.virustotal.com/gui/join-us"

/** The back row and the divider under it, shared by the pages of this file. */
@Composable
private fun BackRow(palette: Palette, onBack: () -> Unit) {
    Row(Modifier.fillMaxWidth().height(56.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(
            stringResource(R.string.back),
            style = MaterialTheme.typography.bodyMedium,
            color = Color(palette.accent),
            modifier = Modifier.clickable(role = Role.Button, onClick = onBack).height(56.dp)
                .padding(horizontal = Margin).padding(vertical = 16.dp),
        )
    }
    Divider(palette)
}

@Composable
private fun PageTitle(palette: Palette, title: Int) {
    Text(
        stringResource(title),
        style = MaterialTheme.typography.headlineMedium,
        color = Color(palette.text),
        modifier = Modifier.padding(horizontal = Margin, vertical = 16.dp).semantics { heading() },
    )
}

// ---- How it works ----

private val SummarySections = listOf(
    R.string.how_s1_head to R.string.how_s1_body,
    R.string.how_s2_head to R.string.how_s2_body,
    R.string.how_s3_head to R.string.how_s3_body,
    R.string.how_s4_head to R.string.how_s4_body,
    R.string.how_s5_head to R.string.how_s5_body,
)

private val TechnicalSections = listOf(
    R.string.how_t1_head to R.string.how_t1_body,
    R.string.how_t2_head to R.string.how_t2_body,
    R.string.how_t3_head to R.string.how_t3_body,
    R.string.how_t4_head to R.string.how_t4_body,
    R.string.how_t5_head to R.string.how_t5_body,
    R.string.how_t6_head to R.string.how_t6_body,
    R.string.how_t7_head to R.string.how_t7_body,
)

@Composable
private fun HowSection(palette: Palette, head: Int, body: Int) {
    Column(Modifier.fillMaxWidth().padding(horizontal = Margin).padding(bottom = 16.dp)) {
        Text(
            stringResource(head),
            style = MaterialTheme.typography.titleSmall,
            color = Color(palette.text),
            modifier = Modifier.semantics { heading() },
        )
        Text(
            stringResource(body),
            style = MaterialTheme.typography.bodyMedium,
            color = Color(palette.secondary),
            modifier = Modifier.padding(top = 4.dp),
        )
    }
}

/** What the app is and how the Shield works: a short summary, then the technical details below a divider. */
@Composable
fun HowItWorksScreen(palette: Palette, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        BackRow(palette, onBack)
        PageTitle(palette, R.string.how_it_works)
        SummarySections.forEach { (head, body) -> HowSection(palette, head, body) }
        Divider(palette)
        Text(
            stringResource(R.string.how_title_technical),
            style = MaterialTheme.typography.headlineSmall,
            color = Color(palette.text),
            modifier = Modifier.padding(horizontal = Margin, vertical = 16.dp).semantics { heading() },
        )
        TechnicalSections.forEach { (head, body) -> HowSection(palette, head, body) }
        Divider(palette)
    }
}

// ---- Security APIs ----

/** One online service: its name, free-tier line, sign-up page and the key it holds (null = none, otherwise the mask). */
private class ApiService(
    val name: Int,
    val limit: Int,
    val signUpUrl: String,
    val hint: Int,
    val deleteTitle: Int,
    val deleteBody: Int,
)

private val VirusTotalService = ApiService(
    R.string.api_vt_name, R.string.api_vt_limit, VtSignUpUrl,
    R.string.virustotal_key_hint, R.string.virustotal_key_delete_title, R.string.virustotal_key_delete_body,
)

@Composable
private fun ApiBlock(palette: Palette, service: ApiService, masked: String?, onSave: (String) -> Unit, onDelete: () -> Unit) {
    val context = LocalContext.current
    var keyInput by remember { mutableStateOf("") }
    var confirmDelete by remember { mutableStateOf(false) }
    fun submit() {
        val clean = keyInput.trim()
        if (clean.isNotEmpty()) {
            keyInput = ""
            onSave(clean)
        }
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            shape = RectangleShape,
            containerColor = Color(opaque(palette.surface)),
            titleContentColor = Color(palette.text),
            textContentColor = Color(palette.secondary),
            title = { Text(stringResource(service.deleteTitle)) },
            text = { Text(stringResource(service.deleteBody)) },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }, shape = RectangleShape) {
                    Text(stringResource(R.string.cancel), style = MaterialTheme.typography.labelLarge, color = Color(palette.accent))
                }
            },
            confirmButton = {
                TextButton(onClick = { confirmDelete = false; keyInput = ""; onDelete() }, shape = RectangleShape) {
                    Text(stringResource(R.string.virustotal_key_delete), style = MaterialTheme.typography.labelLarge, color = Color(palette.error))
                }
            },
        )
    }
    Divider(palette)
    Column(Modifier.fillMaxWidth().padding(horizontal = Margin, vertical = 16.dp)) {
        Text(
            stringResource(service.name),
            style = MaterialTheme.typography.titleSmall,
            color = Color(palette.text),
            modifier = Modifier.semantics { heading() },
        )
        Text(
            if (masked != null) stringResource(R.string.api_status_active, masked) else stringResource(R.string.api_status_none),
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = if (masked != null) FontFamily.Monospace else null,
            color = Color(if (masked != null) palette.success else palette.secondary),
            modifier = Modifier.padding(top = 2.dp),
        )
        Text(
            stringResource(service.limit),
            style = MaterialTheme.typography.bodySmall,
            color = Color(palette.secondary),
            modifier = Modifier.padding(top = 4.dp),
        )
        if (masked != null) {
            Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Spacer(Modifier.weight(1f))
                TrashButton(palette, stringResource(R.string.virustotal_key_delete)) { confirmDelete = true }
            }
        } else {
            listOf(R.string.api_step_1, R.string.api_step_2, R.string.api_step_3).forEach { step ->
                Text(
                    stringResource(step),
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(palette.text),
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
            OutlinedButton(
                onClick = {
                    try {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(service.signUpUrl)))
                    } catch (_: ActivityNotFoundException) {
                        // No browser installed: nothing to open.
                    }
                },
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RectangleShape,
            ) {
                Text(stringResource(R.string.api_create_account), style = MaterialTheme.typography.labelLarge, color = Color(palette.accent))
            }
            Spacer(Modifier.height(8.dp))
            Field(
                palette = palette,
                value = keyInput,
                onValue = { keyInput = it.trim() },
                hint = service.hint,
                keyboard = KeyboardType.Password,
                mono = true,
                imeAction = ImeAction.Done,
                onDone = ::submit,
                visualTransformation = PasswordVisualTransformation('•'),
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = ::submit,
                enabled = keyInput.isNotBlank(),
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RectangleShape,
                colors = ButtonDefaults.buttonColors(),
                elevation = null,
            ) {
                Text(stringResource(R.string.save), style = MaterialTheme.typography.labelLarge)
            }
        }
    }
}

/**
 * Settings, Security APIs: one block per online service, each with its state, its free limit, the three steps to get a
 * key, a button to the sign-up page and the key field. Keys are optional. A saved key is shown only as a mask.
 * [onChanged] runs after a key is saved or deleted.
 */
@Composable
fun SecurityApisScreen(palette: Palette, store: ShieldSettingsStore, onChanged: () -> Unit, onBack: () -> Unit) {
    var vtMask by remember { mutableStateOf(maskOf(store.hasVirusTotalApiKey()) { store.loadVirusTotalApiKey() }) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        BackRow(palette, onBack)
        PageTitle(palette, R.string.security_apis)
        Text(
            stringResource(R.string.security_apis_intro),
            style = MaterialTheme.typography.bodyMedium,
            color = Color(palette.secondary),
            modifier = Modifier.fillMaxWidth().padding(start = Margin, end = Margin, bottom = 16.dp),
        )
        ApiBlock(
            palette, VirusTotalService, vtMask,
            onSave = {
                store.saveVirusTotalApiKey(it)
                store.shieldEnabled = true
                vtMask = maskOf(store.hasVirusTotalApiKey()) { store.loadVirusTotalApiKey() }
                onChanged()
            },
            onDelete = { store.clearVirusTotalApiKey(); vtMask = null; onChanged() },
        )
        Divider(palette)
        Text(
            stringResource(R.string.api_key_stored_note),
            style = MaterialTheme.typography.bodySmall,
            color = Color(palette.secondary),
            modifier = Modifier.padding(horizontal = Margin, vertical = 16.dp),
        )
    }
}

/** The mask of a saved key (the key is read once and never kept); eight bullets when it is saved but cannot be read; null without a key. */
private fun maskOf(has: Boolean, load: () -> String?): String? =
    if (!has) null else maskKey(load()).ifEmpty { "•".repeat(8) }

// ---- First launch ----

/** Shown once on the first launch: recommends the API keys, and says what is lost by skipping. */
@Composable
fun WelcomeScreen(palette: Palette, onSetUp: () -> Unit, onSkip: () -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = Margin, vertical = 24.dp)) {
        Text(
            stringResource(R.string.welcome_title),
            style = MaterialTheme.typography.headlineMedium,
            color = Color(palette.text),
            modifier = Modifier.semantics { heading() },
        )
        Text(
            stringResource(R.string.welcome_body),
            style = MaterialTheme.typography.bodyLarge,
            color = Color(palette.text),
            modifier = Modifier.padding(top = 16.dp),
        )
        Spacer(Modifier.height(24.dp))
        Button(
            onClick = onSetUp,
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RectangleShape,
            colors = ButtonDefaults.buttonColors(),
            elevation = null,
        ) {
            Text(stringResource(R.string.welcome_setup), style = MaterialTheme.typography.labelLarge)
        }
        Spacer(Modifier.height(24.dp))
        Text(
            stringResource(R.string.welcome_skip_note),
            style = MaterialTheme.typography.bodySmall,
            color = Color(palette.secondary),
        )
        OutlinedButton(
            onClick = onSkip,
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RectangleShape,
        ) {
            Text(stringResource(R.string.welcome_skip), style = MaterialTheme.typography.labelLarge, color = Color(palette.accent))
        }
    }
}
