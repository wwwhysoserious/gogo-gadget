package app.gogogadget

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

private const val MaxLogLines = 200
private const val MaxLogLineLength = 240

/**
 * The app's chronological terminal log for everything that is not an install: connecting, pairing (also what the
 * notification service did) and forgetting. Oldest line first, bounded, thread-safe (the pairing service writes from a
 * worker thread). Lines are masked like [diagnostic]: a pairing code or key material never gets in.
 */
class TerminalLog(private val maxLines: Int = MaxLogLines) {
    private val state = MutableStateFlow<List<String>>(emptyList())
    val lines: StateFlow<List<String>> = state.asStateFlow()

    fun add(line: String) {
        val clean = maskSecrets(line).map { if (it.isISOControl()) ' ' else it }.joinToString("").take(MaxLogLineLength)
        state.update { (it + clean).takeLast(maxLines) }
    }

    fun clear() {
        state.value = emptyList()
    }
}
