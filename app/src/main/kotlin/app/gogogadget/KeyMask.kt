package app.gogogadget

private const val MaskChar = '•'
private const val MaskLength = 8
private const val MaxVisible = 4

/**
 * A saved API key as it is shown: bullets, then at most the last 4 characters. A key of 8 characters or fewer shows
 * fewer than 4 (half of it at most), so a short key never reveals more than it hides; a blank key shows nothing.
 */
fun maskKey(key: String?): String {
    val clean = key?.trim().orEmpty()
    if (clean.isEmpty()) return ""
    val visible = minOf(MaxVisible, clean.length / 2)
    return MaskChar.toString().repeat(MaskLength) + clean.takeLast(visible)
}
