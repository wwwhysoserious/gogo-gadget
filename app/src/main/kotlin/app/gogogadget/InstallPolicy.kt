package app.gogogadget

/** What happens to the picked file once an install ends. */
enum class DeleteSourceMode { Off, On, Automatic }

/** What to do with the picked file after an install: nothing, offer the delete button, or delete it right away. */
enum class DeleteSourceAction { None, OfferButton, DeleteNow }

/**
 * Off never touches the file and never offers a button. On offers the button after any install (kept from before).
 * Automatic deletes only after a successful install, with no button; a failed install keeps the file for another try.
 */
fun deleteSourceAction(mode: DeleteSourceMode, installOk: Boolean): DeleteSourceAction = when (mode) {
    DeleteSourceMode.Off -> DeleteSourceAction.None
    DeleteSourceMode.On -> DeleteSourceAction.OfferButton
    DeleteSourceMode.Automatic -> if (installOk) DeleteSourceAction.DeleteNow else DeleteSourceAction.None
}

/**
 * The stored mode: [storedName] when it names a mode, otherwise the old boolean setting ([legacy], true is On, false is
 * Off), otherwise Off.
 */
fun deleteSourceModeFrom(storedName: String?, legacy: Boolean?): DeleteSourceMode =
    DeleteSourceMode.entries.firstOrNull { it.name == storedName }
        ?: when (legacy) {
            true -> DeleteSourceMode.On
            else -> DeleteSourceMode.Off
        }

/** The next mode when the row is tapped: Off, On, Automatic, then Off again. */
fun nextDeleteSourceMode(mode: DeleteSourceMode): DeleteSourceMode =
    DeleteSourceMode.entries[(mode.ordinal + 1) % DeleteSourceMode.entries.size]

/**
 * True when the installed app is saved before an update: the setting is on, the package is known and an older version is
 * installed. With the setting off nothing is read from the device and nothing is written to disk.
 */
fun shouldBackupBeforeUpdate(enabled: Boolean, packageName: String?, installedVersionCode: Long?): Boolean =
    enabled && !packageName.isNullOrBlank() && installedVersionCode != null
