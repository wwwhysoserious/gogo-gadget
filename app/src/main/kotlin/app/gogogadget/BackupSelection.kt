package app.gogogadget

/** Selection keeps backup keys (device and package), not list positions, so it survives searching and deleting. */
internal fun toggleSelection(selected: Set<String>, key: String): Set<String> =
    if (key in selected) selected - key else selected + key

/** "All" means all backups currently visible (after the search filter). */
internal fun selectAllVisible(visible: List<AppBackupItem>): Set<String> = visible.map { it.key }.toSet()

/** True when every visible backup is already selected. */
internal fun allVisibleSelected(selected: Set<String>, visible: List<AppBackupItem>): Boolean =
    visible.isNotEmpty() && visible.all { it.key in selected }

/** Drops selected backups that no longer exist. */
internal fun pruneSelection(selected: Set<String>, existing: List<AppBackupItem>): Set<String> {
    val names = existing.map { it.key }.toSet()
    return selected.filter { it in names }.toSet()
}
