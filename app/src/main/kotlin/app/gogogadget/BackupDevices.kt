package app.gogogadget

import java.io.File

/** Folder for backups made before backups knew their device (see [migrateLegacyBackups]). */
internal const val UNASSIGNED_DEVICE = "_unassigned"

/** Id of the phone itself. */
internal const val LOCAL_DEVICE = "local"

/**
 * Stable id of the device a backup belongs to: "local" for this phone, else the saved device's key id,
 * else the host as a last resort. Safe to use as a folder name.
 */
internal fun backupDeviceId(local: Boolean, keyId: String?, host: String): String {
    if (local) return LOCAL_DEVICE
    val raw = keyId?.takeIf { it.isNotBlank() } ?: host
    val safe = raw.trim().replace(Regex("[^A-Za-z0-9._-]"), "_").trim('.')
    return safe.ifEmpty { UNASSIGNED_DEVICE }
}

internal fun Device.backupId(): String = backupDeviceId(local, deviceId, host)

/** `backups/<deviceId>/<package>`. */
internal fun backupDir(root: File, deviceId: String, packageName: String): File =
    File(File(root, deviceId), packageName)

/**
 * Moves the old `backups/<package>` folders (no device) to `backups/_unassigned/<package>`.
 * A legacy folder holds its files directly; device folders hold only folders. Nothing is deleted:
 * a folder whose target already exists stays where it is.
 */
internal fun migrateLegacyBackups(root: File) {
    val children = root.listFiles { f -> f.isDirectory } ?: return
    val legacy = children.filter { dir ->
        dir.name != UNASSIGNED_DEVICE && dir.listFiles { f -> f.isFile }.orEmpty().any {
            it.name == "backup_meta.json" || it.name.endsWith(".apk")
        }
    }
    if (legacy.isEmpty()) return
    val target = File(root, UNASSIGNED_DEVICE)
    target.mkdirs()
    for (dir in legacy) {
        val dest = File(target, dir.name)
        if (!dest.exists()) dir.renameTo(dest)
    }
}

/** A backup may only be pushed to the device it came from. */
internal fun canRevertBackup(backupDeviceId: String, connectedDeviceId: String?): Boolean =
    connectedDeviceId != null && backupDeviceId == connectedDeviceId

/** Only the connected device's backups; with no device connected there is nothing to show. */
internal fun visibleBackups(all: List<AppBackupItem>, connectedDeviceId: String?): List<AppBackupItem> =
    if (connectedDeviceId == null) emptyList() else all.filter { it.deviceId == connectedDeviceId }

/** The backups whose revert succeeded: they are installed again, so the copy is no longer needed. */
internal fun backupsToRemoveAfterRevert(results: List<Pair<AppBackupItem, Boolean>>): List<AppBackupItem> =
    results.filter { it.second }.map { it.first }
