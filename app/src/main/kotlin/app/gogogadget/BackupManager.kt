package app.gogogadget

import android.content.Context
import android.content.pm.PackageManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Phase 5: Auto-backup & 1-tap Reversion metadata.
 * Persisted in `context.filesDir/backups/<packageName>/backup_meta.json`.
 */
data class BackupMetadata(
    val packageName: String,
    val appName: String,
    val versionCode: Long,
    val versionName: String?,
    val timestamp: Long,
    val apkFileNames: List<String>,
)

/** Represents a saved application backup on disk ready for listing and 1-tap reversion. */
data class AppBackupItem(
    val packageName: String,
    val appName: String,
    val versionCode: Long,
    val versionName: String?,
    val timestamp: Long,
    val totalSizeBytes: Long,
    val apkFiles: List<File>,
)

class BackupManager(
    private val context: Context? = null,
    val backupsDir: File = context?.let { File(it.filesDir, "backups") } ?: File("backups"),
) {

    constructor(backupsDir: File) : this(context = null, backupsDir = backupsDir)

    /**
     * Parses `pm path <packageName>` output into a list of absolute APK paths on the target device.
     */
    fun parsePmPathOutput(output: String): List<String> =
        output.lineSequence()
            .map { it.trim() }
            .filter { it.startsWith("package:") }
            .map { it.removePrefix("package:").trim() }
            .filter { it.isNotEmpty() }
            .toList()

    /**
     * Backs up the installed APKs for [packageName] from the target device over [adb].
     * Overwrites any existing backup for this package (keeps 1 previous version per package).
     * Returns the created [AppBackupItem] or null on failure.
     */
    fun createBackup(
        adb: AdbClient,
        packageName: String,
        installedInfo: InstalledAppInfo?,
    ): AppBackupItem? {
        val safePkg = sanitizePackageName(packageName)
        val pmPathOutput = runCatching { adb.shell("pm path $safePkg") }.getOrDefault("")
        val remotePaths = parsePmPathOutput(pmPathOutput)
        if (remotePaths.isEmpty()) return null

        val pkgDir = File(backupsDir, packageName)
        // Keep only 1 previous version per package (overwrites previous backup)
        if (pkgDir.exists()) {
            pkgDir.deleteRecursively()
        }
        pkgDir.mkdirs()

        val savedFiles = mutableListOf<File>()
        for (remotePath in remotePaths) {
            val fileName = remotePath.substringAfterLast('/')
            val destFile = File(pkgDir, fileName)
            val pulled = pullApk(adb, remotePath, destFile)
            if (pulled && destFile.exists() && destFile.length() > 0L) {
                savedFiles += destFile
            }
        }

        if (savedFiles.isEmpty()) {
            pkgDir.deleteRecursively()
            return null
        }

        val baseApk = savedFiles.find { it.name == "base.apk" } ?: savedFiles.first()
        val archiveInfo = runCatching {
            context?.packageManager?.getPackageArchiveInfo(baseApk.path, 0)
        }.getOrNull()

        val resolvedAppName = installedInfo?.appName
            ?: archiveInfo?.applicationInfo?.let { appInfo ->
                appInfo.sourceDir = baseApk.path
                appInfo.publicSourceDir = baseApk.path
                val pm = context?.packageManager
                if (pm != null) runCatching { appInfo.loadLabel(pm)?.toString() }.getOrNull() else null
            }?.takeIf { it.isNotBlank() }
            ?: packageName

        val resolvedVersionCode = installedInfo?.versionCode
            ?: archiveInfo?.longVersionCode
            ?: 0L

        val resolvedVersionName = installedInfo?.versionName
            ?: archiveInfo?.versionName

        val meta = BackupMetadata(
            packageName = packageName,
            appName = resolvedAppName,
            versionCode = resolvedVersionCode,
            versionName = resolvedVersionName,
            timestamp = System.currentTimeMillis(),
            apkFileNames = savedFiles.map { it.name },
        )

        saveMetadata(pkgDir, meta)

        val totalSize = savedFiles.sumOf { it.length() }
        return AppBackupItem(
            packageName = packageName,
            appName = resolvedAppName,
            versionCode = resolvedVersionCode,
            versionName = resolvedVersionName,
            timestamp = meta.timestamp,
            totalSizeBytes = totalSize,
            apkFiles = savedFiles,
        )
    }

    private fun pullApk(adb: AdbClient, remotePath: String, destFile: File): Boolean {
        // Direct local file copy if readable
        val localFile = File(remotePath)
        if (localFile.exists() && localFile.canRead()) {
            return runCatching {
                localFile.copyTo(destFile, overwrite = true)
                destFile.exists() && destFile.length() > 0L
            }.getOrDefault(false)
        }
        // Pull via ADB
        return runCatching {
            adb.pull(remotePath, destFile)
        }.getOrDefault(false)
    }

    fun saveMetadata(pkgDir: File, meta: BackupMetadata) {
        val json = JSONObject().apply {
            put("packageName", meta.packageName)
            put("appName", meta.appName)
            put("versionCode", meta.versionCode)
            if (meta.versionName != null) put("versionName", meta.versionName)
            put("timestamp", meta.timestamp)
            put("apkFileNames", JSONArray(meta.apkFileNames))
        }
        File(pkgDir, "backup_meta.json").writeText(json.toString(2), Charsets.UTF_8)
    }

    fun readMetadata(pkgDir: File): BackupMetadata? {
        val file = File(pkgDir, "backup_meta.json")
        if (!file.exists() || file.length() <= 0L) return null
        return try {
            val json = JSONObject(file.readText(Charsets.UTF_8))
            val apkNames = mutableListOf<String>()
            val array = json.optJSONArray("apkFileNames")
            if (array != null) {
                for (i in 0 until array.length()) {
                    apkNames += array.getString(i)
                }
            }
            BackupMetadata(
                packageName = json.getString("packageName"),
                appName = json.optString("appName", json.getString("packageName")),
                versionCode = json.getLong("versionCode"),
                versionName = json.optString("versionName").takeIf { it.isNotBlank() },
                timestamp = json.optLong("timestamp", file.lastModified()),
                apkFileNames = apkNames,
            )
        } catch (_: Throwable) {
            null
        }
    }

    fun listBackups(): List<AppBackupItem> {
        if (!backupsDir.exists() || !backupsDir.isDirectory) return emptyList()
        val pkgDirs = backupsDir.listFiles { f -> f.isDirectory } ?: return emptyList()
        val items = mutableListOf<AppBackupItem>()
        for (dir in pkgDirs) {
            val meta = readMetadata(dir)
            val files = if (meta != null && meta.apkFileNames.isNotEmpty()) {
                meta.apkFileNames.map { File(dir, it) }.filter { it.exists() && it.length() > 0L }
            } else {
                dir.listFiles { f -> f.isFile && f.name.endsWith(".apk") }?.toList().orEmpty()
            }
            if (files.isNotEmpty()) {
                val totalSize = files.sumOf { it.length() }
                items += AppBackupItem(
                    packageName = meta?.packageName ?: dir.name,
                    appName = meta?.appName ?: dir.name,
                    versionCode = meta?.versionCode ?: 0L,
                    versionName = meta?.versionName,
                    timestamp = meta?.timestamp ?: dir.lastModified(),
                    totalSizeBytes = totalSize,
                    apkFiles = files,
                )
            }
        }
        return items.sortedByDescending { it.timestamp }
    }

    fun deleteBackup(packageName: String): Boolean {
        val dir = File(backupsDir, packageName)
        return if (dir.exists()) dir.deleteRecursively() else false
    }
}
