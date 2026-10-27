# GoGo Gadget: Specification v1.0

1. **Standalone local install**: direct ADB over Wireless Debugging (no PC, no mandatory Shizuku).
2. **Zero-Trust**: no permissions granted by default.
3. **3-Color Security Tier Architecture (Green, Yellow with Interactive Override, Red)**:
   - **Green (Clean / Silent Install)**:
     * Proven clean by VirusTotal (0 malicious/suspicious detections across engines) and local Deep Scan, or a verified trusted update signed with the same certificate.
     * Automatically and silently streams to Android Package Manager.
   - **Yellow (Caution / Mod Risk / Interactive Override)**:
     * Triggered by mod or unverified conditions without confirmed malware:
       - `DropperDetected`: dynamic code loading (`DexClassLoader`, `InMemoryDexClassLoader`, or `PathClassLoader` paired with dynamic paths) or disguised archive payload. Lottie animations (`.lottie`) and generic data ZIPs are NOT flagged.
       - `DebugOrTestCertificate`: APK signed with public AOSP test keys, platform keys, or common mod/debug certificates.
       - `NotKnownToVirusTotal`: file hash not present in VirusTotal's threat database.
       - `VirusTotalKeyMissing`: no VirusTotal API key configured in Settings.
     * Does NOT hard-block: suspends the install flow and presents an interactive `CautionPromptCard` on HomeScreen.
     * Explains the risk clearly (e.g. dynamic runtime loading), notes the VirusTotal results (e.g. "0 detections on VirusTotal"), and provides two options:
       - `[ Cancel (Recommended) ]`: aborts cleanly and logs `> install: cancelled by user`.
       - `[ Install Anyway (I Trust This Source) ]`: acknowledges risk, logs `> security override: risk acknowledged by user, proceeding with installation`, and resumes streaming to `pm`.
   - **Red (Critical / Hard Block / Protected Fail-Closed)**:
     * Hard blocks without override capability:
       - `MalwareDetected`: one or more VirusTotal antivirus engines flagged the package.
       - `AdwareDetected`: aggressive adware or invasive telemetry SDK detected in bytecode.
       - `SignatureMismatch`: package signed with a different certificate than the currently installed application (prevents impersonation).
       - `AbusivePermissions`: `REQUEST_INSTALL_PACKAGES` combined with overlay (`SYSTEM_ALERT_WINDOW`) or SMS access, or requested by non-store apps.
       - `UnsignedPackage`: missing or unreadable APK signature block.
       - `PackageMismatch`: package name declared in metadata contradicts APK files.
     * Fail-closed: cannot be bypassed or overridden.

   - **Local static bytecode & asset inspector (Deep Scan)**: lightweight, zero-dependency, pure Kotlin scanner that parses DEX string tables (`classes.dex`, `classes2.dex`, etc.) directly from header offsets (`dex\n035` through `dex\n039`) and inspects asset/resource entries without heavy decompilation:
     * Only flags as Dropper if the asset entry is explicitly `.dex`, `.apk`, `.jar`, starts with DEX magic `dex\n`, or is a ZIP that actually contains `classes*.dex` or `.so` files.
     * Animation and data archives such as `.lottie` are never flagged as hidden payloads.
     * Configurable in Security settings (default ON).

   - **VirusTotal proof**: APK files are looked up on VirusTotal by SHA-256. A VirusTotal API key is required, except for updates of an installed app signed with the same certificate. A file VirusTotal does not know is uploaded only after user confirmation.

4. **Phase 5: Auto-Backup & 1-Tap Reversion**:
   - **Automatic Backup Before Update**:
     * When updating an already installed app (`installedInfo != null`), GoGo queries ADB `pm path <pkg>` to locate installed APK paths on the target device.
     * Pulls the installed APK(s) to GoGo's private storage (`context.filesDir/backups/<packageName>/`).
     * Stores `backup_meta.json` with package name, app name, version code, version name, timestamp, and APK file list.
     * Keeps only 1 previous version per package (overwriting earlier backups for that app).
     * Logs `> backup: saved v<versionCode> to local backup`.
   - **Backups Screen (`BackupsScreen.kt`)**:
     * Lists saved app backups with App Name, Package Name, Version, Date saved, and Size.
     * **1-Tap [ Revert ]**: installs the backed-up APK(s) via ADB streaming session (`pm install -r -d` / session install) to restore the previous version. Logs `> revert: restoring v<versionCode>...`.
     * **[ Delete ]**: removes the backup and frees storage.
     * Clean empty state when no backups exist.

5. **Google independence**: no Play Store link anywhere in the app.
6. **Cleanup**: on the success screen, one tap to delete or keep the APK.
7. **Formats**: APK, XAPK, APKM, APKS, ZIP splits.

Identity: italic "GGG" logo with speed lines on a solid dark background.
License: GPL-3.0-or-later. Distribution: GitHub Releases and F-Droid; Play Store optional (paid, for convenience).
