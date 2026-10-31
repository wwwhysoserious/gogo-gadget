<p align="center">
  <img src="assets/banner.png" alt="GoGo Gadget Banner" width="100%">
</p>

<p align="center">
  <a href="https://github.com/wwwhysoserious/gogo-gadget/releases/latest"><img src="https://img.shields.io/github/v/release/wwwhysoserious/gogo-gadget?color=00E676&label=Release&logo=android&logoColor=white&style=for-the-badge" alt="Latest Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL--3.0-blue.svg?style=for-the-badge" alt="License: GPL-3.0"></a>
  <img src="https://img.shields.io/badge/Android-11%2B%20(API%2030%2B)-3DDC84.svg?style=for-the-badge&logo=android&logoColor=white" alt="Android 11+">
  <img src="https://img.shields.io/badge/Architecture-Zero--Trust-black.svg?style=for-the-badge&logo=shield" alt="Zero-Trust">
  <img src="https://img.shields.io/badge/Shizuku-Optional-orange.svg?style=for-the-badge" alt="Shizuku Optional">
  <img src="https://img.shields.io/badge/Root-Not%20Required-success.svg?style=for-the-badge" alt="No Root">
</p>

---

## Overview

**GoGo Gadget** is a modern, standalone, zero-trust package manager and APK installer for Android. It operates independently on your device through Android's native **Wireless Debugging (ADB)** — eliminating the need for a PC, root privileges, or proprietary helper services.

Whether installing split packages (`.apks`, `.xapk`, `.apkm`), deploying to other Android devices across your local network, or reverting failed updates with 1-tap backups, GoGo Gadget delivers an uncompromising, privacy-respecting workflow with zero Google dependencies.

---

## Why GoGo Gadget? (The Key Differentiators)

Most Android installers fall into one of two traps: they either depend on Google Play / proprietary frameworks, or they require intrusive background daemons and root access. GoGo Gadget takes a fundamentally different path:

| Feature | Standard Package Installer | Shizuku-based Installers | **GoGo Gadget** |
| :--- | :---: | :---: | :---: |
| **PC Connection Needed** | Yes (for initial setup) | Often (to start daemon) | **Never** (100% on-device) |
| **Requires Root Access** | No | Optional / Root Mode | **No** (Zero Root needed) |
| **Persistent Background Service**| No | Yes (Always running) | **No** (Runs only on-demand) |
| **Pre-Install Bytecode Security** | None (Basic signature) | None (Blind pass-through) | **Full DEX Bytecode Inspection** |
| **Automatic Rollback / Backup** | None (Overwrites blindly)| None | **1-Tap Instant Downgrade** |
| **Splits & Formats (.xapk, .apkm)**| Fails / Incompatible | Manual handling | **Native Seamless Ingestion** |
| **Remote Network Deploy (Local Wi-Fi)**| No | No | **Built-in mDNS Network Deploy** |
| **Google Play / Tracking Libs** | Yes | Optional | **Zero Google Code (100% FOSS)** |

### The Core Strengths
1. **True Autonomy (No PC & No Running Daemons)**: Connects directly to Android's local pairing service inside the phone. When you close GoGo Gadget, no background daemon stays eating your battery or monitoring your device.
2. **Built-in Bytecode Antivirus (Pre-Install)**: Before letting an APK touch your system, GoGo Gadget scans the actual DEX headers across `classes.dex`, instantly detecting abusive permissions, obfuscated dynamic class loaders, and hidden binary droppers.
3. **Fail-Safe 1-Tap Rollback**: Upgraded an app and the new version crashes or has annoying changes? GoGo Gadget automatically archives your previous working version so you can revert with one tap.
4. **Local & Remote Android Deployment**: Install applications directly on your own smartphone via local ADB, or deploy them over Wi-Fi to any other Android phone, tablet, or device on your local network.

## The Real Problems GoGo Gadget Solves

Sideloading on modern Android is fraught with friction, security risks, and broken workflows. GoGo Gadget was engineered specifically to solve these everyday headaches:

* **The "Split APK Hell" Problem (`.xapk`, `.apkm`, `.apks`)**
  * *The Pain*: You download an app update from third-party repositories and receive a split bundle format that the stock Android installer refuses to open, throwing cryptic parsing errors.
  * *The Solution*: GoGo Gadget natively unpacks and streams split bundles directly through ADB in a single transaction without cluttering your storage with uncompressed files.

* **The "Tethered PC / Broken Shizuku" Problem**
  * *The Pain*: Traditional tools force you to connect to a laptop with a USB cable or maintain a fragile background daemon (like Shizuku) that dies every time the device restarts or aggressive OEM memory management kicks in.
  * *The Solution*: GoGo Gadget pairs directly with Android's built-in Wireless Debugging on localhost. It runs on demand with zero daemons staying alive when you are done.

* **The "Blind Trust / Trojan Dropper" Problem**
  * *The Pain*: Standard sideloading only checks basic signature validity. It won’t warn you if an APK contains suspicious dynamic bytecode loaders (`DexClassLoader`) or droppers that download malware after installation.
  * *The Solution*: Built-in local DEX header analysis inspects classes and permissions **before** installation, surfacing high-risk anomalies before the package ever touches your OS.

* **The "Faulty Update with Lost Data" Problem**
  * *The Pain*: An app update introduces game-breaking bugs, intrusive ads, or breaks compatibility, and Android doesn't allow downgrading without wiping all your application data.
  * *The Solution*: GoGo Gadget automatically archives the current working version before updating. If anything goes wrong, restore the previous APK with one tap.

* **The "Invasive Permissions / Privacy Nightmare" Problem**
  * *The Pain*: Third-party installers and helper apps routinely demand scary high-privilege permissions: `MANAGE_EXTERNAL_STORAGE` (full access to all photos, files, and personal documents), Accessibility services, or Root superuser access, exposing your entire phone to potential data harvesting.
  * *The Solution*: **Zero Dangerous Permissions.** GoGo Gadget never requests `MANAGE_EXTERNAL_STORAGE`, Accessibility, or sensitive personal data permissions. It uses the system file picker (`SAF`) strictly in memory and talks directly to the local ADB loopback. Your photos, private documents, and personal storage remain 100% unreadable and isolated.

* **The "Cross-Device Sideloading" Problem**
  * *The Pain*: Transferring and installing APKs onto a secondary Android device or family member's phone usually involves messaging apps, cloud drives, file transfer utilities, or USB sticks.
  * *The Solution*: Select any target Android device discovered automatically over local Wi-Fi and deploy the package directly from your smartphone.

---

## Screenshots

<p align="center">
  <img src="assets/screenshots/01-home-verified.png" width="30%" alt="GoGo Gadget Home Screen" />
  &nbsp;&nbsp;
  <img src="assets/screenshots/02-security-engine.png" width="30%" alt="Security Engine & APIs" />
  &nbsp;&nbsp;
  <img src="assets/screenshots/03-clean-architecture.png" width="30%" alt="Pre-install Security Scan" />
</p>

---

## How it Works

<p align="center">
  <img src="assets/diagrams/how-it-works-linear.png" width="75%" alt="GoGo Gadget Linear Architecture" />
</p>

---

## Promo Video

<p align="center">
  <img src="assets/promo/phone-promo.gif" width="85%" alt="GoGo Gadget Phone Promo Demonstration" />
  <br>
  <a href="https://github.com/wwwhysoserious/gogo-gadget/releases/download/v1.0.0/GoGo-Gadget-Phone-Promo.mp4">
    <b>⬇️ Download High-Definition Video (Full HD 1080p MP4)</b>
  </a>
</p>

---

1. **Select Package**: Open standard APKs, split APK archives (`APKS`, `APKM`, `XAPK`), or `.zip` bundles. Extraction and validation execute directly in streaming memory without leaving temporary clutter.
2. **Multi-Tier Security Engine**:
   * **Local Bytecode Analyzer**: Inspects DEX bytecode header structures across `classes.dex`, detecting dynamic class loaders (`DexClassLoader`, `InMemoryDexClassLoader`), embedded binary droppers, abusive permission patterns, and obfuscated adware.
   * **Reputation Intelligence**: Cross-references package signatures with optional threat intelligence APIs.
   * **Strict Risk Tiers**: Clear color-coded verdicts: **Green** (verified clean), **Yellow** (caution / interactive override), and **Red** (known threat / signature collision block).
3. **Native Wireless Pairing**: Establishes local ADB sessions directly inside Android via pairing codes entered through a persistent notification or quick-access settings — no computer or external bridge required.
4. **Safety Rollbacks & Auto-Backup**:
   * When upgrading existing applications, previous APK versions are automatically preserved to application-private storage.
   * Revert any problematic update with a single tap from the **Backups** tab.
5. **Post-Install Cleanup**: Automatically removes source installation archives upon successful verification or keeps them according to user preference.

---

## Key Features

- **Zero-Trust Security**: Requests only essential permissions (`INTERNET`, `CHANGE_WIFI_MULTICAST_STATE`, `FOREGROUND_SERVICE`, `POST_NOTIFICATIONS`). Sandboxed isolation ensures your personal storage is never probed.
- **Split Package Native Engine**: Full parsing and installation for `.apk`, `.xapk`, `.apkm`, `.apks`, and compressed splits.
- **Target Flexibility**: Install locally on your smartphone or deploy packages remotely to any other Android device across your local network via mDNS.
- **1-Tap Rollback**: Automated previous-version archives safeguard against faulty app updates.
- **Industrial Clean Flat UI**: Precision high-contrast UI designed for rapid workflow and clarity.
- **100% Google-Independent**: No Google Play Services or Play Protect requirements.

---

## Download & Installation

Download the official signed release from the [GitHub Releases](https://github.com/wwwhysoserious/gogo-gadget/releases/latest) page:

* **[Download GoGo Gadget v1.0.0 APK](https://github.com/wwwhysoserious/gogo-gadget/releases/download/v1.0.0/GoGo-Gadget-v1.0.0.apk)**

---

## Building from Source

Requires **JDK 17** and the Android SDK:

```bash
export ANDROID_HOME=/path/to/android-sdk
./gradlew assembleRelease testDebugUnitTest
```

---

## Credits & Architecture

* ADB pairing and connection engine powered by [libadb-android](https://github.com/MuntashirAkon/libadb-android) (GPL-3.0-or-later / Apache-2.0), utilizing `spake2-java` (LGPL-3.0) and BouncyCastle cryptography.
* UI built with **Jetpack Compose** following an uncompromised dark industrial design spec.

---

## License

Distributed under the **GPL-3.0-or-later** license. See [LICENSE](LICENSE) for details.
