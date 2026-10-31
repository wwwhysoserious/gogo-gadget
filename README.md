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

Whether installing split packages (`.apks`, `.xapk`, `.apkm`), deploying to remote Android TVs across your local network, or reverting failed updates with 1-tap backups, GoGo Gadget delivers an uncompromising, privacy-respecting workflow with zero Google dependencies.

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
| **Remote TV / Local Network Push**| No | No | **Built-in mDNS Network Deploy** |
| **Google Play / Tracking Libs** | Yes | Optional | **Zero Google Code (100% FOSS)** |

### The Core Strengths
1. **True Autonomy (No PC & No Running Daemons)**: Connects directly to Android's local pairing service inside the phone. When you close GoGo Gadget, no background daemon stays eating your battery or monitoring your device.
2. **Built-in Bytecode Antivirus (Pre-Install)**: Before letting an APK touch your system, GoGo Gadget scans the actual DEX headers across `classes.dex`, instantly detecting abusive permissions, obfuscated dynamic class loaders, and hidden binary droppers.
3. **Fail-Safe 1-Tap Rollback**: Upgraded an app and the new version crashes or has annoying changes? GoGo Gadget automatically archives your previous working version so you can revert with one tap.
4. **Remote Device Hub**: Install an app on your phone, and push it directly over Wi-Fi to your Android TV or secondary tablet without installing extra apps on the target device.

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
- **Target Flexibility**: Install locally on your handheld smartphone or push packages remotely to Android TVs and other network devices via mDNS.
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
