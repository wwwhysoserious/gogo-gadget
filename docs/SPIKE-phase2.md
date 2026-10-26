# Spike: Wireless Debugging from inside the app (phase 2)

**Everything in this note is UNTESTED on a device.** The build machine has no phone and no emulator, so none of
the ADB behaviour below has been observed running. What follows separates what could be checked from what could not.

## Question 1: can the app reach the Wireless Debugging of its own phone?

Could be verified without a device:

* The library (libadb-android 3.1.1) is written for exactly this case: it defaults to `127.0.0.1`, and its own
  sample app connects to the phone it runs on. Its source was read: pairing (TLS + SPAKE2) and the TLS connect
  with client certificate are implemented in Java.
* The project builds and the pure logic is unit-tested (see `progress.md` for the test output).

Could NOT be verified:

* That `adbd` accepts a connection to `127.0.0.1:<port>` from an unprivileged app (it should listen on all
  interfaces, but this depends on the Android version and OEM).
* That the pairing service is reachable the same way while the system's pairing dialog is open.
* That `NsdManager` shows this phone's own `_adb-tls-connect._tcp` / `_adb-tls-pairing._tcp` services to its own
  apps. The connect port changes on every restart of Wireless Debugging, so the app depends on this to find it.
  If mDNS does not show the own device, "This device" cannot find its port (the manual form is the fallback).
* That Wireless Debugging stays on while the Wi-Fi is not connected or while the pairing dialog is in the
  background, and that the pairing code can be typed in the app while the dialog stays open.
* That the shell user can read `Android/data/<package>/cache` (install path, see `ADB-LIBRARY.md`).
* Whether any OEM or Android 16+ "local network" permission affects mDNS or the sockets.

### Question 1b (0.4.1): does the "Allow" prompt work for this phone, without pairing first?

"This device" now tries a direct connect first when mDNS shows a connect port on one of this phone's own addresses
(waiting message and 45 s watchdog as for network devices). Only when libadb throws `AdbPairingRequiredException`
or an authentication failure, or when no connect port exists (Wireless debugging off or never paired), it falls back
to the notification pairing.

**Expected: it will usually NOT work.** Wireless debugging's TLS port normally accepts only clients whose key was
registered by pairing, so a never-paired app is expected to hit the fallback straight away. The direct path can only
succeed for a key that is already trusted (for example after an earlier pairing, or an "Always allow" given to a
classic ADB prompt). **UNTESTED on a device**: no phone was available, so nothing here is observed behaviour.

### Question 1c (0.4.3): can the notification show the code field without a tap?

**No public Android API forces it.** The inline reply field belongs to SystemUI; apps only provide a `RemoteInput`
on an action. Context7/Android docs describe Direct Reply as a reply action (`RemoteInput`) on the notification
and say nothing about a persistent field (`setHintDisplayInlineAction` is Wear OS only). So 0.4.3 uses the closest
thing: a `MessagingStyle` notification (the type messaging apps use), category MESSAGE, `IMPORTANCE_HIGH` channel
(heads-up), public visibility, ongoing, not auto-cancel, one action with `SEMANTIC_ACTION_REPLY`, `RemoteInput`
labelled "Insert pairing code here" and `setAllowGeneratedReplies(false)`.

UNTESTED on a device. Expected but not observed: the system offers the reply field directly on that action and in the
heads-up; on some Android versions or OEM skins the user may still have to tap the action once to open the field
and keyboard. If so, that tap cannot be removed from the app side. The in-app screen no longer has a code field for
this phone; it only guides and has a button to post the notification again.

**0.5.1 decision: the floating overlay (tried in 0.5.0) was rejected and removed.** Pairing for this phone is by
notification only, exactly as in 0.4.3. A second look for a documented way to show the reply field already expanded
found nothing beyond what 0.4.3 uses: the platform has no flag on `Notification`, `Notification.Action` or
`RemoteInput` for it (`WearableExtender.setHintDisplayActionInline` only affects Wear OS). Android, not the app,
decides whether the field is expanded; it cannot be forced, so the notification is left as it was in 0.4.3.

## Question 2: does local ADB from inside the app count as ADB for Google's developer verification?

Could be verified: Google's documentation (checked 26/10, see the project plan) says installs done through ADB are
exempt from the verification requirement.

Could NOT be verified: that an install made by an *app* that talks to the phone's own `adbd` is treated the
same as one made by `adb` on a PC. It is the same `adbd` and the same `pm` as the shell user, so it should be,
but the policy text talks about the ADB tool and nothing was observed on a verification-enforcing device.
Treat it as an open question until it is tried on a device in an enforcing region.

## Next step

Run the app on a real phone (Android 11+) and check, in order: mDNS lists the phone's own services; pairing
with the dialog open; reconnect after restarting Wireless Debugging; a single-APK install; then the same against a
second device on the Wi-Fi.
