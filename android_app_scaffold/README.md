# OneClick OTP Guard — Android App Scaffold

Real-time, on-device extension of the OTP Guard feature: instead of pasting a
message into the web dashboard, this app watches your phone's own
notifications and redacts OTPs the moment they arrive.

## ⚠️ Testing status — please read before using this

**This scaffold was written but could not be built or run** in the
environment this project was developed in — there is no Android SDK,
Gradle, emulator, or physical device available there (only a plain Python
sandbox). Everything here is:
- Syntactically standard Kotlin/Android code following the documented
  `NotificationListenerService` API correctly.
- Structurally a complete, buildable Android Studio project (manifest,
  Gradle files, activity, service, resources).
- **Not compiled, not run, not tested on any device or emulator.**

Before relying on this for anything real:
1. Open this folder in Android Studio.
2. Let Gradle sync (needs internet access to Google's Maven repo — not
   available in the sandbox this was built in).
3. Run it on a real device or emulator (Android 8.0+ / API 26+).
4. Grant "Notification access" (Settings → Apps → Special access →
   Notification access) and manually test with a real or simulated
   OTP SMS/WhatsApp message.

## Design / platform constraints (important)

- **Android will not let one app rewrite another app's notification
  content.** The only way to make an OTP "not visible" is to *cancel* the
  original notification and *post a new one* from this app with the code
  masked. There's an unavoidable brief window between the original
  notification appearing and this service reacting — this is **not**
  the same guarantee as true real-time invisibility, and that should be
  communicated honestly to end users of the app, not oversold.
- "Notification access" is a highly sensitive Android permission — it
  cannot be requested via a normal permission dialog; the user must grant
  it manually in system Settings, and Android shows a strong warning when
  doing so (by design, since it lets an app read all your notifications).
- The service only reacts to a curated list of messaging app package names
  (`MONITORED_PACKAGES` in `OtpNotificationListenerService.kt`) — extend
  this list for other SMS/messaging apps you use.
- OTP-detection logic (keyword list + regex patterns) is a manually-synced
  Kotlin port of `modules/otp_guard.py` in the main Python project. If you
  update the detection logic in one place, update the other, or better,
  extract it into a shared spec/test-vector file both sides check against.

## Project structure

```
android_app_scaffold/
├── build.gradle.kts, settings.gradle.kts   # project-level Gradle config
└── app/
    ├── build.gradle.kts                     # app module config (min SDK 26)
    └── src/main/
        ├── AndroidManifest.xml              # declares the notification listener service
        ├── java/com/oneclick/otpguard/
        │   ├── MainActivity.kt              # links to Settings > Notification access
        │   └── OtpNotificationListenerService.kt   # the core redaction logic
        └── res/
            ├── layout/activity_main.xml
            └── values/{strings.xml, themes.xml}
```

## Suggested next steps (once actually running on a device)

- Add a Room database to log redaction events locally (mirroring the
  Python project's `url_scan_history` / `oneclick.db` pattern).
- Add a settings screen to customize `MONITORED_PACKAGES` and the
  keyword list without rebuilding the app.
- Add instrumented tests (`androidTest`) that post a fake notification via
  `NotificationManagerCompat` and assert the listener reacts correctly —
  this is the first thing to write once a real Android toolchain is
  available, to replace "trust me, it's standard code" with an actual
  passing test suite.
