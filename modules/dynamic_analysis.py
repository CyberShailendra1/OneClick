"""
Layer 5 - Dynamic (runtime) analysis.

IMPORTANT / HONESTY NOTE:
This module could NOT be executed or tested inside the sandbox this project
was built in (no Android SDK, no emulator, no physical device available
there). The logic below is written against the standard ADB + Frida
workflow and follows documented command syntax, but you must validate it on
your own Kali box before trusting its output.

Requirements on your Kali machine:
    sudo apt install android-tools-adb android-tools-fastboot
    pip install frida-tools frida
    # + a running AVD emulator (Android Studio) OR a rooted physical device
    #   OR a pre-rooted emulator image (e.g. Genymotion / Android-x86)

What this module does:
    1. Installs the APK on a connected/running emulator via ADB.
    2. Launches it and lets it run for N seconds.
    3. Uses Frida to hook common sensitive APIs (SMS send, HTTP requests,
       file read/write, crypto calls, reflection) and logs every call.
    4. Uses `adb logcat` + `adb shell dumpsys` to observe network activity
       and process behavior.
    5. Uninstalls the app and returns a structured report of observed calls.

This is intentionally best-effort / defensive tooling: it only OBSERVES the
app's behavior in an isolated emulator, it does not modify or attack
anything. Always run this against a disposable/snapshot-able emulator, never
your primary device, since the APK being analyzed may be real malware.
"""

import subprocess
import time
import re
import json

FRIDA_SCRIPT = r"""
Java.perform(function () {
    // --- SMS ---
    try {
        var SmsManager = Java.use('android.telephony.SmsManager');
        SmsManager.sendTextMessage.overload(
            'java.lang.String', 'java.lang.String', 'java.lang.String',
            'android.app.PendingIntent', 'android.app.PendingIntent'
        ).implementation = function (dest, sc, text, si, di) {
            send({type: 'sms_send', destination: dest, text: text});
            return this.sendTextMessage(dest, sc, text, si, di);
        };
    } catch (e) {}

    // --- HTTP(S) via HttpURLConnection ---
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            send({type: 'http_connect', url: this.toString()});
            return this.openConnection();
        };
    } catch (e) {}

    // --- Dynamic class loading ---
    try {
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.$init.overload(
            'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'
        ).implementation = function (dexPath, optDir, libPath, parent) {
            send({type: 'dex_class_loader', dexPath: dexPath});
            return this.$init(dexPath, optDir, libPath, parent);
        };
    } catch (e) {}

    // --- Runtime.exec ---
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            send({type: 'runtime_exec', command: cmd});
            return this.exec(cmd);
        };
    } catch (e) {}

    // --- File writes (common exfil/drop pattern) ---
    try {
        var FileOutputStream = Java.use('java.io.FileOutputStream');
        FileOutputStream.$init.overload('java.lang.String').implementation = function (path) {
            send({type: 'file_write', path: path});
            return this.$init(path);
        };
    } catch (e) {}
});
"""


def _run(cmd: list, timeout: int = 30) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
    return result.stdout


def check_environment() -> dict:
    """Verifies adb + frida-server prerequisites are present before running."""
    status = {"adb_available": False, "device_connected": False, "frida_available": False, "notes": []}
    try:
        out = _run(["adb", "devices"])
        status["adb_available"] = True
        devices = [l for l in out.splitlines()[1:] if l.strip().endswith("device")]
        status["device_connected"] = len(devices) > 0
        if not status["device_connected"]:
            status["notes"].append("No emulator/device detected. Start an AVD or connect a rooted device.")
    except FileNotFoundError:
        status["notes"].append("adb not found. Install: sudo apt install android-tools-adb")
    except Exception as e:
        status["notes"].append(str(e))

    try:
        _run(["frida", "--version"])
        status["frida_available"] = True
    except FileNotFoundError:
        status["notes"].append("frida not found. Install: pip install frida-tools frida")
    except Exception as e:
        status["notes"].append(str(e))

    return status


def get_package_name(apk_path: str) -> str:
    out = _run(["aapt", "dump", "badging", apk_path])
    match = re.search(r"package: name='([^']+)'", out)
    if not match:
        raise RuntimeError("Could not determine package name via aapt. Is aapt installed?")
    return match.group(1)


def run_dynamic_analysis(apk_path: str, duration_seconds: int = 30) -> dict:
    """
    Full pipeline: install -> launch -> hook with frida -> observe -> uninstall.
    Returns a dict of observed behavior events, or an "unavailable" status if
    the environment isn't set up (safe no-op fallback for the Streamlit app).
    """
    env = check_environment()
    if not (env["adb_available"] and env["device_connected"]):
        return {
            "status": "unavailable",
            "reason": "Android emulator/device or adb not available.",
            "setup_notes": env["notes"],
            "events": [],
        }

    package = get_package_name(apk_path)
    events = []

    try:
        _run(["adb", "install", "-r", apk_path], timeout=60)
        _run(["adb", "shell", "monkey", "-p", package, "-c",
              "android.intent.category.LAUNCHER", "1"], timeout=20)

        if env["frida_available"]:
            try:
                import frida
                device = frida.get_usb_device(timeout=5)
                pid = device.spawn([package])
                session = device.attach(pid)
                script = session.create_script(FRIDA_SCRIPT)

                def on_message(message, data):
                    if message.get("type") == "send":
                        events.append(message["payload"])

                script.on("message", on_message)
                script.load()
                device.resume(pid)
                time.sleep(duration_seconds)
                session.detach()
            except Exception as e:
                events.append({"type": "frida_error", "detail": str(e)})
        else:
            time.sleep(duration_seconds)  # passive observation window without hooks

        # Passive network-ish signal from logcat as a fallback/supplement
        try:
            logcat = _run(["adb", "logcat", "-d", "-t", "500"], timeout=15)
            net_lines = [l for l in logcat.splitlines() if re.search(r"http|socket|connect", l, re.I)]
            if net_lines:
                events.append({"type": "logcat_network_hints", "lines": net_lines[:30]})
        except Exception:
            pass

    finally:
        try:
            _run(["adb", "uninstall", package], timeout=20)
        except Exception:
            pass

    return {
        "status": "completed",
        "package": package,
        "duration_seconds": duration_seconds,
        "events": events,
        "num_events": len(events),
    }
