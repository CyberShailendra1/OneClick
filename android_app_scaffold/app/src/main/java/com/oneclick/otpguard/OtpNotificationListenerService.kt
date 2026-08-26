package com.oneclick.otpguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.app.NotificationCompat

/**
 * Reads incoming notifications (SMS/messaging apps only), and if one looks
 * like it contains an OTP/verification code, DISMISSES the original
 * notification and reposts a redacted version in its place.
 *
 * PLATFORM CONSTRAINT (please read before assuming this "just works"):
 * Android does not allow one app to rewrite the *content* of another app's
 * posted notification - only the posting app can do that. The only way to
 * achieve "the OTP doesn't stay visible in the notification shade" is the
 * approach used here: cancel the original notification via
 * `cancelNotification()` (this requires notification-listener "interaction"
 * access, granted the same way as read access) and post our own replacement
 * notification with the code masked. There is an unavoidable brief window
 * between the original notification appearing and this service reacting to
 * cancel it - this is NOT the same as truly preventing it from ever
 * rendering. On a lock screen with a heads-up preview, a fast glance could
 * still catch the original for a moment. This is a platform limitation, not
 * a bug in this code - be upfront with users about it rather than promising
 * perfect real-time invisibility.
 *
 * TESTING STATUS: this file is syntactically standard Kotlin/Android code
 * following the documented NotificationListenerService API, but it has NOT
 * been compiled or run on a device/emulator - this sandbox has no Android
 * SDK/build toolchain. Build this in Android Studio and test on a real
 * device (Settings > Apps > Special access > Notification access > enable
 * for this app) before relying on it.
 */
class OtpNotificationListenerService : NotificationListenerService() {

    companion object {
        private const val REDACTED_CHANNEL_ID = "otp_guard_redacted"

        // Same keyword list and design rationale as modules/otp_guard.py in
        // the Python project - kept in sync manually since this is a
        // separate app/runtime. See that file for the full design notes.
        private val OTP_KEYWORDS = listOf(
            "otp", "one time password", "one-time password", "verification code",
            "security code", "auth code", "authentication code", "login code",
            "access code", "confirmation code", "passcode", "pin is", "code is",
            "your code", "use code", "use otp", "enter otp", "enter code",
            "otp hai", "code hai", "password hai", "pin hai",
        )

        private val NUMERIC_CODE = Regex("""\b\d(?:[ \-]?\d){3,7}\b""")
        private val ALNUM_CODE = Regex("""\b(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{5,8}\b""")

        // Only act on notifications from common messaging/SMS apps - never
        // touch banking-app notifications directly (avoid interfering with
        // any app-specific security behavior banking apps may implement).
        private val MONITORED_PACKAGES = setOf(
            "com.google.android.apps.messaging",   // Google Messages
            "com.samsung.android.messaging",       // Samsung Messages
            "com.whatsapp",
            "com.google.android.gm",               // Gmail
        )
    }

    override fun onCreate() {
        super.onCreate()
        createRedactedChannel()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (sbn.packageName !in MONITORED_PACKAGES) return

        val extras = sbn.notification.extras
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val fullText = "$title $text"

        val redactionResult = redactOtp(fullText)
        if (redactionResult.codesHidden == 0) return  // nothing sensitive found, leave notification untouched

        // Dismiss the original (which still shows the real code) and post our
        // own redacted replacement. Requires notification-listener access
        // (already granted) to cancel; POST_NOTIFICATIONS permission to post.
        cancelNotification(sbn.key)
        postRedactedNotification(sbn.packageName, title, redactionResult.redactedText)
    }

    data class RedactionResult(val redactedText: String, val codesHidden: Int)

    /** Kotlin port of modules/otp_guard.py's redact_message() - see that file for design rationale. */
    private fun redactOtp(text: String): RedactionResult {
        val lower = text.lowercase()
        val hasKeyword = OTP_KEYWORDS.any { lower.contains(it) }
        if (!hasKeyword) return RedactionResult(text, 0)

        var result = text
        var hidden = 0

        for (match in NUMERIC_CODE.findAll(text)) {
            val digits = match.value.filter { it.isDigit() }
            if (digits.length in 4..8) {
                result = result.replace(match.value, "[${"•".repeat(digits.length)} HIDDEN]")
                hidden++
            }
        }
        if (hidden == 0) {
            for (match in ALNUM_CODE.findAll(text)) {
                result = result.replace(match.value, "[${"•".repeat(match.value.length)} HIDDEN]")
                hidden++
            }
        }

        return RedactionResult(result, hidden)
    }

    private fun createRedactedChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                REDACTED_CHANNEL_ID, "OTP Guard (redacted)", NotificationManager.IMPORTANCE_HIGH
            )
            channel.description = "Replacement notifications with OTP/codes hidden"
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun postRedactedNotification(sourcePackage: String, title: String, redactedText: String) {
        val notification = NotificationCompat.Builder(this, REDACTED_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title.ifBlank { "Message (OTP hidden)" })
            .setContentText(redactedText)
            .setStyle(NotificationCompat.BigTextStyle().bigText(redactedText))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        // Stable-ish id per source package so repeated messages don't spam separate notifications.
        nm.notify(sourcePackage.hashCode(), notification)
    }
}
