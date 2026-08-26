package com.oneclick.otpguard

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * Minimal launcher screen: explains what the app does and links directly to
 * the system "Notification access" settings page, since that permission
 * cannot be requested via a normal runtime-permission dialog (Android
 * requires the user to grant it manually in Settings, by design, because
 * it's a highly sensitive capability).
 */
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViewById<TextView>(R.id.explanationText).text = getString(R.string.explanation_text)

        findViewById<Button>(R.id.grantAccessButton).setOnClickListener {
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
        }
    }
}
