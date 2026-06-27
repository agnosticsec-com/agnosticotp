package com.agnosticsec.agnosticotp

import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity

class MainActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // FLAG_SECURE: block screenshots, screen recording, and the
        // app-switcher/recents thumbnail from capturing codes OR a QR that
        // encodes a secret (threat model M2/M3). Applied in RELEASE builds only
        // — debug builds stay screenshot-able so developers/emulators can see
        // the UI; the shipping build is always protected.
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (!debuggable) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
    }
}
