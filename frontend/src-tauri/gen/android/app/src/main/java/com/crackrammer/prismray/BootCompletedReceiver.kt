// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log

class BootCompletedReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "PrismRayBoot"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (
            action != Intent.ACTION_BOOT_COMPLETED &&
            action != "android.intent.action.QUICKBOOT_POWERON" &&
            action != "com.htc.intent.action.QUICKBOOT_POWERON"
        ) {
            return
        }

        val appCtx = context.applicationContext
        if (!AndroidBackendLauncher.isBootAutostartEnabled(appCtx)) {
            return
        }

        val consentIntent = VpnService.prepare(appCtx)
        if (consentIntent != null) {
            Log.i(TAG, "Skipping boot autostart: Android VPN permission not granted yet")
            return
        }

        try {
            val startIntent = Intent(appCtx, ProxyVpnService::class.java).apply {
                this.action = ProxyVpnService.ACTION_START
            }
            appCtx.startForegroundService(startIntent)
            Log.i(TAG, "Triggered PrismRay VPN service on boot")
        } catch (err: Throwable) {
            Log.w(TAG, "Unable to start VPN service directly on boot: ${err.message}")
        }
    }
}
