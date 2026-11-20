// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Non-exported internal receiver for home-screen widget VPN toggle PendingIntents.
 * Isolating ACTION_TOGGLE_VPN here prevents third-party apps from spoofing broadcasts
 * to the exported AppWidgetProvider.
 */
class VpnWidgetActionReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "PrismRayWidgetAction"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != VpnWidgetProvider.ACTION_TOGGLE_VPN) return

        val pendingResult = goAsync()
        val appCtx = context.applicationContext
        Thread({
            try {
                VpnWidgetProvider.handleToggleClick(appCtx)
            } catch (err: Throwable) {
                Log.e(TAG, "Widget VPN toggle failed: ${err.message}", err)
            } finally {
                pendingResult.finish()
            }
        }, "prismray-widget-toggle").start()
    }
}
