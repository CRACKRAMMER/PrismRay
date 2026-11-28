// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.RemoteViews
import org.json.JSONObject

class VpnWidgetProvider : AppWidgetProvider() {
    companion object {
        private const val TAG = "PrismRayWidget"
        const val ACTION_TOGGLE_VPN = "com.crackrammer.prismray.widget.ACTION_TOGGLE_VPN"

        @Volatile
        private var cachedRunning: Boolean = false

        @Volatile
        private var cachedConnecting: Boolean = false

        @Volatile
        private var cachedNodeName: String = ""

        @Volatile
        private var cachedSpeedText: String = ""

        @Volatile
        private var lastStatsPushMs: Long = 0L

        // Tri-state cache: null = unknown (check once), false = zero widgets pinned (skip Binder IPC), true = active.
        @Volatile
        private var hasPinnedWidgets: Boolean? = null

        fun updateAllWidgets(
            context: Context,
            running: Boolean,
            connecting: Boolean = false,
            nodeName: String? = null,
            speedText: String? = null,
            throttleStats: Boolean = false,
        ) {
            if (hasPinnedWidgets == false) return
            val now = System.currentTimeMillis()
            if (throttleStats && running == cachedRunning && connecting == cachedConnecting) {
                if (now - lastStatsPushMs < 3500L) return
            }
            lastStatsPushMs = now

            cachedRunning = running
            cachedConnecting = connecting
            if (nodeName != null) {
                cachedNodeName = nodeName
            } else if (!running && !connecting) {
                cachedNodeName = ""
            }
            if (speedText != null) {
                cachedSpeedText = speedText
            } else if (!running) {
                cachedSpeedText = ""
            }

            val appCtx = context.applicationContext
            val manager = AppWidgetManager.getInstance(appCtx) ?: return
            val ids = manager.getAppWidgetIds(ComponentName(appCtx, VpnWidgetProvider::class.java))
            if (ids.isEmpty()) {
                hasPinnedWidgets = false
                return
            }
            hasPinnedWidgets = true

            for (widgetId in ids) {
                val options = manager.getAppWidgetOptions(widgetId)
                val views = buildRemoteViews(appCtx, options)
                manager.updateAppWidget(widgetId, views)
            }
        }

        private fun buildRemoteViews(context: Context, options: Bundle?): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.widget_vpn_toggle)

            val minWidthDp = options?.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_WIDTH, 140) ?: 140
            val isWide = minWidthDp >= 200

            val openIntent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            val openPending = PendingIntent.getActivity(
                context,
                21810,
                openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            views.setOnClickPendingIntent(R.id.widget_open_area, openPending)

            val toggleIntent = Intent(context, VpnWidgetActionReceiver::class.java).apply {
                action = ACTION_TOGGLE_VPN
            }
            val togglePending = PendingIntent.getBroadcast(
                context,
                21811,
                toggleIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            views.setOnClickPendingIntent(R.id.widget_toggle_btn, togglePending)

            val statusConnected = context.getString(R.string.widget_status_connected)
            val statusDisconnected = context.getString(R.string.widget_status_disconnected)
            val statusConnecting = context.getString(R.string.widget_status_connecting)

            when {
                cachedConnecting -> {
                    views.setImageViewResource(R.id.widget_status_dot, R.drawable.widget_dot_off)
                    views.setInt(R.id.widget_toggle_btn, "setBackgroundResource", R.drawable.widget_toggle_connecting)
                    views.setImageViewResource(R.id.widget_toggle_btn, R.drawable.ic_widget_power)
                    views.setTextViewText(R.id.widget_subtitle, statusConnecting)
                    views.setViewVisibility(R.id.widget_speed, View.GONE)
                }
                cachedRunning -> {
                    views.setImageViewResource(R.id.widget_status_dot, R.drawable.widget_dot_on)
                    views.setInt(R.id.widget_toggle_btn, "setBackgroundResource", R.drawable.widget_toggle_on)
                    views.setImageViewResource(R.id.widget_toggle_btn, R.drawable.ic_widget_power)
                    val subtitle = if (cachedNodeName.isNotBlank()) {
                        if (isWide) "$statusConnected · $cachedNodeName" else cachedNodeName
                    } else {
                        statusConnected
                    }
                    views.setTextViewText(R.id.widget_subtitle, subtitle)
                    if (isWide && cachedSpeedText.isNotBlank()) {
                        views.setTextViewText(R.id.widget_speed, cachedSpeedText)
                        views.setViewVisibility(R.id.widget_speed, View.VISIBLE)
                    } else {
                        views.setViewVisibility(R.id.widget_speed, View.GONE)
                    }
                }
                else -> {
                    views.setImageViewResource(R.id.widget_status_dot, R.drawable.widget_dot_off)
                    views.setInt(R.id.widget_toggle_btn, "setBackgroundResource", R.drawable.widget_toggle_off)
                    views.setImageViewResource(R.id.widget_toggle_btn, R.drawable.ic_widget_power_off)
                    views.setTextViewText(R.id.widget_subtitle, statusDisconnected)
                    views.setViewVisibility(R.id.widget_speed, View.GONE)
                }
            }

            return views
        }

        private val toggleInFlight = java.util.concurrent.atomic.AtomicBoolean(false)

        internal fun handleToggleClick(context: Context) {
            if (!toggleInFlight.compareAndSet(false, true)) {
                return
            }
            try {
                val statusRes = RuntimeIpc.request(context, "GET", "/api/vpn/android/status")
                val backendAlive = statusRes != null && statusRes.statusCode in 200..299
                val isActive = ProxyVpnService.isVpnRunning || (backendAlive && try {
                    val json = JSONObject(statusRes!!.body)
                    json.optBoolean("active", false) && json.optBoolean("running", false)
                } catch (_: Throwable) {
                    false
                })

                if (isActive) {
                    updateAllWidgets(context, running = false, connecting = false)
                    val stopIntent = Intent(context, ProxyVpnService::class.java).apply {
                        action = ProxyVpnService.ACTION_STOP
                    }
                    try {
                        context.startService(stopIntent)
                    } catch (_: Throwable) {
                        // Android 12+ may restrict background startService when the VPN service already exited;
                        // fall back to stopping the local backend directly via IPC.
                        Thread({
                            try {
                                RuntimeIpc.request(context, "POST", "/api/vpn/android/stop", "{}", readTimeoutMs = 3000)
                            } catch (_: Throwable) {
                            }
                            updateAllWidgets(context, running = false, connecting = false)
                        }, "prismray-widget-stop-fallback").apply {
                            isDaemon = true
                            start()
                        }
                    }
                    return
                }

                val prepareIntent = VpnService.prepare(context)
                if (prepareIntent == null) {
                    updateAllWidgets(context, running = false, connecting = true)
                    if (backendAlive || AndroidBackendLauncher.ensureBackendRunning(context, timeoutMs = 6000L)) {
                        val startIntent = Intent(context, ProxyVpnService::class.java).apply {
                            action = ProxyVpnService.ACTION_START
                        }
                        try {
                            context.startForegroundService(startIntent)
                            return
                        } catch (_: Throwable) {
                            // Fall through to launch MainActivity if background FGS start is restricted.
                        }
                    }
                }
                // Either first-time VPN permission consent is required or background FGS was blocked:
                // launch MainActivity with auto-start flag so it completes authorization & connects automatically.
                updateAllWidgets(context, running = false, connecting = true)
                val launchIntent = Intent(context, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
                    putExtra(MainActivity.EXTRA_AUTO_START_VPN, true)
                    putExtra(MainActivity.EXTRA_AUTO_START_NONCE, MainActivity.issueAutoStartNonce())
                }
                try {
                    context.startActivity(launchIntent)
                } catch (_: Throwable) {
                    // Android 14+ Background Activity Launch (BAL) may reject startActivity from a receiver;
                    // reset widget state immediately instead of leaving it permanently stuck on "Connecting...".
                    updateAllWidgets(context, running = ProxyVpnService.isVpnRunning, connecting = false)
                }
            } finally {
                toggleInFlight.set(false)
            }
        }
    }

    override fun onEnabled(context: Context) {
        super.onEnabled(context)
        hasPinnedWidgets = true
    }

    override fun onDisabled(context: Context) {
        super.onDisabled(context)
        hasPinnedWidgets = false
    }

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        super.onUpdate(context, appWidgetManager, appWidgetIds)
        hasPinnedWidgets = appWidgetIds.isNotEmpty()
        val running = ProxyVpnService.isVpnRunning
        updateAllWidgets(context, running = running, connecting = false)
    }

    override fun onAppWidgetOptionsChanged(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetId: Int,
        newOptions: Bundle,
    ) {
        super.onAppWidgetOptionsChanged(context, appWidgetManager, appWidgetId, newOptions)
        val views = buildRemoteViews(context.applicationContext, newOptions)
        appWidgetManager.updateAppWidget(appWidgetId, views)
    }
}
