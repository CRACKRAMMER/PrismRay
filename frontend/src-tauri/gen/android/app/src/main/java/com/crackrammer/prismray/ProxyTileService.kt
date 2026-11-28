// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

class ProxyTileService : TileService() {
    companion object {
        private val toggling = AtomicBoolean(false)
    }

    override fun onStartListening() {
        super.onStartListening()
        refreshTileState()
    }

    override fun onClick() {
        super.onClick()
        if (!toggling.compareAndSet(false, true)) return
        Thread({
            try {
                val active = queryActive()
                if (active) {
                    val stopIntent = Intent(this, ProxyVpnService::class.java).apply {
                        action = ProxyVpnService.ACTION_STOP
                    }
                    try {
                        startService(stopIntent)
                    } catch (_: Throwable) {
                        RuntimeIpc.request(this, "POST", "/api/vpn/android/stop", "{}", readTimeoutMs = 3000)
                    }
                    updateTile(isActive = false)
                    return@Thread
                }

                val prepareIntent = VpnService.prepare(this)
                val backendAlive = RuntimeIpc.request(this, "GET", "/api/vpn/android/status")?.statusCode in 200..299
                if (prepareIntent == null && backendAlive) {
                    val startIntent = Intent(this, ProxyVpnService::class.java).apply {
                        action = ProxyVpnService.ACTION_START
                    }
                    try {
                        startForegroundService(startIntent)
                        updateTile(isActive = true)
                        return@Thread
                    } catch (_: Throwable) {
                        // Fall through to launch MainActivity if background FGS start is restricted.
                    }
                }
                val launchIntent = Intent(this, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
                    putExtra(MainActivity.EXTRA_AUTO_START_VPN, true)
                    putExtra(MainActivity.EXTRA_AUTO_START_NONCE, MainActivity.issueAutoStartNonce())
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    val pending = PendingIntent.getActivity(
                        this,
                        21781,
                        launchIntent,
                        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                    )
                    startActivityAndCollapse(pending)
                } else {
                    @Suppress("DEPRECATION")
                    startActivityAndCollapse(launchIntent)
                }
            } finally {
                toggling.set(false)
            }
        }, "prismray-tile-click").start()
    }

    private fun refreshTileState() {
        Thread({
            val active = queryActive()
            val label = if (active) querySubtitle() else ""
            updateTile(isActive = active, subtitle = label)
        }, "prismray-tile-state").start()
    }

    private fun queryActive(): Boolean {
        if (ProxyVpnService.isVpnRunning) {
            return true
        }
        val res = RuntimeIpc.request(this, "GET", "/api/vpn/android/status") ?: return false
        if (res.statusCode !in 200..299) return false
        return try {
            val json = JSONObject(res.body)
            json.optBoolean("active", false) && json.optBoolean("running", false)
        } catch (_: Throwable) {
            false
        }
    }

    private fun querySubtitle(): String {
        val cached = ProxyVpnService.activeTargetLabel.trim()
        if (cached.isNotEmpty()) return cached
        val res = RuntimeIpc.request(this, "GET", "/api/process/status") ?: return ""
        if (res.statusCode !in 200..299) return ""
        return try {
            val j = JSONObject(res.body)
            val group = j.optString("active_group_name", "").trim()
            val resolved = j.optString("active_resolved_node_name", "").trim()
            val node = j.optString("active_node_name", "").trim()
            when {
                group.isNotEmpty() && resolved.isNotEmpty() && resolved != group -> "$group → $resolved"
                group.isNotEmpty() -> group
                node.isNotEmpty() -> node
                else -> ""
            }
        } catch (_: Throwable) {
            ""
        }
    }

    private fun updateTile(isActive: Boolean, subtitle: String = "") {
        val tile = qsTile ?: return
        tile.state = if (isActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "PrismRay"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (isActive) {
                subtitle.trim().ifEmpty { "Active" }
            } else {
                "Disconnected"
            }
        }
        tile.updateTile()
    }
}
