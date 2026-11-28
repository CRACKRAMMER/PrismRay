// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

class TailscaleTileService : TileService() {
    companion object {
        private const val TAG = "PrismRayTsTile"
        private const val LAUNCH_REQ_CODE = 21782
        private val toggling = AtomicBoolean(false)
    }

    override fun onStartListening() {
        super.onStartListening()
        refreshTileState()
    }

    override fun onClick() {
        super.onClick()
        if (!toggling.compareAndSet(false, true)) return

        val prevState = qsTile?.state ?: Tile.STATE_INACTIVE
        updateTile(state = prevState, subtitle = "Updating...")

        Thread({
            try {
                handleToggleClick()
            } catch (err: Throwable) {
                Log.e(TAG, "Tailscale Quick Settings toggle failed: ${err.message}", err)
                refreshTileStateSync()
            } finally {
                toggling.set(false)
            }
        }, "prismray-ts-tile-click").start()
    }

    private fun handleToggleClick() {
        if (!AndroidBackendLauncher.ensureBackendRunning(this, timeoutMs = 6000L)) {
            openMainApp(autoStartVpn = false)
            updateTile(state = Tile.STATE_INACTIVE, subtitle = "Off")
            return
        }

        val getRes = RuntimeIpc.request(this, "GET", "/api/tailscale")
        if (getRes == null || getRes.statusCode == 401 || getRes.statusCode == 423) {
            // Vault is locked or backend requires interactive unlock.
            openMainApp(autoStartVpn = false)
            updateTile(state = Tile.STATE_INACTIVE, subtitle = if (getRes?.statusCode == 423) "Locked" else "Off")
            return
        }
        if (getRes.statusCode !in 200..299) {
            openMainApp(autoStartVpn = false)
            updateTile(state = Tile.STATE_INACTIVE, subtitle = "Error")
            return
        }

        val root = try {
            JSONObject(getRes.body)
        } catch (_: Throwable) {
            openMainApp(autoStartVpn = false)
            updateTile(state = Tile.STATE_INACTIVE, subtitle = "Error")
            return
        }

        val cfg = root.optJSONObject("config") ?: JSONObject()
        val statusObj = root.optJSONObject("status")
        val liveState = statusObj?.optString("state", "")?.trim()?.lowercase().orEmpty()
        val tsEnabled = cfg.optBoolean("enabled", false)
        val hasAuthKey = cfg.optBoolean("has_auth_key", false)
        val stateInit = root.optBoolean("state_initialized", false)
        val vpnActive = queryVpnActive()

        if (liveState == "needs_auth") {
            // Do not disable Tailscale when waiting for interactive login; open app to complete auth.
            openMainApp(autoStartVpn = false)
            updateTile(state = Tile.STATE_INACTIVE, subtitle = "Needs Auth")
            return
        }

        if (tsEnabled && vpnActive) {
            // Turn Tailscale OFF while keeping the main proxy VPN running.
            val payload = sanitizeTailscalePayload(cfg, enabled = false)
            val putRes = RuntimeIpc.request(this, "PUT", "/api/tailscale", payload.toString())
            if (putRes != null && putRes.statusCode in 200..299) {
                if (queryAllowLanBroadcast()) {
                    // Refresh Android TUN routes so 100.64.0.0/10 is excluded again when LAN broadcast bypass is on.
                    val refreshIntent = Intent(this, ProxyVpnService::class.java).apply {
                        action = ProxyVpnService.ACTION_START
                    }
                    safeStartVpnForeground(refreshIntent, autoStartVpn = false)
                }
                updateTile(state = Tile.STATE_INACTIVE, subtitle = "Off")
            } else {
                Log.w(TAG, "Disable Tailscale failed: HTTP ${putRes?.statusCode ?: 0}")
                refreshTileStateSync()
            }
            return
        }

        // Turning Tailscale ON (or starting VPN when Tailscale is already enabled in Standby).
        if (!hasAuthKey && !stateInit) {
            // User needs to enter a Tailscale Auth Key first inside the app.
            openMainApp(autoStartVpn = false)
            updateTile(state = Tile.STATE_INACTIVE, subtitle = "Setup required")
            return
        }

        if (!tsEnabled) {
            val payload = sanitizeTailscalePayload(cfg, enabled = true)
            val putRes = RuntimeIpc.request(this, "PUT", "/api/tailscale", payload.toString())
            if (putRes == null || putRes.statusCode !in 200..299) {
                Log.w(TAG, "Enable Tailscale failed: HTTP ${putRes?.statusCode ?: 0} ${putRes?.body.orEmpty()}")
                updateTile(state = Tile.STATE_INACTIVE, subtitle = "Start failed")
                return
            }
        }

        if (vpnActive) {
            // Backend PUT /api/tailscale already hot-reloaded sing-box; refresh TUN routes if LAN broadcast bypass is active.
            if (queryAllowLanBroadcast()) {
                val refreshIntent = Intent(this, ProxyVpnService::class.java).apply {
                    action = ProxyVpnService.ACTION_START
                }
                safeStartVpnForeground(refreshIntent, autoStartVpn = false)
            }
            updateTile(state = Tile.STATE_ACTIVE, subtitle = "Connecting...")
            scheduleDelayedRefresh()
        } else {
            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent == null) {
                val startIntent = Intent(this, ProxyVpnService::class.java).apply {
                    action = ProxyVpnService.ACTION_START
                }
                if (safeStartVpnForeground(startIntent, autoStartVpn = true)) {
                    updateTile(state = Tile.STATE_ACTIVE, subtitle = "Connecting...")
                    requestProxyTileRefresh()
                    scheduleDelayedRefresh()
                } else {
                    updateTile(state = Tile.STATE_INACTIVE, subtitle = "Standby")
                }
            } else {
                openMainApp(autoStartVpn = true)
                updateTile(state = Tile.STATE_INACTIVE, subtitle = "Standby")
            }
        }
    }

    private fun scheduleDelayedRefresh() {
        Thread({
            try {
                Thread.sleep(3500L)
                refreshTileStateSync()
            } catch (_: InterruptedException) {
            }
        }, "prismray-ts-tile-recheck").apply {
            isDaemon = true
            start()
        }
    }

    private fun sanitizeTailscalePayload(cfg: JSONObject, enabled: Boolean): JSONObject {
        val out = JSONObject(cfg.toString())
        out.put("enabled", enabled)
        // Preserve encrypted stored auth key unless explicitly replaced/cleared in UI.
        out.remove("auth_key")
        out.remove("has_auth_key")
        out.remove("clear_auth_key")
        return out
    }

    private fun refreshTileState() {
        Thread({
            refreshTileStateSync()
        }, "prismray-ts-tile-state").start()
    }

    private fun refreshTileStateSync() {
        val getRes = RuntimeIpc.request(this, "GET", "/api/tailscale")
        if (getRes == null) {
            updateTile(state = Tile.STATE_INACTIVE, subtitle = "Off")
            return
        }
        if (getRes.statusCode == 423) {
            updateTile(state = Tile.STATE_INACTIVE, subtitle = "Locked")
            return
        }
        if (getRes.statusCode !in 200..299) {
            updateTile(state = Tile.STATE_INACTIVE, subtitle = "Off")
            return
        }

        try {
            val root = JSONObject(getRes.body)
            val cfg = root.optJSONObject("config") ?: JSONObject()
            val status = root.optJSONObject("status")
            val tsEnabled = cfg.optBoolean("enabled", false)
            val hostname = cfg.optString("hostname", "").trim()
            val vpnActive = queryVpnActive()

            if (status != null) {
                val st = status.optString("state", "").trim().lowercase()
                val ipv4 = status.optString("ipv4", "").trim()
                val liveHost = status.optString("hostname", "").trim().ifEmpty { hostname }
                when (st) {
                    "connected" -> {
                        val sub = ipv4.ifEmpty { liveHost.ifEmpty { "Connected" } }
                        updateTile(state = Tile.STATE_ACTIVE, subtitle = sub)
                        return
                    }
                    "connecting" -> {
                        updateTile(state = Tile.STATE_ACTIVE, subtitle = "Connecting...")
                        return
                    }
                    "needs_auth" -> {
                        updateTile(state = Tile.STATE_INACTIVE, subtitle = "Needs Auth")
                        return
                    }
                    "error" -> {
                        updateTile(state = Tile.STATE_INACTIVE, subtitle = "Error")
                        return
                    }
                    "stopped" -> {
                        updateTile(state = Tile.STATE_INACTIVE, subtitle = "Standby")
                        return
                    }
                    "disabled" -> {
                        updateTile(state = Tile.STATE_INACTIVE, subtitle = "Off")
                        return
                    }
                }
            }

            when {
                tsEnabled && vpnActive -> {
                    updateTile(state = Tile.STATE_ACTIVE, subtitle = hostname.ifEmpty { "Active" })
                }
                tsEnabled && !vpnActive -> {
                    updateTile(state = Tile.STATE_INACTIVE, subtitle = "Standby")
                }
                else -> {
                    updateTile(state = Tile.STATE_INACTIVE, subtitle = "Off")
                }
            }
        } catch (_: Throwable) {
            updateTile(state = Tile.STATE_INACTIVE, subtitle = "Off")
        }
    }

    private fun queryVpnActive(): Boolean {
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

    private fun queryAllowLanBroadcast(): Boolean {
        val res = RuntimeIpc.request(this, "GET", "/api/routing") ?: return false
        if (res.statusCode !in 200..299) return false
        return try {
            JSONObject(res.body).optBoolean("allow_lan_broadcast", false)
        } catch (_: Throwable) {
            false
        }
    }

    private fun safeStartVpnForeground(intent: Intent, autoStartVpn: Boolean): Boolean {
        return try {
            startForegroundService(intent)
            true
        } catch (err: Throwable) {
            Log.w(TAG, "ForegroundService start blocked, falling back to MainActivity: ${err.message}", err)
            openMainApp(autoStartVpn = autoStartVpn)
            false
        }
    }

    private fun openMainApp(autoStartVpn: Boolean) {
        val launchIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            if (autoStartVpn) {
                putExtra(MainActivity.EXTRA_AUTO_START_VPN, true)
                putExtra(MainActivity.EXTRA_AUTO_START_NONCE, MainActivity.issueAutoStartNonce())
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pending = PendingIntent.getActivity(
                this,
                LAUNCH_REQ_CODE,
                launchIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            startActivityAndCollapse(pending)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(launchIntent)
        }
    }

    private fun requestProxyTileRefresh() {
        try {
            TileService.requestListeningState(
                this,
                ComponentName(this, ProxyTileService::class.java)
            )
        } catch (_: Throwable) {
        }
    }

    private fun updateTile(state: Int, subtitle: String) {
        val tile = qsTile ?: return
        tile.state = state
        tile.label = "PrismRay Tailscale"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = subtitle.trim().ifEmpty {
                if (state == Tile.STATE_ACTIVE) "Active" else "Off"
            }
        }
        tile.updateTile()
    }
}
