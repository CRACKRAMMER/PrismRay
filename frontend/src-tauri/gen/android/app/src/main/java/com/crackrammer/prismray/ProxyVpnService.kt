// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.Process
import android.service.quicksettings.TileService
import android.system.Os
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class ProxyVpnService : VpnService() {
    companion object {
        private const val TAG = "PrismRayVPN"
        const val ACTION_START = "com.crackrammer.prismray.action.START_VPN"
        const val ACTION_STOP = "com.crackrammer.prismray.action.STOP_VPN"
        const val EXTRA_CONFIG_JSON = "config_json"

        private const val CHANNEL_ID = "prismray_vpn"
        private const val NOTIFICATION_ID = 21780

        @Volatile
        var isVpnRunning: Boolean = false
            private set

        @Volatile
        var lastError: String? = null
            private set

        @Volatile
        var activeTargetLabel: String = ""
            private set

        @Volatile
        var stateListener: ((running: Boolean, error: String?) -> Unit)? = null
    }

    private val running = AtomicBoolean(false)
    private val stopping = AtomicBoolean(false)
    private val sessionSeq = AtomicLong(0L)
    private val screenWakeMonitor = Object()
    private val uidPackageCache = ConcurrentHashMap<Int, String>()

    @Volatile
    private var screenReceiverRegistered = false

    private val screenOnReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == Intent.ACTION_SCREEN_ON) {
                synchronized(screenWakeMonitor) {
                    screenWakeMonitor.notifyAll()
                }
            }
        }
    }

    @Volatile
    private var boundProtectSocket: LocalSocket? = null

    @Volatile
    private var protectServerSocket: LocalServerSocket? = null

    @Volatile
    private var boundOwnerSocket: LocalSocket? = null

    @Volatile
    private var ownerServerSocket: LocalServerSocket? = null

    @Volatile
    private var vpnInterface: ParcelFileDescriptor? = null

    private var protectFile: File? = null
    private var ownerFile: File? = null
    private var protectThread: Thread? = null
    private var ownerThread: Thread? = null
    private var statsThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpnSession(notifyBackend = true)
                return START_NOT_STICKY
            }
            else -> {
                val configJson = intent?.getStringExtra(EXTRA_CONFIG_JSON)
                stopping.set(false)
                lastError = null
                startForegroundWithNotification("PrismRay", "Connecting...")
                try {
                    VpnWidgetProvider.updateAllWidgets(this, running = false, connecting = true)
                } catch (_: Throwable) {
                }
                Thread({
                    try {
                        startVpnSession(configJson)
                    } catch (err: Throwable) {
                        val msg = "Android VPN 启动异常: ${err.message ?: err.javaClass.simpleName}"
                        Log.e(TAG, msg, err)
                        failVpnStart(msg, notifyBackend = false)
                    }
                }, "prismray-vpn-start").start()
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        stopVpnSession(notifyBackend = true)
        super.onRevoke()
    }

    override fun onDestroy() {
        unregisterScreenReceiver()
        stopVpnSession(notifyBackend = false)
        super.onDestroy()
    }

    private fun registerScreenReceiver() {
        if (screenReceiverRegistered) return
        try {
            val filter = IntentFilter(Intent.ACTION_SCREEN_ON)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(screenOnReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("DEPRECATION")
                registerReceiver(screenOnReceiver, filter)
            }
            screenReceiverRegistered = true
        } catch (_: Throwable) {
        }
    }

    private fun unregisterScreenReceiver() {
        if (!screenReceiverRegistered) return
        screenReceiverRegistered = false
        try {
            unregisterReceiver(screenOnReceiver)
        } catch (_: Throwable) {
        }
    }

    private fun isScreenInteractive(): Boolean {
        return try {
            val pm = getSystemService(PowerManager::class.java)
            pm?.isInteractive ?: true
        } catch (_: Throwable) {
            true
        }
    }

    private fun notificationTitle(label: String): String {
        val trimmed = label.trim()
        return if (trimmed.isNotEmpty()) "PrismRay · $trimmed" else "PrismRay VPN"
    }

    private fun startOwnerServer(socketFile: File) {
        socketFile.parentFile?.mkdirs()
        if (socketFile.exists()) {
            socketFile.delete()
        }
        val bound = LocalSocket(LocalSocket.SOCKET_STREAM)
        bound.bind(LocalSocketAddress(socketFile.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
        val server = LocalServerSocket(bound.fileDescriptor)
        ownerFile = socketFile
        boundOwnerSocket = bound
        ownerServerSocket = server

        ownerThread = Thread({
            val cm = getSystemService(ConnectivityManager::class.java)
            while (running.get()) {
                val client = try {
                    server.accept()
                } catch (_: Throwable) {
                    if (!running.get()) break
                    continue
                } ?: continue
                try {
                    client.soTimeout = 1000
                    val reader = BufferedReader(InputStreamReader(client.inputStream))
                    val req = reader.readLine()?.trim().orEmpty()
                    val pkg = resolveConnectionOwnerPackage(cm, req)
                    client.outputStream.write("$pkg\n".toByteArray(Charsets.UTF_8))
                    client.outputStream.flush()
                } catch (_: Throwable) {
                } finally {
                    try {
                        client.close()
                    } catch (_: Throwable) {
                    }
                }
            }
        }, "prismray-owner").apply {
            isDaemon = true
            start()
        }
    }

    private fun resolveConnectionOwnerPackage(cm: ConnectivityManager?, req: String): String {
        if (cm == null || req.isEmpty() || Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return ""
        }
        val parts = req.split(',')
        if (parts.size != 5) return ""
        return try {
            val proto = parts[0].toInt()
            val srcAddr = InetSocketAddress(InetAddress.getByName(parts[1]), parts[2].toInt())
            val dstAddr = InetSocketAddress(InetAddress.getByName(parts[3]), parts[4].toInt())
            val uid = cm.getConnectionOwnerUid(proto, srcAddr, dstAddr)
            if (uid == Process.INVALID_UID || uid <= 0) {
                ""
            } else {
                uidPackageCache.computeIfAbsent(uid) { u ->
                    try {
                        packageManager.getPackagesForUid(u)?.firstOrNull().orEmpty()
                    } catch (_: Throwable) {
                        ""
                    }
                }
            }
        } catch (_: Throwable) {
            ""
        }
    }

    private fun ensureNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            val ch = NotificationChannel(
                CHANNEL_ID,
                "PrismRay VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Active VPN proxy session & live throughput"
                setShowBadge(false)
            }
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(title: String, text: String): Notification {
        ensureNotificationChannel()
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPending = PendingIntent.getActivity(
            this,
            1,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, ProxyVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            this,
            2,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val disconnectAction = Notification.Action.Builder(
            android.R.drawable.ic_menu_close_clear_cancel,
            "Disconnect",
            stopPending
        ).build()

        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_prismray_tile)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openPending)
            .addAction(disconnectAction)
            .build()
    }

    private fun startForegroundWithNotification(title: String, text: String) {
        val notif = buildNotification(title, text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notif,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notif)
        }
    }

    private fun updateNotification(title: String, text: String) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.notify(NOTIFICATION_ID, buildNotification(title, text))
    }

    private fun startProtectServer(socketFile: File) {
        socketFile.parentFile?.mkdirs()
        if (socketFile.exists()) {
            socketFile.delete()
        }
        val bound = LocalSocket(LocalSocket.SOCKET_STREAM)
        bound.bind(LocalSocketAddress(socketFile.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
        val server = LocalServerSocket(bound.fileDescriptor)
        protectFile = socketFile
        boundProtectSocket = bound
        protectServerSocket = server

        protectThread = Thread({
            while (running.get()) {
                val client = try {
                    server.accept()
                } catch (_: Throwable) {
                    if (!running.get()) break
                    continue
                } ?: continue
                try {
                    client.soTimeout = 2000
                    val b = client.inputStream.read()
                    if (b < 0) continue
                    val fds = client.ancillaryFileDescriptors
                    var ok = !fds.isNullOrEmpty()
                    if (fds != null) {
                        for (fd in fds) {
                            try {
                                ParcelFileDescriptor.dup(fd).use { pfd ->
                                    if (!protect(pfd.fd)) {
                                        ok = false
                                    }
                                }
                            } catch (_: Throwable) {
                                ok = false
                            } finally {
                                try {
                                    Os.close(fd)
                                } catch (_: Throwable) {
                                }
                            }
                        }
                    }
                    client.outputStream.write(byteArrayOf(if (ok) 0 else 1))
                    client.outputStream.flush()
                } catch (_: Throwable) {
                    // Ignore transient client errors on protect socket.
                } finally {
                    try {
                        client.close()
                    } catch (_: Throwable) {
                    }
                }
            }
        }, "prismray-protect").apply {
            isDaemon = true
            start()
        }
    }

    private fun failVpnStart(message: String, notifyBackend: Boolean) {
        lastError = message
        RuntimeIpc.reportVpnError(this, message)
        stateListener?.invoke(false, message)
        stopVpnSession(notifyBackend = notifyBackend)
    }

    private fun sendTunFdToBackend(tunSocketPath: String, pfd: ParcelFileDescriptor): Pair<Boolean, String> {
        if (tunSocketPath.isBlank()) return Pair(false, "tun_socket_path 为空")
        return try {
            LocalSocket(LocalSocket.SOCKET_STREAM).use { client ->
                client.connect(LocalSocketAddress(tunSocketPath, LocalSocketAddress.Namespace.FILESYSTEM))
                client.soTimeout = 5000
                client.setFileDescriptorsForSend(arrayOf(pfd.fileDescriptor))
                client.outputStream.write(byteArrayOf(1))
                client.outputStream.flush()
                val ack = client.inputStream.read()
                Log.i(TAG, "Sent TUN fd to backend via $tunSocketPath (ack=$ack)")
                if (ack == 0) Pair(true, "") else Pair(false, "TUN 转发器返回错误码 ack=$ack")
            }
        } catch (err: Throwable) {
            val detail = err.message ?: err.javaClass.simpleName
            Log.e(TAG, "Failed to hand off TUN fd to $tunSocketPath: $detail", err)
            Pair(false, "传递 TUN FD 失败 ($tunSocketPath): $detail")
        }
    }

    private fun startVpnSession(configJsonRaw: String?) {
        val mySeq = sessionSeq.incrementAndGet()
        stopping.set(false)
        closeSocketsAndInterface()
        running.set(true)

        // Ensure Go backend is online (supports BOOT_COMPLETED, Always-on VPN, and cold-start widget toggles).
        if (!AndroidBackendLauncher.ensureBackendRunning(this, timeoutMs = 8000L)) {
            val msg = "本地后台服务未能就绪 (libprismray.so 启动超时)"
            Log.e(TAG, msg)
            failVpnStart(msg, notifyBackend = false)
            return
        }

        // Push current active network DNS before establishing VPN so backend DNS uses live ISP/Wi-Fi resolvers.
        RuntimeIpc.syncSystemDns(this)

        val protectSockFile = File(RuntimeIpc.dataDirectory(this), "protect.sock")
        try {
            startProtectServer(protectSockFile)
        } catch (err: Throwable) {
            val msg = "Protect socket 启动失败: ${err.message ?: err.javaClass.simpleName}"
            Log.e(TAG, msg, err)
            failVpnStart(msg, notifyBackend = false)
            return
        }

        val ownerSockFile = File(RuntimeIpc.dataDirectory(this), "owner.sock")
        try {
            startOwnerServer(ownerSockFile)
        } catch (err: Throwable) {
            Log.w(TAG, "Owner socket 启动失败 (自定义应用分流将不可用): ${err.message ?: err.javaClass.simpleName}")
        }

        val inputJson = try {
            if (!configJsonRaw.isNullOrBlank()) JSONObject(configJsonRaw) else JSONObject()
        } catch (_: Throwable) {
            JSONObject()
        }

        // Preserve saved per-app policy when launched from Quick Settings Tile without UI payload.
        if (!inputJson.has("per_app_mode") && !inputJson.has("per_app_packages")) {
            val statusRes = RuntimeIpc.request(this, "GET", "/api/vpn/android/status")
            if (statusRes != null && statusRes.statusCode in 200..299) {
                try {
                    val saved = JSONObject(statusRes.body)
                    if (saved.has("per_app_mode")) {
                        inputJson.put("per_app_mode", saved.optString("per_app_mode", "all"))
                    }
                    if (saved.has("per_app_packages")) {
                        inputJson.put("per_app_packages", saved.optJSONArray("per_app_packages") ?: JSONArray())
                    }
                    if (!inputJson.has("active_node_id") && saved.has("active_node_id")) {
                        inputJson.put("active_node_id", saved.optString("active_node_id", ""))
                    }
                    if (!inputJson.has("active_group_id") && saved.has("active_group_id")) {
                        inputJson.put("active_group_id", saved.optString("active_group_id", ""))
                    }
                } catch (_: Throwable) {
                }
            }
        }

        val startPayload = JSONObject().apply {
            put("protect_path", protectSockFile.absolutePath)
            if (ownerServerSocket != null) {
                put("owner_path", ownerSockFile.absolutePath)
            }
            if (inputJson.has("per_app_mode")) {
                put("per_app_mode", inputJson.optString("per_app_mode", "all"))
            }
            if (inputJson.has("per_app_packages")) {
                put("per_app_packages", inputJson.optJSONArray("per_app_packages") ?: JSONArray())
            }
            if (inputJson.has("active_node_id")) {
                put("active_node_id", inputJson.optString("active_node_id", ""))
            }
            if (inputJson.has("active_group_id")) {
                put("active_group_id", inputJson.optString("active_group_id", ""))
            }
        }

        if (RuntimeIpc.readEndpoint(this) == null) {
            val msg = "本地后台 IPC 尚未就绪 (runtime-ipc.json 未找到)"
            Log.e(TAG, msg)
            failVpnStart(msg, notifyBackend = false)
            return
        }

        val res = RuntimeIpc.request(this, "POST", "/api/vpn/android/start", startPayload.toString())
        if (res == null || res.statusCode !in 200..299) {
            val errDetail = try {
                val j = JSONObject(res?.body ?: "")
                j.optString("error", "").ifBlank { res?.body?.trim().orEmpty() }
            } catch (_: Throwable) {
                res?.body?.trim().orEmpty()
            }
            val msg = if (errDetail.isNotEmpty()) {
                "内核启动失败 (${res?.statusCode ?: 0}): $errDetail"
            } else {
                "本地后台 /api/vpn/android/start 请求失败 (HTTP ${res?.statusCode ?: 0})"
            }
            Log.e(TAG, msg)
            failVpnStart(msg, notifyBackend = false)
            return
        }

        var tunSocketPath = ""
        var perAppMode = inputJson.optString("per_app_mode", "all")
        var bypassLan = inputJson.optBoolean("bypass_lan", true)
        var allowLanBroadcast = inputJson.optBoolean("allow_lan_broadcast", false)
        val packages = mutableListOf<String>()
        try {
            val started = JSONObject(res.body)
            tunSocketPath = started.optString("tun_socket_path", "").trim()
            val returnedMode = started.optString("per_app_mode", "").trim().lowercase()
            if (returnedMode.isNotEmpty()) perAppMode = returnedMode
            if (started.has("bypass_lan")) {
                bypassLan = started.optBoolean("bypass_lan", bypassLan)
            }
            if (started.has("allow_lan_broadcast")) {
                allowLanBroadcast = started.optBoolean("allow_lan_broadcast", allowLanBroadcast)
            }
            val pkgArray = started.optJSONArray("per_app_packages") ?: inputJson.optJSONArray("per_app_packages")
            if (pkgArray != null) {
                for (i in 0 until pkgArray.length()) {
                    val pkg = pkgArray.optString(i, "").trim()
                    if (pkg.isNotEmpty()) packages.add(pkg)
                }
            }
        } catch (_: Throwable) {
        }

        val effectiveLanBroadcast = bypassLan && allowLanBroadcast

        val builder = Builder()
            .setSession("PrismRay")
            .setMtu(1500)
            .addAddress("172.19.0.1", 30)
            .addAddress("fdfe:dcba:9876::1", 126)
            .addDnsServer("172.19.0.2")
            .setBlocking(false)
        applyVpnRoutes(builder, effectiveLanBroadcast)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        when (perAppMode) {
            "whitelist" -> {
                if (packages.isNotEmpty()) {
                    for (pkg in packages) {
                        if (pkg == packageName) continue
                        try {
                            builder.addAllowedApplication(pkg)
                        } catch (_: PackageManager.NameNotFoundException) {
                        }
                    }
                } else {
                    try {
                        builder.addDisallowedApplication(packageName)
                    } catch (_: PackageManager.NameNotFoundException) {
                    }
                }
            }
            "blacklist" -> {
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (_: PackageManager.NameNotFoundException) {
                }
                for (pkg in packages) {
                    if (pkg == packageName) continue
                    try {
                        builder.addDisallowedApplication(pkg)
                    } catch (_: PackageManager.NameNotFoundException) {
                    }
                }
            }
            else -> {
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (_: PackageManager.NameNotFoundException) {
                }
            }
        }

        val established = try {
            builder.establish()
        } catch (err: Throwable) {
            val msg = "VpnService.establish 异常: ${err.message ?: err.javaClass.simpleName}"
            Log.e(TAG, msg, err)
            failVpnStart(msg, notifyBackend = true)
            return
        }
        if (established == null) {
            failVpnStart("Android 系统拒绝建立 VPN 隧道 (可能未授予 VPN 权限或被其他 VPN 占用)", notifyBackend = true)
            return
        }

        vpnInterface = established
        val (tunStarted, tunErr) = sendTunFdToBackend(tunSocketPath, established)
        if (!tunStarted) {
            val msg = "TUN 转发引擎挂载失败: $tunErr"
            Log.e(TAG, msg)
            failVpnStart(msg, notifyBackend = true)
            return
        }

        isVpnRunning = true
        lastError = null
        val initialNodeName = queryActiveTargetLabel()
        activeTargetLabel = initialNodeName
        registerScreenReceiver()
        requestTileRefresh()
        stateListener?.invoke(true, null)
        VpnWidgetProvider.updateAllWidgets(
            this,
            running = true,
            connecting = false,
            nodeName = initialNodeName,
            speedText = "↑ 0 B/s · ↓ 0 B/s",
        )
        updateNotification(notificationTitle(initialNodeName), "↑ 0 B/s · ↓ 0 B/s")

        statsThread = Thread({
            var lastUp = 0L
            var lastDown = 0L
            var lastTickMs = System.currentTimeMillis()
            var activeLabel = initialNodeName
            var wasScreenOff = false
            while (running.get() && sessionSeq.get() == mySeq) {
                val interactive = isScreenInteractive()
                val sleepMs = if (interactive) 2000L else 15000L
                try {
                    synchronized(screenWakeMonitor) {
                        if (running.get() && sessionSeq.get() == mySeq) {
                            screenWakeMonitor.wait(sleepMs)
                        }
                    }
                } catch (_: InterruptedException) {
                    break
                }
                if (!running.get() || sessionSeq.get() != mySeq) break

                val nowInteractive = isScreenInteractive()
                val statusRes = RuntimeIpc.request(this, "GET", "/api/process/status")
                if (statusRes != null && statusRes.statusCode in 200..299) {
                    try {
                        val statusJson = JSONObject(statusRes.body)
                        if (!statusJson.optBoolean("running", false)) {
                            stopVpnSession(notifyBackend = false)
                            break
                        }
                        val label = extractTargetLabel(statusJson)
                        if (label.isNotBlank() && label != activeLabel) {
                            activeLabel = label
                            activeTargetLabel = label
                            requestTileRefresh()
                        }
                    } catch (_: Throwable) {
                    }
                }

                // Battery optimization: while screen is off, skip /api/connections polling,
                // notification redraws, and widget updates until ACTION_SCREEN_ON wakes us.
                if (!nowInteractive) {
                    wasScreenOff = true
                    continue
                }
                if (wasScreenOff) {
                    // Reset rate baseline on wake so cumulative screen-off bytes don't spike throughput.
                    wasScreenOff = false
                    lastUp = 0L
                    lastDown = 0L
                    lastTickMs = System.currentTimeMillis()
                }

                val connRes = RuntimeIpc.request(this, "GET", "/api/connections")
                if (connRes != null && connRes.statusCode in 200..299) {
                    try {
                        val snap = JSONObject(connRes.body)
                        val upTotal = snap.optLong("uploadTotal", 0L)
                        val downTotal = snap.optLong("downloadTotal", 0L)
                        val nowMs = System.currentTimeMillis()
                        val elapsedSec = ((nowMs - lastTickMs).coerceAtLeast(500L)) / 1000.0
                        val upRate = if (lastUp > 0L && upTotal >= lastUp) ((upTotal - lastUp) / elapsedSec).toLong() else 0L
                        val downRate = if (lastDown > 0L && downTotal >= lastDown) ((downTotal - lastDown) / elapsedSec).toLong() else 0L
                        lastUp = upTotal
                        lastDown = downTotal
                        lastTickMs = nowMs
                        val speedLine = "↑ ${formatRate(upRate)} · ↓ ${formatRate(downRate)}"
                        updateNotification(
                            notificationTitle(activeLabel),
                            speedLine
                        )
                        VpnWidgetProvider.updateAllWidgets(
                            this,
                            running = true,
                            connecting = false,
                            nodeName = activeLabel,
                            speedText = speedLine,
                            throttleStats = true,
                        )
                    } catch (_: Throwable) {
                    }
                }
            }
        }, "prismray-vpn-stats").apply {
            isDaemon = true
            start()
        }
    }

    private fun closeSocketsAndInterface() {
        running.set(false)
        synchronized(screenWakeMonitor) {
            screenWakeMonitor.notifyAll()
        }
        try {
            vpnInterface?.close()
        } catch (_: Throwable) {
        }
        vpnInterface = null

        try {
            protectServerSocket?.close()
        } catch (_: Throwable) {
        }
        protectServerSocket = null

        try {
            boundProtectSocket?.close()
        } catch (_: Throwable) {
        }
        boundProtectSocket = null

        try {
            protectFile?.delete()
        } catch (_: Throwable) {
        }
        protectFile = null

        try {
            ownerServerSocket?.close()
        } catch (_: Throwable) {
        }
        ownerServerSocket = null

        try {
            boundOwnerSocket?.close()
        } catch (_: Throwable) {
        }
        boundOwnerSocket = null

        try {
            ownerFile?.delete()
        } catch (_: Throwable) {
        }
        ownerFile = null
        uidPackageCache.clear()
    }

    private fun stopVpnSession(notifyBackend: Boolean) {
        if (!stopping.compareAndSet(false, true)) return
        sessionSeq.incrementAndGet()
        isVpnRunning = false
        activeTargetLabel = ""
        unregisterScreenReceiver()
        closeSocketsAndInterface()
        statsThread?.interrupt()
        if (notifyBackend) {
            Thread({
                RuntimeIpc.request(this, "POST", "/api/vpn/android/stop", "{}")
                RuntimeIpc.request(this, "POST", "/api/process/stop", "{}")
            }, "prismray-vpn-stop").start()
        }
        requestTileRefresh()
        VpnWidgetProvider.updateAllWidgets(this, running = false, connecting = false)
        stateListener?.invoke(false, lastError)
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Throwable) {
        }
        stopSelf()
    }

    private fun queryActiveTargetLabel(): String {
        val statusRes = RuntimeIpc.request(this, "GET", "/api/process/status") ?: return ""
        if (statusRes.statusCode !in 200..299) return ""
        return try {
            extractTargetLabel(JSONObject(statusRes.body))
        } catch (_: Throwable) {
            ""
        }
    }

    private fun extractTargetLabel(statusJson: JSONObject): String {
        val group = statusJson.optString("active_group_name", "").trim()
        val resolved = statusJson.optString("active_resolved_node_name", "").trim()
        val node = statusJson.optString("active_node_name", "").trim()
        return when {
            group.isNotEmpty() && resolved.isNotEmpty() && resolved != group -> "$group → $resolved"
            group.isNotEmpty() -> group
            node.isNotEmpty() -> node
            else -> ""
        }
    }

    private fun requestTileRefresh() {
        try {
            TileService.requestListeningState(
                this,
                ComponentName(this, ProxyTileService::class.java)
            )
        } catch (_: Throwable) {
        }
    }

    private fun formatRate(bytesPerSec: Long): String {
        val v = bytesPerSec.coerceAtLeast(0L).toDouble()
        return when {
            v >= 1024.0 * 1024.0 -> String.format("%.1f MB/s", v / (1024.0 * 1024.0))
            v >= 1024.0 -> String.format("%.1f KB/s", v / 1024.0)
            else -> "${bytesPerSec.coerceAtLeast(0L)} B/s"
        }
    }

    private fun applyVpnRoutes(builder: Builder, allowLanBroadcast: Boolean) {
        if (!allowLanBroadcast) {
            builder.addRoute("0.0.0.0", 0)
            // Always capture IPv6 in tun0 so carrier 5G/Wi-Fi IPv6 never leaks around VPN;
            // sing-box routes or rejects 2000::/3 cleanly based on user's IPv6 preference.
            builder.addRoute("::", 0)
            return
        }
        // Exclude non-global / LAN / multicast / broadcast ranges so local discovery
        // (KDE Connect UDP 1716 broadcast, mDNS, SSDP, LAN peers) bypasses tun0
        // across Android 8–16 without relying on API 33+ excludeRoute().
        val excluded = listOf(
            ipv4Range("0.0.0.0", 8),      // Current network
            ipv4Range("10.0.0.0", 8),     // RFC 1918 LAN
            ipv4Range("100.64.0.0", 10),  // RFC 6598 CGNAT / Tailscale
            ipv4Range("127.0.0.0", 8),    // Loopback
            ipv4Range("169.254.0.0", 16), // Link-local
            ipv4Range("172.16.0.0", 12),  // RFC 1918 LAN (TUN 172.19.0.0/30 re-added below)
            ipv4Range("192.168.0.0", 16), // RFC 1918 LAN
            ipv4Range("224.0.0.0", 4),    // IPv4 Multicast (mDNS, SSDP, DLNA)
            ipv4Range("240.0.0.0", 4),    // Reserved + Limited Broadcast (255.255.255.255)
        ).sortedBy { it.first }

        var cursor = 0L
        val maxIp = 0xFFFFFFFFL
        var routeCount = 0
        for ((start, end) in excluded) {
            if (cursor < start) {
                routeCount += addRangeAsCidrs(builder, cursor, start - 1L)
            }
            if (end >= cursor) {
                cursor = end + 1L
            }
        }
        if (cursor <= maxIp) {
            routeCount += addRangeAsCidrs(builder, cursor, maxIp)
        }
        // Always route TUN subnet (including DNS server 172.19.0.2) back into tun0.
        builder.addRoute("172.19.0.0", 30)
        routeCount += 1
        // Capture global unicast IPv6 (2000::/3) while keeping fe80::/10 link-local,
        // fc00::/7 ULA, and ff00::/8 multicast on local LAN.
        builder.addRoute("2000::", 3)
        Log.i(TAG, "Applied LAN+broadcast bypass routes ($routeCount IPv4 CIDR + 2000::/3 IPv6 entries)")
    }

    private fun ipv4Range(ip: String, prefix: Int): Pair<Long, Long> {
        val parts = ip.split(".")
        var addr = 0L
        for (p in parts) {
            addr = (addr shl 8) or (p.toLong() and 0xFFL)
        }
        val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        val start = addr and mask
        val size = 1L shl (32 - prefix)
        return Pair(start, start + size - 1L)
    }

    private fun addRangeAsCidrs(builder: Builder, startIp: Long, endIp: Long): Int {
        var cur = startIp
        var count = 0
        while (cur <= endIp) {
            var maxSize = if (cur == 0L) (1L shl 32) else (cur and -cur)
            val remaining = endIp - cur + 1L
            while (maxSize > remaining) {
                maxSize = maxSize ushr 1
            }
            val hostBits = java.lang.Long.numberOfTrailingZeros(maxSize)
            val prefix = 32 - hostBits
            val ipStr = "${(cur ushr 24) and 0xFF}.${(cur ushr 16) and 0xFF}.${(cur ushr 8) and 0xFF}.${cur and 0xFF}"
            builder.addRoute(ipStr, prefix)
            cur += maxSize
            count += 1
        }
        return count
    }
}
