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
import android.net.LinkProperties
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.Process
import android.service.quicksettings.TileService
import android.system.Os
import android.util.Log
import hev.htproxy.TProxyService
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
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
    private val startGeneration = AtomicLong(0L)
    @Volatile
    private var latestStartId: Int = 0
    private val screenWakeMonitor = Object()
    private val uidPackageCache = ConcurrentHashMap<Int, String>()

    // Serialize all VPN start/stop transitions off the Android main thread to prevent ANR and start/stop races.
    private val sessionExecutor: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "prismray-vpn-lifecycle").apply { isDaemon = true }
    }

    // Bounded worker pool for protect.sock / owner.sock requests so one slow client never head-of-line blocks VpnService.protect().
    private val socketWorkerPool: ExecutorService = Executors.newFixedThreadPool(4) { r ->
        Thread(r, "prismray-vpn-sock").apply { isDaemon = true }
    }

    private val cachedOpenPendingIntent: PendingIntent by lazy {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        PendingIntent.getActivity(
            this,
            1,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    private val cachedDisconnectAction: Notification.Action by lazy {
        val stopIntent = Intent(this, ProxyVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            this,
            2,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        Notification.Action.Builder(
            android.R.drawable.ic_menu_close_clear_cancel,
            "Disconnect",
            stopPending
        ).build()
    }

    @Volatile
    private var screenReceiverRegistered = false

    @Volatile
    private var networkCallbackRegistered = false

    private val underlyingNetworkCallback = object : ConnectivityManager.NetworkCallback() {
        private fun triggerSync() {
            if (!running.get()) return
            try {
                socketWorkerPool.execute {
                    RuntimeIpc.syncSystemDns(this@ProxyVpnService)
                }
            } catch (_: RejectedExecutionException) {
            }
        }

        override fun onAvailable(network: Network) = triggerSync()
        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) = triggerSync()
        override fun onLost(network: Network) = triggerSync()
    }

    private val screenOnReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val action = intent?.action ?: return
            if (action == Intent.ACTION_SCREEN_ON || action == Intent.ACTION_SCREEN_OFF) {
                synchronized(screenWakeMonitor) {
                    screenWakeMonitor.notifyAll()
                }
            }
        }
    }

    @Volatile
    private var hevTunnelActive = false

    @Volatile
    private var hevConfigFile: File? = null

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
    @Volatile
    private var statsThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        when (intent?.action) {
            ACTION_STOP -> {
                val stopGen = startGeneration.get()
                scheduleStopVpnSession(notifyBackend = true, expectedGen = stopGen, stopStartId = startId)
                return START_NOT_STICKY
            }
            else -> {
                val configJson = intent?.getStringExtra(EXTRA_CONFIG_JSON)
                val startGen = startGeneration.incrementAndGet()
                stopping.set(false)
                lastError = null
                startForegroundWithNotification("PrismRay", "Connecting...")
                try {
                    VpnWidgetProvider.updateAllWidgets(this, running = false, connecting = true)
                } catch (_: Throwable) {
                }
                try {
                    sessionExecutor.execute {
                        if (startGeneration.get() != startGen) return@execute
                        try {
                            startVpnSession(configJson, startGen)
                        } catch (err: Throwable) {
                            val msg = "Android VPN 启动异常: ${err.message ?: err.javaClass.simpleName}"
                            Log.e(TAG, msg, err)
                            failVpnStart(msg, notifyBackend = false, expectedGen = startGen)
                        }
                    }
                } catch (err: RejectedExecutionException) {
                    Log.w(TAG, "VPN start ignored while service is shutting down", err)
                }
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        scheduleStopVpnSession(notifyBackend = true, expectedGen = startGeneration.get())
        super.onRevoke()
    }

    override fun onDestroy() {
        unregisterScreenReceiver()
        scheduleStopVpnSession(notifyBackend = false, expectedGen = startGeneration.get())
        sessionExecutor.shutdown()
        socketWorkerPool.shutdownNow()
        super.onDestroy()
    }

    private fun scheduleStopVpnSession(
        notifyBackend: Boolean,
        expectedGen: Long = startGeneration.get(),
        stopStartId: Int = 0,
    ) {
        try {
            sessionExecutor.execute {
                stopVpnSession(notifyBackend = notifyBackend, expectedGen = expectedGen, stopStartId = stopStartId)
            }
        } catch (_: RejectedExecutionException) {
            // Executor already shutting down; perform quick in-place teardown.
            stopVpnSession(notifyBackend = notifyBackend, expectedGen = expectedGen, stopStartId = stopStartId)
        }
    }

    private fun registerScreenReceiver() {
        if (screenReceiverRegistered) return
        try {
            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_SCREEN_OFF)
            }
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

    private fun registerUnderlyingNetworkCallback() {
        if (networkCallbackRegistered) return
        try {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(req, underlyingNetworkCallback)
            networkCallbackRegistered = true
        } catch (_: Throwable) {
        }
    }

    private fun unregisterUnderlyingNetworkCallback() {
        if (!networkCallbackRegistered) return
        networkCallbackRegistered = false
        try {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return
            cm.unregisterNetworkCallback(underlyingNetworkCallback)
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
        try {
            Os.chmod(socketFile.absolutePath, 0b110_000_000) // 0600
        } catch (_: Throwable) {
        }
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
                val peerUid = try {
                    client.peerCredentials?.uid ?: -1
                } catch (_: Throwable) {
                    -1
                }
                if (peerUid != Process.myUid()) {
                    try {
                        client.close()
                    } catch (_: Throwable) {
                    }
                    continue
                }
                try {
                    socketWorkerPool.execute {
                        try {
                            client.soTimeout = 30_000
                            val reader = BufferedReader(InputStreamReader(client.inputStream))
                            val out = client.outputStream
                            // Support persistent multiplexed line-by-line queries on a single Unix socket
                            // (while staying backward-compatible with legacy single-shot callers).
                            while (running.get()) {
                                val req = reader.readLine()?.trim() ?: break
                                if (req.isEmpty()) continue
                                val pkg = resolveConnectionOwnerPackage(cm, req)
                                out.write("$pkg\n".toByteArray(Charsets.UTF_8))
                                out.flush()
                            }
                        } catch (_: Throwable) {
                        } finally {
                            try {
                                client.close()
                            } catch (_: Throwable) {
                            }
                        }
                    }
                } catch (_: RejectedExecutionException) {
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

    @Volatile
    private var notificationChannelReady = false

    private fun ensureNotificationChannel() {
        if (notificationChannelReady) return
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
        notificationChannelReady = true
    }

    private fun buildNotification(title: String, text: String, bigText: String? = null): Notification {
        ensureNotificationChannel()
        val builder = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_prismray_tile)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(cachedOpenPendingIntent)
            .addAction(cachedDisconnectAction)
        if (!bigText.isNullOrBlank()) {
            builder.style = Notification.BigTextStyle().bigText(bigText)
        }
        return builder.build()
    }

    private fun startForegroundWithNotification(title: String, text: String, bigText: String? = null) {
        val notif = buildNotification(title, text, bigText)
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

    private fun updateNotification(title: String, text: String, bigText: String? = null) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.notify(NOTIFICATION_ID, buildNotification(title, text, bigText))
    }

    private fun startProtectServer(socketFile: File) {
        socketFile.parentFile?.mkdirs()
        if (socketFile.exists()) {
            socketFile.delete()
        }
        val bound = LocalSocket(LocalSocket.SOCKET_STREAM)
        bound.bind(LocalSocketAddress(socketFile.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
        try {
            Os.chmod(socketFile.absolutePath, 0b110_000_000) // 0600
        } catch (_: Throwable) {
        }
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
                val peerUid = try {
                    client.peerCredentials?.uid ?: -1
                } catch (_: Throwable) {
                    -1
                }
                if (peerUid != Process.myUid()) {
                    try {
                        client.close()
                    } catch (_: Throwable) {
                    }
                    continue
                }
                try {
                    socketWorkerPool.execute {
                        try {
                            client.soTimeout = 2000
                            val b = client.inputStream.read()
                            if (b < 0) return@execute
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
                } catch (_: RejectedExecutionException) {
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

    private fun failVpnStart(message: String, notifyBackend: Boolean, expectedGen: Long = startGeneration.get()) {
        if (startGeneration.get() != expectedGen) return
        lastError = message
        RuntimeIpc.reportVpnError(this, message)
        stateListener?.invoke(false, message)
        stopVpnSession(notifyBackend = notifyBackend, expectedGen = expectedGen)
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

    private fun startVpnSession(configJsonRaw: String?, startGen: Long = startGeneration.get()) {
        if (startGeneration.get() != startGen) return
        val mySeq = sessionSeq.incrementAndGet()
        stopping.set(false)
        closeSocketsAndInterface()
        running.set(true)

        // Ensure Go backend is online (supports BOOT_COMPLETED, Always-on VPN, and cold-start widget toggles).
        if (!AndroidBackendLauncher.ensureBackendRunning(this, timeoutMs = 8000L)) {
            val msg = "本地后台服务未能就绪 (libprismray.so 启动超时)"
            Log.e(TAG, msg)
            failVpnStart(msg, notifyBackend = false, expectedGen = startGen)
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
            failVpnStart(msg, notifyBackend = false, expectedGen = startGen)
            return
        }

        val ownerSockFile = File(RuntimeIpc.dataDirectory(this), "owner.sock")

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
            put("owner_path", ownerSockFile.absolutePath)
            put("hev_available", TProxyService.libraryLoaded)
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
            val msg = getString(R.string.vpn_err_ipc_not_ready)
            Log.e(TAG, msg)
            failVpnStart(msg, notifyBackend = false, expectedGen = startGen)
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
                getString(R.string.vpn_err_core_start, res?.statusCode ?: 0, errDetail)
            } else {
                getString(R.string.vpn_err_start_request, res?.statusCode ?: 0)
            }
            Log.e(TAG, msg)
            failVpnStart(msg, notifyBackend = false, expectedGen = startGen)
            return
        }

        var tunSocketPath = ""
        var tunEngine = "hev"
        var mixedPort = 10808
        var tunMtu = 8500
        var perAppMode = inputJson.optString("per_app_mode", "all")
        var bypassLan = inputJson.optBoolean("bypass_lan", true)
        var allowLanBroadcast = inputJson.optBoolean("allow_lan_broadcast", false)
        var tailscaleEnabled = false
        val tailscaleSubnets = mutableListOf<String>()
        val packages = mutableListOf<String>()
        try {
            val started = JSONObject(res.body)
            tunSocketPath = started.optString("tun_socket_path", "").trim()
            val returnedEngine = started.optString("tun_engine", "").trim().lowercase()
            if (returnedEngine.isNotEmpty()) tunEngine = returnedEngine
            val returnedMixed = started.optInt("mixed_port", 0)
            if (returnedMixed > 0) mixedPort = returnedMixed
            val returnedMtu = started.optInt("mtu", 8500)
            if (returnedMtu in 1280..9000) tunMtu = returnedMtu
            val returnedMode = started.optString("per_app_mode", "").trim().lowercase()
            if (returnedMode.isNotEmpty()) perAppMode = returnedMode
            if (started.has("bypass_lan")) {
                bypassLan = started.optBoolean("bypass_lan", bypassLan)
            }
            if (started.has("allow_lan_broadcast")) {
                allowLanBroadcast = started.optBoolean("allow_lan_broadcast", allowLanBroadcast)
            }
            tailscaleEnabled = started.optBoolean("tailscale_enabled", false)
            val tsSubnetsArr = started.optJSONArray("tailscale_subnets")
            if (tsSubnetsArr != null) {
                for (i in 0 until tsSubnetsArr.length()) {
                    val cidr = tsSubnetsArr.optString(i, "").trim()
                    if (cidr.isNotEmpty()) tailscaleSubnets.add(cidr)
                }
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
            .setMtu(tunMtu)
            .addAddress("172.19.0.1", 30)
            .addAddress("fdfe:dcba:9876::1", 126)
            .addDnsServer("172.19.0.2")
            .setBlocking(false)
        applyVpnRoutes(builder, effectiveLanBroadcast, tailscaleEnabled, tailscaleSubnets)

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

        if (startGeneration.get() != startGen) {
            closeSocketsAndInterface()
            return
        }
        val established = try {
            builder.establish()
        } catch (err: Throwable) {
            val msg = getString(R.string.vpn_err_establish_exception, err.message ?: err.javaClass.simpleName)
            Log.e(TAG, msg, err)
            failVpnStart(msg, notifyBackend = true, expectedGen = startGen)
            return
        }
        if (established == null) {
            failVpnStart(getString(R.string.vpn_err_establish_denied), notifyBackend = true, expectedGen = startGen)
            return
        }
        if (startGeneration.get() != startGen) {
            try {
                established.close()
            } catch (_: Throwable) {
            }
            closeSocketsAndInterface()
            return
        }

        vpnInterface = established
        val useHev = tunEngine == "hev" && TProxyService.libraryLoaded && mixedPort > 0
        if (useHev) {
            val cfgFile = writeHevTunnelConfig(mixedPort, tunMtu)
            hevConfigFile = cfgFile
            val startedOk = try {
                TProxyService.TProxyStartService(cfgFile.absolutePath, established.fd)
            } catch (err: Throwable) {
                Log.e(TAG, "hev-socks5-tunnel JNI start failed: ${err.message}", err)
                false
            }
            if (!startedOk) {
                val msg = getString(R.string.vpn_err_hev_start, mixedPort, tunMtu)
                Log.e(TAG, msg)
                failVpnStart(msg, notifyBackend = true, expectedGen = startGen)
                return
            }
            hevTunnelActive = true
            Log.i(TAG, "Started native C/lwIP hev-socks5-tunnel (mtu=$tunMtu, socks5=127.0.0.1:$mixedPort)")
        } else {
            try {
                startOwnerServer(ownerSockFile)
            } catch (err: Throwable) {
                Log.w(TAG, "Owner socket failed to start (custom per-app routing unavailable): ${err.message ?: err.javaClass.simpleName}")
            }
            val (tunStarted, tunErr) = sendTunFdToBackend(tunSocketPath, established)
            if (!tunStarted) {
                val msg = getString(R.string.vpn_err_tun_attach, tunErr ?: "")
                Log.e(TAG, msg)
                failVpnStart(msg, notifyBackend = true, expectedGen = startGen)
                return
            }
            Log.i(TAG, "Started Go tun2socks fallback engine (mtu=$tunMtu, per-app rules active)")
        }

        isVpnRunning = true
        lastError = null
        val initialNodeName = queryActiveTargetLabel()
        activeTargetLabel = initialNodeName
        registerScreenReceiver()
        registerUnderlyingNetworkCallback()
        requestTileRefresh()
        stateListener?.invoke(true, null)
        val initialTitle = notificationTitle(initialNodeName)
        val (initialSpeed, initialBigSpeed) = formatSplitSpeed(0L, 0L, 0L, 0L)
        VpnWidgetProvider.updateAllWidgets(
            this,
            running = true,
            connecting = false,
            nodeName = initialNodeName,
            speedText = initialSpeed,
        )
        updateNotification(initialTitle, initialSpeed, initialBigSpeed)

        statsThread = Thread({
            var lastUp = 0L
            var lastDown = 0L
            var lastTickMs = System.currentTimeMillis()
            var activeLabel = initialNodeName
            var lastNotifTitle = initialTitle
            var lastNotifText = initialSpeed
            var lastNotifBigText: String? = initialBigSpeed
            var wasScreenOff = false
            while (running.get() && sessionSeq.get() == mySeq && startGeneration.get() == startGen) {
                // Zero-wakeup screen-off sleep: park completely until ACTION_SCREEN_ON or service stop.
                if (!isScreenInteractive()) {
                    wasScreenOff = true
                    try {
                        synchronized(screenWakeMonitor) {
                            if (running.get() && sessionSeq.get() == mySeq && startGeneration.get() == startGen && !isScreenInteractive()) {
                                screenWakeMonitor.wait()
                            }
                        }
                    } catch (_: InterruptedException) {
                        break
                    }
                    continue
                }

                try {
                    synchronized(screenWakeMonitor) {
                        if (running.get() && sessionSeq.get() == mySeq && startGeneration.get() == startGen && isScreenInteractive()) {
                            screenWakeMonitor.wait(3000L)
                        }
                    }
                } catch (_: InterruptedException) {
                    break
                }
                if (!running.get() || sessionSeq.get() != mySeq || startGeneration.get() != startGen) break
                if (!isScreenInteractive()) {
                    wasScreenOff = true
                    continue
                }

                if (wasScreenOff) {
                    // Reset rate baseline on screen wake so cumulative screen-off bytes never spike throughput.
                    wasScreenOff = false
                    lastUp = 0L
                    lastDown = 0L
                    lastTickMs = System.currentTimeMillis()
                }

                var speedLine: String? = null
                var speedBigText: String? = null
                val tel = queryAndroidTelemetry(includeTraffic = true)
                if (tel != null) {
                    if (!tel.optBoolean("running", true)) {
                        scheduleStopVpnSession(notifyBackend = false, expectedGen = startGen)
                        break
                    }
                    val label = tel.optString("active_label", "").trim()
                    if (label.isNotBlank() && label != activeLabel) {
                        activeLabel = label
                        activeTargetLabel = label
                        requestTileRefresh()
                    }
                    if (tel.optBoolean("has_split_rates", false)) {
                        val proxyUp = tel.optLong("proxy_up_rate", 0L).coerceAtLeast(0L)
                        val proxyDown = tel.optLong("proxy_down_rate", 0L).coerceAtLeast(0L)
                        val directUp = tel.optLong("direct_up_rate", 0L).coerceAtLeast(0L)
                        val directDown = tel.optLong("direct_down_rate", 0L).coerceAtLeast(0L)
                        val formatted = formatSplitSpeed(proxyUp, proxyDown, directUp, directDown)
                        speedLine = formatted.first
                        speedBigText = formatted.second
                    }
                }

                // Fallback to total byte counters when split telemetry is unavailable.
                if (speedLine == null) {
                    var upTotal = -1L
                    var downTotal = -1L
                    if (useHev) {
                        try {
                            val stats = TProxyService.TProxyGetStats()
                            if (stats.size >= 4) {
                                upTotal = stats[1]
                                downTotal = stats[3]
                            }
                        } catch (_: Throwable) {
                        }
                    } else if (tel != null) {
                        upTotal = tel.optLong("upload_total", 0L)
                        downTotal = tel.optLong("download_total", 0L)
                    }
                    if (upTotal >= 0L && downTotal >= 0L) {
                        val nowMs = System.currentTimeMillis()
                        val elapsedSec = ((nowMs - lastTickMs).coerceAtLeast(500L)) / 1000.0
                        val upRate = if (lastUp > 0L && upTotal >= lastUp) ((upTotal - lastUp) / elapsedSec).toLong() else 0L
                        val downRate = if (lastDown > 0L && downTotal >= lastDown) ((downTotal - lastDown) / elapsedSec).toLong() else 0L
                        lastUp = upTotal
                        lastDown = downTotal
                        lastTickMs = nowMs
                        speedLine = "↑ ${formatRate(upRate)} · ↓ ${formatRate(downRate)}"
                        speedBigText = null
                    }
                }

                if (speedLine != null) {
                    val nextTitle = notificationTitle(activeLabel)
                    if (nextTitle != lastNotifTitle || speedLine != lastNotifText || speedBigText != lastNotifBigText) {
                        lastNotifTitle = nextTitle
                        lastNotifText = speedLine
                        lastNotifBigText = speedBigText
                        updateNotification(nextTitle, speedLine, speedBigText)
                        VpnWidgetProvider.updateAllWidgets(
                            this,
                            running = true,
                            connecting = false,
                            nodeName = activeLabel,
                            speedText = speedLine,
                            throttleStats = true,
                        )
                    }
                }
            }
        }, "prismray-vpn-stats").apply {
            isDaemon = true
            start()
        }
    }

    private fun writeHevTunnelConfig(mixedPort: Int, mtu: Int): File {
        val cfgFile = File(cacheDir, "hev-socks5-tunnel.yml")
        val yaml = """
            tunnel:
              mtu: $mtu
              ipv4: 172.19.0.1
              ipv6: 'fdfe:dcba:9876::1'
            socks5:
              port: $mixedPort
              address: 127.0.0.1
              udp: 'udp'
            misc:
              tcp-read-write-timeout: 300000
              udp-read-write-timeout: 30000
              log-level: warn
        """.trimIndent()
        cfgFile.writeText(yaml, Charsets.UTF_8)
        return cfgFile
    }

    private fun closeSocketsAndInterface() {
        running.set(false)
        unregisterUnderlyingNetworkCallback()
        synchronized(screenWakeMonitor) {
            screenWakeMonitor.notifyAll()
        }
        // Stop native hev-socks5-tunnel BEFORE closing vpnInterface so C worker thread exits cleanly first.
        if (hevTunnelActive || (TProxyService.libraryLoaded && try { TProxyService.TProxyIsRunning() } catch (_: Throwable) { false })) {
            hevTunnelActive = false
            try {
                TProxyService.TProxyStopService()
            } catch (_: Throwable) {
            }
        }
        try {
            hevConfigFile?.delete()
        } catch (_: Throwable) {
        }
        hevConfigFile = null

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

    private fun stopVpnSession(
        notifyBackend: Boolean,
        expectedGen: Long = startGeneration.get(),
        stopStartId: Int = 0,
    ) {
        if (startGeneration.get() != expectedGen) return
        if (!stopping.compareAndSet(false, true)) return
        val stopSeq = sessionSeq.incrementAndGet()
        isVpnRunning = false
        activeTargetLabel = ""
        unregisterScreenReceiver()
        closeSocketsAndInterface()
        statsThread?.interrupt()
        if (notifyBackend && sessionSeq.get() == stopSeq && startGeneration.get() == expectedGen) {
            // Execute backend VPN stop synchronously on sessionExecutor so a rapid OFF->ON toggle
            // cannot race with a detached stop thread killing the newly started sing-box core.
            try {
                RuntimeIpc.request(this, "POST", "/api/vpn/android/stop", "{}", readTimeoutMs = 3000)
            } catch (_: Throwable) {
            }
        }
        // Only tear down foreground notification/widgets and stopSelf when no newer ACTION_START
        // arrived while this stop transition was executing.
        if (startGeneration.get() != expectedGen) {
            return
        }
        requestTileRefresh()
        VpnWidgetProvider.updateAllWidgets(this, running = false, connecting = false)
        stateListener?.invoke(false, lastError)
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Throwable) {
        }
        val targetStopId = if (stopStartId > 0) stopStartId else latestStartId
        if (targetStopId > 0) {
            stopSelf(targetStopId)
        } else {
            stopSelf()
        }
    }

    private fun queryAndroidTelemetry(includeTraffic: Boolean): JSONObject? {
        val path = if (includeTraffic) "/api/vpn/android/telemetry?include_traffic=1" else "/api/vpn/android/telemetry?include_traffic=0"
        val res = RuntimeIpc.request(this, "GET", path) ?: return null
        if (res.statusCode !in 200..299) return null
        return try {
            JSONObject(res.body)
        } catch (_: Throwable) {
            null
        }
    }

    private fun queryActiveTargetLabel(): String {
        val tel = queryAndroidTelemetry(includeTraffic = false)
        if (tel != null) {
            val label = tel.optString("active_label", "").trim()
            if (label.isNotBlank()) return label
        }
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
        try {
            TileService.requestListeningState(
                this,
                ComponentName(this, TailscaleTileService::class.java)
            )
        } catch (_: Throwable) {
        }
    }

    private fun formatRate(bytesPerSec: Long): String {
        val v = bytesPerSec.coerceAtLeast(0L).toDouble()
        return when {
            v >= 1024.0 * 1024.0 -> String.format(Locale.US, "%.1f MB/s", v / (1024.0 * 1024.0))
            v >= 1024.0 -> String.format(Locale.US, "%.1f KB/s", v / 1024.0)
            else -> "${bytesPerSec.coerceAtLeast(0L)} B/s"
        }
    }

    private fun formatCompactRate(bytesPerSec: Long): String {
        val v = bytesPerSec.coerceAtLeast(0L).toDouble()
        return when {
            v >= 1024.0 * 1024.0 -> String.format(Locale.US, "%.1fM", v / (1024.0 * 1024.0))
            v >= 1024.0 -> String.format(Locale.US, "%.0fK", v / 1024.0)
            else -> "${bytesPerSec.coerceAtLeast(0L)}B"
        }
    }

    private fun formatSplitSpeed(
        proxyUp: Long,
        proxyDown: Long,
        directUp: Long,
        directDown: Long,
    ): Pair<String, String> {
        val zh = Locale.getDefault().language.startsWith("zh", ignoreCase = true)
        val proxyTag = if (zh) "代理" else "Proxy"
        val directTag = if (zh) "直连" else "Direct"
        val compact =
            "$proxyTag ↑${formatCompactRate(proxyUp)} ↓${formatCompactRate(proxyDown)} · $directTag ↑${formatCompactRate(directUp)} ↓${formatCompactRate(directDown)}"
        val expanded =
            "$proxyTag ↑ ${formatRate(proxyUp)} · ↓ ${formatRate(proxyDown)}\n$directTag ↑ ${formatRate(directUp)} · ↓ ${formatRate(directDown)}"
        return Pair(compact, expanded)
    }

    private fun applyVpnRoutes(
        builder: Builder,
        allowLanBroadcast: Boolean,
        tailscaleEnabled: Boolean = false,
        tailscaleSubnets: List<String> = emptyList(),
    ) {
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
        val excludedList = mutableListOf(
            ipv4Range("0.0.0.0", 8),      // Current network
            ipv4Range("10.0.0.0", 8),     // RFC 1918 LAN
            ipv4Range("127.0.0.0", 8),    // Loopback
            ipv4Range("169.254.0.0", 16), // Link-local
            ipv4Range("172.16.0.0", 12),  // RFC 1918 LAN (TUN 172.19.0.0/30 re-added below)
            ipv4Range("192.168.0.0", 16), // RFC 1918 LAN
            ipv4Range("224.0.0.0", 4),    // IPv4 Multicast (mDNS, SSDP, DLNA)
            ipv4Range("240.0.0.0", 4),    // Reserved + Limited Broadcast (255.255.255.255)
        )
        // When built-in Tailscale Mesh is active, keep 100.64.0.0/10 routed into tun0 so sing-box's tsnet handles it.
        if (!tailscaleEnabled) {
            excludedList.add(ipv4Range("100.64.0.0", 10)) // RFC 6598 CGNAT
        }
        val excluded = excludedList.sortedBy { it.first }

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
        if (tailscaleEnabled) {
            // Route Tailscale IPv6 ULA and any custom tailnet subnet CIDRs explicitly into tun0.
            try {
                builder.addRoute("fd7a:115c:a1e0::", 48)
            } catch (_: Throwable) {
            }
            for (rawCidr in tailscaleSubnets) {
                val parts = rawCidr.trim().split('/')
                if (parts.size != 2) continue
                val addr = parts[0].trim()
                val prefix = parts[1].trim().toIntOrNull() ?: continue
                if (addr == "100.64.0.0" && prefix == 10) continue
                if (addr.equals("fd7a:115c:a1e0::", ignoreCase = true) && prefix == 48) continue
                try {
                    builder.addRoute(addr, prefix)
                    routeCount += 1
                } catch (_: Throwable) {
                }
            }
        }
        Log.i(TAG, "Applied LAN+broadcast bypass routes ($routeCount IPv4/tailnet CIDR + 2000::/3 IPv6, tailscale=$tailscaleEnabled)")
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
