// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

internal object RuntimeIpc {
    private const val TAG = "PrismRayIPC"

    data class Endpoint(val url: String, val token: String)

    data class HttpResult(val statusCode: Int, val body: String)

    @Volatile
    private var cachedEndpoint: Endpoint? = null

    @Volatile
    private var cachedFilePath: String = ""

    @Volatile
    private var cachedFileMtime: Long = 0L

    @Volatile
    private var cachedCheckedAtMs: Long = 0L

    fun invalidateEndpointCache() {
        cachedEndpoint = null
        cachedFilePath = ""
        cachedFileMtime = 0L
        cachedCheckedAtMs = 0L
    }

    fun readEndpoint(context: Context): Endpoint? {
        val now = System.currentTimeMillis()
        val cached = cachedEndpoint
        if (cached != null && now - cachedCheckedAtMs < 5000L) {
            return cached
        }

        val candidates = mutableListOf<File>()
        candidates.add(File(context.filesDir, "runtime-ipc.json"))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            candidates.add(File(context.dataDir, "runtime-ipc.json"))
        } else {
            context.applicationInfo.dataDir?.let {
                candidates.add(File(it, "runtime-ipc.json"))
            }
        }

        val existing = candidates
            .filter { it.isFile }
            .sortedByDescending { it.lastModified() }

        val newest = existing.firstOrNull()
        if (cached != null && newest != null &&
            newest.absolutePath == cachedFilePath &&
            newest.lastModified() == cachedFileMtime
        ) {
            cachedCheckedAtMs = now
            return cached
        }

        for (file in existing) {
            try {
                val raw = file.readText(Charsets.UTF_8)
                val json = JSONObject(raw)
                val url = json.optString("url", "").trim().trimEnd('/')
                val token = json.optString("token", "").trim()
                if (url.isNotEmpty() && token.isNotEmpty()) {
                    val ep = Endpoint(url, token)
                    cachedEndpoint = ep
                    cachedFilePath = file.absolutePath
                    cachedFileMtime = file.lastModified()
                    cachedCheckedAtMs = now
                    return ep
                }
            } catch (_: Throwable) {
                // Ignore partially written or unreadable IPC file and inspect fallback candidates.
            }
        }
        return null
    }

    fun dataDirectory(context: Context): File {
        return context.filesDir
    }

    @Suppress("DEPRECATION")
    private fun findActivePhysicalNetwork(cm: ConnectivityManager): Network? {
        val active = cm.activeNetwork
        if (active != null) {
            val caps = cm.getNetworkCapabilities(active)
            if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                return active
            }
        }
        return cm.allNetworks.firstOrNull { net ->
            val caps = cm.getNetworkCapabilities(net) ?: return@firstOrNull false
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
    }

    fun collectSystemDnsServers(context: Context): List<String> {
        return try {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
            val network = findActivePhysicalNetwork(cm) ?: return emptyList()
            val lp = cm.getLinkProperties(network) ?: return emptyList()
            lp.dnsServers.mapNotNull { addr ->
                val host = addr.hostAddress?.trim()
                if (host.isNullOrEmpty() || host.startsWith("127.") || host == "::1" || host.startsWith("172.19.0.")) {
                    null
                } else {
                    host
                }
            }.distinct()
        } catch (_: Throwable) {
            emptyList()
        }
    }

    @Suppress("DEPRECATION")
    fun collectNetworkInterfaces(context: Context): JSONArray {
        val arr = JSONArray()
        try {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return arr
            val defaultNet = findActivePhysicalNetwork(cm)
            val seenNames = mutableSetOf<String>()
            var idx = 2
            val networks = cm.allNetworks.toList().sortedByDescending { it == defaultNet }
            for (net in networks) {
                val caps = cm.getNetworkCapabilities(net) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                val lp = cm.getLinkProperties(net) ?: continue
                val ifName = lp.interfaceName?.trim().orEmpty()
                if (ifName.isEmpty() || ifName.startsWith("tun") || !seenNames.add(ifName)) continue

                val addrs = JSONArray()
                for (la in lp.linkAddresses) {
                    val host = la.address?.hostAddress?.substringBefore('%')?.trim().orEmpty()
                    if (host.isNotEmpty() && !host.startsWith("172.19.0.")) {
                        addrs.put("$host/${la.prefixLength}")
                    }
                }
                if (addrs.length() == 0) continue

                val gateways = JSONArray()
                for (route in lp.routes) {
                    val gw = route.gateway?.hostAddress?.substringBefore('%')?.trim().orEmpty()
                    if (gw.isNotEmpty() && gw != "0.0.0.0" && gw != "::") {
                        gateways.put(gw)
                    }
                }
                val dns = JSONArray()
                for (d in lp.dnsServers) {
                    val host = d.hostAddress?.substringBefore('%')?.trim().orEmpty()
                    if (host.isNotEmpty() && !host.startsWith("127.") && host != "::1" && !host.startsWith("172.19.0.")) {
                        dns.put(host)
                    }
                }
                val ifType = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                    else -> "other"
                }
                val mtu = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && lp.mtu > 0) lp.mtu else 1500
                val expensive = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)

                arr.put(JSONObject().apply {
                    put("name", ifName)
                    put("index", idx++)
                    put("mtu", mtu)
                    put("type", ifType)
                    put("addresses", addrs)
                    put("gateways", gateways)
                    put("dns_servers", dns)
                    put("is_default", net == defaultNet)
                    put("expensive", expensive)
                    put("constrained", false)
                })
            }
        } catch (err: Throwable) {
            Log.w(TAG, "Failed to collect Android network interfaces: ${err.message}")
        }
        return arr
    }

    fun syncSystemDns(context: Context): Boolean {
        val servers = collectSystemDnsServers(context)
        val interfaces = collectNetworkInterfaces(context)
        val payload = JSONObject()
            .put("servers", JSONArray(servers))
            .put("interfaces", interfaces)
            .toString()
        val res = request(context, "POST", "/api/vpn/android/dns", payload)
        val ok = res != null && res.statusCode in 200..299
        if (ok) {
            Log.i(TAG, "Synced Android DNS ($servers) & ${interfaces.length()} interface(s) to backend")
        }
        return ok
    }

    fun reportVpnError(context: Context, message: String) {
        val clean = message.trim()
        if (clean.isEmpty()) return
        try {
            val payload = JSONObject().put("message", clean).toString()
            request(context, "POST", "/api/vpn/android/error", payload)
        } catch (_: Throwable) {
        }
    }

    fun request(
        context: Context,
        method: String,
        path: String,
        bodyJson: String? = null,
        readTimeoutMs: Int = 15000,
    ): HttpResult? {
        val first = executeRequest(context, method, path, bodyJson, readTimeoutMs)
        if (first != null && first.statusCode == 401) {
            // Backend may have restarted with a rotated IPC token; refresh cache once and retry.
            invalidateEndpointCache()
            return executeRequest(context, method, path, bodyJson, readTimeoutMs)
        }
        return first
    }

    private fun executeRequest(
        context: Context,
        method: String,
        path: String,
        bodyJson: String?,
        readTimeoutMs: Int,
    ): HttpResult? {
        val endpoint = readEndpoint(context) ?: return null
        val normalizedPath = if (path.startsWith("/")) path else "/$path"
        val baseUrl = if (endpoint.url.endsWith("/api") && normalizedPath.startsWith("/api/")) {
            endpoint.url.removeSuffix("/api")
        } else {
            endpoint.url
        }
        val targetUrl = "$baseUrl$normalizedPath"
        val conn = (URL(targetUrl).openConnection() as HttpURLConnection)
        return try {
            conn.requestMethod = method
            conn.connectTimeout = 3000
            conn.readTimeout = readTimeoutMs
            conn.useCaches = false
            conn.setRequestProperty("Authorization", "Bearer ${endpoint.token}")
            conn.setRequestProperty("Accept", "application/json")
            conn.setRequestProperty("Connection", "keep-alive")
            if (bodyJson != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { out ->
                    out.write(bodyJson.toByteArray(Charsets.UTF_8))
                }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else (conn.errorStream ?: conn.inputStream)
            // Fully consume and close the response stream WITHOUT calling conn.disconnect()
            // so Android's HttpURLConnection pool reuses keep-alive loopback sockets.
            val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            HttpResult(code, body)
        } catch (err: Throwable) {
            Log.w(TAG, "IPC $method $targetUrl failed: ${err.message}")
            try {
                conn.disconnect()
            } catch (_: Throwable) {
            }
            null
        }
    }
}
