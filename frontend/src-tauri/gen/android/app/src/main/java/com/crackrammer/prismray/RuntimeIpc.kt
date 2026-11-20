// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.content.Context
import android.net.ConnectivityManager
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

    fun readEndpoint(context: Context): Endpoint? {
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

        for (file in existing) {
            try {
                val raw = file.readText(Charsets.UTF_8)
                val json = JSONObject(raw)
                val url = json.optString("url", "").trim().trimEnd('/')
                val token = json.optString("token", "").trim()
                if (url.isNotEmpty() && token.isNotEmpty()) {
                    return Endpoint(url, token)
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

    fun collectSystemDnsServers(context: Context): List<String> {
        return try {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
            val network = cm.activeNetwork ?: return emptyList()
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

    fun syncSystemDns(context: Context): Boolean {
        val servers = collectSystemDnsServers(context)
        val payload = JSONObject().put("servers", JSONArray(servers)).toString()
        val res = request(context, "POST", "/api/vpn/android/dns", payload)
        val ok = res != null && res.statusCode in 200..299
        if (ok) {
            Log.i(TAG, "Synced Android system DNS to backend: $servers")
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
        bodyJson: String? = null
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
            conn.readTimeout = 15000
            conn.useCaches = false
            conn.setRequestProperty("Authorization", "Bearer ${endpoint.token}")
            conn.setRequestProperty("Accept", "application/json")
            if (bodyJson != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { out ->
                    out.write(bodyJson.toByteArray(Charsets.UTF_8))
                }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else (conn.errorStream ?: conn.inputStream)
            val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            HttpResult(code, body)
        } catch (err: Throwable) {
            Log.w(TAG, "IPC $method $targetUrl failed: ${err.message}")
            null
        } finally {
            conn.disconnect()
        }
    }
}
