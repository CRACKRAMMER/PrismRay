// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Base64
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap

class MainActivity : TauriActivity() {
    companion object {
        private const val TAG = "PrismRayMain"
        const val EXTRA_AUTO_START_VPN = "com.crackrammer.prismray.extra.AUTO_START_VPN"
    }

    private lateinit var vpnConsentLauncher: ActivityResultLauncher<Intent>
    private lateinit var notificationPermissionLauncher: ActivityResultLauncher<String>
    private lateinit var qrScanLauncher: ActivityResultLauncher<ScanOptions>
    private lateinit var backPressedCallback: OnBackPressedCallback

    private val appIconCache = ConcurrentHashMap<String, String>()

    @Volatile
    private var attachedWebView: WebView? = null

    @Volatile
    private var pendingConfigJson: String = "{}"

    @Volatile
    private var lastInsetsJs: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        vpnConsentLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            val granted = result.resultCode == Activity.RESULT_OK
            if (granted) {
                startVpnForegroundService(pendingConfigJson)
            } else {
                VpnWidgetProvider.updateAllWidgets(this, running = false, connecting = false)
            }
            notifyVpnPermissionEvent(granted)
        }

        notificationPermissionLauncher = registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { _ -> }

        qrScanLauncher = registerForActivityResult(ScanContract()) { result ->
            val contents = result?.contents
            dispatchQrResult(contents, cancelled = contents == null)
        }

        super.onCreate(savedInstanceState)

        // Close only the topmost open <dialog> on Android back gesture so nested sheets never dismiss parents.
        backPressedCallback = object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                val wv = attachedWebView
                if (wv == null) {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                    isEnabled = true
                    return
                }
                wv.evaluateJavascript(
                    """
                    (function() {
                      var dialogs = document.querySelectorAll('dialog[open]');
                      if (dialogs.length > 0) {
                        var top = dialogs[dialogs.length - 1];
                        if (typeof top.close === 'function') {
                          top.close();
                          return 'closed_dialog';
                        }
                      }
                      return 'none';
                    })();
                    """.trimIndent()
                ) { result ->
                    if (result != "\"closed_dialog\"") {
                        runOnUiThread {
                            isEnabled = false
                            onBackPressedDispatcher.onBackPressed()
                            isEnabled = true
                        }
                    }
                }
            }
        }
        onBackPressedDispatcher.addCallback(this, backPressedCallback)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        // Sync active Android network DNS servers once the local Go backend finishes booting.
        Thread({
            for (attempt in 0 until 15) {
                if (RuntimeIpc.syncSystemDns(this)) break
                try {
                    Thread.sleep(600)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }, "prismray-dns-sync").apply {
            isDaemon = true
            start()
        }

        ProxyVpnService.stateListener = { running, error ->
            dispatchVpnStateEvent(running = running, error = error)
        }

        handleAutoStartVpnIntent(intent)
    }

    override fun onDestroy() {
        ProxyVpnService.stateListener = null
        super.onDestroy()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleAutoStartVpnIntent(intent)
    }

    private fun handleAutoStartVpnIntent(intent: Intent?) {
        if (intent?.getBooleanExtra(EXTRA_AUTO_START_VPN, false) != true) return
        intent.removeExtra(EXTRA_AUTO_START_VPN)
        if (ProxyVpnService.isVpnRunning) {
            VpnWidgetProvider.updateAllWidgets(this, running = true, connecting = false)
            return
        }
        VpnWidgetProvider.updateAllWidgets(this, running = false, connecting = true)
        Thread({
            var ready = false
            for (attempt in 0 until 25) {
                val res = RuntimeIpc.request(this, "GET", "/api/process/status")
                if (res != null && res.statusCode in 200..299) {
                    ready = true
                    break
                }
                try {
                    Thread.sleep(500)
                } catch (_: InterruptedException) {
                    break
                }
            }
            runOnUiThread {
                if (!ready) {
                    VpnWidgetProvider.updateAllWidgets(this, running = false, connecting = false)
                    return@runOnUiThread
                }
                pendingConfigJson = "{}"
                val prepareIntent = VpnService.prepare(this)
                if (prepareIntent != null) {
                    vpnConsentLauncher.launch(prepareIntent)
                } else {
                    startVpnForegroundService("{}")
                }
            }
        }, "prismray-widget-autostart").apply {
            isDaemon = true
            start()
        }
    }

    override fun onWebViewCreate(webView: WebView) {
        super.onWebViewCreate(webView)
        attachedWebView = webView
        if (BuildConfig.DEBUG) {
            WebView.setWebContentsDebuggingEnabled(true)
            Log.i(TAG, "WebView remote debugging enabled (inspect via chrome://inspect)")
        }
        webView.addJavascriptInterface(AndroidVpnBridge(), "PrismRayAndroid")
        installWindowInsetsBridge(webView)
    }

    private fun installWindowInsetsBridge(webView: WebView) {
        ViewCompat.setOnApplyWindowInsetsListener(webView) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            val density = v.resources.displayMetrics.density.coerceAtLeast(1f)
            val topDp = (bars.top / density).toInt()
            val bottomDp = (maxOf(bars.bottom, ime.bottom) / density).toInt()
            val leftDp = (bars.left / density).toInt()
            val rightDp = (bars.right / density).toInt()
            val js = """
                (function() {
                  var r = document.documentElement;
                  if (!r) return;
                  r.style.setProperty('--prismray-inset-top', '${topDp}px');
                  r.style.setProperty('--prismray-inset-bottom', '${bottomDp}px');
                  r.style.setProperty('--prismray-inset-left', '${leftDp}px');
                  r.style.setProperty('--prismray-inset-right', '${rightDp}px');
                  r.dataset.androidInsets = '${topDp},${bottomDp}';
                })();
            """.trimIndent()
            lastInsetsJs = js
            v.post { webView.evaluateJavascript(js, null) }
            insets
        }
        ViewCompat.requestApplyInsets(webView)
    }

    private fun drawableToDataUri(drawable: Drawable, sizePx: Int = 64): String {
        val bitmap = if (drawable is BitmapDrawable && drawable.bitmap != null) {
            Bitmap.createScaledBitmap(drawable.bitmap, sizePx, sizePx, true)
        } else {
            val bmp = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bmp)
            drawable.setBounds(0, 0, canvas.width, canvas.height)
            drawable.draw(canvas)
            bmp
        }
        val out = ByteArrayOutputStream()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            bitmap.compress(Bitmap.CompressFormat.WEBP_LOSSY, 80, out)
            val encoded = Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
            return "data:image/webp;base64,$encoded"
        }
        bitmap.compress(Bitmap.CompressFormat.PNG, 85, out)
        val encoded = Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
        return "data:image/png;base64,$encoded"
    }

    private fun startVpnForegroundService(configJson: String) {
        val intent = Intent(this, ProxyVpnService::class.java).apply {
            action = ProxyVpnService.ACTION_START
            putExtra(ProxyVpnService.EXTRA_CONFIG_JSON, configJson)
        }
        startForegroundService(intent)
    }

    private fun notifyVpnPermissionEvent(approved: Boolean) {
        val wv = attachedWebView ?: return
        val detail = JSONObject().apply {
            put("approved", approved)
            if (!approved) {
                put("error", "未授予 Android VPN 权限")
            }
        }.toString()
        runOnUiThread {
            wv.evaluateJavascript(
                "window.dispatchEvent(new CustomEvent('prismray-vpn-changed',{detail:$detail}));",
                null
            )
        }
    }

    private fun dispatchVpnStateEvent(running: Boolean, error: String?) {
        val wv = attachedWebView ?: return
        val detail = JSONObject().apply {
            put("running", running)
            if (!error.isNullOrBlank()) {
                put("error", error)
            }
        }.toString()
        runOnUiThread {
            wv.evaluateJavascript(
                "window.dispatchEvent(new CustomEvent('prismray-vpn-changed',{detail:$detail}));",
                null
            )
        }
    }

    private fun dispatchBiometricResult(success: Boolean, error: String? = null) {
        val wv = attachedWebView ?: return
        val detail = JSONObject().apply {
            put("success", success)
            if (!error.isNullOrBlank()) {
                put("error", error)
            }
        }.toString()
        runOnUiThread {
            wv.evaluateJavascript(
                "window.dispatchEvent(new CustomEvent('prismray-biometric-result',{detail:$detail}));",
                null
            )
        }
    }

    private fun dispatchQrResult(text: String?, cancelled: Boolean) {
        val wv = attachedWebView ?: return
        val detail = JSONObject().apply {
            put("text", text ?: "")
            put("cancelled", cancelled)
        }.toString()
        runOnUiThread {
            wv.evaluateJavascript(
                "window.dispatchEvent(new CustomEvent('prismray-qr-result',{detail:$detail}));",
                null
            )
        }
    }

    inner class AndroidVpnBridge {
        @JavascriptInterface
        fun isAndroid(): Boolean = true

        @JavascriptInterface
        fun copyToClipboard(text: String?): Boolean {
            val value = text ?: return false
            return try {
                val cm = getSystemService(ClipboardManager::class.java) ?: return false
                cm.setPrimaryClip(ClipData.newPlainText("PrismRay", value))
                true
            } catch (_: Throwable) {
                false
            }
        }

        @JavascriptInterface
        fun getBiometricStatus(): String {
            return try {
                val bm = BiometricManager.from(this@MainActivity)
                val authenticators = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.BIOMETRIC_WEAK or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL
                } else {
                    BiometricManager.Authenticators.BIOMETRIC_WEAK
                }
                val code = bm.canAuthenticate(authenticators)
                val available = code == BiometricManager.BIOMETRIC_SUCCESS
                val detail = when (code) {
                    BiometricManager.BIOMETRIC_SUCCESS -> "Android BiometricPrompt (Fingerprint / Face / Device Lock)"
                    BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "No fingerprint or screen lock enrolled in Android Settings"
                    BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "No biometric hardware detected"
                    BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "Biometric hardware currently unavailable"
                    else -> "Biometric authentication unavailable (code=$code)"
                }
                JSONObject()
                    .put("available", available)
                    .put("platform", "android")
                    .put("detail", detail)
                    .toString()
            } catch (err: Throwable) {
                JSONObject()
                    .put("available", false)
                    .put("platform", "android")
                    .put("detail", err.message ?: "Biometric check failed")
                    .toString()
            }
        }

        @JavascriptInterface
        fun authenticateBiometric(reason: String?): Boolean {
            val subtitle = reason?.takeIf { it.isNotBlank() } ?: "Unlock PrismRay"
            runOnUiThread {
                try {
                    val executor = ContextCompat.getMainExecutor(this@MainActivity)
                    val prompt = BiometricPrompt(
                        this@MainActivity,
                        executor,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                dispatchBiometricResult(true)
                            }

                            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                                dispatchBiometricResult(false, errString.toString())
                            }

                            override fun onAuthenticationFailed() {
                                // System prompt stays open for retry; only final error dispatches failure.
                            }
                        }
                    )
                    val infoBuilder = BiometricPrompt.PromptInfo.Builder()
                        .setTitle("PrismRay")
                        .setSubtitle(subtitle)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        infoBuilder.setAllowedAuthenticators(
                            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                                BiometricManager.Authenticators.BIOMETRIC_WEAK or
                                BiometricManager.Authenticators.DEVICE_CREDENTIAL
                        )
                    } else {
                        infoBuilder
                            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
                            .setNegativeButtonText("Cancel")
                    }
                    prompt.authenticate(infoBuilder.build())
                } catch (err: Throwable) {
                    dispatchBiometricResult(false, err.message ?: err.javaClass.simpleName)
                }
            }
            return true
        }

        @JavascriptInterface
        fun getBootAutostart(): Boolean {
            return AndroidBackendLauncher.isBootAutostartEnabled(this@MainActivity)
        }

        @JavascriptInterface
        fun setBootAutostart(enabled: Boolean): Boolean {
            AndroidBackendLauncher.setBootAutostartEnabled(this@MainActivity, enabled)
            return true
        }

        @JavascriptInterface
        fun openVpnSettings(): Boolean {
            return try {
                val intent = Intent(Settings.ACTION_VPN_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                startActivity(intent)
                true
            } catch (_: Throwable) {
                false
            }
        }

        @JavascriptInterface
        fun applyInsetsNow(): Boolean {
            val wv = attachedWebView ?: return false
            val js = lastInsetsJs
            if (js.isNotEmpty()) {
                runOnUiThread { wv.evaluateJavascript(js, null) }
                return true
            }
            runOnUiThread { ViewCompat.requestApplyInsets(wv) }
            return true
        }

        @JavascriptInterface
        fun startQrScan(): Boolean {
            runOnUiThread {
                val options = ScanOptions().apply {
                    setCaptureActivity(QrScannerActivity::class.java)
                    setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    setPrompt("Scan PrismRay node or subscription QR code")
                    setBeepEnabled(false)
                    setOrientationLocked(false)
                }
                qrScanLauncher.launch(options)
            }
            return true
        }

        @JavascriptInterface
        fun prepareAndStartVpn(configJson: String?): String {
            return try {
                val payload = if (configJson.isNullOrBlank()) "{}" else configJson
                pendingConfigJson = payload
                val consentIntent = VpnService.prepare(this@MainActivity)
                if (consentIntent != null) {
                    runOnUiThread {
                        try {
                            vpnConsentLauncher.launch(consentIntent)
                        } catch (err: Throwable) {
                            dispatchVpnStateEvent(false, "拉起 VPN 授权弹窗失败: ${err.message ?: err.javaClass.simpleName}")
                        }
                    }
                    JSONObject().put("status", "permission_required").toString()
                } else {
                    runOnUiThread {
                        try {
                            startVpnForegroundService(payload)
                        } catch (err: Throwable) {
                            val msg = "启动 Android VPN 服务失败: ${err.message ?: err.javaClass.simpleName}"
                            Log.e(TAG, msg, err)
                            dispatchVpnStateEvent(false, msg)
                        }
                    }
                    JSONObject().put("status", "starting").toString()
                }
            } catch (err: Throwable) {
                val msg = "准备 Android VPN 失败: ${err.message ?: err.javaClass.simpleName}"
                Log.e(TAG, msg, err)
                JSONObject().put("status", "error").put("error", msg).toString()
            }
        }

        @JavascriptInterface
        fun stopVpn(): Boolean {
            val intent = Intent(this@MainActivity, ProxyVpnService::class.java).apply {
                action = ProxyVpnService.ACTION_STOP
            }
            startService(intent)
            return true
        }

        @JavascriptInterface
        fun getVpnStatus(): String {
            val res = RuntimeIpc.request(this@MainActivity, "GET", "/api/vpn/android/status")
            if (res != null && res.statusCode in 200..299 && res.body.isNotBlank()) {
                return res.body
            }
            return JSONObject()
                .put("active", ProxyVpnService.isVpnRunning)
                .put("running", false)
                .toString()
        }

        @JavascriptInterface
        fun listInstalledApps(): String {
            val pm = packageManager
            val selfPkg = packageName
            val apps = pm.getInstalledApplications(0)
            val entries = apps.mapNotNull { info ->
                if (info.packageName == selfPkg) return@mapNotNull null
                val isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                    (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
                val label = try {
                    pm.getApplicationLabel(info).toString()
                } catch (_: Throwable) {
                    info.packageName
                }
                Triple(isSystem, label.lowercase(), JSONObject().apply {
                    put("packageName", info.packageName)
                    put("label", label)
                    put("system", isSystem)
                })
            }.sortedWith(compareBy<Triple<Boolean, String, JSONObject>> { it.first }.thenBy { it.second })

            val arr = JSONArray()
            for ((_, _, obj) in entries) {
                arr.put(obj)
            }
            return arr.toString()
        }

        @JavascriptInterface
        fun getAppIcons(packagesJson: String?): String {
            val result = JSONObject()
            if (packagesJson.isNullOrBlank()) return result.toString()
            val pm = packageManager
            try {
                val arr = JSONArray(packagesJson)
                val limit = minOf(arr.length(), 40)
                for (i in 0 until limit) {
                    val pkg = arr.optString(i, "").trim()
                    if (pkg.isEmpty()) continue
                    val cached = appIconCache[pkg]
                    if (cached != null) {
                        result.put(pkg, cached)
                        continue
                    }
                    try {
                        val icon = pm.getApplicationIcon(pkg)
                        val dataUri = drawableToDataUri(icon, 64)
                        appIconCache[pkg] = dataUri
                        result.put(pkg, dataUri)
                    } catch (_: Throwable) {
                    }
                }
            } catch (_: Throwable) {
            }
            return result.toString()
        }
    }
}
