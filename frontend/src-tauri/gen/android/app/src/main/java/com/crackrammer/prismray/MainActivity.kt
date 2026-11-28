// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Looper
import android.provider.Settings
import android.service.quicksettings.TileService
import android.util.Base64
import android.util.Log
import android.util.LruCache
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : TauriActivity() {
    companion object {
        private const val TAG = "PrismRayMain"
        const val EXTRA_AUTO_START_VPN = "com.crackrammer.prismray.extra.AUTO_START_VPN"
        const val EXTRA_AUTO_START_NONCE = "com.crackrammer.prismray.extra.AUTO_START_NONCE"

        private val nonceRng = SecureRandom()
        private val pendingAutoStartNonces = ConcurrentHashMap<String, Long>()

        fun issueAutoStartNonce(): String {
            val now = System.currentTimeMillis()
            pendingAutoStartNonces.entries.removeIf { now - it.value > 60_000L }
            val bytes = ByteArray(16)
            nonceRng.nextBytes(bytes)
            val nonce = bytes.joinToString("") { "%02x".format(it) }
            pendingAutoStartNonces[nonce] = now
            return nonce
        }

        private fun consumeAutoStartNonce(nonce: String?): Boolean {
            if (nonce.isNullOrBlank()) return false
            val issuedAt = pendingAutoStartNonces.remove(nonce) ?: return false
            return System.currentTimeMillis() - issuedAt <= 60_000L
        }
    }

    private lateinit var vpnConsentLauncher: ActivityResultLauncher<Intent>
    private lateinit var notificationPermissionLauncher: ActivityResultLauncher<String>
    private lateinit var qrScanLauncher: ActivityResultLauncher<ScanOptions>
    private lateinit var backPressedCallback: OnBackPressedCallback

    private val appIconCache = LruCache<String, String>(128)
    private val pendingAppsResults = ConcurrentHashMap<String, String>()
    private val apkUpdateInFlight = AtomicBoolean(false)

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

    override fun onStart() {
        super.onStart()
        dispatchAppLifecycleEvent(foreground = true)
    }

    override fun onStop() {
        dispatchAppLifecycleEvent(foreground = false)
        super.onStop()
    }

    private fun dispatchAppLifecycleEvent(foreground: Boolean) {
        val wv = attachedWebView ?: return
        val js = "window.dispatchEvent(new CustomEvent('prismray-app-lifecycle',{detail:{foreground:$foreground}}));"
        wv.post {
            try {
                wv.evaluateJavascript(js, null)
            } catch (_: Throwable) {
            }
        }
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
        val nonce = intent.getStringExtra(EXTRA_AUTO_START_NONCE)
        intent.removeExtra(EXTRA_AUTO_START_VPN)
        intent.removeExtra(EXTRA_AUTO_START_NONCE)
        if (!consumeAutoStartNonce(nonce)) {
            Log.w(TAG, "Ignoring unverified EXTRA_AUTO_START_VPN intent without valid internal nonce")
            return
        }
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
        val (bitmap, shouldRecycle) = if (drawable is BitmapDrawable && drawable.bitmap != null) {
            val src = drawable.bitmap
            val scaled = Bitmap.createScaledBitmap(src, sizePx, sizePx, true)
            scaled to (scaled !== src)
        } else {
            val bmp = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bmp)
            drawable.setBounds(0, 0, canvas.width, canvas.height)
            drawable.draw(canvas)
            bmp to true
        }
        try {
            val out = ByteArrayOutputStream()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                bitmap.compress(Bitmap.CompressFormat.WEBP_LOSSY, 80, out)
                val encoded = Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
                return "data:image/webp;base64,$encoded"
            }
            bitmap.compress(Bitmap.CompressFormat.PNG, 85, out)
            val encoded = Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
            return "data:image/png;base64,$encoded"
        } finally {
            if (shouldRecycle && !bitmap.isRecycled) {
                bitmap.recycle()
            }
        }
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

    private fun dispatchBiometricResult(success: Boolean, error: String? = null, biometricKek: String? = null) {
        val wv = attachedWebView ?: return
        val detail = JSONObject().apply {
            put("success", success)
            if (!error.isNullOrBlank()) {
                put("error", error)
            }
            if (!biometricKek.isNullOrBlank()) {
                put("biometric_kek", biometricKek)
            }
        }.toString()
        runOnUiThread {
            wv.evaluateJavascript(
                "window.dispatchEvent(new CustomEvent('prismray-biometric-result',{detail:$detail}));",
                null
            )
        }
    }

    private fun dispatchBiometricEnrollResult(success: Boolean, error: String? = null) {
        val wv = attachedWebView ?: return
        val detail = JSONObject().apply {
            put("success", success)
            if (!error.isNullOrBlank()) {
                put("error", error)
            }
        }.toString()
        runOnUiThread {
            wv.evaluateJavascript(
                "window.dispatchEvent(new CustomEvent('prismray-biometric-enroll-result',{detail:$detail}));",
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
            if (Looper.myLooper() == Looper.getMainLooper()) {
                return try {
                    val cm = getSystemService(ClipboardManager::class.java) ?: return false
                    cm.setPrimaryClip(ClipData.newPlainText("PrismRay", value))
                    true
                } catch (_: Throwable) {
                    false
                }
            }
            val ok = AtomicBoolean(false)
            val latch = CountDownLatch(1)
            runOnUiThread {
                try {
                    val cm = getSystemService(ClipboardManager::class.java)
                    if (cm != null) {
                        cm.setPrimaryClip(ClipData.newPlainText("PrismRay", value))
                        ok.set(true)
                    }
                } catch (_: Throwable) {
                } finally {
                    latch.countDown()
                }
            }
            return try {
                latch.await(500, TimeUnit.MILLISECONDS)
                ok.get()
            } catch (_: InterruptedException) {
                false
            }
        }

        @JavascriptInterface
        fun getBiometricStatus(): String {
            return try {
                val bm = BiometricManager.from(this@MainActivity)
                val code = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                val available = code == BiometricManager.BIOMETRIC_SUCCESS
                val detail = when (code) {
                    BiometricManager.BIOMETRIC_SUCCESS -> "Android Keystore Hardware Biometric (Strong)"
                    BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "No strong fingerprint/biometric enrolled in Android Settings"
                    BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "No strong biometric hardware detected"
                    BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "Biometric hardware currently unavailable"
                    else -> "Strong biometric authentication unavailable (code=$code)"
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
        fun enrollBiometricKey(kekBase64: String?, reason: String?): Boolean {
            val kek = kekBase64?.trim().orEmpty()
            if (kek.isEmpty()) {
                dispatchBiometricEnrollResult(false, "Missing biometric key material")
                return false
            }
            val subtitle = reason?.takeIf { it.isNotBlank() } ?: "Confirm biometrics to protect PrismRay key"
            runOnUiThread {
                try {
                    val cipher = AndroidBiometricCrypto.prepareEncryptCipher()
                    val executor = ContextCompat.getMainExecutor(this@MainActivity)
                    val prompt = BiometricPrompt(
                        this@MainActivity,
                        executor,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                try {
                                    val authCipher = result.cryptoObject?.cipher
                                        ?: throw IllegalStateException("Missing authenticated keystore cipher")
                                    AndroidBiometricCrypto.persistEncryptedKek(this@MainActivity, authCipher, kek)
                                    dispatchBiometricEnrollResult(true)
                                } catch (err: Throwable) {
                                    AndroidBiometricCrypto.clear(this@MainActivity)
                                    dispatchBiometricEnrollResult(false, err.message ?: err.javaClass.simpleName)
                                }
                            }

                            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                                AndroidBiometricCrypto.clear(this@MainActivity)
                                dispatchBiometricEnrollResult(false, errString.toString())
                            }

                            override fun onAuthenticationFailed() {
                                // System prompt stays open for retry.
                            }
                        }
                    )
                    val promptInfo = BiometricPrompt.PromptInfo.Builder()
                        .setTitle("PrismRay")
                        .setSubtitle(subtitle)
                        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                        .setNegativeButtonText("Cancel")
                        .build()
                    prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
                } catch (err: Throwable) {
                    AndroidBiometricCrypto.clear(this@MainActivity)
                    dispatchBiometricEnrollResult(false, err.message ?: err.javaClass.simpleName)
                }
            }
            return true
        }

        @JavascriptInterface
        fun clearBiometricKey(): Boolean {
            AndroidBiometricCrypto.clear(this@MainActivity)
            return true
        }

        @JavascriptInterface
        fun authenticateBiometric(reason: String?): Boolean {
            val subtitle = reason?.takeIf { it.isNotBlank() } ?: "Unlock PrismRay"
            runOnUiThread {
                try {
                    val cipher = AndroidBiometricCrypto.prepareDecryptCipher(this@MainActivity)
                    val executor = ContextCompat.getMainExecutor(this@MainActivity)
                    val prompt = BiometricPrompt(
                        this@MainActivity,
                        executor,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                try {
                                    val authCipher = result.cryptoObject?.cipher
                                        ?: throw IllegalStateException("Missing authenticated keystore cipher")
                                    val kek = AndroidBiometricCrypto.decryptStoredKek(this@MainActivity, authCipher)
                                    dispatchBiometricResult(true, biometricKek = kek)
                                } catch (err: Throwable) {
                                    dispatchBiometricResult(false, err.message ?: err.javaClass.simpleName)
                                }
                            }

                            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                                dispatchBiometricResult(false, errString.toString())
                            }

                            override fun onAuthenticationFailed() {
                                // System prompt stays open for retry; only final error dispatches failure.
                            }
                        }
                    )
                    val promptInfo = BiometricPrompt.PromptInfo.Builder()
                        .setTitle("PrismRay")
                        .setSubtitle(subtitle)
                        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                        .setNegativeButtonText("Cancel")
                        .build()
                    prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
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
        fun refreshQuickTiles(): Boolean {
            return try {
                TileService.requestListeningState(
                    this@MainActivity,
                    ComponentName(this@MainActivity, ProxyTileService::class.java)
                )
                TileService.requestListeningState(
                    this@MainActivity,
                    ComponentName(this@MainActivity, TailscaleTileService::class.java)
                )
                true
            } catch (_: Throwable) {
                false
            }
        }

        @JavascriptInterface
        fun getVpnStatus(): String {
            // Return authoritative in-process VpnService state without blocking the WebView JS thread on HTTP.
            val serviceRunning = ProxyVpnService.isVpnRunning
            return JSONObject()
                .put("active", serviceRunning)
                .put("service_running", serviceRunning)
                .put("running", serviceRunning)
                .toString()
        }

        @JavascriptInterface
        fun openExternalUrl(rawUrl: String?): Boolean {
            val clean = rawUrl?.trim().orEmpty()
            val parsed = try {
                Uri.parse(clean)
            } catch (_: Throwable) {
                return false
            }
            val scheme = parsed.scheme?.lowercase().orEmpty()
            if (scheme != "https" && scheme != "http") return false
            return try {
                val viewIntent = Intent(Intent.ACTION_VIEW, parsed).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                startActivity(viewIntent)
                true
            } catch (_: Throwable) {
                false
            }
        }

        private fun dispatchApkUpdateEvent(
            phase: String,
            progress: Int = 0,
            message: String = "",
            downloaded: Long = 0,
            total: Long = 0
        ) {
            val payload = JSONObject()
                .put("phase", phase)
                .put("progress", progress)
                .put("message", message)
                .put("downloaded", downloaded)
                .put("total", total)
                .toString()
            val js = "window.dispatchEvent(new CustomEvent('prismray-apk-update-progress',{detail:$payload}));"
            attachedWebView?.post {
                try {
                    attachedWebView?.evaluateJavascript(js, null)
                } catch (_: Throwable) {
                }
            }
        }

        private fun isAllowedApkHost(host: String?): Boolean {
            val h = host?.trim()?.lowercase()?.trimEnd('.') ?: return false
            return h == "github.com" ||
                h == "objects.githubusercontent.com" ||
                h == "release-assets.githubusercontent.com" ||
                h == "github-releases.githubusercontent.com" ||
                h.endsWith(".githubusercontent.com")
        }

        private fun isValidSha256Hex(sha: String): Boolean {
            return sha.length == 64 && sha.all { it in '0'..'9' || it in 'a'..'f' }
        }

        @JavascriptInterface
        fun downloadAndInstallApk(rawUrl: String?, expectedSha256: String?): Boolean {
            val cleanUrl = rawUrl?.trim().orEmpty()
            val parsed = try {
                Uri.parse(cleanUrl)
            } catch (_: Throwable) {
                return false
            }
            if (parsed.scheme?.lowercase() != "https" || !isAllowedApkHost(parsed.host)) {
                dispatchApkUpdateEvent("error", 0, "Only HTTPS GitHub Releases APK downloads are permitted")
                return false
            }
            val normalizedSha = expectedSha256?.trim()?.lowercase().orEmpty()
            if (!isValidSha256Hex(normalizedSha)) {
                dispatchApkUpdateEvent("error", 0, "Missing or invalid SHA-256 checksum; refusing unverified APK install")
                return false
            }
            if (!apkUpdateInFlight.compareAndSet(false, true)) {
                return false
            }
            Thread({
                var conn: HttpURLConnection? = null
                try {
                    dispatchApkUpdateEvent("downloading", 0, "")
                    val updatesDir = File(cacheDir, "updates").apply { mkdirs() }
                    val tmpFile = File(updatesDir, "prismray-update.apk.tmp")
                    val targetFile = File(updatesDir, "prismray-update.apk")
                    if (tmpFile.exists()) tmpFile.delete()

                    // Follow up to 5 HTTPS redirects restricted to GitHub release asset hosts.
                    var currentUrl = cleanUrl
                    var redirects = 0
                    while (true) {
                        val c = (URL(currentUrl).openConnection() as HttpURLConnection).apply {
                            instanceFollowRedirects = false
                            connectTimeout = 15_000
                            readTimeout = 30_000
                            requestMethod = "GET"
                            setRequestProperty("User-Agent", "PrismRay-Android")
                        }
                        val code = c.responseCode
                        if (code in 300..399) {
                            val loc = c.getHeaderField("Location")?.trim().orEmpty()
                            c.disconnect()
                            if (loc.isEmpty() || ++redirects > 5) {
                                throw IllegalStateException("Too many redirects downloading APK")
                            }
                            val nextUri = Uri.parse(loc)
                            if (nextUri.scheme?.lowercase() != "https" || !isAllowedApkHost(nextUri.host)) {
                                throw SecurityException("Redirect to untrusted host blocked: ${nextUri.host}")
                            }
                            currentUrl = loc
                            continue
                        }
                        if (code !in 200..299) {
                            c.disconnect()
                            throw IllegalStateException("APK download failed: HTTP $code")
                        }
                        conn = c
                        break
                    }

                    val totalBytes = conn!!.contentLengthLong
                    val digest = MessageDigest.getInstance("SHA-256")
                    var downloadedBytes = 0L
                    var lastPct = -1
                    val buf = ByteArray(32 * 1024)
                    conn!!.inputStream.use { input ->
                        FileOutputStream(tmpFile).use { output ->
                            while (true) {
                                val n = input.read(buf)
                                if (n <= 0) break
                                output.write(buf, 0, n)
                                digest.update(buf, 0, n)
                                downloadedBytes += n
                                val pct = if (totalBytes > 0) {
                                    ((downloadedBytes * 100L) / totalBytes).toInt().coerceIn(0, 100)
                                } else {
                                    0
                                }
                                if (pct != lastPct) {
                                    lastPct = pct
                                    dispatchApkUpdateEvent("downloading", pct, "", downloadedBytes, totalBytes)
                                }
                            }
                        }
                    }

                    dispatchApkUpdateEvent("verifying", 100, "", downloadedBytes, totalBytes)
                    val actualSha = digest.digest().joinToString("") { "%02x".format(it) }
                    if (actualSha != normalizedSha) {
                        tmpFile.delete()
                        throw SecurityException("APK SHA-256 mismatch (expected $normalizedSha, got $actualSha)")
                    }
                    if (targetFile.exists()) targetFile.delete()
                    if (!tmpFile.renameTo(targetFile)) {
                        tmpFile.copyTo(targetFile, overwrite = true)
                        tmpFile.delete()
                    }

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !packageManager.canRequestPackageInstalls()) {
                        dispatchApkUpdateEvent(
                            "permission_required",
                            100,
                            "Please grant install-unknown-apps permission for PrismRay, then tap Install again."
                        )
                        runOnUiThread {
                            try {
                                val settingsIntent = Intent(
                                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                    Uri.parse("package:$packageName")
                                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                startActivity(settingsIntent)
                            } catch (err: Throwable) {
                                Log.w(TAG, "Unable to open unknown sources settings", err)
                            }
                        }
                        return@Thread
                    }

                    val apkUri = FileProvider.getUriForFile(
                        this@MainActivity,
                        "$packageName.fileprovider",
                        targetFile
                    )
                    dispatchApkUpdateEvent("installing", 100, "", downloadedBytes, totalBytes)
                    runOnUiThread {
                        try {
                            val installIntent = Intent(Intent.ACTION_VIEW).apply {
                                setDataAndType(apkUri, "application/vnd.android.package-archive")
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            }
                            startActivity(installIntent)
                        } catch (err: Throwable) {
                            dispatchApkUpdateEvent("error", 0, err.message ?: "Failed to launch installer")
                        }
                    }
                } catch (err: Throwable) {
                    Log.e(TAG, "APK download/install failed", err)
                    dispatchApkUpdateEvent("error", 0, err.message ?: err.javaClass.simpleName)
                } finally {
                    try {
                        conn?.disconnect()
                    } catch (_: Throwable) {
                    }
                    apkUpdateInFlight.set(false)
                }
            }, "prismray-apk-update").apply {
                isDaemon = true
                start()
            }
            return true
        }

        @JavascriptInterface
        fun listInstalledAppsAsync(requestId: String?): Boolean {
            val reqId = requestId?.trim().orEmpty()
            if (reqId.isEmpty()) return false
            Thread({
                val appsJson = try {
                    listInstalledApps()
                } catch (_: Throwable) {
                    "[]"
                }
                if (pendingAppsResults.size > 8) {
                    pendingAppsResults.clear()
                }
                pendingAppsResults[reqId] = appsJson
                val payload = JSONObject()
                    .put("requestId", reqId)
                    .toString()
                val js = "window.dispatchEvent(new CustomEvent('prismray-android-apps',{detail:$payload}));"
                attachedWebView?.post {
                    try {
                        attachedWebView?.evaluateJavascript(js, null)
                    } catch (_: Throwable) {
                    }
                }
            }, "prismray-list-apps").apply {
                isDaemon = true
                start()
            }
            return true
        }

        @JavascriptInterface
        fun takeInstalledAppsResult(requestId: String?): String {
            val reqId = requestId?.trim().orEmpty()
            if (reqId.isEmpty()) return ""
            return pendingAppsResults.remove(reqId) ?: ""
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
                    val cached = appIconCache.get(pkg)
                    if (cached != null) {
                        result.put(pkg, cached)
                        continue
                    }
                    try {
                        val icon = pm.getApplicationIcon(pkg)
                        val dataUri = drawableToDataUri(icon, 64)
                        appIconCache.put(pkg, dataUri)
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
