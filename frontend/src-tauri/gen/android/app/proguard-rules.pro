# PrismRay Android R8 / ProGuard keep rules

# Keep JavaScriptInterface bridge and Android components invoked by system/WebView/JNI.
-keepclassmembers class com.crackrammer.prismray.MainActivity$AndroidVpnBridge {
    @android.webkit.JavascriptInterface <methods>;
}
-keep class com.crackrammer.prismray.MainActivity { *; }
-keep class com.crackrammer.prismray.MainActivity$AndroidVpnBridge { *; }
-keep class com.crackrammer.prismray.ProxyVpnService { *; }
-keep class com.crackrammer.prismray.ProxyTileService { *; }
-keep class com.crackrammer.prismray.VpnWidgetProvider { *; }
-keep class com.crackrammer.prismray.VpnWidgetActionReceiver { *; }
-keep class com.crackrammer.prismray.BootCompletedReceiver { *; }
-keep class com.crackrammer.prismray.QrScannerActivity { *; }
-keep class com.crackrammer.prismray.generated.** { *; }

# Keep hev-socks5-tunnel JNI entrypoint (registered via JNI_OnLoad).
-keep class hev.htproxy.TProxyService { *; }

# Keep Tauri Android bridge classes and JNI entrypoints.
-keep class app.tauri.** { *; }
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# Keep ZXing QR scanner reflection hooks and BiometricPrompt callbacks.
-keep class com.journeyapps.barcodescanner.** { *; }
-keep class com.google.zxing.** { *; }
-keep class androidx.biometric.** { *; }
-dontwarn com.google.zxing.**
