// SPDX-License-Identifier: MPL-2.0
package hev.htproxy

import android.os.Build

/**
 * JNI bridge for libhev-socks5-tunnel.so (MIT, heiher/hev-socks5-tunnel).
 * Class/package name and method signatures must remain exact to match JNI_OnLoad.
 */
object TProxyService {
    @Volatile
    var libraryLoaded: Boolean = false
        private set

    init {
        // Upstream prebuilt libhev-socks5-tunnel.so targets Android API 29+; older APIs fall back cleanly to tun2socks.
        libraryLoaded = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                System.loadLibrary("hev-socks5-tunnel")
                true
            } catch (_: Throwable) {
                false
            }
        } else {
            false
        }
    }

    @JvmStatic
    external fun TProxyStartService(configPath: String, fd: Int): Boolean

    @JvmStatic
    external fun TProxyStopService(): Boolean

    @JvmStatic
    external fun TProxyIsRunning(): Boolean

    @JvmStatic
    external fun TProxyGetStats(): LongArray
}
