// SPDX-License-Identifier: MPL-2.0
package com.crackrammer.prismray

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File

internal object AndroidBackendLauncher {
    private const val TAG = "PrismRayBackend"
    private const val PREFS_NAME = "prismray_prefs"
    private const val KEY_BOOT_AUTOSTART = "boot_autostart"

    private val lock = Any()

    @Volatile
    private var managedProcess: Process? = null

    fun isBootAutostartEnabled(context: Context): Boolean {
        return context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_BOOT_AUTOSTART, false)
    }

    fun setBootAutostartEnabled(context: Context, enabled: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_BOOT_AUTOSTART, enabled)
            .apply()
    }

    private fun resolveDataDir(context: Context): File {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val dataDir = context.dataDir
            if (File(dataDir, "prismray.db").exists() || File(dataDir, "runtime-ipc.json").exists()) {
                return dataDir
            }
        }
        return context.filesDir
    }

    fun isBackendAlive(context: Context): Boolean {
        val res = RuntimeIpc.request(context, "GET", "/api/auth/status")
        return res != null && res.statusCode in 200..299
    }

    /**
     * Ensures the local Go backend (`libprismray.so`) is listening for IPC requests.
     * Used during headless BOOT_COMPLETED, Android Always-on VPN, or cold-start Home Screen Widget toggles.
     */
    fun ensureBackendRunning(context: Context, timeoutMs: Long = 7000L): Boolean {
        val appCtx = context.applicationContext
        if (isBackendAlive(appCtx)) {
            return true
        }

        synchronized(lock) {
            if (isBackendAlive(appCtx)) {
                return true
            }

            val nativeDir = appCtx.applicationInfo.nativeLibraryDir
            if (nativeDir.isNullOrBlank()) {
                Log.e(TAG, "nativeLibraryDir is unavailable")
                return false
            }
            val exe = File(nativeDir, "libprismray.so")
            if (!exe.isFile) {
                Log.e(TAG, "Missing native backend binary: ${exe.absolutePath}")
                return false
            }

            val existing = managedProcess
            if (existing == null || !isProcessAlive(existing)) {
                val dataDir = resolveDataDir(appCtx).apply { mkdirs() }
                val tmpDir = appCtx.cacheDir.apply { mkdirs() }
                try {
                    val pb = ProcessBuilder(
                        exe.absolutePath,
                        "--mode=android",
                        "--data-dir",
                        dataDir.absolutePath,
                    )
                    pb.directory(dataDir)
                    val env = pb.environment()
                    env["HOME"] = dataDir.absolutePath
                    env["TMPDIR"] = tmpDir.absolutePath
                    env["PRISMRAY_NATIVE_LIB_DIR"] = nativeDir
                    pb.redirectErrorStream(true)
                    val proc = pb.start()
                    managedProcess = proc
                    // Drain stdout/stderr so child never blocks on a full pipe buffer.
                    Thread({
                        try {
                            proc.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                                while (reader.readLine() != null) {
                                    // Keep pipe drained.
                                }
                            }
                        } catch (_: Throwable) {
                        }
                    }, "prismray-bg-backend-io").apply {
                        isDaemon = true
                        start()
                    }
                    Log.i(TAG, "Spawned headless Android backend in ${dataDir.absolutePath}")
                } catch (err: Throwable) {
                    Log.e(TAG, "Failed to spawn headless backend: ${err.message}", err)
                    return false
                }
            }
        }

        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (isBackendAlive(appCtx)) {
                return true
            }
            try {
                Thread.sleep(250)
            } catch (_: InterruptedException) {
                break
            }
        }
        return isBackendAlive(appCtx)
    }

    private fun isProcessAlive(proc: Process): Boolean {
        return try {
            proc.exitValue()
            false
        } catch (_: IllegalThreadStateException) {
            true
        }
    }
}
