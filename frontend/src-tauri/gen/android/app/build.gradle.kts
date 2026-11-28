import java.io.File
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

val keystoreProperties = Properties().apply {
    listOf(
        file("../keystore.properties"),
        file("../../../../../keystore/keystore.properties"),
    ).firstOrNull { it.exists() }?.let { propFile ->
        propFile.inputStream().use { load(it) }
        putIfAbsent("__baseDir", propFile.parentFile.absolutePath)
    }
}

fun resolveReleaseSigning(): Map<String, String>? {
    val envPath = System.getenv("PRISMRAY_ANDROID_KEYSTORE_PATH")?.trim().orEmpty()
    val envStorePass = System.getenv("PRISMRAY_ANDROID_KEYSTORE_PASSWORD")?.trim().orEmpty()
    val envAlias = System.getenv("PRISMRAY_ANDROID_KEY_ALIAS")?.trim().orEmpty()
    val envKeyPass = System.getenv("PRISMRAY_ANDROID_KEY_PASSWORD")?.trim().orEmpty()
    if (envPath.isNotEmpty() && envStorePass.isNotEmpty() && envAlias.isNotEmpty()) {
        val f = File(envPath)
        if (f.isFile) {
            return mapOf(
                "storeFile" to f.absolutePath,
                "storePassword" to envStorePass,
                "keyAlias" to envAlias,
                "keyPassword" to envKeyPass.ifEmpty { envStorePass },
            )
        }
    }
    val propPath = keystoreProperties.getProperty("storeFile", "").trim()
    val propStorePass = keystoreProperties.getProperty("storePassword", "").trim()
    val propAlias = keystoreProperties.getProperty("keyAlias", "").trim()
    val propKeyPass = keystoreProperties.getProperty("keyPassword", "").trim()
    if (propPath.isNotEmpty() && propStorePass.isNotEmpty() && propAlias.isNotEmpty()) {
        val baseDir = keystoreProperties.getProperty("__baseDir", projectDir.absolutePath)
        val f = File(propPath).let { if (it.isAbsolute) it else File(baseDir, propPath) }
        if (f.isFile) {
            return mapOf(
                "storeFile" to f.canonicalPath,
                "storePassword" to propStorePass,
                "keyAlias" to propAlias,
                "keyPassword" to propKeyPass.ifEmpty { propStorePass },
            )
        }
    }
    return null
}

val releaseSigning = resolveReleaseSigning()

val baseVersionName = tauriProperties.getProperty("tauri.android.versionName", "1.1.0").trim().ifEmpty { "1.1.0" }
val localBuildSeq = System.getenv("PRISMRAY_ANDROID_LOCAL_BUILD_SEQ")?.trim()?.toIntOrNull()?.takeIf { it in 1..998 }

fun computeMonotonicVersionCode(verName: String, localSeq: Int?): Int {
    val parts = verName.split("-", limit = 2)[0].split(".")
    val major = parts.getOrNull(0)?.toIntOrNull() ?: 1
    val minor = parts.getOrNull(1)?.toIntOrNull() ?: 0
    val patch = parts.getOrNull(2)?.toIntOrNull() ?: 0
    // Monotonic formula: major*10_000_000 + minor*100_000 + patch*1_000 + buildOffset
    // - Official CI releases: buildOffset = 999 (e.g. 1.0.2 -> 10002999)
    // - Local iterative builds: buildOffset = 1..998 (e.g. 1.0.2-local.1 -> 10002001)
    // Strictly > legacy 1.0.1 (1000001) and local builds always upgrade cleanly to official releases.
    val offset = localSeq ?: 999
    return major * 10_000_000 + minor * 100_000 + patch * 1_000 + offset
}

val resolvedVersionCode = computeMonotonicVersionCode(baseVersionName, localBuildSeq)
val resolvedVersionName = if (localBuildSeq != null) "$baseVersionName-local.$localBuildSeq" else baseVersionName

android {
    compileSdk = 36
    namespace = "com.crackrammer.prismray"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "com.crackrammer.prismray"
        minSdk = 26
        targetSdk = 36
        versionCode = resolvedVersionCode
        versionName = resolvedVersionName
    }
    signingConfigs {
        if (releaseSigning != null) {
            create("release") {
                storeFile = file(releaseSigning.getValue("storeFile"))
                storePassword = releaseSigning.getValue("storePassword")
                keyAlias = releaseSigning.getValue("keyAlias")
                keyPassword = releaseSigning.getValue("keyPassword")
            }
        }
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {
                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            isDebuggable = false
            isMinifyEnabled = true
            if (releaseSigning != null) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
        }
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        buildConfig = true
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

apply(from = "tauri.build.gradle.kts")
