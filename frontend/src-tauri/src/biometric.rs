// SPDX-License-Identifier: MPL-2.0

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BiometricStatus {
    pub available: bool,
    pub kind: String,
    pub detail: String,
}

#[cfg(target_os = "linux")]
fn find_in_path(bin: &str) -> Option<std::path::PathBuf> {
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let cand = dir.join(bin);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    for dir in ["/usr/bin", "/bin", "/usr/local/bin"] {
        let cand = std::path::PathBuf::from(dir).join(bin);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn current_linux_user() -> Option<String> {
    let out = std::process::Command::new("id").arg("-un").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let user = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if user.is_empty()
        || !user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return None;
    }
    Some(user)
}

#[cfg(target_os = "linux")]
fn has_enrolled_fprintd(user: &str) -> bool {
    let Some(list_bin) = find_in_path("fprintd-list") else {
        return false;
    };
    let Ok(out) = std::process::Command::new(list_bin).arg(user).output() else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with('-') && trimmed.contains("finger")
    })
}

#[tauri::command]
pub fn biometric_status() -> BiometricStatus {
    #[cfg(target_os = "linux")]
    {
        if let Some(user) = current_linux_user() {
            if has_enrolled_fprintd(&user) && find_in_path("fprintd-verify").is_some() {
                return BiometricStatus {
                    available: true,
                    kind: "fprintd".into(),
                    detail: "Linux Fingerprint (fprintd)".into(),
                };
            }
            if find_in_path("pkexec").is_some() {
                return BiometricStatus {
                    available: true,
                    kind: "polkit".into(),
                    detail: "Linux System Auth / Fingerprint (Polkit)".into(),
                };
            }
        }
        return BiometricStatus {
            available: false,
            kind: "unavailable".into(),
            detail: "No fprintd or Polkit authentication agent detected".into(),
        };
    }

    #[cfg(target_os = "macos")]
    {
        let script = r#"
import LocalAuthentication
let ctx = LAContext()
var err: NSError?
if ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) {
    print("touchid")
} else if ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) {
    print("system")
} else {
    print("none")
}
"#;
        if let Ok(out) = std::process::Command::new("/usr/bin/swift")
            .args(["-e", script])
            .output()
        {
            let mode = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if mode == "touchid" {
                return BiometricStatus {
                    available: true,
                    kind: "touchid".into(),
                    detail: "macOS Touch ID".into(),
                };
            }
            if mode == "system" {
                return BiometricStatus {
                    available: true,
                    kind: "macos_auth".into(),
                    detail: "macOS System Authentication".into(),
                };
            }
        }
        return BiometricStatus {
            available: false,
            kind: "unavailable".into(),
            detail: "Touch ID unavailable".into(),
        };
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let ps = r#"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()
$task = [System.WindowsRuntimeSystemExtensions]::AsTask($op)
$task.Wait()
Write-Output $task.Result.ToString()
"#;
        if let Ok(out) = std::process::Command::new("powershell.exe")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-NoProfile", "-NonInteractive", "-Command", ps])
            .output()
        {
            let res = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if res == "Available" {
                return BiometricStatus {
                    available: true,
                    kind: "windows_hello".into(),
                    detail: "Windows Hello".into(),
                };
            }
        }
        return BiometricStatus {
            available: false,
            kind: "unavailable".into(),
            detail: "Windows Hello is not configured".into(),
        };
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        BiometricStatus {
            available: false,
            kind: "unsupported".into(),
            detail: "System biometric unlock is not supported on this platform".into(),
        }
    }
}

#[tauri::command]
pub async fn biometric_authenticate(reason: String) -> Result<(), String> {
    let prompt = if reason.trim().is_empty() {
        "Unlock PrismRay".to_string()
    } else {
        reason.trim().to_string()
    };

    tauri::async_runtime::spawn_blocking(move || authenticate_blocking(&prompt))
        .await
        .map_err(|e| format!("biometric task failed: {}", e))?
}

fn authenticate_blocking(reason: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let _ = reason;
        let user = current_linux_user()
            .ok_or_else(|| "Unable to determine current Linux user".to_string())?;
        if has_enrolled_fprintd(&user) {
            if let Some(verify_bin) = find_in_path("fprintd-verify") {
                let status = std::process::Command::new(verify_bin)
                    .arg(&user)
                    .status()
                    .map_err(|e| format!("failed to run fprintd-verify: {}", e))?;
                if status.success() {
                    return Ok(());
                }
            }
        }
        if let Some(pkexec_bin) = find_in_path("pkexec") {
            let status = std::process::Command::new(pkexec_bin)
                .args(["--user", &user, "/bin/true"])
                .status()
                .map_err(|e| format!("failed to run pkexec: {}", e))?;
            if status.success() {
                return Ok(());
            }
            return Err("系统认证已取消或验证失败".into());
        }
        return Err("当前系统未检测到可用的指纹服务 (fprintd) 或 Polkit 认证代理".into());
    }

    #[cfg(target_os = "macos")]
    {
        let script = r#"
import Foundation
import LocalAuthentication

let ctx = LAContext()
let reason = ProcessInfo.processInfo.environment["PRISMRAY_BIO_REASON"] ?? "Unlock PrismRay"
let sema = DispatchSemaphore(value: 0)
var ok = false
var errMsg = "Authentication cancelled"
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, err in
    ok = success
    if let err = err { errMsg = err.localizedDescription }
    sema.signal()
}
sema.wait()
if ok {
    exit(0)
} else {
    fputs(errMsg + "\n", stderr)
    exit(1)
}
"#;
        let out = std::process::Command::new("/usr/bin/swift")
            .env("PRISMRAY_BIO_REASON", reason)
            .args(["-e", script])
            .output()
            .map_err(|e| format!("failed to invoke macOS LocalAuthentication: {}", e))?;
        if out.status.success() {
            return Ok(());
        }
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if msg.is_empty() {
            "Touch ID / 系统认证失败".into()
        } else {
            msg
        });
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let ps = r#"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($env:PRISMRAY_BIO_REASON)
$task = [System.WindowsRuntimeSystemExtensions]::AsTask($op)
$task.Wait()
Write-Output $task.Result.ToString()
"#;
        let out = std::process::Command::new("powershell.exe")
            .creation_flags(CREATE_NO_WINDOW)
            .env("PRISMRAY_BIO_REASON", reason)
            .args(["-NoProfile", "-NonInteractive", "-Command", ps])
            .output()
            .map_err(|e| format!("failed to invoke Windows Hello: {}", e))?;
        let res = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() && res == "Verified" {
            return Ok(());
        }
        return Err(format!("Windows Hello 验证未通过 ({})", res));
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = reason;
        Err("当前平台暂不支持系统生物认证".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biometric_status_returns_well_formed_kind() {
        let st = biometric_status();
        assert!(!st.kind.is_empty());
        assert!(!st.detail.is_empty());
    }
}
