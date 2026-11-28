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
pub async fn biometric_status() -> BiometricStatus {
    tauri::async_runtime::spawn_blocking(biometric_status_blocking)
        .await
        .unwrap_or_else(|_| BiometricStatus {
            available: false,
            kind: "unavailable".into(),
            detail: "Biometric status check failed".into(),
        })
}

fn biometric_status_blocking() -> BiometricStatus {
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
        return macos_la::biometric_status();
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

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let digest = sha256(key);
        k_block[..32].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    for &b in &k_block {
        inner.push(b ^ 0x36);
    }
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(64 + 32);
    for &b in &k_block {
        outer.push(b ^ 0x5c);
    }
    outer.extend_from_slice(&inner_hash);
    let mac = sha256(&outer);

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex_out = String::with_capacity(64);
    for b in mac {
        hex_out.push(HEX[(b >> 4) as usize] as char);
        hex_out.push(HEX[(b & 0x0f) as usize] as char);
    }
    hex_out
}

#[tauri::command]
pub async fn biometric_authenticate(
    state: tauri::State<'_, crate::backend::State>,
    reason: String,
    challenge: Option<String>,
) -> Result<String, String> {
    let prompt = if reason.trim().is_empty() {
        "Unlock PrismRay".to_string()
    } else {
        reason.trim().to_string()
    };
    let hmac_key = crate::backend::biometric_hmac_key_bytes(state.inner());
    let challenge_trimmed = challenge.unwrap_or_default().trim().to_string();

    tauri::async_runtime::spawn_blocking(move || {
        authenticate_blocking(&prompt)?;
        if challenge_trimmed.is_empty() {
            Ok(String::new())
        } else {
            Ok(hmac_sha256_hex(&hmac_key, challenge_trimmed.as_bytes()))
        }
    })
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
        return macos_la::authenticate(reason);
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

#[cfg(target_os = "macos")]
mod macos_la {
    use super::BiometricStatus;
    use std::ffi::{c_char, c_int, c_long, c_void, CStr, CString};
    use std::ptr;
    use std::sync::{Arc, Condvar, Mutex};

    // LAPolicy constants from Apple LocalAuthentication framework
    const LA_POLICY_BIOMETRICS: c_long = 1;
    const LA_POLICY_DEVICE_OWNER: c_long = 2;

    // Clang Objective-C Block ABI (stack/global block literal)
    const BLOCK_HAS_COPY_DISPOSE: c_int = 1 << 25;

    #[repr(C)]
    struct BlockDescriptor {
        reserved: usize,
        size: usize,
        copy_helper: unsafe extern "C" fn(*mut c_void, *const c_void),
        dispose_helper: unsafe extern "C" fn(*mut c_void),
    }

    struct ReplyState {
        done: Mutex<Option<Result<(), String>>>,
        cvar: Condvar,
    }

    #[repr(C)]
    struct ReplyBlock {
        isa: *const c_void,
        flags: c_int,
        reserved: c_int,
        invoke: unsafe extern "C" fn(*mut ReplyBlock, std::ffi::c_schar, *mut c_void),
        descriptor: *const BlockDescriptor,
        state: *const ReplyState,
    }

    extern "C" {
        static _NSConcreteStackBlock: c_void;
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn objc_msgSend();
        fn objc_autoreleasePoolPush() -> *mut c_void;
        fn objc_autoreleasePoolPop(pool: *mut c_void);
    }

    unsafe extern "C" fn block_copy(dst: *mut c_void, src: *const c_void) {
        let src_blk = &*(src as *const ReplyBlock);
        let dst_blk = &mut *(dst as *mut ReplyBlock);
        Arc::increment_strong_count(src_blk.state);
        dst_blk.state = src_blk.state;
    }

    unsafe extern "C" fn block_dispose(src: *mut c_void) {
        let blk = &*(src as *const ReplyBlock);
        if !blk.state.is_null() {
            Arc::decrement_strong_count(blk.state);
        }
    }

    static REPLY_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
        reserved: 0,
        size: std::mem::size_of::<ReplyBlock>(),
        copy_helper: block_copy,
        dispose_helper: block_dispose,
    };

    unsafe fn ns_error_message(err_obj: *mut c_void) -> String {
        if err_obj.is_null() {
            return "Touch ID / 系统认证未通过".into();
        }
        let msg_send_obj: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const ());
        let msg_send_cstr: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const c_char =
            std::mem::transmute(objc_msgSend as *const ());
        let desc = msg_send_obj(err_obj, sel_registerName(c"localizedDescription".as_ptr()));
        if desc.is_null() {
            return "Touch ID / 系统认证未通过".into();
        }
        let utf8 = msg_send_cstr(desc, sel_registerName(c"UTF8String".as_ptr()));
        if utf8.is_null() {
            return "Touch ID / 系统认证未通过".into();
        }
        CStr::from_ptr(utf8).to_string_lossy().into_owned()
    }

    unsafe extern "C" fn reply_invoke(blk: *mut ReplyBlock, success: std::ffi::c_schar, err_obj: *mut c_void) {
        let state = &*(*blk).state;
        let outcome = if success != 0 {
            Ok(())
        } else {
            Err(ns_error_message(err_obj))
        };
        if let Ok(mut guard) = state.done.lock() {
            *guard = Some(outcome);
            state.cvar.notify_all();
        }
    }

    unsafe fn alloc_init_la_context() -> *mut c_void {
        let cls = objc_getClass(c"LAContext".as_ptr());
        if cls.is_null() {
            return ptr::null_mut();
        }
        let msg_send_0: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const ());
        let alloced = msg_send_0(cls, sel_registerName(c"alloc".as_ptr()));
        if alloced.is_null() {
            return ptr::null_mut();
        }
        msg_send_0(alloced, sel_registerName(c"init".as_ptr()))
    }

    unsafe fn release_obj(obj: *mut c_void) {
        if !obj.is_null() {
            let msg_send_void: unsafe extern "C" fn(*mut c_void, *mut c_void) =
                std::mem::transmute(objc_msgSend as *const ());
            msg_send_void(obj, sel_registerName(c"release".as_ptr()));
        }
    }

    pub fn biometric_status() -> BiometricStatus {
        unsafe {
            let pool = objc_autoreleasePoolPush();
            let ctx = alloc_init_la_context();
            if ctx.is_null() {
                objc_autoreleasePoolPop(pool);
                return BiometricStatus {
                    available: false,
                    kind: "unavailable".into(),
                    detail: "LocalAuthentication framework unavailable".into(),
                };
            }
            let can_eval: unsafe extern "C" fn(*mut c_void, *mut c_void, c_long, *mut *mut c_void) -> std::ffi::c_schar =
                std::mem::transmute(objc_msgSend as *const ());
            let sel = sel_registerName(c"canEvaluatePolicy:error:".as_ptr());
            let mut err_ptr: *mut c_void = ptr::null_mut();
            let bio_ok = can_eval(ctx, sel, LA_POLICY_BIOMETRICS, &mut err_ptr) != 0;
            let owner_ok = if !bio_ok {
                err_ptr = ptr::null_mut();
                can_eval(ctx, sel, LA_POLICY_DEVICE_OWNER, &mut err_ptr) != 0
            } else {
                false
            };
            release_obj(ctx);
            objc_autoreleasePoolPop(pool);

            if bio_ok {
                BiometricStatus {
                    available: true,
                    kind: "touchid".into(),
                    detail: "macOS Touch ID".into(),
                }
            } else if owner_ok {
                BiometricStatus {
                    available: true,
                    kind: "macos_auth".into(),
                    detail: "macOS System Authentication".into(),
                }
            } else {
                BiometricStatus {
                    available: false,
                    kind: "unavailable".into(),
                    detail: "Touch ID unavailable".into(),
                }
            }
        }
    }

    pub fn authenticate(reason: &str) -> Result<(), String> {
        unsafe {
            let pool = objc_autoreleasePoolPush();
            let ctx = alloc_init_la_context();
            if ctx.is_null() {
                objc_autoreleasePoolPop(pool);
                return Err("macOS LocalAuthentication 不可用".into());
            }
            let ns_string_cls = objc_getClass(c"NSString".as_ptr());
            let c_reason = CString::new(reason).unwrap_or_else(|_| CString::new("Unlock PrismRay").unwrap());
            let make_str: unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_char) -> *mut c_void =
                std::mem::transmute(objc_msgSend as *const ());
            let ns_reason = make_str(
                ns_string_cls,
                sel_registerName(c"stringWithUTF8String:".as_ptr()),
                c_reason.as_ptr(),
            );

            let state = Arc::new(ReplyState {
                done: Mutex::new(None),
                cvar: Condvar::new(),
            });
            let mut block = ReplyBlock {
                isa: &_NSConcreteStackBlock as *const c_void,
                flags: BLOCK_HAS_COPY_DISPOSE,
                reserved: 0,
                invoke: reply_invoke,
                descriptor: &REPLY_DESCRIPTOR,
                state: Arc::as_ptr(&state),
            };

            let eval_fn: unsafe extern "C" fn(*mut c_void, *mut c_void, c_long, *mut c_void, *mut ReplyBlock) =
                std::mem::transmute(objc_msgSend as *const ());
            eval_fn(
                ctx,
                sel_registerName(c"evaluatePolicy:localizedReason:reply:".as_ptr()),
                LA_POLICY_DEVICE_OWNER,
                ns_reason,
                &mut block,
            );

            let result = {
                let mut guard = state.done.lock().map_err(|_| "biometric lock poisoned".to_string())?;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
                while guard.is_none() {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    let (next_guard, wait_res) = state
                        .cvar
                        .wait_timeout(guard, remaining)
                        .map_err(|_| "biometric wait interrupted".to_string())?;
                    guard = next_guard;
                    if wait_res.timed_out() {
                        break;
                    }
                }
                guard.take().unwrap_or_else(|| Err("Touch ID authentication timed out or failed".into()))
            };

            release_obj(ctx);
            objc_autoreleasePoolPop(pool);
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biometric_status_returns_well_formed_kind() {
        let st = biometric_status_blocking();
        assert!(!st.kind.is_empty());
        assert!(!st.detail.is_empty());
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_case2() {
        let mac = hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
