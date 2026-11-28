// SPDX-License-Identifier: MPL-2.0
use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};
use tauri::Manager;

pub struct Backend {
    pub child_stdin: Option<ChildStdin>,
    pub child_pid: Option<u32>,
    pub connection: Option<serde_json::Value>,
    pub data_dir: Option<PathBuf>,
    pub biometric_hmac_key: [u8; 32],
    pub exit_signal: Arc<(Mutex<bool>, Condvar)>,
    pub error: String,
    pub stopping: bool,
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            child_stdin: None,
            child_pid: None,
            connection: None,
            data_dir: None,
            biometric_hmac_key: generate_hmac_key(),
            exit_signal: Arc::new((Mutex::new(false), Condvar::new())),
            error: String::new(),
            stopping: false,
        }
    }
}

pub type State = Arc<Mutex<Backend>>;

fn generate_hmac_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(&mut key).is_ok() {
                return key;
            }
        }
    }
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                h_algorithm: *mut core::ffi::c_void,
                pb_buffer: *mut u8,
                cb_buffer: u32,
                dw_flags: u32,
            ) -> i32;
        }
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                key.as_mut_ptr(),
                key.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status == 0 {
            return key;
        }
    }
    // Defensive fallback if OS RNG is unavailable in a restricted sandbox.
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    for chunk in key.chunks_mut(8) {
        let mut h = RandomState::new().build_hasher();
        h.write_u32(std::process::id());
        if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            h.write_u128(d.as_nanos());
        }
        let bytes = h.finish().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    key
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn biometric_hmac_key_bytes(state: &State) -> [u8; 32] {
    state
        .lock()
        .map(|s| s.biometric_hmac_key)
        .unwrap_or([0u8; 32])
}

#[tauri::command]
pub fn backend_connection(state: tauri::State<'_, State>) -> Result<serde_json::Value, String> {
    #[cfg(target_os = "android")]
    {
        let existing_dir = {
            let s = state.lock().map_err(|e| e.to_string())?;
            if let Some(conn) = s.connection.clone() {
                return Ok(conn);
            }
            s.data_dir.clone()
        };
        if let Some(dir) = existing_dir {
            if let Some(conn) = probe_existing_android_ipc(&dir) {
                let mut s = state.lock().map_err(|e| e.to_string())?;
                s.connection = Some(conn.clone());
                s.error.clear();
                return Ok(conn);
            }
        }
    }
    let s = state.lock().map_err(|e| e.to_string())?;
    s.connection.clone().ok_or_else(|| {
        if s.error.is_empty() {
            "后台正在启动".into()
        } else {
            s.error.clone()
        }
    })
}

#[cfg(target_os = "android")]
fn detect_android_timezone() -> (Option<String>, Option<i32>) {
    let tz_name = Command::new("/system/bin/getprop")
        .arg("persist.sys.timezone")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());

    let offset_sec = Command::new("/system/bin/date")
        .arg("+%z")
        .output()
        .or_else(|_| Command::new("date").arg("+%z").output())
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let raw = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if raw.len() == 5 && (raw.starts_with('+') || raw.starts_with('-')) {
                let sign = if raw.starts_with('-') { -1 } else { 1 };
                let hours: i32 = raw[1..3].parse().ok()?;
                let mins: i32 = raw[3..5].parse().ok()?;
                Some(sign * (hours * 3600 + mins * 60))
            } else {
                None
            }
        });
    (tz_name, offset_sec)
}

#[cfg(target_os = "android")]
fn find_android_native_lib_dir() -> Result<PathBuf, String> {
    let maps = std::fs::read_to_string("/proc/self/maps")
        .map_err(|e| format!("failed to read /proc/self/maps: {}", e))?;
    for line in maps.lines() {
        if let Some(idx) = line.find('/') {
            let path_str = line[idx..].trim();
            if path_str.ends_with("/libfrontend_lib.so") || path_str.ends_with("/libprismray.so") {
                if let Some(parent) = std::path::Path::new(path_str).parent() {
                    return Ok(parent.to_path_buf());
                }
            }
        }
    }
    Err("unable to locate nativeLibraryDir from /proc/self/maps".into())
}

#[cfg(target_os = "android")]
fn probe_existing_android_ipc(data_dir: &PathBuf) -> Option<serde_json::Value> {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};

    let raw = std::fs::read_to_string(data_dir.join("runtime-ipc.json")).ok()?;
    let val: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let url = val.get("url")?.as_str()?.trim();
    let token = val.get("token")?.as_str()?.trim();
    if url.is_empty() || token.is_empty() {
        return None;
    }
    let without_scheme = url.strip_prefix("http://")?;
    let host_port = without_scheme.split('/').next()?;
    let addr: SocketAddr = host_port.parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(800)));
    let req = format!(
        "GET /api/auth/status HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        host_port, token
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).ok()?;
    let head = String::from_utf8_lossy(&buf[..n]);
    if head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200") {
        Some(val)
    } else {
        None
    }
}

pub fn start(app: &tauri::AppHandle, state: State) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "android")]
    let (config_path, data_dir, cache_dir, native_dir, exe) = {
        let dir = app.path().app_data_dir()?;
        std::fs::create_dir_all(&dir)?;
        let tmp_dir = app
            .path()
            .app_cache_dir()
            .unwrap_or_else(|_| dir.join("tmp"));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let lib_dir = find_android_native_lib_dir()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
        let bin = lib_dir.join("libprismray.so");
        (None::<PathBuf>, dir, Some(tmp_dir), Some(lib_dir), bin)
    };

    #[cfg(not(target_os = "android"))]
    let (config_path, data_dir, cache_dir, native_dir, exe): (
        Option<PathBuf>,
        PathBuf,
        Option<PathBuf>,
        Option<PathBuf>,
        PathBuf,
    ) = {
        let cfg_dir = app.path().config_dir()?.join("prismray");
        let run_dir = app.path().local_data_dir()?.join("prismray");
        std::fs::create_dir_all(&cfg_dir)?;
        std::fs::create_dir_all(&run_dir)?;
        let bin = std::env::current_exe()?
            .parent()
            .ok_or("missing executable directory")?
            .join(if cfg!(windows) {
                "prismray-server.exe"
            } else {
                "prismray-server"
            });
        (Some(cfg_dir.join("settings.json")), run_dir, None, None, bin)
    };

    {
        let mut s = state.lock().unwrap();
        s.data_dir = Some(data_dir.clone());
    }
    let hmac_hex = encode_hex(&biometric_hmac_key_bytes(&state));

    std::thread::spawn(move || loop {
        if state.lock().unwrap().stopping {
            break;
        }
        #[cfg(target_os = "android")]
        if let Some(existing) = probe_existing_android_ipc(&data_dir) {
            let mut s = state.lock().unwrap();
            s.connection = Some(existing);
            s.error.clear();
            // Attached to an existing Kotlin-managed libprismray.so; exit monitor cleanly with zero wakeups.
            return;
        }
        let result = (|| -> Result<Child, String> {
            let mut cmd = Command::new(&exe);
            #[cfg(target_os = "android")]
            {
                cmd.arg("--mode=android");
                cmd.arg("--data-dir").arg(&data_dir);
                cmd.env("HOME", &data_dir);
                if let Some(ref tmp_dir) = cache_dir {
                    cmd.env("TMPDIR", tmp_dir);
                }
                let _ = (&config_path, &hmac_hex);
                if let Some(ref lib_dir) = native_dir {
                    cmd.env("PRISMRAY_NATIVE_LIB_DIR", lib_dir);
                }
                let (tz_name, tz_offset) = detect_android_timezone();
                if let Some(ref tz) = tz_name {
                    cmd.env("TZ", tz);
                    cmd.env("PRISMRAY_TZ_NAME", tz);
                }
                if let Some(off) = tz_offset {
                    cmd.env("PRISMRAY_TZ_OFFSET_SEC", off.to_string());
                }
                cmd.env("GOGC", "200");
                cmd.env("GOMEMLIMIT", "96MiB");
            }
            #[cfg(not(target_os = "android"))]
            {
                cmd.arg("--mode=desktop").arg("--desktop");
                if let Some(ref cfg_file) = config_path {
                    cmd.arg("--config").arg(cfg_file);
                }
                cmd.arg("--data-dir").arg(&data_dir);
                cmd.env("PRISMRAY_BIOMETRIC_HMAC_KEY", &hmac_hex);
                if let Ok(appimage) = std::env::var("APPIMAGE") {
                    if !appimage.trim().is_empty() {
                        cmd.env("PRISMRAY_DESKTOP_EXECUTABLE", appimage);
                    }
                } else if let Ok(current_exe) = std::env::current_exe() {
                    cmd.env("PRISMRAY_DESKTOP_EXECUTABLE", current_exe);
                }
                let _ = (&native_dir, &cache_dir);
            }
            cmd.current_dir(&data_dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x08000000);
            }
            let mut child = cmd
                .spawn()
                .map_err(|e| format!("无法启动后台 {}: {}", exe.display(), e))?;
            let last_stderr: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
            if let Some(stderr) = child.stderr.take() {
                let err_buf = Arc::clone(&last_stderr);
                std::thread::spawn(move || {
                    let reader = BufReader::new(stderr);
                    for line in reader.lines().map_while(Result::ok) {
                        eprintln!("{}", line);
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            if let Ok(mut guard) = err_buf.lock() {
                                *guard = trimmed.to_string();
                            }
                        }
                    }
                });
            }
            let stdout = child.stdout.take().ok_or("missing stdout")?;
            let mut line = String::new();
            let read = BufReader::new(stdout).read_line(&mut line);
            if read.is_err() || line.trim().is_empty() {
                std::thread::sleep(Duration::from_millis(80));
                let _ = child.kill();
                let _ = child.wait();
                let detail = last_stderr
                    .lock()
                    .ok()
                    .map(|g| g.clone())
                    .filter(|s| !s.is_empty());
                if let Some(msg) = detail {
                    return Err(format!("后台启动失败: {}", msg));
                }
                return Err("无法读取后台启动状态".into());
            }
            match serde_json::from_str(&line) {
                Ok(value) => {
                    let mut s = state.lock().unwrap();
                    s.connection = Some(value);
                    s.error.clear();
                }
                Err(e) => {
                    std::thread::sleep(Duration::from_millis(80));
                    let _ = child.kill();
                    let _ = child.wait();
                    let detail = last_stderr
                        .lock()
                        .ok()
                        .map(|g| g.clone())
                        .filter(|s| !s.is_empty());
                    if let Some(msg) = detail {
                        return Err(format!("后台启动失败: {}", msg));
                    }
                    return Err(format!("后台启动失败: {}", e));
                }
            }
            Ok(child)
        })();
        match result {
            Ok(mut child) => {
                let exit_signal = {
                    let mut s = state.lock().unwrap();
                    s.child_stdin = child.stdin.take();
                    s.child_pid = Some(child.id());
                    let sig = Arc::clone(&s.exit_signal);
                    if let Ok(mut exited) = sig.0.lock() {
                        *exited = false;
                    }
                    if s.stopping {
                        s.child_stdin = None;
                    }
                    sig
                };
                // Event-driven blocking wait: zero periodic wakeups while child is running.
                let _ = child.wait();
                let stopping = {
                    let mut s = state.lock().unwrap();
                    s.connection = None;
                    s.child_stdin = None;
                    s.child_pid = None;
                    s.stopping
                };
                if let Ok(mut exited) = exit_signal.0.lock() {
                    *exited = true;
                    exit_signal.1.notify_all();
                }
                if stopping {
                    return;
                }
            }
            Err(e) => {
                let mut s = state.lock().unwrap();
                s.error = e;
                s.connection = None;
                if s.stopping {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    });
    Ok(())
}

fn force_terminate_pid(pid: u32) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill")
            .creation_flags(0x08000000)
            .args(["/F", "/PID", &pid.to_string()])
            .status();
    }
}

pub fn stop(state: &State) {
    let (pid, exit_signal) = {
        let mut s = state.lock().unwrap();
        s.stopping = true;
        // Closing child stdin triggers graceful shutdown inside prismray-server.
        drop(s.child_stdin.take());
        (s.child_pid, Arc::clone(&s.exit_signal))
    };
    if let Some(pid) = pid {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut exited = exit_signal.0.lock().unwrap();
        while !*exited {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let (guard, timeout) = exit_signal.1.wait_timeout(exited, remaining).unwrap();
            exited = guard;
            if timeout.timed_out() {
                break;
            }
        }
        let still_running = !*exited;
        drop(exited);
        if still_running {
            force_terminate_pid(pid);
        }
    }
}

#[tauri::command]
pub async fn prepare_update(state: tauri::State<'_, State>) -> Result<(), String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let cloned = state.inner().clone();
        tauri::async_runtime::spawn_blocking(move || stop(&cloned))
            .await
            .map_err(|e| format!("prepare_update failed: {}", e))?;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let _ = state;
    Ok(())
}

#[tauri::command]
pub fn resume_backend(app: tauri::AppHandle, state: tauri::State<'_, State>) -> Result<(), String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let needs_start = {
            let mut s = state.lock().map_err(|e| e.to_string())?;
            s.stopping = false;
            s.child_pid.is_none()
        };
        if needs_start {
            start(&app, state.inner().clone()).map_err(|e| e.to_string())?;
        }
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let _ = (app, state);
    Ok(())
}
