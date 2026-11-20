// SPDX-License-Identifier: MPL-2.0
use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::Manager;

#[derive(Default)]
pub struct Backend {
    pub child: Option<Child>,
    pub connection: Option<serde_json::Value>,
    pub error: String,
    pub stopping: bool,
}

pub type State = Arc<Mutex<Backend>>;

#[tauri::command]
pub fn backend_connection(state: tauri::State<'_, State>) -> Result<serde_json::Value, String> {
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

    std::thread::spawn(move || loop {
        if state.lock().unwrap().stopping {
            break;
        }
        #[cfg(target_os = "android")]
        if let Some(existing) = probe_existing_android_ipc(&data_dir) {
            {
                let mut s = state.lock().unwrap();
                s.connection = Some(existing);
                s.error.clear();
            }
            loop {
                std::thread::sleep(Duration::from_secs(2));
                if state.lock().unwrap().stopping {
                    return;
                }
                if probe_existing_android_ipc(&data_dir).is_none() {
                    let mut s = state.lock().unwrap();
                    s.connection = None;
                    break;
                }
            }
            continue;
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
                let _ = &config_path;
                if let Some(ref lib_dir) = native_dir {
                    cmd.env("PRISMRAY_NATIVE_LIB_DIR", lib_dir);
                }
            }
            #[cfg(not(target_os = "android"))]
            {
                cmd.arg("--mode=desktop").arg("--desktop");
                if let Some(ref cfg_file) = config_path {
                    cmd.arg("--config").arg(cfg_file);
                }
                cmd.arg("--data-dir").arg(&data_dir);
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
            Ok(child) => state.lock().unwrap().child = Some(child),
            Err(e) => {
                let mut s = state.lock().unwrap();
                s.error = e;
                s.connection = None;
            }
        }
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let mut s = state.lock().unwrap();
            if s.stopping {
                return;
            }
            let alive = s
                .child
                .as_mut()
                .and_then(|c| c.try_wait().ok())
                .map(|v| v.is_none())
                .unwrap_or(false);
            if !alive {
                s.connection = None;
                s.child = None;
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    });
    Ok(())
}

pub fn stop(state: &State) {
    let mut s = state.lock().unwrap();
    s.stopping = true;
    if let Some(mut child) = s.child.take() {
        drop(child.stdin.take());
        for _ in 0..100 {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[tauri::command]
pub fn prepare_update(state: tauri::State<'_, State>) {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    stop(state.inner());
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let _ = state;
}
