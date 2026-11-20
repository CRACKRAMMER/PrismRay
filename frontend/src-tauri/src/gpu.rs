// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    sync::OnceLock,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GpuMode {
    Auto,
    On,
    Off,
}

impl GpuMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "on" | "enable" | "enabled" | "true" | "1" => Some(Self::On),
            "off" | "disable" | "disabled" | "false" | "0" => Some(Self::Off),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RenderConfigFile {
    gpu_mode: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GpuStatus {
    pub configured_mode: String,
    pub effective_mode: String,
    pub cli_override: Option<String>,
    pub active: bool,
    pub session: String,
    pub vendor: String,
    pub has_render_node: bool,
    pub detail: String,
    pub restart_required: bool,
}

static INITIAL_CLI_OVERRIDE: OnceLock<Option<GpuMode>> = OnceLock::new();
static INITIAL_ACTIVE: OnceLock<(bool, String, String, bool, String)> = OnceLock::new();

fn config_file_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return Some(PathBuf::from(appdata).join("prismray").join("desktop-render.json"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return Some(
                PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("prismray")
                    .join("desktop-render.json"),
            );
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            return Some(PathBuf::from(xdg).join("prismray").join("desktop-render.json"));
        }
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".config").join("prismray").join("desktop-render.json"))
}

fn load_saved_mode() -> GpuMode {
    let Some(path) = config_file_path() else {
        return GpuMode::Auto;
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return GpuMode::Auto;
    };
    serde_json::from_str::<RenderConfigFile>(&raw)
        .ok()
        .and_then(|c| GpuMode::parse(&c.gpu_mode))
        .unwrap_or(GpuMode::Auto)
}

fn save_mode(mode: &GpuMode) -> Result<(), String> {
    let path = config_file_path().ok_or_else(|| "unable to resolve config directory".to_string())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let body = serde_json::to_string_pretty(&RenderConfigFile {
        gpu_mode: mode.as_str().to_string(),
    })
    .map_err(|e| e.to_string())?;
    fs::write(path, body).map_err(|e| e.to_string())
}

fn parse_cli_override() -> Option<GpuMode> {
    let args: Vec<String> = std::env::args().collect();
    let mut override_mode: Option<GpuMode> = None;
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-h" | "--help" => {
                println!(
                    "PrismRay v1.0.0\n\
                     Usage: prismray [OPTIONS]\n\
                       --gpu=auto|on|off    Configure GPU hardware rendering (overrides saved preference)\n\
                       --enable-gpu         Force enable GPU hardware acceleration\n\
                       --disable-gpu        Force software compatibility rendering\n\
                       --minimized          Start minimized in the system tray\n\
                       -h, --help           Show this help message"
                );
                std::process::exit(0);
            }
            "--enable-gpu" => override_mode = Some(GpuMode::On),
            "--disable-gpu" => override_mode = Some(GpuMode::Off),
            "--gpu" => {
                if let Some(next) = args.get(i + 1) {
                    if let Some(parsed) = GpuMode::parse(next) {
                        override_mode = Some(parsed);
                        i += 1;
                    }
                }
            }
            _ if arg.starts_with("--gpu=") => {
                if let Some(parsed) = GpuMode::parse(&arg["--gpu=".len()..]) {
                    override_mode = Some(parsed);
                }
            }
            _ => {}
        }
        i += 1;
    }
    override_mode
}

fn detect_environment() -> (String, String, bool) {
    #[cfg(target_os = "linux")]
    {
        let session = if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            "wayland".to_string()
        } else if std::env::var_os("DISPLAY").is_some() {
            "x11".to_string()
        } else {
            "headless".to_string()
        };

        let mut has_render_node = false;
        if let Ok(entries) = fs::read_dir("/dev/dri") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("renderD") {
                    if fs::OpenOptions::new().read(true).open(entry.path()).is_ok()
                        || entry.metadata().is_ok()
                    {
                        has_render_node = true;
                        break;
                    }
                }
            }
        }

        let mut vendor = "Unknown".to_string();
        if let Ok(entries) = fs::read_dir("/sys/class/drm") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if !name_str.starts_with("card") || name_str.contains('-') {
                    continue;
                }
                if let Ok(raw_vendor) = fs::read_to_string(entry.path().join("device/vendor")) {
                    vendor = match raw_vendor.trim().to_ascii_lowercase().as_str() {
                        "0x1002" => "AMD Radeon (DRM)".into(),
                        "0x8086" => "Intel Graphics (DRM)".into(),
                        "0x10de" => "NVIDIA".into(),
                        "0x1af4" => "VirtIO GPU".into(),
                        "0x15ad" => "VMware SVGA".into(),
                        other => format!("GPU ({})", other),
                    };
                    break;
                }
            }
        }

        return (session, vendor, has_render_node);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let session = if cfg!(target_os = "windows") {
            "win32-webview2".to_string()
        } else if cfg!(target_os = "macos") {
            "cocoa-webkit".to_string()
        } else {
            "desktop".to_string()
        };
        (session, "System Native GPU".to_string(), true)
    }
}

/// Inspects CLI arguments, saved preference, and system DRM/display state before WebView init.
pub fn init_gpu_environment() {
    let cli = parse_cli_override();
    let _ = INITIAL_CLI_OVERRIDE.set(cli.clone());
    let saved = load_saved_mode();
    let effective = cli.unwrap_or(saved);
    let (session, vendor, has_render_node) = detect_environment();

    let (active, detail) = match effective {
        GpuMode::Off => {
            #[cfg(target_os = "linux")]
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
            #[cfg(target_os = "windows")]
            std::env::set_var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "--disable-gpu");
            (false, "已强制关闭硬件加速（软件兼容渲染）".to_string())
        }
        GpuMode::On => {
            #[cfg(target_os = "linux")]
            std::env::remove_var("WEBKIT_DISABLE_DMABUF_RENDERER");
            #[cfg(target_os = "windows")]
            std::env::remove_var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
            (
                true,
                format!("已强制开启 GPU 硬件加速（{} / {}）", session, vendor),
            )
        }
        GpuMode::Auto => {
            #[cfg(target_os = "linux")]
            {
                let predisabled =
                    std::env::var("WEBKIT_DISABLE_DMABUF_RENDERER").ok().as_deref() == Some("1");
                if has_render_node && !predisabled {
                    (
                        true,
                        format!("自动检测通过：已启用 GPU 硬件加速（{} / {}）", session, vendor),
                    )
                } else if predisabled {
                    (
                        false,
                        "检测到外部环境变量 WEBKIT_DISABLE_DMABUF_RENDERER=1，已沿用软件渲染"
                            .to_string(),
                    )
                } else {
                    std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
                    (
                        false,
                        format!("未检测到可用的 /dev/dri/renderD* 渲染节点（{}），已自动切换软件渲染", session),
                    )
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                (true, format!("自动检测通过：系统原生 GPU 加速（{}）", session))
            }
        }
    };

    let _ = INITIAL_ACTIVE.set((active, session, vendor, has_render_node, detail));
}

fn current_status(restart_required: bool) -> GpuStatus {
    let saved = load_saved_mode();
    let cli = INITIAL_CLI_OVERRIDE.get().cloned().flatten();
    let effective = cli.as_ref().unwrap_or(&saved).clone();
    let (active, session, vendor, has_render_node, detail) =
        INITIAL_ACTIVE.get().cloned().unwrap_or_else(|| {
            let (s, v, has) = detect_environment();
            (has, s, v, has, "Runtime initialized".to_string())
        });

    GpuStatus {
        configured_mode: saved.as_str().to_string(),
        effective_mode: effective.as_str().to_string(),
        cli_override: cli.map(|c| c.as_str().to_string()),
        active,
        session,
        vendor,
        has_render_node,
        detail,
        restart_required,
    }
}

#[tauri::command]
pub fn get_gpu_status() -> GpuStatus {
    current_status(false)
}

#[tauri::command]
pub fn set_gpu_mode(mode: String) -> Result<GpuStatus, String> {
    let parsed = GpuMode::parse(&mode)
        .ok_or_else(|| "invalid gpu mode (expected auto, on, or off)".to_string())?;
    let previous = load_saved_mode();
    save_mode(&parsed)?;
    Ok(current_status(parsed != previous))
}
