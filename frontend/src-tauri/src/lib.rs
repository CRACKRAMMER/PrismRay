// SPDX-License-Identifier: MPL-2.0

mod backend;
mod biometric;
mod gpu;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tray_icons;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::sync::{Arc, Mutex};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::time::{Duration, Instant};

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use tauri::{
    image::Image,
    menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager,
};

pub fn init_gpu_environment() {
    gpu::init_gpu_environment();
    #[cfg(target_os = "linux")]
    ensure_linux_desktop_icon();
}

#[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrayTargetItem {
    action_id: String,
    label: String,
    #[serde(default)]
    active: bool,
}

#[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrayStatePayload {
    running: bool,
    tun_enabled: bool,
    system_proxy_enabled: bool,
    mode: String,
    active_label: String,
    #[serde(default)]
    recent_targets: Vec<TrayTargetItem>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn is_double_click_trigger(last_click: &Mutex<Option<Instant>>, now: Instant) -> bool {
    if let Ok(mut guard) = last_click.lock() {
        if let Some(prev) = *guard {
            if now.saturating_duration_since(prev) <= Duration::from_millis(450) {
                *guard = None;
                return true;
            }
        }
        *guard = Some(now);
    }
    false
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn build_tray_tooltip(payload: &TrayStatePayload) -> String {
    if !payload.running {
        return "PrismRay · 已断开".to_string();
    }
    let mut channels = Vec::new();
    if payload.tun_enabled {
        channels.push("TUN");
    }
    if payload.system_proxy_enabled {
        channels.push("系统代理");
    }
    if channels.is_empty() {
        channels.push("端口监听");
    }
    let target = if payload.active_label.trim().is_empty() {
        "已连接"
    } else {
        payload.active_label.trim()
    };
    format!("PrismRay · {} · {}", channels.join(" + "), target)
}

#[cfg(target_os = "linux")]
fn ensure_linux_desktop_icon() {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Once;

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        fn write_if_changed(path: &Path, content: &[u8]) -> bool {
            if let Ok(existing) = std::fs::read(path) {
                if existing == content {
                    return false;
                }
            }
            std::fs::write(path, content).is_ok()
        }

        let data_home = std::env::var("XDG_DATA_HOME")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".local/share"))
            });

        let Some(base_dir) = data_home else {
            return;
        };

        const ICON_128_PNG: &[u8] = include_bytes!("../icons/128x128.png");
        const ICON_256_PNG: &[u8] = include_bytes!("../icons/128x128@2x.png");
        const ICON_SVG: &str = include_str!("../icons/prismray-icon.svg");

        let mut changed = false;
        let icon_names = ["prismray", "com.crackrammer.prismray", "PrismRay"];

        let png128_dir = base_dir.join("icons/hicolor/128x128/apps");
        if std::fs::create_dir_all(&png128_dir).is_ok() {
            for name in &icon_names {
                changed |= write_if_changed(&png128_dir.join(format!("{name}.png")), ICON_128_PNG);
            }
        }

        let png256_dir = base_dir.join("icons/hicolor/256x256/apps");
        if std::fs::create_dir_all(&png256_dir).is_ok() {
            for name in &icon_names {
                changed |= write_if_changed(&png256_dir.join(format!("{name}.png")), ICON_256_PNG);
            }
        }

        let svg_dir = base_dir.join("icons/hicolor/scalable/apps");
        let svg_icon_path = svg_dir.join("prismray.svg");
        if std::fs::create_dir_all(&svg_dir).is_ok() {
            for name in &icon_names {
                changed |= write_if_changed(&svg_dir.join(format!("{name}.svg")), ICON_SVG.as_bytes());
            }
        }

        let icon_ref = if svg_icon_path.exists() {
            svg_icon_path.to_string_lossy().into_owned()
        } else {
            "prismray".to_string()
        };

        let apps_dir = base_dir.join("applications");
        if std::fs::create_dir_all(&apps_dir).is_ok() {
            let exec_cmd = std::env::var("APPIMAGE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::current_exe().ok().map(|p| p.to_string_lossy().into_owned()))
                .unwrap_or_else(|| "prismray".to_string());
            let escaped_exec = exec_cmd.replace('"', "\\\"");

            // Bind every possible Wayland app_id / GTK prgname ("prismray", "PrismRay", "com.crackrammer.prismray")
            // when launched outside a system .desktop package (e.g. standalone AppImage).
            let desktop_variants = [
                ("com.crackrammer.prismray.desktop", "prismray"),
                ("prismray.desktop", "com.crackrammer.prismray"),
                ("PrismRay.desktop", "prismray"),
            ];
            for (filename, wm_class) in desktop_variants {
                let sys_desktop = PathBuf::from("/usr/share/applications").join(filename);
                if sys_desktop.exists() {
                    continue;
                }
                let desktop_entry = format!(
                    "[Desktop Entry]\nType=Application\nName=PrismRay\nExec=\"{}\"\nIcon={}\nStartupWMClass={}\nNoDisplay=true\nCategories=Network;\n",
                    escaped_exec, icon_ref, wm_class
                );
                changed |= write_if_changed(&apps_dir.join(filename), desktop_entry.as_bytes());
            }
        }

        if changed {
            let hicolor_dir = base_dir.join("icons/hicolor");
            let _ = Command::new("gtk-update-icon-cache")
                .args(["-q", "-f", "-t"])
                .arg(&hicolor_dir)
                .env_remove("LD_LIBRARY_PATH")
                .output();
            let _ = Command::new("update-desktop-database")
                .arg(&apps_dir)
                .env_remove("LD_LIBRARY_PATH")
                .output();
            let _ = Command::new("kbuildsycoca6")
                .arg("--noincremental")
                .env_remove("LD_LIBRARY_PATH")
                .output();
        }
    });
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn configure_desktop_plugins(builder: tauri::Builder<tauri::Wry>) -> tauri::Builder<tauri::Wry> {
    builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            #[cfg(target_os = "linux")]
            ensure_linux_desktop_icon();
            if let Some(icon) = app.default_window_icon().cloned() {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.set_icon(icon);
                }
            }
            backend::start(app.handle(), app.state::<backend::State>().inner().clone())?;
            if std::env::args().any(|arg| arg == "--minimized") {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            let show_item = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
            let tun_item =
                CheckMenuItem::with_id(app, "toggle:tun", "TUN 透明隧道", true, false, None::<&str>)?;
            let sys_item = CheckMenuItem::with_id(
                app,
                "toggle:sysproxy",
                "系统代理",
                true,
                false,
                None::<&str>,
            )?;
            let sep = PredefinedMenuItem::separator(app)?;
            let stop_item = MenuItem::with_id(app, "disconnect", "断开连接", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "退出 PrismRay", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[&show_item, &tun_item, &sys_item, &sep, &stop_item, &quit_item],
            )?;

            let (rgba, w, h) = tray_icons::render_tray_icon(tray_icons::TrayVisualState::Idle);
            let idle_icon = Image::new_owned(rgba, w, h);
            let last_left_click: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
            let click_tracker = Arc::clone(&last_left_click);

            let _tray = TrayIconBuilder::with_id("main")
                .icon(idle_icon)
                .tooltip("PrismRay · 待机")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main_window(app),
                    "disconnect" => {
                        let _ = app.emit("proxy-disconnect", ());
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    other => {
                        let _ = app.emit("proxy-tray-action", other);
                    }
                })
                .on_tray_icon_event(move |tray, event| match event {
                    TrayIconEvent::DoubleClick {
                        button: MouseButton::Left,
                        ..
                    } => {
                        if let Ok(mut guard) = click_tracker.lock() {
                            *guard = None;
                        }
                        show_main_window(tray.app_handle());
                    }
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } => {
                        if is_double_click_trigger(&click_tracker, Instant::now()) {
                            show_main_window(tray.app_handle());
                        }
                    }
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn configure_mobile_plugins(builder: tauri::Builder<tauri::Wry>) -> tauri::Builder<tauri::Wry> {
    builder.setup(|app| {
        use tauri::Manager;
        backend::start(app.handle(), app.state::<backend::State>().inner().clone())?;
        Ok(())
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state: backend::State = Default::default();
    let exit_state = state.clone();

    let builder = tauri::Builder::default()
        .manage(state)
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            backend::backend_connection,
            backend::prepare_update,
            biometric::biometric_status,
            biometric::biometric_authenticate,
            gpu::get_gpu_status,
            gpu::set_gpu_mode,
            update_tray
        ]);

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let builder = configure_desktop_plugins(builder);

    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = configure_mobile_plugins(builder);

    builder
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(move |_app, event| {
            if let tauri::RunEvent::Exit = event {
                backend::stop(&exit_state)
            }
        });
}

#[tauri::command]
fn update_tray(app: tauri::AppHandle, payload: TrayStatePayload) -> Result<(), String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let tray = app.tray_by_id("main").ok_or("tray missing")?;
        let visual = tray_icons::TrayVisualState::from_flags(
            payload.running,
            payload.tun_enabled,
            payload.system_proxy_enabled,
        );
        let (rgba, w, h) = tray_icons::render_tray_icon(visual);
        tray.set_icon(Some(Image::new_owned(rgba, w, h)))
            .map_err(|e| e.to_string())?;
        tray.set_tooltip(Some(build_tray_tooltip(&payload)))
            .map_err(|e| e.to_string())?;

        let menu = Menu::new(&app).map_err(|e| e.to_string())?;
        let show_item =
            MenuItem::with_id(&app, "show", "显示主窗口", true, None::<&str>).map_err(|e| e.to_string())?;
        menu.append(&show_item).map_err(|e| e.to_string())?;

        let sep1 = PredefinedMenuItem::separator(&app).map_err(|e| e.to_string())?;
        menu.append(&sep1).map_err(|e| e.to_string())?;

        let tun_item = CheckMenuItem::with_id(
            &app,
            "toggle:tun",
            "TUN 透明隧道",
            true,
            payload.tun_enabled,
            None::<&str>,
        )
        .map_err(|e| e.to_string())?;
        let sys_item = CheckMenuItem::with_id(
            &app,
            "toggle:sysproxy",
            "系统代理",
            true,
            payload.system_proxy_enabled,
            None::<&str>,
        )
        .map_err(|e| e.to_string())?;
        menu.append(&tun_item).map_err(|e| e.to_string())?;
        menu.append(&sys_item).map_err(|e| e.to_string())?;

        let sep2 = PredefinedMenuItem::separator(&app).map_err(|e| e.to_string())?;
        menu.append(&sep2).map_err(|e| e.to_string())?;

        for (id, label, key) in [
            ("mode:rule", "规则模式", "rule"),
            ("mode:global", "全局模式", "global"),
            ("mode:direct", "直连模式", "direct"),
        ] {
            let item = CheckMenuItem::with_id(
                &app,
                id,
                label,
                true,
                payload.mode.eq_ignore_ascii_case(key),
                None::<&str>,
            )
            .map_err(|e| e.to_string())?;
            menu.append(&item).map_err(|e| e.to_string())?;
        }

        if !payload.recent_targets.is_empty() {
            let sep_nodes = PredefinedMenuItem::separator(&app).map_err(|e| e.to_string())?;
            menu.append(&sep_nodes).map_err(|e| e.to_string())?;
            let recent_hdr = MenuItem::with_id(&app, "recent:header", "最近连接", false, None::<&str>)
                .map_err(|e| e.to_string())?;
            menu.append(&recent_hdr).map_err(|e| e.to_string())?;
            for target in payload.recent_targets.into_iter().take(5) {
                let item = CheckMenuItem::with_id(
                    &app,
                    &target.action_id,
                    &target.label,
                    true,
                    target.active,
                    None::<&str>,
                )
                .map_err(|e| e.to_string())?;
                menu.append(&item).map_err(|e| e.to_string())?;
            }
        }

        let sep3 = PredefinedMenuItem::separator(&app).map_err(|e| e.to_string())?;
        menu.append(&sep3).map_err(|e| e.to_string())?;

        let toggle_conn = MenuItem::with_id(
            &app,
            if payload.running { "disconnect" } else { "connect" },
            if payload.running { "断开连接" } else { "连接代理" },
            true,
            None::<&str>,
        )
        .map_err(|e| e.to_string())?;
        let quit_item =
            MenuItem::with_id(&app, "quit", "退出 PrismRay", true, None::<&str>).map_err(|e| e.to_string())?;
        menu.append(&toggle_conn).map_err(|e| e.to_string())?;
        menu.append(&quit_item).map_err(|e| e.to_string())?;

        tray.set_menu(Some(menu)).map_err(|e| e.to_string())?;
        #[cfg(target_os = "linux")]
        let _ = tray.with_inner_tray_icon(|_| linux_tray_radio::apply_linux_tray_radio_items());
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = (app, payload);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux_tray_radio {
    use gtk::prelude::*;
    use std::ffi::{c_char, c_void};
    use std::sync::OnceLock;

    struct DbusmenuRadioApi {
        _lib: libloading::Library,
        get_cached_item: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        property_set: unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> i32,
        #[cfg(test)]
        parse_menu_structure: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        #[cfg(test)]
        property_get: unsafe extern "C" fn(*mut c_void, *const c_char) -> *const c_char,
    }

    // SAFETY: Library handle and resolved C symbols are read-only once initialized in OnceLock.
    unsafe impl Send for DbusmenuRadioApi {}
    unsafe impl Sync for DbusmenuRadioApi {}

    fn api() -> Option<&'static DbusmenuRadioApi> {
        static API: OnceLock<Option<DbusmenuRadioApi>> = OnceLock::new();
        API.get_or_init(|| unsafe {
            let lib = libloading::Library::new("libdbusmenu-gtk3.so.4")
                .or_else(|_| libloading::Library::new("libdbusmenu-gtk3.so"))
                .ok()?;
            let get_cached_item = *lib
                .get::<unsafe extern "C" fn(*mut c_void) -> *mut c_void>(
                    b"dbusmenu_gtk_parse_get_cached_item\0",
                )
                .ok()?;
            let property_set = *lib
                .get::<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> i32>(
                    b"dbusmenu_menuitem_property_set\0",
                )
                .ok()?;
            #[cfg(test)]
            let parse_menu_structure = *lib
                .get::<unsafe extern "C" fn(*mut c_void) -> *mut c_void>(
                    b"dbusmenu_gtk_parse_menu_structure\0",
                )
                .ok()?;
            #[cfg(test)]
            let property_get = *lib
                .get::<unsafe extern "C" fn(*mut c_void, *const c_char) -> *const c_char>(
                    b"dbusmenu_menuitem_property_get\0",
                )
                .ok()?;
            Some(DbusmenuRadioApi {
                _lib: lib,
                get_cached_item,
                property_set,
                #[cfg(test)]
                parse_menu_structure,
                #[cfg(test)]
                property_get,
            })
        })
        .as_ref()
    }

    fn set_dbusmenu_toggle_type_radio(check: &gtk::CheckMenuItem) {
        let Some(dm) = api() else {
            return;
        };
        unsafe {
            let widget_ptr = check.as_ptr() as *mut c_void;
            let dm_item = (dm.get_cached_item)(widget_ptr);
            if !dm_item.is_null() {
                (dm.property_set)(
                    dm_item,
                    b"toggle-type\0".as_ptr() as *const c_char,
                    b"radio\0".as_ptr() as *const c_char,
                );
            }
        }
    }

    pub fn apply_linux_tray_radio_items_on_menu(gtk_menu: &gtk::Menu) {
        let mut in_recent_section = false;
        for child in gtk_menu.children() {
            if child.is::<gtk::SeparatorMenuItem>() {
                in_recent_section = false;
                continue;
            }
            let Some(mi) = child.dynamic_cast_ref::<gtk::MenuItem>() else {
                continue;
            };
            let label = mi.label().map(|s| s.to_string()).unwrap_or_default();
            if label == "最近连接" {
                in_recent_section = true;
                continue;
            }
            let Some(check) = child.dynamic_cast_ref::<gtk::CheckMenuItem>() else {
                continue;
            };
            let is_mode_radio = matches!(label.as_str(), "规则模式" | "全局模式" | "直连模式");
            if is_mode_radio || in_recent_section {
                check.set_draw_as_radio(true);
                set_dbusmenu_toggle_type_radio(check);
            }
        }
    }

    pub fn apply_linux_tray_radio_items() {
        for win in gtk::Window::list_toplevels() {
            let Some(container) = win.dynamic_cast_ref::<gtk::Container>() else {
                continue;
            };
            for child in container.children() {
                let Some(gtk_menu) = child.dynamic_cast_ref::<gtk::Menu>() else {
                    continue;
                };
                let is_prismray_menu = gtk_menu.children().iter().any(|item| {
                    item.dynamic_cast_ref::<gtk::MenuItem>()
                        .and_then(|mi| mi.label())
                        .map(|lbl| lbl == "显示主窗口")
                        .unwrap_or(false)
                });
                if is_prismray_menu {
                    apply_linux_tray_radio_items_on_menu(gtk_menu);
                }
            }
        }
    }

    #[cfg(test)]
    pub fn debug_read_toggle_type(check: &gtk::CheckMenuItem) -> Option<String> {
        let dm = api()?;
        unsafe {
            let dm_item = (dm.get_cached_item)(check.as_ptr() as *mut c_void);
            if dm_item.is_null() {
                return None;
            }
            let ptr = (dm.property_get)(dm_item, b"toggle-type\0".as_ptr() as *const c_char);
            if ptr.is_null() {
                return None;
            }
            Some(
                std::ffi::CStr::from_ptr(ptr)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }

    #[cfg(test)]
    pub fn debug_parse_menu(menu: &gtk::Menu) {
        if let Some(dm) = api() {
            unsafe {
                let _ = (dm.parse_menu_structure)(menu.as_ptr() as *mut c_void);
            }
        }
    }
}

#[cfg(all(test, not(any(target_os = "android", target_os = "ios"))))]
mod tests {
    use super::*;

    #[test]
    fn double_click_window_triggers_only_within_450ms() {
        let tracker = Mutex::new(None);
        let t0 = Instant::now();
        assert!(!is_double_click_trigger(&tracker, t0));
        assert!(is_double_click_trigger(
            &tracker,
            t0 + Duration::from_millis(250)
        ));
        // Third click immediately after starts a fresh sequence.
        assert!(!is_double_click_trigger(
            &tracker,
            t0 + Duration::from_millis(320)
        ));
        // Slow click (>450ms) does not fire double-click.
        assert!(!is_double_click_trigger(
            &tracker,
            t0 + Duration::from_millis(900)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tray_menu_marks_modes_and_targets_as_radio_not_checkbox() {
        use gtk::prelude::*;

        if gtk::init().is_err() {
            // Skip cleanly on headless runners without an active X11/Wayland display.
            return;
        }

        let menu = gtk::Menu::new();
        let show = gtk::MenuItem::with_label("显示主窗口");
        let tun = gtk::CheckMenuItem::with_label("TUN 透明隧道");
        let sys = gtk::CheckMenuItem::with_label("系统代理");
        let rule = gtk::CheckMenuItem::with_label("规则模式");
        rule.set_active(true);
        let recent_sep = gtk::SeparatorMenuItem::new();
        let recent_hdr = gtk::MenuItem::with_label("最近连接");
        recent_hdr.set_sensitive(false);
        let recent_grp = gtk::CheckMenuItem::with_label("[组] 美国");
        recent_grp.set_active(true);

        for item in [
            show.upcast_ref::<gtk::MenuItem>(),
            tun.upcast_ref::<gtk::MenuItem>(),
            sys.upcast_ref::<gtk::MenuItem>(),
            rule.upcast_ref::<gtk::MenuItem>(),
            recent_sep.upcast_ref::<gtk::MenuItem>(),
            recent_hdr.upcast_ref::<gtk::MenuItem>(),
            recent_grp.upcast_ref::<gtk::MenuItem>(),
        ] {
            menu.append(item);
            item.show();
        }

        linux_tray_radio::debug_parse_menu(&menu);
        linux_tray_radio::apply_linux_tray_radio_items_on_menu(&menu);

        assert!(!tun.draws_as_radio());
        assert!(!sys.draws_as_radio());
        assert!(rule.draws_as_radio());
        assert!(recent_grp.draws_as_radio());

        if let Some(t_tun) = linux_tray_radio::debug_read_toggle_type(&tun) {
            assert_eq!(t_tun, "checkmark");
            assert_eq!(
                linux_tray_radio::debug_read_toggle_type(&rule).as_deref(),
                Some("radio")
            );
            assert_eq!(
                linux_tray_radio::debug_read_toggle_type(&recent_grp).as_deref(),
                Some("radio")
            );
        }
    }
}
