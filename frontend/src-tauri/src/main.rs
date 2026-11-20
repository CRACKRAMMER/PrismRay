// SPDX-License-Identifier: MPL-2.0

// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    frontend_lib::init_gpu_environment();
    frontend_lib::run()
}
