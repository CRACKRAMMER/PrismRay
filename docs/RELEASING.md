# 使用 GitHub Actions 构建 Release (v1.0.0)

工作流：
- `.github/workflows/build.yml`（`Build desktop packages and draft release`）：跨平台原生安装包与草稿 Release
- `.github/workflows/arch-repo.yml`（`Build Arch Linux Pacman repository`）：原生 Arch Linux Pacman 统一软件源（`CRACKRAMMER/arch-repo`）与 `.pkg.tar.zst`
- `.github/workflows/homebrew-tap.yml`（`Publish Homebrew Cask to tap`）：在 Release 正式发布后自动同步 `Casks/prismray.rb` 与 `Casks/prismray-lite.rb` 到 `CRACKRAMMER/homebrew-tap`

## 触发与产物矩阵

- **手动触发（分支）**：先运行 `.github/workflows/ci.yml`（Go `-race`/`vet` + Frontend `npm test`/`npm run build` + Headless Web/Desktop/Subscription 集成测试 + Cargo `--locked` 检查），随后并行为以下目标构建并直出独立安装包（桌面端同时输出 **Full 内置 `sing-box` + `Xray` 版** 与 **Lite 精简壳体版**）：
  - `linux-x64`：`prismray-linux-x64-{full,lite}.deb`、`prismray-linux-x64-{full,lite}.rpm`、`prismray-linux-x64-{full,lite}.AppImage`
  - `windows-x64`：`prismray-windows-x64-{full,lite}.exe`（NSIS）、`prismray-windows-x64-{full,lite}.msi`（WiX）
  - `macos-arm64`：`prismray-macos-arm64-{full,lite}.dmg`
  - `headless-linux-x64` / `headless-linux-arm64`：`prismray-headless-linux-*.tar.gz`（纯静态 `prismray-server` + `web/` 静态前端 + `prismray-server.service`）
  - `android-arm64`：`prismray-android-arm64.apk`（包名 `com.crackrammer.prismray`，内嵌 `libprismray.so` / `libsingbox.so` / `libxray.so` + 全流量 TUN + 原生扫码）
- **Arch Linux Pacman 统一源（`.github/workflows/arch-repo.yml`）**：
  - 在 `archlinux:base-devel` 容器内原生构建 `prismray` 与 `prismray-server` 的 `.pkg.tar.zst`
  - 配置仓库 Secret `ARCH_REPO_TOKEN`（对 `CRACKRAMMER/arch-repo` 具备 `Contents: Read and write` 的 Fine-grained PAT）时，自动拉取 `CRACKRAMMER/arch-repo` 现有 `gh-pages` 进行**多项目增量合并**（仅替换 `prismray` / `prismray-server` 旧版本，完整保留其他项目的 `.pkg.tar.zst`、`.sig`、其他架构目录及 `CNAME`），并发布至 `[crackrammer]`（`https://crackrammer.github.io/arch-repo/arch/$arch`）；可通过仓库变量 `ARCH_REPO_SLUG` / `ARCH_REPO_NAME` / `ARCH_PAGES_URL` 覆盖默认值
  - 未配置 `ARCH_REPO_TOKEN` 时（如社区 Fork），自动回退为当前仓库 `gh-pages` 独立源 `[prismray]`
  - 配置仓库 Secret `ARCH_GPG_PRIVATE_KEY`（及可选 `ARCH_GPG_PASSPHRASE`）时自动启用 GPG 签名并导出 `<repo_name>.gpg`（多项目共享 `CRACKRAMMER/arch-repo` 时请使用同一把 GPG 密钥）；未配置时优雅降级为 HTTPS 无签名源
  - 如对应 `v<VERSION>` Release 已存在，自动附带上传 `.pkg.tar.zst`（及 `.sig`）
- **macOS Homebrew Tap（`.github/workflows/homebrew-tap.yml`）**：
  - 仅在 GitHub Release **正式发布（`published`）** 或手动 `workflow_dispatch` 时运行，确保 Cask 下载地址不会指向尚未公开的草稿 Release
  - 配置仓库 Secret `HOMEBREW_TAP_TOKEN`（对 `CRACKRAMMER/homebrew-tap` 具备 `Contents: Read and write` 的 Fine-grained PAT）时，自动下载 Release 的 `SHA256SUMS.txt`，调用 `scripts/update_homebrew_cask.py` 更新 `Casks/prismray.rb`（Full）与 `Casks/prismray-lite.rb`（Lite）并推送至 `CRACKRAMMER/homebrew-tap`（可通过变量 `HOMEBREW_TAP_REPO` 覆盖目标仓库）
  - 未配置 `HOMEBREW_TAP_TOKEN` 时优雅跳过，不阻断社区 Fork 构建
- **推送 `v*` 标签（例如 `v1.0.0`）**：校验 tag 与所有清单版本严格一致，全部任务通过后自动创建或更新 **draft + prerelease**，附带所有平台独立安装包与 `SHA256SUMS.txt`（绝不覆盖已公开发布的 Release）。

## 版本一致性要求

`scripts/release.py`（`RELEASE_VALIDATE_ONLY=1`）强校验 `v<VERSION>` 与以下所有文件中的版本一致：

1. `frontend/package.json`（`"version"`）
2. `frontend/package-lock.json`（根 `"version"` 与 `packages[""]["version"]`）
3. `frontend/src-tauri/tauri.conf.json`（`"version"`）
4. `frontend/src-tauri/Cargo.toml`（`[package].version`，需同时更新 `Cargo.lock` 并通过 `cargo check --locked`）

当前版本为 **`1.0.0`**（对应标签 `v1.0.0`）。发布草稿生成后请先下载安装包核对 `SHA256SUMS.txt` 并在目标真机测试通过，再于 GitHub Releases 页面点击发布。

## 本地打包与 Android 正式签名

不触发 GitHub Actions 时，可直接在 Linux 开发机运行本地统一打包脚本，产物默认输出至已忽略的 `releases/` 目录并生成 `SHA256SUMS.txt`：

```sh
# 打包 Linux Full AppImage + Headless (x64/arm64) + Android arm64 APK
python3 scripts/build_local_release.py

# 仅打包指定目标
python3 scripts/build_local_release.py --targets linux-appimage,android
```

### Android Release 签名配置

- **本地构建**：在被 `.gitignore` 忽略的 `keystore/keystore.properties` 中提供 `storeFile`、`storePassword`、`keyAlias`、`keyPassword`（或通过环境变量 `PRISMRAY_ANDROID_KEYSTORE_PATH` / `PRISMRAY_ANDROID_KEYSTORE_PASSWORD` / `PRISMRAY_ANDROID_KEY_ALIAS` / `PRISMRAY_ANDROID_KEY_PASSWORD`），`build_local_release.py` 会自动构建经 R8 混淆与签名的正式 Release APK；未配置密钥时自动回退为 Debug APK 以便零配置开发调试。
- **GitHub Actions**：在仓库 Secrets 配置 `ANDROID_KEYSTORE_BASE64`、`ANDROID_KEYSTORE_PASSWORD`、`ANDROID_KEY_ALIAS` 与 `ANDROID_KEY_PASSWORD` 即可在 CI 中自动产出正式签名 Release APK。
