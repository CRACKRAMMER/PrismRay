# 无桌面 Linux / Web 模式 (v1.0.0)

Web 服务默认监听 **http://127.0.0.1:2178**。Go 控制面同时提供 REST/WebSocket API 与生产前端静态资源；运行时不需要 Tauri、GTK、显示服务器、浏览器或 Node.js。

## 便携包构建与运行

从 GitHub Releases 下载 `prismray-headless-linux-x64.tar.gz`（或 `linux-arm64`），或在安装 Node.js 22+ 与 Go 1.26+ 的环境自行打包：

```sh
python3 scripts/build_headless.py
tar -xzf artifacts/headless/prismray-headless-linux-x64.tar.gz
cd prismray-headless-linux-x64
./prismray-server
```

若 `./web/index.html` 位于可执行文件同级目录，则无须显式传入 `--web-dir`。运行数据与配置默认保存在当前工作目录，也可分别通过 `--config` 与 `--data-dir` 指定路径（例如 `--config ~/.config/prismray/settings.json --data-dir ~/.local/share/prismray`）。

## 首次初始化与远程访问

1. 首次启动会在服务端日志打印一次性 `bootstrap_token`。
2. 在浏览器打开 http://127.0.0.1:2178，输入初始化令牌并设置主密码（至少 8 位），初始化后敏感节点凭据与订阅密钥将以 AES-256-GCM 密文写入 `prismray.db`。
3. 远程服务器建议保持回环监听并通过 SSH 隧道访问：

```sh
ssh -L 2178:127.0.0.1:2178 user@server
```

若通过反向代理公开访问，请务必启用 HTTPS 并在设置中精确配置 `server.allowed_origins`。

## Arch / CachyOS 无桌面包

`packaging/aur/prismray-server-git` 提供纯 Go + Web 静态产物安装与可选 systemd 用户单元：

```sh
systemctl --user enable --now prismray-server
journalctl --user -u prismray-server -b | grep 'First-run initialization token'
```

## 双核心与 TUN

Web 设置页支持一键检查、下载并校验 `sing-box` 与 `xray`；无桌面环境中可通过预设网络能力（`cap_net_admin`）或已登录设置页 `pkexec`/sudo 策略授权 TUN 接口。

## 自动化验证

```sh
PRISMRAY_TEST_BINARY=/path/to/prismray-server \
PRISMRAY_WEB_DIR=/path/to/web python3 scripts/test_headless_backend.py
```

测试移除 `DISPLAY`、`WAYLAND_DISPLAY`、`DBUS_SESSION_BUS_ADDRESS` 并关闭 `stdin`，验证前端静态资源无阻塞外链、首次令牌初始化、多格式订阅导入、敏感路径隔离及优雅退出。
