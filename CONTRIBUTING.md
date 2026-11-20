# Contributing to PrismRay

Thank you for your interest in contributing to PrismRay!

## Prerequisites

- **Go** `1.26+`
- **Node.js** `22+` and `npm`
- **Rust** (`stable`) for Tauri v2 desktop and Android builds
- **Desktop Linux libraries**: `webkit2gtk-4.1`, `gtk3`, `libayatana-appindicator3`, `openssl`, `librsvg`
- **Android (optional)**: JDK 21, Android SDK (`platforms;android-36`, `build-tools;35.0.0`), NDK `29.0.14206865`, Rust target `aarch64-linux-android`

## Local Development Workflow

```sh
# 1. Backend tests & vet
cd backend
gofmt -l .
go vet ./...
go test -race ./...

# 2. Frontend tests, typecheck & production build
cd ../frontend
npm ci
npm test
npx tsc --noEmit
npm run build

# 3. Rust desktop check & unit tests
cd src-tauri
cargo test --locked

# 4. Python packaging unit tests
cd ../..
python3 -m unittest discover -s scripts -p 'test_*.py'
```

## Coding & PR Guidelines

- **Go**: Always format with `gofmt` and ensure `go test -race ./...` passes.
- **Frontend i18n**: Keep `zh-CN` and `en-US` translation keys in 100% parity (enforced by `npm test` in `frontend/src/lib/v1.test.ts`).
- **Privacy & Security**: Never commit real proxy nodes, subscription URLs, personal host paths, `.db` files, or Android `.jks` keystores.
- **License**: All source contributions are licensed under **MPL-2.0** (matching `LICENSE`). Include the `// SPDX-License-Identifier: MPL-2.0` header in new source files.
- **Commits**: Use concise Conventional Commit prefixes (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
