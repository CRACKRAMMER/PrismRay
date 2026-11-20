# Licensing and third-party materials

PrismRay application code is licensed under the Mozilla Public License 2.0 (SPDX: MPL-2.0). See the root LICENSE. Existing third-party notices and licenses remain applicable to their respective materials.

## Xray-core

PrismRay manages Xray-core as an external executable. Xray-core is a separate project: https://github.com/XTLS/Xray-core . Its source and license are available from that repository.

The Project X document retained at `backend/README.md` originates from Xray-core. The existing MPL 2.0 text at `backend/LICENSE` is preserved. These files are not replaced by runtime downloads.

When distributing an Xray binary with an application package, retain its applicable notices and provide the corresponding source location. Runtime binaries and geo databases are not tracked in this repository.

## Dependencies and generated components

Go, npm and Cargo dependencies retain their own licenses; the application license does not replace them. Dependency versions are recorded in `backend/go.sum`, `frontend/package-lock.json` and `frontend/src-tauri/Cargo.lock`. Retain dependency license files and attribution notices when distributing bundles.

The UI uses shadcn/ui-style components, Radix UI, Lucide and framework-generated assets. Their applicable upstream notices and asset/trademark terms remain separate from the application's license.

## Optional TUN engine

The optional TUN integration downloads or invokes a separately distributed sing-box executable (https://github.com/SagerNet/sing-box). Its upstream license and notices apply to its distribution; managed runtime downloads are not application source files.

## SQLite and cryptography

The Go backend uses modernc.org/sqlite (https://pkg.go.dev/modernc.org/sqlite) and its transitive dependencies to provide a pure-Go SQLite driver. Their upstream BSD, MIT and other applicable license notices remain in force.

Password derivation uses golang.org/x/crypto/argon2 (https://pkg.go.dev/golang.org/x/crypto/argon2), distributed under the Go project's BSD-style license. The application additionally uses Go standard-library AES-GCM for authenticated encryption.

## QR code generation

The frontend includes node-qrcode (https://github.com/soldair/node-qrcode), with the following notice:

The MIT License (MIT)

Copyright (c) 2012 Ryan Day

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## YAML subscription parser

Subscriptions use gopkg.in/yaml.v3 v3.0.1 (https://github.com/go-yaml/yaml).
The following upstream notice is retained:


This project is covered by two different licenses: MIT and Apache.

#### MIT License ####

The following files were ported to Go from C files of libyaml, and thus
are still covered by their original MIT license, with the additional
copyright staring in 2011 when the project was ported over:

    apic.go emitterc.go parserc.go readerc.go scannerc.go
    writerc.go yamlh.go yamlprivateh.go

Copyright (c) 2006-2010 Kirill Simonov
Copyright (c) 2006-2011 Kirill Simonov

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

### Apache License ###

All the remaining project files are covered by the Apache license:

Copyright (c) 2011-2019 Canonical Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
