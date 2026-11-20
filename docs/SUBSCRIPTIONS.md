# Subscription Compatibility (v1.0.0)

The URL subscription refresh, batch paste import, and API `POST /api/subscription/import` endpoints share a unified parser (`backend/internal/config`) supporting all **11 protocols** of PrismRay `v1.0.0`.

## Supported Inputs & Protocols

| Input Format | Supported Coverage |
| --- | --- |
| Share links / Base64 | `vless://`, `vmess://`, `trojan://`, `ss://` (SIP002 / SS2022 / legacy), `hysteria2://` / `hy2://`, `tuic://`, `anytls://`, `wireguard://` / `wg://`, `naive+https://` / `naive+quic://`, `socks5://` / `socks://`, `http://` / `https://` |
| Clash / Clash.Meta / Mihomo / Stash YAML | `proxies` entries across all supported protocols (`skip-cert-verify`, `alpn`, `sni`, `obfs`, `ports`, `mport`, `up`/`down`, `reality-opts`, etc.) |
| sing-box JSON | `outbounds` and `endpoints` (`wireguard`), preserving transport, TLS/REALITY, and protocol extensions |
| Xray / V2Ray JSON | `outbounds` including `vless` + `xhttp` (`xhttpSettings`), `httpupgrade`, `vless_encryption`, `mldsa65_verify` |
| V2Ray batch JSON | Array of Xray/V2Ray configuration objects |
| Shadowsocks SIP008 JSON | `servers` wrapper, object, or array of server objects |
| WireGuard `.conf` | INI `[Interface]` + `[Peer]` profiles (`PrivateKey`, `Address`, `MTU`, `PublicKey`, `PresharedKey`, `Endpoint`, `Reserved`) |

## Resilient Import & Diagnostics

- Mixed batches use **resilient parsing**: valid entries are imported cleanly while unsupported schemes (such as `ssr://`), broken lines, or non-AEAD legacy options are recorded in structured `skipped` entries (`index`, `name`, `reason`, `raw`) rather than aborting the valid nodes.
- If **zero** valid nodes can be extracted from a payload, the API returns HTTP `400` and preserves existing stored nodes untouched.
- Nodes with `allow_insecure: true` (or `skip-cert-verify: true` / `insecure=1`) are preserved with an explicit red `Insecure TLS` badge in the UI and surfaced in `warnings`.
- Nodes using `xhttp`, `httpupgrade`, `vless_encryption`, or `mldsa65_verify` are automatically tagged as needing the `Xray Coprocessor` (`engine_pref`/auto-routing).
- `NaiveProxy` nodes import and persist in `prismray.db`; when compiling `sing-box` configs on hosts where `libcronet` / `with_naive_outbound` is unavailable, those nodes are gracefully skipped with `skipped_naive` surfaced in `/api/process/status` and the UI Overview alert.
- Scheduled or manual refreshes (`POST /api/subscriptions/{id}/refresh`) preserve existing `user_alias` overrides and `favorite` flags across syncs, and extract subscription `Subscription-Userinfo` (`upload`, `download`, `total`, `expire`) quota headers.
