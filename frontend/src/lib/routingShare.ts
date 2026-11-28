// SPDX-License-Identifier: MPL-2.0

import type { RoutingProfile } from "./api.ts";

export const ROUTING_SHARE_GZIP_PREFIX = "prismray-route://v1/";
export const ROUTING_SHARE_PLAIN_PREFIX = "prismray-route://v1-plain/";
export const QR_MAX_SAFE_CHARS = 2900;
export const MAX_DECOMPRESSED_SHARE_BYTES = 2 * 1024 * 1024;

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(input: string): Uint8Array {
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const binary = atob(b64 + pad);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

async function gzipBytes(data: Uint8Array): Promise<Uint8Array | null> {
  if (typeof CompressionStream === "undefined") return null;
  try {
    const cs = new CompressionStream("gzip");
    const outPromise = new Response(cs.readable).arrayBuffer();
    const writer = cs.writable.getWriter();
    await writer.write(new Uint8Array(data));
    await writer.close();
    const buf = await outPromise;
    return new Uint8Array(buf);
  } catch {
    return null;
  }
}

async function gunzipBytes(data: Uint8Array, maxBytes = MAX_DECOMPRESSED_SHARE_BYTES): Promise<Uint8Array> {
  if (typeof DecompressionStream === "undefined") {
    throw new Error("DecompressionStream is unavailable in this runtime");
  }
  const ds = new DecompressionStream("gzip");
  const writer = ds.writable.getWriter();
  const writePromise = (async () => {
    await writer.write(new Uint8Array(data));
    await writer.close();
  })();

  const reader = ds.readable.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        totalBytes += value.byteLength;
        if (totalBytes > maxBytes) {
          await reader.cancel().catch(() => {});
          throw new Error(`Routing share payload exceeds ${maxBytes} byte safety limit`);
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
    await writePromise.catch(() => {});
  }

  const out = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/**
 * Compactly encodes a RoutingProfile into a QR-friendly share string using gzip + base64url.
 */
export async function encodeRoutingShareString(profile: RoutingProfile): Promise<string> {
  const jsonText = JSON.stringify(profile);
  const rawBytes = new TextEncoder().encode(jsonText);
  const compressed = await gzipBytes(rawBytes);
  if (compressed && compressed.length < rawBytes.length) {
    return ROUTING_SHARE_GZIP_PREFIX + bytesToBase64Url(compressed);
  }
  return ROUTING_SHARE_PLAIN_PREFIX + bytesToBase64Url(rawBytes);
}

function extractRoutingProfile(parsed: unknown): RoutingProfile {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Invalid routing profile JSON object");
  }
  const obj = parsed as Record<string, unknown>;
  const candidate =
    obj.routing_profile && typeof obj.routing_profile === "object" && !Array.isArray(obj.routing_profile)
      ? (obj.routing_profile as Record<string, unknown>)
      : obj;

  const hasKnownKey =
    "mode" in candidate ||
    "custom_rules" in candidate ||
    "local_dns" in candidate ||
    "remote_dns" in candidate ||
    "bypass_cn" in candidate ||
    "block_ads" in candidate;
  if (!hasKnownKey) {
    throw new Error("No valid routing or DNS policy fields detected");
  }

  const modeRaw = typeof candidate.mode === "string" ? candidate.mode.trim() : "rule";
  const mode = modeRaw === "global" || modeRaw === "direct" ? modeRaw : "rule";
  const customRules = Array.isArray(candidate.custom_rules) ? candidate.custom_rules : [];

  const bypassLan = typeof candidate.bypass_lan === "boolean" ? candidate.bypass_lan : true;

  return {
    ...(candidate as unknown as RoutingProfile),
    mode,
    block_ads: typeof candidate.block_ads === "boolean" ? candidate.block_ads : true,
    bypass_lan: bypassLan,
    allow_lan_broadcast:
      bypassLan && typeof candidate.allow_lan_broadcast === "boolean" ? candidate.allow_lan_broadcast : false,
    bypass_cn: typeof candidate.bypass_cn === "boolean" ? candidate.bypass_cn : true,
    local_dns: typeof candidate.local_dns === "string" && candidate.local_dns.trim() ? candidate.local_dns.trim() : "223.5.5.5",
    remote_dns:
      typeof candidate.remote_dns === "string" && candidate.remote_dns.trim()
        ? candidate.remote_dns.trim()
        : "https://1.1.1.1/dns-query",
    custom_rules_enabled:
      typeof candidate.custom_rules_enabled === "boolean" ? candidate.custom_rules_enabled : true,
    custom_rules: customRules as RoutingProfile["custom_rules"],
  };
}

/**
 * Decodes either a compressed `prismray-route://v1/...` share string, a plain share string,
 * a standalone RoutingProfile JSON, or a full v4 backup JSON containing `routing_profile`.
 */
export async function decodeRoutingShareInput(rawInput: string): Promise<RoutingProfile> {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new Error("Please enter or scan valid routing configuration content");
  }
  let jsonText = trimmed;
  if (trimmed.startsWith(ROUTING_SHARE_GZIP_PREFIX)) {
    const payload = trimmed.slice(ROUTING_SHARE_GZIP_PREFIX.length).trim();
    const inflated = await gunzipBytes(base64UrlToBytes(payload));
    jsonText = new TextDecoder().decode(inflated);
  } else if (trimmed.startsWith(ROUTING_SHARE_PLAIN_PREFIX)) {
    const payload = trimmed.slice(ROUTING_SHARE_PLAIN_PREFIX.length).trim();
    const rawBytes = base64UrlToBytes(payload);
    if (rawBytes.byteLength > MAX_DECOMPRESSED_SHARE_BYTES) {
      throw new Error(`Routing share payload exceeds ${MAX_DECOMPRESSED_SHARE_BYTES} byte safety limit`);
    }
    jsonText = new TextDecoder().decode(rawBytes);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    throw new Error("Unable to parse as valid JSON or PrismRay routing share string");
  }
  return extractRoutingProfile(parsed);
}
