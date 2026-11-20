// SPDX-License-Identifier: MPL-2.0

export type QrImportKind = "subscription" | "nodes";

export interface QrPayloadClassification {
  kind: QrImportKind;
  value: string;
  suggestedName: string;
  allowSwitch: boolean;
}

const NODE_URI_PREFIXES = [
  "vless://",
  "vmess://",
  "ss://",
  "ssr://",
  "trojan://",
  "hysteria2://",
  "hy2://",
  "tuic://",
  "anytls://",
  "socks://",
  "socks5://",
  "naive+https://",
  "naive+quic://",
  "wg://",
  "wireguard://",
];

export function classifyQrPayload(rawInput: string): QrPayloadClassification {
  const value = rawInput.trim();
  const lines = value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length === 1) {
    const single = lines[0];
    const lower = single.toLowerCase();
    if (NODE_URI_PREFIXES.some((prefix) => lower.startsWith(prefix))) {
      return {
        kind: "nodes",
        value: single,
        suggestedName: "",
        allowSwitch: false,
      };
    }
    if (lower.startsWith("http://") || lower.startsWith("https://")) {
      try {
        const parsed = new URL(single);
        // HTTP/HTTPS proxy share links carry explicit credentials + port and empty/root path.
        const looksLikeHttpProxyNode =
          Boolean(parsed.username || parsed.password) &&
          Boolean(parsed.port) &&
          (parsed.pathname === "" || parsed.pathname === "/");
        if (looksLikeHttpProxyNode) {
          return {
            kind: "nodes",
            value: single,
            suggestedName: parsed.hostname,
            allowSwitch: true,
          };
        }
        const suggestedName = decodeURIComponent(parsed.hash.replace(/^#/, "").trim()) || parsed.hostname;
        return {
          kind: "subscription",
          value: single,
          suggestedName,
          allowSwitch: true,
        };
      } catch {
        // Fall through to generic node/batch import.
      }
    }
  }

  return {
    kind: "nodes",
    value,
    suggestedName: "",
    allowSwitch: false,
  };
}

export async function decodeCanvasQr(
  source: HTMLImageElement | HTMLVideoElement | ImageBitmap,
  width: number,
  height: number
): Promise<string | null> {
  if (width <= 0 || height <= 0) return null;
  const maxDim = 1600;
  const scale = Math.min(1, maxDim / Math.max(width, height));
  const w = Math.max(1, Math.round(width * scale));
  const h = Math.max(1, Math.round(height * scale));
  const canvas = document.createElement("canvas");
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return null;
  ctx.drawImage(source, 0, 0, w, h);
  const imageData = ctx.getImageData(0, 0, w, h);
  const mod = await import("jsqr");
  const jsQR = mod.default;
  const found = jsQR(imageData.data, imageData.width, imageData.height, {
    inversionAttempts: "attemptBoth",
  });
  return found?.data?.trim() || null;
}

export async function decodeImageFileQr(file: Blob): Promise<string | null> {
  const objectUrl = URL.createObjectURL(file);
  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const el = new Image();
      el.onload = () => resolve(el);
      el.onerror = () => reject(new Error("Invalid image"));
      el.src = objectUrl;
    });
    return await decodeCanvasQr(img, img.naturalWidth || img.width, img.naturalHeight || img.height);
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}
