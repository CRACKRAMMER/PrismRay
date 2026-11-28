// SPDX-License-Identifier: MPL-2.0

export type BackgroundPresetId = "none" | "aurora" | "ocean" | "sunset" | "midnight" | "custom";
export type UiDensity = "ultra" | "compact" | "comfortable";

export interface AccentPreset {
  id: string;
  hex: string;
  labelZh: string;
  labelEn: string;
}

export interface BackgroundPreset {
  id: Exclude<BackgroundPresetId, "custom">;
  labelZh: string;
  labelEn: string;
  lightGradient: string;
  darkGradient: string;
}

export interface AppearanceConfig {
  /** Custom primary accent hex (e.g. "#4f46e5"), or "" for default theme token */
  accentHex: string;
  /** Active background preset or "custom" for uploaded IndexedDB image */
  bgPreset: BackgroundPresetId;
  /** Background image/gradient blur in px (0 - 24) */
  bgBlur: number;
  /** Frosted-glass backdrop blur for sidebar, cards, and modals in px (0 - 32) */
  glassBlur: number;
  /** Background overlay dim/scrim strength in % (0 - 85) */
  bgDim: number;
  /** Translucent frosted-glass surface opacity in % (20 - 96) when custom bg is active */
  cardOpacity: number;
  /** Mobile / touch control & icon density ("ultra" | "compact" | "comfortable") */
  uiDensity: UiDensity;
}

export const APPEARANCE_STORAGE_KEY = "prismray-appearance-v1";
const WALLPAPER_DB_NAME = "prismray-appearance-db";
const WALLPAPER_STORE = "wallpapers";
const WALLPAPER_KEY = "active-wallpaper";
export const APPEARANCE_EVENT = "prismray-appearance-changed";

export const DEFAULT_APPEARANCE: AppearanceConfig = {
  accentHex: "",
  bgPreset: "none",
  bgBlur: 6,
  glassBlur: 18,
  bgDim: 14,
  cardOpacity: 64,
  uiDensity: "compact",
};

export const ACCENT_PRESETS: AccentPreset[] = [
  { id: "indigo", hex: "", labelZh: "默认蓝紫", labelEn: "Indigo" },
  { id: "emerald", hex: "#059669", labelZh: "翡翠绿", labelEn: "Emerald" },
  { id: "sky", hex: "#0284c7", labelZh: "晴空蓝", labelEn: "Sky" },
  { id: "rose", hex: "#e11d48", labelZh: "绯红", labelEn: "Rose" },
  { id: "amber", hex: "#d97706", labelZh: "琥珀橙", labelEn: "Amber" },
  { id: "violet", hex: "#7c3aed", labelZh: "紫罗兰", labelEn: "Violet" },
  { id: "slate", hex: "#475569", labelZh: "极简石墨", labelEn: "Slate" },
];

export const BACKGROUND_PRESETS: BackgroundPreset[] = [
  {
    id: "none",
    labelZh: "纯色默认",
    labelEn: "None",
    lightGradient: "none",
    darkGradient: "none",
  },
  {
    id: "aurora",
    labelZh: "极光微雾",
    labelEn: "Aurora",
    lightGradient:
      "radial-gradient(ellipse 75% 65% at 12% 16%, rgba(99, 102, 241, 0.56), transparent 60%), radial-gradient(ellipse 70% 60% at 88% 18%, rgba(16, 185, 129, 0.50), transparent 58%), radial-gradient(ellipse 75% 65% at 45% 92%, rgba(14, 165, 233, 0.48), transparent 62%), linear-gradient(135deg, #c7d2fe 0%, #99f6e4 52%, #bae6fd 100%)",
    darkGradient:
      "radial-gradient(ellipse 75% 58% at 16% 12%, rgba(99, 102, 241, 0.55), transparent 62%), radial-gradient(ellipse 70% 58% at 86% 22%, rgba(16, 185, 129, 0.45), transparent 58%), radial-gradient(ellipse 80% 62% at 48% 92%, rgba(56, 189, 248, 0.40), transparent 62%), linear-gradient(145deg, #0b1024 0%, #0d1f2d 55%, #0a1426 100%)",
  },
  {
    id: "ocean",
    labelZh: "深海折射",
    labelEn: "Ocean",
    lightGradient:
      "radial-gradient(circle at 18% 22%, rgba(2, 132, 199, 0.52), transparent 56%), radial-gradient(circle at 82% 76%, rgba(79, 70, 229, 0.44), transparent 60%), radial-gradient(circle at 55% 45%, rgba(6, 182, 212, 0.36), transparent 58%), linear-gradient(155deg, #bae6fd 0%, #cffafe 48%, #c7d2fe 100%)",
    darkGradient:
      "radial-gradient(circle at 18% 24%, rgba(14, 165, 233, 0.52), transparent 56%), radial-gradient(circle at 82% 78%, rgba(59, 130, 246, 0.48), transparent 60%), radial-gradient(circle at 52% 42%, rgba(6, 182, 212, 0.32), transparent 58%), linear-gradient(160deg, #05182e 0%, #0a2442 52%, #081229 100%)",
  },
  {
    id: "sunset",
    labelZh: "暮光暖岚",
    labelEn: "Sunset",
    lightGradient:
      "radial-gradient(ellipse 75% 60% at 18% 18%, rgba(244, 63, 94, 0.46), transparent 58%), radial-gradient(ellipse 70% 65% at 86% 28%, rgba(245, 158, 11, 0.48), transparent 60%), radial-gradient(ellipse 75% 58% at 50% 90%, rgba(139, 92, 246, 0.42), transparent 60%), linear-gradient(135deg, #fecdd3 0%, #fde68a 50%, #ddd6fe 100%)",
    darkGradient:
      "radial-gradient(ellipse 75% 60% at 18% 18%, rgba(225, 29, 72, 0.48), transparent 58%), radial-gradient(ellipse 70% 65% at 85% 28%, rgba(217, 119, 6, 0.44), transparent 60%), radial-gradient(ellipse 75% 58% at 50% 90%, rgba(124, 58, 237, 0.46), transparent 60%), linear-gradient(145deg, #240c1a 0%, #2b1815 52%, #18102b 100%)",
  },
  {
    id: "midnight",
    labelZh: "暗夜星云",
    labelEn: "Midnight",
    lightGradient:
      "radial-gradient(circle at 22% 20%, rgba(124, 58, 237, 0.48), transparent 56%), radial-gradient(circle at 78% 80%, rgba(14, 165, 233, 0.42), transparent 58%), radial-gradient(circle at 55% 40%, rgba(236, 72, 153, 0.30), transparent 55%), linear-gradient(145deg, #ddd6fe 0%, #e0e7ff 55%, #cbd5e1 100%)",
    darkGradient:
      "radial-gradient(circle at 22% 18%, rgba(139, 92, 246, 0.54), transparent 54%), radial-gradient(circle at 78% 78%, rgba(56, 189, 248, 0.40), transparent 56%), radial-gradient(circle at 52% 48%, rgba(236, 72, 153, 0.28), transparent 64%), linear-gradient(160deg, #0c0720 0%, #141736 55%, #090b18 100%)",
  },
];

export function clampNumber(value: number, min: number, max: number, fallback: number): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, value));
}

export function normalizeHexColor(raw: string): string {
  const s = (raw || "").trim();
  if (!s) return "";
  const full = /^#([0-9a-fA-F]{6})$/.exec(s);
  if (full) return `#${full[1].toLowerCase()}`;
  const short = /^#([0-9a-fA-F]{3})$/.exec(s);
  if (short) {
    const [r, g, b] = short[1].toLowerCase().split("");
    return `#${r}${r}${g}${g}${b}${b}`;
  }
  return "";
}

export function hexToRgb(hex: string): { r: number; g: number; b: number } | null {
  const norm = normalizeHexColor(hex);
  if (!norm) return null;
  const n = parseInt(norm.slice(1), 16);
  return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255 };
}

export function rgbToHex(r: number, g: number, b: number): string {
  const toByte = (v: number) => Math.round(clampNumber(v, 0, 255, 0)).toString(16).padStart(2, "0");
  return `#${toByte(r)}${toByte(g)}${toByte(b)}`;
}

/** Convert HSV (h in [0, 360), s in [0, 1], v in [0, 1]) to RGB (0-255) */
export function hsvToRgb(h: number, s: number, v: number): { r: number; g: number; b: number } {
  const hh = ((h % 360) + 360) % 360;
  const ss = clampNumber(s, 0, 1, 0);
  const vv = clampNumber(v, 0, 1, 0);
  const c = vv * ss;
  const x = c * (1 - Math.abs(((hh / 60) % 2) - 1));
  const m = vv - c;
  let rp = 0;
  let gp = 0;
  let bp = 0;
  if (hh < 60) [rp, gp, bp] = [c, x, 0];
  else if (hh < 120) [rp, gp, bp] = [x, c, 0];
  else if (hh < 180) [rp, gp, bp] = [0, c, x];
  else if (hh < 240) [rp, gp, bp] = [0, x, c];
  else if (hh < 300) [rp, gp, bp] = [x, 0, c];
  else [rp, gp, bp] = [c, 0, x];
  return {
    r: Math.round((rp + m) * 255),
    g: Math.round((gp + m) * 255),
    b: Math.round((bp + m) * 255),
  };
}

/** Convert RGB (0-255) to HSV (h in [0, 360), s in [0, 1], v in [0, 1]) */
export function rgbToHsv(r: number, g: number, b: number): { h: number; s: number; v: number } {
  const rn = clampNumber(r, 0, 255, 0) / 255;
  const gn = clampNumber(g, 0, 255, 0) / 255;
  const bn = clampNumber(b, 0, 255, 0) / 255;
  const max = Math.max(rn, gn, bn);
  const min = Math.min(rn, gn, bn);
  const d = max - min;
  let h = 0;
  if (d > 0) {
    if (max === rn) h = 60 * (((gn - bn) / d) % 6);
    else if (max === gn) h = 60 * ((bn - rn) / d + 2);
    else h = 60 * ((rn - gn) / d + 4);
  }
  if (h < 0) h += 360;
  const s = max === 0 ? 0 : d / max;
  return { h, s, v: max };
}

function linearizeChannel(channel255: number): number {
  const c = channel255 / 255;
  return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
}

/** WCAG 2.x relative luminance in [0, 1] */
export function relativeLuminance(rgb: { r: number; g: number; b: number }): number {
  return (
    0.2126 * linearizeChannel(rgb.r) +
    0.7152 * linearizeChannel(rgb.g) +
    0.0722 * linearizeChannel(rgb.b)
  );
}

export function contrastRatioForHex(hexA: string, hexB: string): number {
  const a = hexToRgb(hexA);
  const b = hexToRgb(hexB);
  if (!a || !b) return 1;
  const l1 = relativeLuminance(a);
  const l2 = relativeLuminance(b);
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}

/** Pick WCAG-accessible foreground (#ffffff or #0f172a) for any custom accent color */
export function pickAccessibleForeground(hex: string): string {
  const whiteContrast = contrastRatioForHex(hex, "#ffffff");
  const darkContrast = contrastRatioForHex(hex, "#0f172a");
  return whiteContrast >= darkContrast ? "#ffffff" : "#0f172a";
}

function mixRgb(
  a: { r: number; g: number; b: number },
  b: { r: number; g: number; b: number },
  weightB: number,
): string {
  const w = Math.min(1, Math.max(0, weightB));
  const r = Math.round(a.r * (1 - w) + b.r * w);
  const g = Math.round(a.g * (1 - w) + b.g * w);
  const bl = Math.round(a.b * (1 - w) + b.b * w);
  return `rgb(${r}, ${g}, ${bl})`;
}

export function normalizeAppearance(raw: Partial<AppearanceConfig> | null | undefined): AppearanceConfig {
  const validPresets: BackgroundPresetId[] = ["none", "aurora", "ocean", "sunset", "midnight", "custom"];
  const validDensities: UiDensity[] = ["ultra", "compact", "comfortable"];
  const bgPreset =
    raw?.bgPreset && validPresets.includes(raw.bgPreset) ? raw.bgPreset : DEFAULT_APPEARANCE.bgPreset;
  const uiDensity =
    raw?.uiDensity && validDensities.includes(raw.uiDensity)
      ? raw.uiDensity
      : DEFAULT_APPEARANCE.uiDensity;
  return {
    accentHex: normalizeHexColor(raw?.accentHex ?? ""),
    bgPreset,
    bgBlur: Math.round(clampNumber(Number(raw?.bgBlur), 0, 24, DEFAULT_APPEARANCE.bgBlur)),
    glassBlur: Math.round(clampNumber(Number(raw?.glassBlur), 0, 32, DEFAULT_APPEARANCE.glassBlur)),
    bgDim: Math.round(clampNumber(Number(raw?.bgDim), 0, 85, DEFAULT_APPEARANCE.bgDim)),
    cardOpacity: Math.round(clampNumber(Number(raw?.cardOpacity), 20, 96, DEFAULT_APPEARANCE.cardOpacity)),
    uiDensity,
  };
}

export function loadAppearanceConfig(): AppearanceConfig {
  if (typeof window === "undefined") return { ...DEFAULT_APPEARANCE };
  try {
    const raw = window.localStorage.getItem(APPEARANCE_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_APPEARANCE };
    return normalizeAppearance(JSON.parse(raw) as Partial<AppearanceConfig>);
  } catch {
    return { ...DEFAULT_APPEARANCE };
  }
}

export function saveAppearanceConfig(config: AppearanceConfig): AppearanceConfig {
  const normalized = normalizeAppearance(config);
  if (typeof window !== "undefined") {
    try {
      window.localStorage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify(normalized));
    } catch {
      // Ignore storage write errors in restricted environments.
    }
    window.dispatchEvent(new CustomEvent(APPEARANCE_EVENT, { detail: normalized }));
  }
  return normalized;
}

/**
 * Apply custom accent colors and frosted-glass surface tokens onto document.documentElement.
 * Uses sRGB-derived mixing rather than oklch+neutrals to guarantee consistent hues across
 * Chromium and WebKitGTK without low-chroma hue-shift artifacts.
 */
export function applyAppearanceToDocument(
  config: AppearanceConfig,
  resolvedTheme: "light" | "dark",
  hasWallpaperImage = false,
): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.setAttribute("data-ui-density", config.uiDensity || DEFAULT_APPEARANCE.uiDensity);
  const rgb = hexToRgb(config.accentHex);

  if (rgb) {
    const accentBgAlpha = resolvedTheme === "dark" ? 0.2 : 0.12;
    const accentFg =
      resolvedTheme === "dark"
        ? mixRgb(rgb, { r: 248, g: 250, b: 252 }, 0.62)
        : mixRgb(rgb, { r: 15, g: 23, b: 42 }, 0.24);
    const glowAlpha = resolvedTheme === "dark" ? 0.26 : 0.16;

    root.style.setProperty("--primary", config.accentHex);
    root.style.setProperty("--primary-foreground", pickAccessibleForeground(config.accentHex));
    root.style.setProperty("--ring", config.accentHex);
    root.style.setProperty("--accent", `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${accentBgAlpha})`);
    root.style.setProperty("--accent-foreground", accentFg);
    root.style.setProperty("--hero-glow", `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${glowAlpha})`);
    root.style.setProperty("--primary-rgb", `${rgb.r}, ${rgb.g}, ${rgb.b}`);
  } else {
    root.style.removeProperty("--primary");
    root.style.removeProperty("--primary-foreground");
    root.style.removeProperty("--ring");
    root.style.removeProperty("--accent");
    root.style.removeProperty("--accent-foreground");
    root.style.removeProperty("--hero-glow");
    root.style.removeProperty("--primary-rgb");
  }

  const customBgActive = config.bgPreset !== "none" && (config.bgPreset !== "custom" || hasWallpaperImage);
  if (customBgActive) {
    const opacity = clampNumber(config.cardOpacity, 20, 96, DEFAULT_APPEARANCE.cardOpacity) / 100;
    const sidebarOpacity = Math.max(0.18, opacity - 0.04);
    const popoverOpacity = Math.min(0.95, opacity + 0.16);
    const mutedOpacity = Math.max(0.16, opacity - 0.16);

    root.setAttribute("data-custom-bg", "true");
    root.style.setProperty("--bg-blur", `${config.bgBlur}px`);
    root.style.setProperty("--glass-blur", `${config.glassBlur}px`);
    root.style.setProperty("--bg-dim", `${clampNumber(config.bgDim, 0, 85, DEFAULT_APPEARANCE.bgDim) / 100}`);

    if (resolvedTheme === "dark") {
      root.style.setProperty("--card", `rgba(18, 20, 28, ${opacity.toFixed(2)})`);
      root.style.setProperty("--surface-elevated", `rgba(18, 20, 28, ${opacity.toFixed(2)})`);
      root.style.setProperty("--sidebar-surface", `rgba(13, 15, 22, ${sidebarOpacity.toFixed(2)})`);
      root.style.setProperty("--popover", `rgba(22, 25, 35, ${popoverOpacity.toFixed(2)})`);
      root.style.setProperty("--muted", `rgba(28, 32, 44, ${mutedOpacity.toFixed(2)})`);
      root.style.setProperty("--glass-border", "rgba(255, 255, 255, 0.13)");
    } else {
      root.style.setProperty("--card", `rgba(255, 255, 255, ${opacity.toFixed(2)})`);
      root.style.setProperty("--surface-elevated", `rgba(255, 255, 255, ${opacity.toFixed(2)})`);
      root.style.setProperty("--sidebar-surface", `rgba(255, 255, 255, ${sidebarOpacity.toFixed(2)})`);
      root.style.setProperty("--popover", `rgba(255, 255, 255, ${popoverOpacity.toFixed(2)})`);
      root.style.setProperty("--muted", `rgba(241, 245, 249, ${mutedOpacity.toFixed(2)})`);
      root.style.setProperty("--glass-border", "rgba(255, 255, 255, 0.52)");
    }
  } else {
    root.removeAttribute("data-custom-bg");
    root.style.removeProperty("--bg-blur");
    root.style.removeProperty("--glass-blur");
    root.style.removeProperty("--bg-dim");
    root.style.removeProperty("--card");
    root.style.removeProperty("--surface-elevated");
    root.style.removeProperty("--sidebar-surface");
    root.style.removeProperty("--popover");
    root.style.removeProperty("--muted");
    root.style.removeProperty("--glass-border");
  }
}

/* ---------- IndexedDB storage for compressed local wallpaper images ---------- */

let cachedWallpaperDBPromise: Promise<IDBDatabase> | null = null;

function openWallpaperDB(): Promise<IDBDatabase> {
  if (cachedWallpaperDBPromise) {
    return cachedWallpaperDBPromise;
  }
  cachedWallpaperDBPromise = new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      cachedWallpaperDBPromise = null;
      reject(new Error("IndexedDB unavailable"));
      return;
    }
    const req = indexedDB.open(WALLPAPER_DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(WALLPAPER_STORE)) {
        db.createObjectStore(WALLPAPER_STORE);
      }
    };
    req.onsuccess = () => {
      const db = req.result;
      db.onclose = () => {
        cachedWallpaperDBPromise = null;
      };
      db.onversionchange = () => {
        db.close();
        cachedWallpaperDBPromise = null;
      };
      resolve(db);
    };
    req.onerror = () => {
      cachedWallpaperDBPromise = null;
      reject(req.error ?? new Error("IndexedDB open failed"));
    };
  });
  return cachedWallpaperDBPromise;
}

export async function loadWallpaperDataUrl(): Promise<string | null> {
  try {
    const db = await openWallpaperDB();
    return await new Promise<string | null>((resolve, reject) => {
      const tx = db.transaction(WALLPAPER_STORE, "readonly");
      const store = tx.objectStore(WALLPAPER_STORE);
      const req = store.get(WALLPAPER_KEY);
      req.onsuccess = () => resolve(typeof req.result === "string" ? req.result : null);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return null;
  }
}

export async function saveWallpaperDataUrl(dataUrl: string): Promise<void> {
  const db = await openWallpaperDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(WALLPAPER_STORE, "readwrite");
    const store = tx.objectStore(WALLPAPER_STORE);
    const req = store.put(dataUrl, WALLPAPER_KEY);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(APPEARANCE_EVENT, { detail: { wallpaperUpdated: true } }));
  }
}

export async function clearWallpaperDataUrl(): Promise<void> {
  try {
    const db = await openWallpaperDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(WALLPAPER_STORE, "readwrite");
      const store = tx.objectStore(WALLPAPER_STORE);
      const req = store.delete(WALLPAPER_KEY);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  } catch {
    // Ignore cleanup errors.
  }
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(APPEARANCE_EVENT, { detail: { wallpaperUpdated: true } }));
  }
}

/**
 * Downscale and compress a user-selected image file to max 1920px along its longest edge
 * so even 4K/8K photos load instantly from IndexedDB with low GPU texture memory usage.
 */
export async function compressWallpaperFile(file: File, maxDimension = 1920): Promise<string> {
  const rawDataUrl = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(reader.error ?? new Error("Failed to read image file"));
    reader.readAsDataURL(file);
  });

  if (typeof Image === "undefined" || typeof document === "undefined") {
    return rawDataUrl;
  }

  return await new Promise<string>((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      try {
        const w = img.naturalWidth || img.width;
        const h = img.naturalHeight || img.height;
        if (!w || !h) {
          resolve(rawDataUrl);
          return;
        }
        const scale = Math.min(1, maxDimension / Math.max(w, h));
        const targetW = Math.max(1, Math.round(w * scale));
        const targetH = Math.max(1, Math.round(h * scale));

        const canvas = document.createElement("canvas");
        canvas.width = targetW;
        canvas.height = targetH;
        const ctx = canvas.getContext("2d");
        if (!ctx) {
          resolve(rawDataUrl);
          return;
        }
        ctx.imageSmoothingEnabled = true;
        ctx.imageSmoothingQuality = "high";
        ctx.drawImage(img, 0, 0, targetW, targetH);

        const webp = canvas.toDataURL("image/webp", 0.86);
        if (webp.startsWith("data:image/webp")) {
          resolve(webp);
          return;
        }
        resolve(canvas.toDataURL("image/jpeg", 0.86));
      } catch {
        resolve(rawDataUrl);
      }
    };
    img.onerror = () => reject(new Error("Invalid image file"));
    img.src = rawDataUrl;
  });
}
