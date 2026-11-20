// SPDX-License-Identifier: MPL-2.0

export type ThemeMode = "system" | "light" | "dark";
export const THEME_STORAGE_KEY = "prismray-color-scheme";

export function normalizeThemeMode(raw: string | null | undefined): ThemeMode {
  if (raw === "light" || raw === "dark" || raw === "system") {
    return raw;
  }
  return "system";
}

export function resolveColorScheme(mode: ThemeMode, systemPrefersDark: boolean): "light" | "dark" {
  if (mode === "light" || mode === "dark") {
    return mode;
  }
  return systemPrefersDark ? "dark" : "light";
}

export function getStoredThemeMode(): ThemeMode {
  if (typeof window === "undefined") {
    return "system";
  }
  try {
    return normalizeThemeMode(window.localStorage.getItem(THEME_STORAGE_KEY));
  } catch {
    return "system";
  }
}

export function applyThemeMode(mode: ThemeMode, persist = true): "light" | "dark" {
  const systemDark =
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches;
  const resolved = resolveColorScheme(mode, systemDark);

  if (typeof document !== "undefined") {
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) {
      meta.setAttribute("content", mode === "system" ? "light dark" : mode);
    }
    document.documentElement.classList.toggle("dark", resolved === "dark");
    document.documentElement.style.colorScheme = resolved;
  }

  if (persist && typeof window !== "undefined") {
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, mode);
    } catch {
      // Ignore storage access errors in locked-down webviews.
    }
  }
  return resolved;
}

export function subscribeThemeChanges(onChange: (mode: ThemeMode, resolved: "light" | "dark") => void): () => void {
  if (typeof window === "undefined") {
    return () => {};
  }
  const media =
    typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-color-scheme: dark)")
      : null;

  const sync = () => {
    const mode = getStoredThemeMode();
    const resolved = applyThemeMode(mode, false);
    onChange(mode, resolved);
  };

  const onStorage = (event: StorageEvent) => {
    if (event.key === null || event.key === THEME_STORAGE_KEY) {
      sync();
    }
  };

  media?.addEventListener("change", sync);
  window.addEventListener("storage", onStorage);
  return () => {
    media?.removeEventListener("change", sync);
    window.removeEventListener("storage", onStorage);
  };
}
