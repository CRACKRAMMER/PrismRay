// SPDX-License-Identifier: MPL-2.0

import React, { useCallback, useEffect, useId, useRef, useState } from "react";
import { AlertTriangle, Camera, CameraOff, Check, Copy, Download, ImageUp, QrCode, Upload } from "lucide-react";
import QRCode from "qrcode";
import { androidBridge, type RoutingProfile } from "../lib/api.ts";
import {
  QR_MAX_SAFE_CHARS,
  decodeRoutingShareInput,
  encodeRoutingShareString,
} from "../lib/routingShare.ts";
import { useAppStore } from "../store/appStore.ts";
import { ContextInspector } from "./ContextInspector.tsx";
import { Button } from "./ui/button.tsx";

export interface RoutingQrModalProps {
  open: boolean;
  initialTab?: "export" | "import";
  profile: RoutingProfile;
  onClose: () => void;
  onImported: (profile: RoutingProfile) => Promise<void> | void;
}

async function decodeImageElementQr(source: HTMLImageElement | HTMLVideoElement, w: number, h: number): Promise<string | null> {
  if (w <= 0 || h <= 0) return null;
  const maxDim = 1600;
  let tw = w;
  let th = h;
  if (Math.max(w, h) > maxDim) {
    const scale = maxDim / Math.max(w, h);
    tw = Math.max(1, Math.round(w * scale));
    th = Math.max(1, Math.round(h * scale));
  }
  const canvas = document.createElement("canvas");
  canvas.width = tw;
  canvas.height = th;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return null;
  ctx.drawImage(source, 0, 0, tw, th);
  const imageData = ctx.getImageData(0, 0, tw, th);
  const mod = await import("jsqr");
  const jsQR = mod.default;
  const found = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
  return found?.data || null;
}

export function RoutingQrModal({
  open,
  initialTab = "export",
  profile,
  onClose,
  onImported,
}: RoutingQrModalProps) {
  const { tr, locale, notify } = useAppStore();
  const fileInputId = useId();
  const jsonFileInputId = useId();

  const [tab, setTab] = useState<"export" | "import">(initialTab);
  const [shareText, setShareText] = useState("");
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [tooLarge, setTooLarge] = useState(false);
  const [copied, setCopied] = useState(false);

  const [importText, setImportText] = useState("");
  const [importError, setImportError] = useState("");
  const [importing, setImporting] = useState(false);
  const [cameraActive, setCameraActive] = useState(false);
  const [cameraError, setCameraError] = useState("");

  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const scanRafRef = useRef<number>(0);
  const scanBusyRef = useRef<boolean>(false);

  const stopCamera = useCallback(() => {
    if (scanRafRef.current) {
      window.cancelAnimationFrame(scanRafRef.current);
      scanRafRef.current = 0;
    }
    if (streamRef.current) {
      for (const track of streamRef.current.getTracks()) {
        track.stop();
      }
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setCameraActive(false);
  }, []);

  useEffect(() => {
    if (open) {
      setTab(initialTab);
      setImportError("");
      setCameraError("");
    } else {
      stopCamera();
    }
  }, [open, initialTab, stopCamera]);

  useEffect(() => {
    return () => stopCamera();
  }, [stopCamera]);

  useEffect(() => {
    if (!open || tab !== "export") return;
    let cancelled = false;
    void (async () => {
      try {
        const encoded = await encodeRoutingShareString(profile);
        if (cancelled) return;
        setShareText(encoded);
        if (encoded.length > QR_MAX_SAFE_CHARS) {
          setTooLarge(true);
          setQrDataUrl("");
          return;
        }
        setTooLarge(false);
        const url = await QRCode.toDataURL(encoded, {
          width: 300,
          margin: 2,
          errorCorrectionLevel: "L",
        });
        if (!cancelled) {
          setQrDataUrl(url);
        }
      } catch {
        if (!cancelled) {
          setTooLarge(true);
          setQrDataUrl("");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open, tab, profile]);

  const applyDecodedString = useCallback(
    async (raw: string) => {
      setImporting(true);
      setImportError("");
      try {
        const decoded = await decodeRoutingShareInput(raw);
        await onImported(decoded);
        notify(tr("routing.qrDecodeSuccess", { rules: decoded.custom_rules?.length || 0 }));
        stopCamera();
        setImportText("");
        onClose();
      } catch (err) {
        setImportError(err instanceof Error ? err.message : String(err));
      } finally {
        setImporting(false);
      }
    },
    [onImported, notify, tr, stopCamera, onClose],
  );

  const decodeImageFile = useCallback(
    async (file: File) => {
      setImportError("");
      const objectUrl = URL.createObjectURL(file);
      try {
        const img = await new Promise<HTMLImageElement>((resolve, reject) => {
          const el = new Image();
          el.onload = () => resolve(el);
          el.onerror = () => reject(new Error(locale === "zh-CN" ? "图片加载失败" : "Failed to load image"));
          el.src = objectUrl;
        });
        const decoded = await decodeImageElementQr(img, img.naturalWidth, img.naturalHeight);
        if (!decoded) {
          setImportError(tr("routing.qrNoCodeFound"));
          return;
        }
        setImportText(decoded);
        await applyDecodedString(decoded);
      } catch (err) {
        setImportError(err instanceof Error ? err.message : tr("routing.qrNoCodeFound"));
      } finally {
        URL.revokeObjectURL(objectUrl);
      }
    },
    [tr, locale, applyDecodedString],
  );

  useEffect(() => {
    if (!open || !androidBridge.available()) return;
    const onNativeQr = (ev: Event) => {
      const detail = (ev as CustomEvent<{ text?: string; error?: string }>).detail;
      if (detail?.error) {
        setCameraError(detail.error);
        return;
      }
      if (detail?.text) {
        setImportText(detail.text);
        void applyDecodedString(detail.text);
      }
    };
    window.addEventListener("prismray-qr-result", onNativeQr);
    return () => window.removeEventListener("prismray-qr-result", onNativeQr);
  }, [open, applyDecodedString]);

  const startCamera = useCallback(async () => {
    setCameraError("");
    setImportError("");
    if (androidBridge.available() && typeof window.PrismRayAndroid?.startQrScan === "function") {
      window.PrismRayAndroid.startQrScan();
      return;
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      setCameraError(
        tr("routing.qrCameraError", {
          err: locale === "zh-CN" ? "当前浏览器不支持摄像头接口" : "getUserMedia unsupported",
        }),
      );
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
        audio: false,
      });
      streamRef.current = stream;
      setCameraActive(true);
      window.setTimeout(() => {
        const video = videoRef.current;
        if (!video) return;
        video.srcObject = stream;
        void video.play();
        let lastScan = 0;
        const tick = (now: number) => {
          if (!streamRef.current) return;
          if (!scanBusyRef.current && now - lastScan >= 250 && video.readyState >= 2 && video.videoWidth > 0) {
            lastScan = now;
            scanBusyRef.current = true;
            void decodeImageElementQr(video, video.videoWidth, video.videoHeight)
              .then((found) => {
                if (found && streamRef.current) {
                  stopCamera();
                  setImportText(found);
                  void applyDecodedString(found);
                }
              })
              .finally(() => {
                scanBusyRef.current = false;
              });
          }
          scanRafRef.current = window.requestAnimationFrame(tick);
        };
        scanRafRef.current = window.requestAnimationFrame(tick);
      }, 60);
    } catch (err) {
      stopCamera();
      setCameraError(
        tr("routing.qrCameraError", { err: err instanceof Error ? err.message : String(err) }),
      );
    }
  }, [tr, locale, stopCamera, applyDecodedString]);

  const handleDownloadJson = () => {
    const blob = new Blob([JSON.stringify(profile, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `prismray-routing-profile-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
  };

  const handleDownloadPng = () => {
    if (!qrDataUrl) return;
    const a = document.createElement("a");
    a.href = qrDataUrl;
    a.download = `prismray-routing-qr-${new Date().toISOString().slice(0, 10)}.png`;
    a.click();
  };

  const handleCopyShare = async () => {
    if (!shareText) return;
    try {
      if (!androidBridge.copyToClipboard(shareText)) {
        await navigator.clipboard.writeText(shareText);
      }
      setCopied(true);
      notify(locale === "zh-CN" ? "路由分享串已复制" : "Routing share string copied");
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Ignore clipboard restriction.
    }
  };

  const handlePasteEvent = (e: React.ClipboardEvent) => {
    const items = Array.from(e.clipboardData?.items || []);
    const imgItem = items.find((item) => item.type.startsWith("image/"));
    if (imgItem) {
      const file = imgItem.getAsFile();
      if (file) {
        e.preventDefault();
        void decodeImageFile(file);
      }
    }
  };

  return (
    <ContextInspector
      open={open}
      title={tr("routing.qrModalTitle")}
      subtitle={
        locale === "zh-CN"
          ? `模式: ${profile.mode} · 自定义规则: ${profile.custom_rules?.length || 0} 条`
          : `Mode: ${profile.mode} · Custom Rules: ${profile.custom_rules?.length || 0}`
      }
      onClose={() => {
        stopCamera();
        onClose();
      }}
    >
      <div className="space-y-4 text-xs" onPaste={handlePasteEvent}>
        <div className="grid grid-cols-2 gap-1 rounded-[8px] border border-border bg-muted/40 p-1">
          <button
            type="button"
            onClick={() => {
              stopCamera();
              setTab("export");
            }}
            className={`rounded-[6px] px-3 py-1.5 font-medium transition-colors ${
              tab === "export"
                ? "bg-card text-foreground shadow-xs"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <QrCode className="mr-1.5 inline-block h-3.5 w-3.5" aria-hidden="true" />
            {tr("routing.qrTabExport")}
          </button>
          <button
            type="button"
            onClick={() => setTab("import")}
            className={`rounded-[6px] px-3 py-1.5 font-medium transition-colors ${
              tab === "import"
                ? "bg-card text-foreground shadow-xs"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <Upload className="mr-1.5 inline-block h-3.5 w-3.5" aria-hidden="true" />
            {tr("routing.qrTabImport")}
          </button>
        </div>

        {tab === "export" ? (
          <div className="space-y-3">
            {qrDataUrl && !tooLarge ? (
              <div className="flex flex-col items-center gap-2 rounded-[10px] border border-border bg-card p-4">
                <img
                  src={qrDataUrl}
                  alt={tr("routing.qrModalTitle")}
                  className="h-64 w-64 rounded-lg bg-white p-2 shadow-sm"
                />
                <span className="mono-num text-[11px] text-muted-foreground">
                  {shareText.length} chars · gzip+base64url
                </span>
              </div>
            ) : (
              <div className="flex items-start gap-2 rounded-[10px] border border-amber-500/40 bg-amber-500/10 p-3 text-amber-600 dark:text-amber-300">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                <span>{tr("routing.qrTooLarge", { size: shareText.length })}</span>
              </div>
            )}

            <div className="flex flex-wrap gap-2">
              {qrDataUrl && !tooLarge ? (
                <Button type="button" size="sm" variant="outline" onClick={handleDownloadPng}>
                  <Download className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  {tr("routing.qrDownloadPng")}
                </Button>
              ) : null}
              <Button type="button" size="sm" variant="outline" onClick={() => void handleCopyShare()} disabled={!shareText}>
                {copied ? <Check className="mr-1.5 h-3.5 w-3.5 text-primary" /> : <Copy className="mr-1.5 h-3.5 w-3.5" />}
                {tr("routing.qrCopyShare")}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={handleDownloadJson}>
                <Download className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                {tr("routing.exportJson")}
              </Button>
            </div>

            {shareText ? (
              <textarea
                readOnly
                value={shareText}
                rows={3}
                className="w-full rounded-[6px] border border-border bg-muted/40 p-2 font-mono text-[11px] text-muted-foreground focus:outline-none"
              />
            ) : null}
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <div className="relative inline-flex items-center">
                <input
                  id={fileInputId}
                  type="file"
                  accept="image/*"
                  className="visually-hidden peer"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    e.target.value = "";
                    if (file) void decodeImageFile(file);
                  }}
                />
                <label
                  htmlFor={fileInputId}
                  className="inline-flex min-h-9 cursor-pointer items-center rounded-md border border-input bg-background px-3 py-1.5 text-xs font-medium hover:bg-accent"
                >
                  <ImageUp className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  {tr("routing.qrUploadImage")}
                </label>
              </div>

              <div className="relative inline-flex items-center">
                <input
                  id={jsonFileInputId}
                  type="file"
                  accept="application/json,.json"
                  className="visually-hidden peer"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    e.target.value = "";
                    if (file) {
                      void file.text().then((txt) => applyDecodedString(txt));
                    }
                  }}
                />
                <label
                  htmlFor={jsonFileInputId}
                  className="inline-flex min-h-9 cursor-pointer items-center rounded-md border border-input bg-background px-3 py-1.5 text-xs font-medium hover:bg-accent"
                >
                  <Upload className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  {tr("routing.importJson")}
                </label>
              </div>

              {cameraActive ? (
                <Button type="button" size="sm" variant="destructive" onClick={stopCamera}>
                  <CameraOff className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  {tr("routing.qrStopCamera")}
                </Button>
              ) : (
                <Button type="button" size="sm" variant="outline" onClick={() => void startCamera()}>
                  <Camera className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  {tr("routing.qrStartCamera")}
                </Button>
              )}
            </div>

            {cameraActive ? (
              <div className="overflow-hidden rounded-[10px] border border-primary/40 bg-black">
                <video ref={videoRef} playsInline muted className="max-h-60 w-full object-cover" />
              </div>
            ) : null}

            {cameraError ? (
              <div className="rounded-[6px] border border-destructive/40 bg-destructive/10 px-3 py-2 text-destructive">
                {cameraError}
              </div>
            ) : null}

            <div className="space-y-1.5">
              <label className="text-muted-foreground">{tr("routing.qrPasteHint")}</label>
              <textarea
                value={importText}
                onChange={(e) => setImportText(e.target.value)}
                rows={4}
                placeholder="prismray-route://v1/... or { ... }"
                className="w-full rounded-[6px] border border-input bg-background p-2.5 font-mono text-[11px] focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>

            {importError ? (
              <div className="rounded-[6px] border border-destructive/40 bg-destructive/10 px-3 py-2 text-destructive">
                {importError}
              </div>
            ) : null}

            <div className="flex justify-end">
              <Button
                type="button"
                size="sm"
                disabled={importing || !importText.trim()}
                onClick={() => void applyDecodedString(importText)}
              >
                {tr("routing.qrApplyImport")}
              </Button>
            </div>
          </div>
        )}
      </div>
    </ContextInspector>
  );
}
