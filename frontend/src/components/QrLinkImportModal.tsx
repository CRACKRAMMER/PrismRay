// SPDX-License-Identifier: MPL-2.0

import React, { useCallback, useEffect, useId, useRef, useState } from "react";
import {
  Camera,
  CameraOff,
  ClipboardPaste,
  DownloadCloud,
  ImageUp,
  Loader2,
  QrCode,
  Rss,
} from "lucide-react";
import { api, formatApiError, isAndroidClient } from "../lib/api.ts";
import { classifyQrPayload, decodeCanvasQr, decodeImageFileQr, type QrImportKind } from "../lib/qrImport.ts";
import { useAppStore } from "../store/appStore.ts";
import { ContextInspector } from "./ContextInspector.tsx";
import { Button } from "./ui/button.tsx";
import { Input } from "./ui/input.tsx";

export interface QrLinkImportModalProps {
  open: boolean;
  defaultMode?: QrImportKind;
  onClose: () => void;
  onImported?: () => void;
}

export function QrLinkImportModal({
  open,
  defaultMode,
  onClose,
  onImported,
}: QrLinkImportModalProps) {
  const { tr, refreshAll, setLastImportDiagnostic, notify } = useAppStore();
  const fileInputId = useId();

  const [payloadText, setPayloadText] = useState("");
  const [importKind, setImportKind] = useState<QrImportKind>(defaultMode || "nodes");
  const [allowSwitch, setAllowSwitch] = useState(false);
  const [subName, setSubName] = useState("");
  const [statusError, setStatusError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [cameraActive, setCameraActive] = useState(false);

  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const rafRef = useRef<number>(0);

  const stopCamera = useCallback(() => {
    if (rafRef.current) {
      window.cancelAnimationFrame(rafRef.current);
      rafRef.current = 0;
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

  const applyScannedPayload = useCallback(
    (raw: string) => {
      const trimmed = raw.trim();
      if (!trimmed) return;
      const cls = classifyQrPayload(trimmed);
      setPayloadText(cls.value);
      setImportKind(cls.kind);
      setAllowSwitch(cls.allowSwitch);
      if (cls.suggestedName) {
        setSubName((prev) => prev.trim() || cls.suggestedName);
      }
      setStatusError("");
      stopCamera();
      notify(tr("qr.decodedSuccess"));
    },
    [notify, stopCamera, tr]
  );

  useEffect(() => {
    if (!open) {
      stopCamera();
      return;
    }
    setStatusError("");
    if (defaultMode && !payloadText) {
      setImportKind(defaultMode);
    }
  }, [open, defaultMode, payloadText, stopCamera]);

  useEffect(() => {
    return () => stopCamera();
  }, [stopCamera]);

  // Listen for Android native ZXing scanner callback
  useEffect(() => {
    if (!open) return;
    const onNativeQr = (event: Event) => {
      const detail = (event as CustomEvent<{ text?: string; cancelled?: boolean }>).detail;
      if (detail?.cancelled || !detail?.text) return;
      applyScannedPayload(detail.text);
    };
    window.addEventListener("prismray-qr-result", onNativeQr);
    return () => window.removeEventListener("prismray-qr-result", onNativeQr);
  }, [open, applyScannedPayload]);

  // Listen for Ctrl+V pasted QR screenshots on Desktop/Web
  useEffect(() => {
    if (!open) return;
    const onPaste = (event: ClipboardEvent) => {
      const items = event.clipboardData?.items;
      if (!items) return;
      for (const item of Array.from(items)) {
        if (item.type.startsWith("image/")) {
          const blob = item.getAsFile();
          if (!blob) continue;
          event.preventDefault();
          void decodeImageFileQr(blob)
            .then((decoded) => {
              if (decoded) {
                applyScannedPayload(decoded);
              } else {
                setStatusError(tr("qr.noCodeFound"));
              }
            })
            .catch(() => setStatusError(tr("qr.noCodeFound")));
          return;
        }
      }
    };
    window.addEventListener("paste", onPaste);
    return () => window.removeEventListener("paste", onPaste);
  }, [open, applyScannedPayload, tr]);

  const startScanner = async () => {
    setStatusError("");
    if (isAndroidClient() && typeof window.PrismRayAndroid?.startQrScan === "function") {
      try {
        window.PrismRayAndroid.startQrScan();
        return;
      } catch {
        // Fall through to WebView getUserMedia scanner.
      }
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      setStatusError(tr("qr.cameraUnsupported"));
      return;
    }
    try {
      stopCamera();
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: "environment" } },
        audio: false,
      });
      streamRef.current = stream;
      setCameraActive(true);
      requestAnimationFrame(() => {
        const video = videoRef.current;
        if (!video) return;
        video.srcObject = stream;
        void video.play().catch(() => {});
        let busy = false;
        const tick = () => {
          if (!streamRef.current || !videoRef.current) return;
          if (!busy && video.readyState >= 2 && video.videoWidth > 0) {
            busy = true;
            void decodeCanvasQr(video, video.videoWidth, video.videoHeight)
              .then((decoded) => {
                if (decoded) {
                  applyScannedPayload(decoded);
                }
              })
              .finally(() => {
                busy = false;
              });
          }
          rafRef.current = window.requestAnimationFrame(tick);
        };
        rafRef.current = window.requestAnimationFrame(tick);
      });
    } catch (err) {
      setStatusError(formatApiError(err));
      stopCamera();
    }
  };

  const handleImageFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setStatusError("");
    try {
      const decoded = await decodeImageFileQr(file);
      if (decoded) {
        applyScannedPayload(decoded);
      } else {
        setStatusError(tr("qr.noCodeFound"));
      }
    } catch {
      setStatusError(tr("qr.noCodeFound"));
    }
  };

  const handleManualChange = (next: string) => {
    setPayloadText(next);
    const cls = classifyQrPayload(next);
    setImportKind(cls.kind);
    setAllowSwitch(cls.allowSwitch);
    if (cls.suggestedName && !subName.trim()) {
      setSubName(cls.suggestedName);
    }
  };

  const handleImportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = payloadText.trim();
    if (!trimmed) {
      setStatusError(tr("qr.emptyPayload"));
      return;
    }
    setSubmitting(true);
    setStatusError("");
    try {
      if (importKind === "subscription") {
        const name = subName.trim() || classifyQrPayload(trimmed).suggestedName || "QR Feed";
        const subs = await api.createSubscription({
          name,
          url: trimmed,
          auto_update_hours: 24,
        });
        const created = subs.find((s) => s.url === trimmed) || subs[subs.length - 1];
        if (created?.id) {
          try {
            await api.refreshSubscription(created.id);
          } catch (refreshErr) {
            notify(formatApiError(refreshErr), "error");
          }
        }
        await refreshAll();
        notify(tr("qr.subAdded", { name }));
      } else {
        const isUrl = /^https?:\/\//i.test(trimmed) && !trimmed.includes("\n");
        const res = await api.importSubscription(isUrl ? { url: trimmed } : { content: trimmed });
        setLastImportDiagnostic(res);
        await refreshAll();
        notify(tr("subs.importedCount", { count: res.imported || 0 }));
      }
      setPayloadText("");
      setSubName("");
      onImported?.();
      onClose();
    } catch (err) {
      setStatusError(formatApiError(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <ContextInspector open={open} title={tr("qr.modalTitle")} onClose={onClose}>
      <form onSubmit={(e) => void handleImportSubmit(e)} className="space-y-4">
        <p className="text-xs text-muted-foreground leading-relaxed">{tr("qr.modalDesc")}</p>

        {/* Scan & Upload Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {cameraActive ? (
            <Button type="button" size="sm" variant="destructive" onClick={stopCamera}>
              <CameraOff className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              {tr("qr.stopCamera")}
            </Button>
          ) : (
            <Button type="button" size="sm" onClick={() => void startScanner()}>
              <Camera className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              {tr("qr.scanCamera")}
            </Button>
          )}
          <label
            htmlFor={fileInputId}
            className="inline-flex h-8 cursor-pointer items-center justify-center rounded-[6px] border border-border bg-background px-3 text-xs font-medium text-foreground transition-colors hover:bg-muted"
          >
            <ImageUp className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            {tr("qr.uploadImage")}
          </label>
          <input
            id={fileInputId}
            type="file"
            accept="image/*"
            className="visually-hidden"
            onChange={(e) => void handleImageFileChange(e)}
          />
          <span className="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
            <ClipboardPaste className="h-3.5 w-3.5" aria-hidden="true" />
            {tr("qr.pasteHint")}
          </span>
        </div>

        {/* Live Web/Desktop Camera Preview */}
        {cameraActive ? (
          <div className="relative overflow-hidden rounded-[8px] border border-border bg-black">
            <video ref={videoRef} playsInline muted className="aspect-video w-full object-cover" />
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
              <div className="h-44 w-44 rounded-[12px] border-2 border-primary/80 shadow-[0_0_0_9999px_rgba(0,0,0,0.35)]" />
            </div>
          </div>
        ) : null}

        {/* Decoded Payload & Smart Type Selector */}
        <div className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <label className="text-xs font-medium text-muted-foreground">{tr("qr.payloadLabel")}</label>
            <div className="inline-flex items-center rounded-[6px] border border-border bg-muted/40 p-0.5 text-[11px]">
              <button
                type="button"
                onClick={() => setImportKind("nodes")}
                className={[
                  "inline-flex items-center gap-1 rounded-[4px] px-2 py-1 font-medium transition-colors",
                  importKind === "nodes"
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground",
                ].join(" ")}
              >
                <DownloadCloud className="h-3 w-3" aria-hidden="true" />
                {tr("qr.modeNodes")}
              </button>
              <button
                type="button"
                disabled={!allowSwitch && importKind !== "subscription" && !/^https?:\/\//i.test(payloadText.trim())}
                onClick={() => setImportKind("subscription")}
                className={[
                  "inline-flex items-center gap-1 rounded-[4px] px-2 py-1 font-medium transition-colors disabled:opacity-45",
                  importKind === "subscription"
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground",
                ].join(" ")}
              >
                <Rss className="h-3 w-3" aria-hidden="true" />
                {tr("qr.modeSubscription")}
              </button>
            </div>
          </div>
          <textarea
            rows={4}
            value={payloadText}
            onChange={(e) => handleManualChange(e.target.value)}
            placeholder={tr("qr.payloadPlaceholder")}
            className="w-full rounded-[6px] border border-border bg-background px-3 py-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>

        {importKind === "subscription" ? (
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">{tr("subs.name")}</label>
            <Input
              value={subName}
              onChange={(e) => setSubName(e.target.value)}
              placeholder="My Airport / QR Feed"
            />
          </div>
        ) : null}

        {statusError ? (
          <div className="rounded-[6px] border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {statusError}
          </div>
        ) : null}

        <div className="flex items-center justify-end gap-2 pt-1">
          <Button type="button" variant="outline" size="sm" onClick={onClose}>
            {tr("action.cancel")}
          </Button>
          <Button type="submit" size="sm" disabled={submitting || !payloadText.trim()}>
            {submitting ? (
              <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <QrCode className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            )}
            {importKind === "subscription" ? tr("qr.confirmSub") : tr("qr.confirmNodes")}
          </Button>
        </div>
      </form>
    </ContextInspector>
  );
}
