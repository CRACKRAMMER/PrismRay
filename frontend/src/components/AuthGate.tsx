// SPDX-License-Identifier: MPL-2.0

import React, { useCallback, useEffect, useState } from "react";
import { Fingerprint, KeyRound, Loader2, Lock } from "lucide-react";
import {
  API_URL,
  AUTH_REQUIRED_EVENT,
  type BiometricStatus,
  api,
  authenticateBiometric,
  formatApiError,
  getBiometricStatus,
  initializeBackend,
  isAndroidClient,
  isDesktop,
} from "../lib/api.ts";
import { useAppStore } from "../store/appStore.ts";
import { ConnectionError } from "./ConnectionError.tsx";
import { PrismRayLogo } from "./PrismRayLogo.tsx";
import { Button } from "./ui/button.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card.tsx";
import { Input } from "./ui/input.tsx";

export function AuthGate({ children }: { children: React.ReactNode }) {
  const { authStatus, setAuthStatus, locale, setLocale, tr } = useAppStore();

  const [checking, setChecking] = useState(true);
  const [connectError, setConnectError] = useState("");
  const [bootstrapToken, setBootstrapToken] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [biometricInfo, setBiometricInfo] = useState<BiometricStatus | null>(null);
  const [bioUnlocking, setBioUnlocking] = useState(false);

  const loadStatus = useCallback(async () => {
    setChecking(true);
    setConnectError("");
    try {
      await initializeBackend();
      const status = await api.getAuthStatus();
      setAuthStatus(status);
    } catch (err) {
      setConnectError(formatApiError(err));
    } finally {
      setChecking(false);
    }
  }, [setAuthStatus]);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  useEffect(() => {
    if ((!isDesktop && !isAndroidClient()) || !authStatus?.biometric_enabled) {
      setBiometricInfo(null);
      return;
    }
    void getBiometricStatus().then(setBiometricInfo);
  }, [authStatus?.biometric_enabled]);

  const handleBiometricUnlock = useCallback(async () => {
    setFormError("");
    setBioUnlocking(true);
    try {
      const reason =
        locale === "zh-CN" ? "验证系统生物信息以解锁 PrismRay 配置库" : "Authenticate to unlock PrismRay";
      if (isAndroidClient()) {
        const res = await authenticateBiometric(reason);
        await api.biometricUnlock({ biometric_kek: res.biometric_kek });
      } else {
        const { challenge } = await api.requestBiometricChallenge();
        const res = await authenticateBiometric(reason, challenge);
        await api.biometricUnlock({ challenge, signature: res.signature });
      }
      const next = await api.getAuthStatus();
      setAuthStatus(next);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : formatApiError(err));
    } finally {
      setBioUnlocking(false);
    }
  }, [locale, setAuthStatus]);

  useEffect(() => {
    const onAuthRequired = () => {
      setPassword("");
      setFormError("");
      void loadStatus();
    };
    window.addEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, onAuthRequired);
  }, [loadStatus]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authStatus) return;

    const initializing = !authStatus.initialized;
    setFormError("");

    if (initializing) {
      if (password.length < 8) {
        setFormError(
          locale === "zh-CN"
            ? "主密码长度至少需要 8 个字符"
            : "Master password must be at least 8 characters",
        );
        return;
      }
      if (password !== confirmPassword) {
        setFormError(tr("auth.passwordMismatch"));
        return;
      }
    }

    setSubmitting(true);
    try {
      if (initializing) {
        await api.initializeAuth(password, bootstrapToken.trim());
        await api.ensureCores().catch(() => {});
      } else {
        await api.loginAuth(password);
      }
      setPassword("");
      setConfirmPassword("");
      setBootstrapToken("");
      const next = await api.getAuthStatus();
      setAuthStatus(next);
    } catch (err) {
      setFormError(formatApiError(err));
    } finally {
      setSubmitting(false);
    }
  };

  if (connectError && !authStatus) {
    return (
      <ConnectionError
        endpoint={API_URL}
        error={connectError}
        retrying={checking}
        onRetry={() => void loadStatus()}
      />
    );
  }

  if (checking && !authStatus) {
    return (
      <div className="flex min-h-dvh items-center justify-center bg-background p-4">
        <div className="flex items-center gap-3 rounded-xl border bg-card px-5 py-4 text-sm text-muted-foreground shadow-sm">
          <Loader2 className="h-4 w-4 animate-spin text-primary" aria-hidden="true" />
          <span>{tr("auth.checking")}</span>
        </div>
      </div>
    );
  }

  const isUnlocked = Boolean(
    authStatus &&
      authStatus.initialized &&
      (!authStatus.authentication || (authStatus.authenticated && authStatus.unlocked)),
  );

  if (isUnlocked) {
    return <>{children}</>;
  }

  const initializing = Boolean(authStatus && !authStatus.initialized);

  return (
    <div className="flex min-h-dvh flex-col items-center justify-center bg-background p-4">
      <div className="mb-4 flex w-full max-w-md items-center justify-between">
        <div className="flex items-center gap-2 font-semibold text-foreground">
          <PrismRayLogo className="h-7 w-7 shrink-0 rounded-[7px]" />
          <span>
            {tr("app.name")} <span className="text-xs font-normal text-muted-foreground">{tr("app.version")}</span>
          </span>
        </div>
        <button
          type="button"
          onClick={() => setLocale(locale === "zh-CN" ? "en-US" : "zh-CN")}
          className="rounded-lg border bg-card px-2.5 py-1 text-xs font-medium text-muted-foreground hover:text-foreground"
        >
          {locale === "zh-CN" ? "English" : "中文"}
        </button>
      </div>

      <Card className="w-full max-w-md shadow-lg">
        <CardHeader className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-primary/15 text-primary">
              {initializing ? (
                <KeyRound className="h-5 w-5" aria-hidden="true" />
              ) : (
                <Lock className="h-5 w-5" aria-hidden="true" />
              )}
            </span>
            <div>
              <CardTitle className="text-lg">
                {initializing ? tr("auth.initTitle") : tr("auth.unlockTitle")}
              </CardTitle>
              <CardDescription className="text-xs">
                {initializing ? tr("auth.initDesc") : tr("auth.unlockDesc")}
              </CardDescription>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {!initializing && authStatus?.password_lock_enabled && authStatus?.biometric_enabled && biometricInfo?.available ? (
            <div className="space-y-2 border-b border-border pb-4">
              <Button
                type="button"
                className="w-full"
                disabled={bioUnlocking || submitting}
                onClick={() => void handleBiometricUnlock()}
              >
                {bioUnlocking ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                ) : (
                  <Fingerprint className="mr-2 h-4 w-4" aria-hidden="true" />
                )}
                {bioUnlocking ? tr("auth.biometricAuthenticating") : tr("auth.biometricUnlock")}
              </Button>
              <p className="text-center text-[11px] text-muted-foreground">{biometricInfo.detail}</p>
            </div>
          ) : null}

          <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
            {initializing && authStatus?.bootstrap_token_required ? (
              <div className="space-y-1.5">
                <label htmlFor="auth-bootstrap" className="text-xs font-medium text-foreground">
                  {tr("auth.bootstrapToken")}
                </label>
                <Input
                  id="auth-bootstrap"
                  type="text"
                  autoComplete="one-time-code"
                  value={bootstrapToken}
                  onChange={(e) => setBootstrapToken(e.target.value)}
                  required
                />
                <p className="text-xs text-muted-foreground">{tr("auth.bootstrapHint")}</p>
              </div>
            ) : null}

            <div className="space-y-1.5">
              <label htmlFor="auth-password" className="text-xs font-medium text-foreground">
                {tr("auth.password")}
              </label>
              <Input
                id="auth-password"
                type="password"
                autoComplete={initializing ? "new-password" : "current-password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {initializing ? (
              <div className="space-y-1.5">
                <label htmlFor="auth-confirm-password" className="text-xs font-medium text-foreground">
                  {tr("auth.confirmPassword")}
                </label>
                <Input
                  id="auth-confirm-password"
                  type="password"
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                />
              </div>
            ) : null}

            {/* Reserve fixed height so validation errors do not shift the submit button */}
            <div className="min-h-6 text-xs leading-5 text-destructive" role="alert" aria-live="polite">
              {formError || ""}
            </div>

            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" /> : null}
              {initializing ? tr("auth.submitInit") : tr("auth.submitUnlock")}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
