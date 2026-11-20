// SPDX-License-Identifier: MPL-2.0

package androidvpn

import "testing"

func TestManagerLifecycleAndValidation(t *testing.T) {
	m := NewManager()
	if st := m.Status(); st.Active || st.PerAppMode != "all" {
		t.Fatalf("unexpected initial status: %+v", st)
	}

	if _, err := m.Start(Config{ProtectPath: ""}); err == nil {
		t.Fatalf("expected error on missing protect_path")
	}
	if _, err := m.Start(Config{ProtectPath: "/tmp/protect.sock", PerAppMode: "invalid"}); err == nil {
		t.Fatalf("expected error on invalid per_app_mode")
	}

	st, err := m.Start(Config{
		ProtectPath:    "/data/user/0/com.crackrammer.prismray/files/protect.sock",
		TunFD:          42,
		MixedPort:      10808,
		PerAppMode:     "whitelist",
		PerAppPackages: []string{"org.mozilla.firefox", " "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Active || st.TunFD != 42 || st.MixedPort != 10808 || len(st.PerAppPackages) != 1 {
		t.Fatalf("unexpected active status: %+v", st)
	}

	stopped := m.Stop()
	if stopped.Active || stopped.TunFD != 0 {
		t.Fatalf("expected stopped status, got %+v", stopped)
	}
}
