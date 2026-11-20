// SPDX-License-Identifier: MPL-2.0

package process

import (
	"strings"
	"testing"
)

func TestLogClassificationAndRedaction(t *testing.T) {
	line := formatLog("warning: failed vmess://secret@example.test", "ERROR")
	if !strings.HasPrefix(line, "[WARNING]") || strings.Contains(line, "secret") {
		t.Fatalf("unexpected formatted log: %s", line)
	}
	if got := formatLog("debug connection", "INFO"); !strings.HasPrefix(got, "[DEBUG]") {
		t.Fatal(got)
	}
}
