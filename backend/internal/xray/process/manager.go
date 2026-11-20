// SPDX-License-Identifier: MPL-2.0

package process

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Manager serializes lifecycle operations and broadcasts logs to every subscriber.
type Manager struct {
	mu          sync.Mutex
	process     *Process
	history     []string
	logMu       sync.Mutex
	subscribers map[chan string]struct{}
}

func NewManager(configPath string) *Manager {
	m := &Manager{process: NewProcess(configPath), subscribers: make(map[chan string]struct{})}
	m.process.StdoutCallback = func(line string) { m.publish(formatLog(line, "INFO")) }
	m.process.StderrCallback = func(line string) { m.publish(formatLog(line, "ERROR")) }
	return m
}

var sensitiveURI = regexp.MustCompile(`(?i)(vmess|vless|trojan|ss)://\S+`)

func formatLog(line, fallback string) string {
	lower := strings.ToLower(line)
	level := fallback
	for _, candidate := range []string{"DEBUG", "INFO", "WARNING", "ERROR"} {
		needle := strings.ToLower(candidate)
		if strings.Contains(lower, "["+needle+"]") || strings.Contains(lower, needle+":") || strings.Contains(lower, needle+" ") {
			level = candidate
			break
		}
	}
	line = sensitiveURI.ReplaceAllString(line, "$1://[redacted]")
	return fmt.Sprintf("[%s] %s", level, line)
}
func (m *Manager) SetBinaryPath(path string) { m.process.SetBinaryPath(path) }
func (m *Manager) Start() error              { m.mu.Lock(); defer m.mu.Unlock(); return m.process.Start() }
func (m *Manager) Stop() error               { m.mu.Lock(); defer m.mu.Unlock(); return m.process.Stop() }
func (m *Manager) Restart() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.process.Stop(); err != nil {
		return err
	}
	return m.process.Start()
}
func (m *Manager) Status() string {
	if m.process.Running() {
		return "running"
	}
	return "stopped"
}
func (m *Manager) SubscribeLogs() chan string {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	ch := make(chan string, 100)
	m.subscribers[ch] = struct{}{}
	return ch
}
func (m *Manager) UnsubscribeLogs(ch chan string) {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	if _, ok := m.subscribers[ch]; ok {
		delete(m.subscribers, ch)
		close(ch)
	}
}
func (m *Manager) publish(line string) {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	m.history = append(m.history, line)
	if len(m.history) > 1000 {
		m.history = append([]string(nil), m.history[len(m.history)-1000:]...)
	}
	for ch := range m.subscribers {
		select {
		case ch <- line:
		default:
		}
	}
}

func (m *Manager) ValidateConfig(path string) error { return m.process.ValidateConfig(path) }

func (m *Manager) LogHistory() []string {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	return append([]string(nil), m.history...)
}
