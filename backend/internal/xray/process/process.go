// SPDX-License-Identifier: MPL-2.0

package process

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/install"
)

// Process owns one child and reaps it on every exit, including crashes.
type Process struct {
	mu             sync.Mutex
	cmd            *exec.Cmd
	done           chan struct{}
	configPath     string
	binaryPath     string
	StdoutCallback func(string)
	StderrCallback func(string)
}

func NewProcess(configPath string) *Process {
	if configPath == "" {
		configPath = "config.json"
	}
	return &Process{configPath: configPath}
}

func (p *Process) SetBinaryPath(path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.binaryPath = path
}

func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.runningLocked()
}

func (p *Process) runningLocked() bool {
	if p.cmd == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *Process) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.runningLocked() {
		return fmt.Errorf("xray is already running")
	}
	binPath, err := p.resolveBinaryLocked()
	if err != nil {
		return err
	}
	if err := validateConfig(binPath, p.configPath); err != nil {
		return err
	}

	cmd := exec.Command(binPath, "run", "-c", p.configPath)
	bindParent(cmd)
	// os/exec waits for these readers before Wait returns.
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter
	if err := cmd.Start(); err != nil {
		stdoutReader.Close()
		stdoutWriter.Close()
		stderrReader.Close()
		stderrWriter.Close()
		return fmt.Errorf("failed to start process: %w", err)
	}
	p.cmd = cmd
	p.done = make(chan struct{})
	done := p.done
	go readLines(stdoutReader, p.StdoutCallback)
	go readLines(stderrReader, p.StderrCallback)
	go func() {
		err := cmd.Wait()
		stdoutWriter.Close()
		stderrWriter.Close()
		if err != nil && p.StderrCallback != nil {
			p.StderrCallback(fmt.Sprintf("Xray exited: %v", err))
		}
		close(done)
	}()
	return nil
}

func readLines(reader *io.PipeReader, callback func(string)) {
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		if callback != nil {
			callback(scanner.Text())
		}
	}
}

func (p *Process) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil {
		return nil
	}
	if p.runningLocked() {
		if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("failed to kill process: %w", err)
		}
	}
	<-p.done
	p.cmd = nil
	return nil
}

func (p *Process) resolveBinaryLocked() (string, error) {
	if p.binaryPath != "" {
		return filepath.Abs(p.binaryPath)
	}
	return install.FindXrayBinary()
}

func (p *Process) ValidateConfig(path string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	binary, err := p.resolveBinaryLocked()
	if err != nil {
		return err
	}
	return validateConfig(binary, path)
}

func validateConfig(binary, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "run", "-test", "-c", path)
	command.WaitDelay = time.Second
	if _, err := command.CombinedOutput(); err != nil {
		// Do not return raw Xray diagnostics: malformed configs can include secrets.
		return fmt.Errorf("Xray configuration validation failed: %w", err)
	}
	return nil
}
