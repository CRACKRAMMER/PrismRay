// SPDX-License-Identifier: MPL-2.0
//go:build !unix

package main

import "errors"

var errInstanceAlreadyRunning = errors.New("backend instance already running")

func acquireSingleInstanceLock(_ string) (func(), error) {
	return func() {}, nil
}
