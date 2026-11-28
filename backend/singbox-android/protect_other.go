// SPDX-License-Identifier: MPL-2.0
//go:build !unix

package main

func protectFD(_ string, _ int) error {
	return nil
}
