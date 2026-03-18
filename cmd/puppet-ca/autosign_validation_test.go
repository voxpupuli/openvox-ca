// Copyright (C) 2026 Trevor Vaughan
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAutosignExecutable_ValidFile(t *testing.T) {
	// Create a temp file owned by current user, mode 0755 (not world-writable).
	tmp := t.TempDir()
	exe := filepath.Join(tmp, "autosign.sh")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := validateAutosignExecutable(exe); err != nil {
		t.Errorf("expected no error for valid executable, got: %v", err)
	}
}

func TestValidateAutosignExecutable_WorldWritable(t *testing.T) {
	tmp := t.TempDir()
	exe := filepath.Join(tmp, "autosign.sh")
	// Create file then explicitly chmod to 0757 (world-writable).
	// os.WriteFile alone may be affected by umask.
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.Chmod(exe, 0757); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	err := validateAutosignExecutable(exe)
	if err == nil {
		t.Fatal("expected error for world-writable file, got nil")
	}
	if !strings.Contains(err.Error(), "world-writable") {
		t.Errorf("expected error containing 'world-writable', got: %v", err)
	}
}

func TestValidateAutosignExecutable_NonExistentFile(t *testing.T) {
	err := validateAutosignExecutable("/nonexistent/path/autosign.sh")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

func TestValidateAutosignExecutable_SymlinkToValidFile(t *testing.T) {
	tmp := t.TempDir()
	exe := filepath.Join(tmp, "autosign.sh")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("setup: %v", err)
	}

	link := filepath.Join(tmp, "autosign-link.sh")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatalf("setup symlink: %v", err)
	}

	if err := validateAutosignExecutable(link); err != nil {
		t.Errorf("expected no error for symlink to valid file, got: %v", err)
	}
}

func TestValidateAutosignExecutable_GroupWritableNotWorldWritable(t *testing.T) {
	tmp := t.TempDir()
	exe := filepath.Join(tmp, "autosign.sh")
	// Mode 0770 — group-writable but not world-writable.
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0770); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := validateAutosignExecutable(exe); err != nil {
		t.Errorf("expected no error for group-writable (non-world-writable) file, got: %v", err)
	}
}
