// Copyright (C) 2026 Chris Boot
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

package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// OverlayBackend wraps a Backend, redirecting reads and writes for a fixed
// set of logical keys to explicit local filesystem paths. The typical use
// is to keep the CA certificate and/or private key on local disk (or a
// mounted secret volume) even when the rest of the CA state lives in a
// remote backend such as etcd.
//
// Only single-blob keys (KeyCACert, KeyCAKey, KeyCAPubKey, etc.) are safe
// to override. Operations on list-style keys (csrPrefix, certPrefix) and
// append-style keys (KeyInventory) are always delegated to the underlying
// backend; AppendLine on an overridden key returns an error.
type OverlayBackend struct {
	base      Backend
	overrides map[string]string // logical key -> absolute local path
}

// NewOverlayBackend returns a backend that serves overrides from local
// files and delegates everything else to base. Empty override values are
// ignored; the backend requires at least one non-empty override. All paths
// are resolved to absolutes.
func NewOverlayBackend(base Backend, overrides map[string]string) (*OverlayBackend, error) {
	if base == nil {
		return nil, fmt.Errorf("overlay backend requires a base backend")
	}
	clean := make(map[string]string, len(overrides))
	for k, p := range overrides {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("resolving override path for %q: %w", k, err)
		}
		clean[k] = abs
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("overlay backend requires at least one non-empty override")
	}
	return &OverlayBackend{base: base, overrides: clean}, nil
}

// EnsureReady prepares the base backend and ensures each override's parent
// directory exists. Operators supplying a pre-existing file still need to
// ensure the directory mode is acceptable; EnsureReady only creates the
// directory when missing.
func (o *OverlayBackend) EnsureReady() error {
	if err := o.base.EnsureReady(); err != nil {
		return err
	}
	for _, p := range o.overrides {
		if err := os.MkdirAll(filepath.Dir(p), DirPerm); err != nil {
			return err
		}
	}
	return nil
}

// Get reads an overridden key from its local file (returning fs.ErrNotExist
// when absent) or delegates to the base backend.
func (o *OverlayBackend) Get(key string) ([]byte, error) {
	if p, ok := o.overrides[key]; ok {
		data, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
			}
			return nil, err
		}
		return data, nil
	}
	return o.base.Get(key)
}

// Put writes to the overridden file atomically (temp + rename) honouring
// kind for permissions, or delegates to the base backend.
func (o *OverlayBackend) Put(key string, data []byte, kind BlobKind) error {
	if p, ok := o.overrides[key]; ok {
		if err := os.MkdirAll(filepath.Dir(p), DirPerm); err != nil {
			return err
		}
		return atomicWriteFile(p, data, permFor(kind))
	}
	return o.base.Put(key, data, kind)
}

// Delete removes the local file for an overridden key, wrapping
// fs.ErrNotExist when absent; otherwise delegates.
func (o *OverlayBackend) Delete(key string) error {
	if p, ok := o.overrides[key]; ok {
		if err := os.Remove(p); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return &fs.PathError{Op: "delete", Path: key, Err: fs.ErrNotExist}
			}
			return err
		}
		return nil
	}
	return o.base.Delete(key)
}

// Exists reports whether the overridden file exists, or delegates.
func (o *OverlayBackend) Exists(key string) (bool, error) {
	if p, ok := o.overrides[key]; ok {
		_, err := os.Stat(p)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return o.base.Exists(key)
}

// List always delegates: override keys are single-blob, not list-style.
func (o *OverlayBackend) List(prefix string) ([]string, error) {
	return o.base.List(prefix)
}

// AppendLine rejects overridden keys — the override targets single blobs —
// and otherwise delegates.
func (o *OverlayBackend) AppendLine(key string, data []byte, kind BlobKind) error {
	if _, ok := o.overrides[key]; ok {
		return fmt.Errorf("AppendLine is not supported on overridden key %q", key)
	}
	return o.base.AppendLine(key, data, kind)
}

// ModTime reports the local file mtime for overridden keys, or delegates.
func (o *OverlayBackend) ModTime(key string) (time.Time, error) {
	if p, ok := o.overrides[key]; ok {
		info, err := os.Stat(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return time.Time{}, &fs.PathError{Op: "modtime", Path: key, Err: fs.ErrNotExist}
			}
			return time.Time{}, err
		}
		return info.ModTime(), nil
	}
	return o.base.ModTime(key)
}

// Close closes the base backend.
func (o *OverlayBackend) Close() error {
	return o.base.Close()
}

// Path implements PathProvider: returns the override path for overridden
// keys, or delegates to the base if it implements PathProvider.
func (o *OverlayBackend) Path(key string) string {
	if p, ok := o.overrides[key]; ok {
		return p
	}
	if pp, ok := o.base.(PathProvider); ok {
		return pp.Path(key)
	}
	return ""
}

// BaseDir implements PathProvider by delegating; overlay has no single root.
func (o *OverlayBackend) BaseDir() string {
	if pp, ok := o.base.(PathProvider); ok {
		return pp.BaseDir()
	}
	return ""
}
