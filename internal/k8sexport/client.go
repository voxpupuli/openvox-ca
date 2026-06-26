// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
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

package k8sexport

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// namespaceFile is the standard in-cluster path holding the pod's own
// namespace, mounted from its ServiceAccount.
const namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// newInClusterClientset builds a Kubernetes clientset from the in-cluster
// ServiceAccount credentials (token, CA, and KUBERNETES_SERVICE_HOST/PORT).
// It returns a clear error when openvox-ca is not running inside a cluster.
func newInClusterClientset() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("loading in-cluster Kubernetes config (openvox-ca must run inside a pod for kubernetes_export): %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building Kubernetes client: %w", err)
	}
	return cs, nil
}

// podNamespace reads the pod's own namespace from the ServiceAccount mount,
// used as the default for targets that do not set one. Returns an error when
// the file is absent (i.e. not running in-cluster).
func podNamespace() (string, error) {
	data, err := os.ReadFile(namespaceFile)
	if err != nil {
		return "", fmt.Errorf("reading pod namespace from %s: %w", namespaceFile, err)
	}
	ns := strings.TrimSpace(string(data))
	if ns == "" {
		return "", fmt.Errorf("pod namespace file %s is empty", namespaceFile)
	}
	return ns, nil
}
