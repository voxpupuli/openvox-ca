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

// Package k8sclient builds a Kubernetes client from the credentials a pod is
// given, for the optional features that talk to the API server.
//
// It holds no policy of its own. It exists because more than one such feature
// now needs the same two things -- a clientset built from the in-cluster
// ServiceAccount, and the pod's own namespace -- and the second copy of the
// path to a token mount is the copy that goes stale.
package k8sclient

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// NamespaceFile is the standard in-cluster path holding the pod's own
// namespace, mounted from its ServiceAccount.
const NamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// InClusterClientset builds a Kubernetes clientset from the in-cluster
// ServiceAccount credentials (token, CA, and KUBERNETES_SERVICE_HOST/PORT).
//
// feature names whatever asked for the client, as a noun phrase completing
// "openvox-ca must run inside a pod for ...". It may be a configuration block
// (`kubernetes_export`) or a description of the feature ("a managed
// certificate's Kubernetes Secret store"), whichever tells an operator where to
// look -- the point is that the error names the thing they enabled rather than
// reporting that a client could not be built.
func InClusterClientset(feature string) (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("loading in-cluster Kubernetes config "+
			"(openvox-ca must run inside a pod for %s): %w", feature, err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		// Named here too. Neither caller adds the attribution itself, and one
		// of them returns this straight out of startup, so an unattributed
		// error would leave an operator with two features enabled and no way
		// to tell which one failed.
		return nil, fmt.Errorf("building Kubernetes client for %s: %w", feature, err)
	}
	return cs, nil
}

// PodNamespace reads the pod's own namespace from the ServiceAccount mount,
// used as the default wherever a feature does not name one.
//
// It returns an error when that file cannot be read or is empty. Usually that
// means this is not running in a pod -- but not always: a pod with
// automountServiceAccountToken: false is in-cluster and still has no namespace
// file, so a caller must not turn this error into a claim about where the
// process is running. Both errors name the path, which is what an operator
// needs either way.
func PodNamespace() (string, error) {
	data, err := os.ReadFile(NamespaceFile)
	if err != nil {
		return "", fmt.Errorf("reading pod namespace from %s: %w", NamespaceFile, err)
	}
	ns := strings.TrimSpace(string(data))
	if ns == "" {
		return "", fmt.Errorf("pod namespace file %s is empty", NamespaceFile)
	}
	return ns, nil
}
