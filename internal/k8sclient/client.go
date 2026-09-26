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
// It exists because more than one such feature needs the same things -- a
// clientset built from the in-cluster ServiceAccount, and the pod's own
// namespace -- and the second copy of the path to a token mount is the copy
// that goes stale.
//
// It holds one piece of policy, deliberately: the managed-by label every
// object this CA maintains carries, and the helper that merges it in. That is
// here rather than in either feature because the claim "one selector finds
// everything openvox-ca owns" is a contract *between* them, not a fact about
// either, and docs/kubernetes-export.md publishes it to operators. Both
// packages previously held their own copy, each asserting in a comment that it
// matched the other, with nothing making it so.
//
// This paragraph exists because the doc said "It holds no policy of its own"
// while the package owned that label -- a description that stopped being true
// when the label moved here, and which would have told the next reader this was
// the wrong home for it.
package k8sclient

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The managed-by label marks every object openvox-ca maintains in a cluster,
// whichever feature wrote it: a kubernetes_export target, or the Secret a
// managed certificate lives in. One selector therefore finds everything this CA
// owns, which is what docs/kubernetes-export.md tells operators to rely on.
//
// It lives here, in the package both features already depend on for their
// client, because that claim is a contract between them rather than a fact
// about either. Both packages held their own copy of this pair and a merge
// helper to go with it, each asserting in a comment that it matched the other,
// with nothing making it so: changing one value would have left the other
// behind and quietly broken the selector the documentation promises.
const (
	ManagedByLabelKey   = "app.kubernetes.io/managed-by"
	ManagedByLabelValue = "openvox-ca"
)

// WithManagedByLabel returns configured with the managed-by label added.
//
// The label always wins, so ownership cannot be masked by an operator setting
// the same key -- a selector that skipped an object this CA is overwriting
// would be worse than no selector. The input is never modified: callers hold
// configuration that outlives the call and is read again on the next pass.
func WithManagedByLabel(configured map[string]string) map[string]string {
	labels := make(map[string]string, len(configured)+1)
	for k, v := range configured {
		labels[k] = v
	}
	labels[ManagedByLabelKey] = ManagedByLabelValue
	return labels
}

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
func PodNamespace() (string, error) { return podNamespaceFrom(NamespaceFile) }

// podNamespaceFrom is PodNamespace against a caller-supplied path, so the
// read-failure, all-whitespace and success arms can be driven directly.
//
// A seam rather than a var: making NamespaceFile writable to reach these
// branches would leave the real path mutable at runtime for the benefit of a
// test, and this value decides which namespace a Secret store writes into when
// an entry does not name one. That is worth keeping constant.
func podNamespaceFrom(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading pod namespace from %s: %w", path, err)
	}
	ns := strings.TrimSpace(string(data))
	if ns == "" {
		return "", fmt.Errorf("pod namespace file %s is empty", path)
	}
	return ns, nil
}
