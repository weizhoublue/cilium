// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"fmt"
	"maps"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	SourceKindAnnotation      = "secretsync.cilium.io/source-kind"
	SourceNamespaceAnnotation = "secretsync.cilium.io/source-namespace"
	SourceNameAnnotation      = "secretsync.cilium.io/source-name"

	SourceKindSecret    = "Secret"
	SourceKindConfigMap = "ConfigMap"
)

func ownerFromLabels(obj client.Object, namespaceLabel, nameLabel string) (types.NamespacedName, bool) {
	labels := obj.GetLabels()
	if labels == nil {
		return types.NamespacedName{}, false
	}

	namespace, hasNamespace := labels[namespaceLabel]
	name, hasName := labels[nameLabel]
	if !hasNamespace || !hasName || namespace == "" || name == "" {
		return types.NamespacedName{}, false
	}

	return types.NamespacedName{Namespace: namespace, Name: name}, true
}

func ownerFromAnnotationsOrLabels(obj client.Object, namespaceLabel, nameLabel string) (types.NamespacedName, bool) {
	annotations := obj.GetAnnotations()
	namespace, hasNamespace := annotations[SourceNamespaceAnnotation]
	name, hasName := annotations[SourceNameAnnotation]
	if hasNamespace && hasName && namespace != "" && name != "" {
		return types.NamespacedName{Namespace: namespace, Name: name}, true
	}

	return ownerFromLabels(obj, namespaceLabel, nameLabel)
}

func isOwnedBy(obj client.Object, owner types.NamespacedName, namespaceLabel, nameLabel string) bool {
	existingOwner, ok := ownerFromAnnotationsOrLabels(obj, namespaceLabel, nameLabel)
	return ok && existingOwner == owner
}

func ensureOwnedBy(existing, desired client.Object, namespaceLabel, nameLabel string) error {
	desiredOwner, ok := ownerFromAnnotationsOrLabels(desired, namespaceLabel, nameLabel)
	if !ok {
		return fmt.Errorf("desired synced Secret %s/%s is missing ownership metadata", desired.GetNamespace(), desired.GetName())
	}

	existingOwner, ok := ownerFromAnnotationsOrLabels(existing, namespaceLabel, nameLabel)
	if !ok {
		return fmt.Errorf("refusing to overwrite synced Secret %s/%s without ownership metadata", existing.GetNamespace(), existing.GetName())
	}
	if existingOwner != desiredOwner {
		return fmt.Errorf("refusing to overwrite synced Secret %s/%s owned by %s/%s with data from %s/%s", existing.GetNamespace(), existing.GetName(), existingOwner.Namespace, existingOwner.Name, desiredOwner.Namespace, desiredOwner.Name)
	}

	return nil
}

func setSourceAnnotations(obj client.Object, kind string, source types.NamespacedName) {
	annotations := make(map[string]string, len(obj.GetAnnotations())+3)
	maps.Copy(annotations, obj.GetAnnotations())

	annotations[SourceKindAnnotation] = kind
	annotations[SourceNamespaceAnnotation] = source.Namespace
	annotations[SourceNameAnnotation] = source.Name

	obj.SetAnnotations(annotations)
}
