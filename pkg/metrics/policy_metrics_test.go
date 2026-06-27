// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/source"
)

func TestPolicyImplementationDelayPreScopesDirectorySource(t *testing.T) {
	metrics := collectMetrics(t, NewLegacyMetrics().PolicyImplementationDelay)

	for _, metric := range metrics {
		for _, label := range metric.GetLabel() {
			if label.GetName() == LabelPolicySource && label.GetValue() == string(source.Directory) {
				return
			}
		}
	}

	require.Failf(t, "missing label value", "expected %s=%q", LabelPolicySource, source.Directory)
}

func collectMetrics(t *testing.T, collector prometheus.Collector) []*dto.Metric {
	t.Helper()

	ch := make(chan prometheus.Metric)
	done := make(chan struct{})
	metrics := make([]prometheus.Metric, 0)

	go func() {
		defer close(done)
		for metric := range ch {
			metrics = append(metrics, metric)
		}
	}()

	collector.Collect(ch)
	close(ch)
	<-done

	dtoMetrics := make([]*dto.Metric, 0, len(metrics))
	for _, metric := range metrics {
		dtoMetric := &dto.Metric{}
		require.NoError(t, metric.Write(dtoMetric))
		dtoMetrics = append(dtoMetrics, dtoMetric)
	}
	return dtoMetrics
}
