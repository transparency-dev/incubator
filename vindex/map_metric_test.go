// Copyright 2026 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vindex_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path"
	"slices"
	"testing"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestVerifiableIndex_Metrics(t *testing.T) {
	ctx := t.Context()
	s, v, err := fnote.NewEd25519SignerVerifier(skey)
	if err != nil {
		t.Fatal(err)
	}
	inputLog := &inMemoryTreeSource{
		t:      testonly.New(rfc6962.DefaultHasher),
		leaves: make([][]byte, 0),
		s:      s,
		v:      v,
	}
	// Add 3 leaves.
	// Leaf 1: maps to 1 key
	// Leaf 2: maps to 2 keys
	// Leaf 3: maps to 0 keys
	inputLog.Append("foo: 2")
	inputLog.Append("bar,baz: 5") // we will parse this to return 2 keys
	inputLog.Append("empty:")     // maps to 0 keys

	mapFn := func(leaf []byte) [][sha256.Size]byte {
		key, _, found := bytes.Cut(leaf, []byte(":"))
		if !found {
			panic("colon not found")
		}
		if len(key) == 0 || bytes.Equal(key, []byte("empty")) {
			return nil
		}
		var keys [][sha256.Size]byte
		for _, k := range bytes.Split(key, []byte(",")) {
			keys = append(keys, sha256.Sum256(k))
		}
		return keys
	}

	f, err := os.MkdirTemp("", "vindexMetricTestDir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(f)

	old := path.Join(f, "outputlog")
	outputLog, closer, err := vindex.NewOutputLog(ctx, old, s, v, vindex.OutputLogOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closer(context.Background()) }()

	// Setup OTel Reader
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))

	opts := vindex.Options{
		MeterProvider: provider,
	}

	vi, err := vindex.NewVerifiableIndex(ctx, inputLog, mapFn, outputLog, f, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = vi.Close() }()

	if err := vi.Update(ctx); err != nil {
		t.Fatal(err)
	}

	// Collect metrics
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}

	// Find the metric we care about
	var foundMetric *metricdata.Metrics
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "vindex.map_fn.keys" {
				foundMetric = &m
				break
			}
		}
	}

	if foundMetric == nil {
		t.Fatal("metric vindex.map_fn.keys not found")
	}

	histogram, ok := foundMetric.Data.(metricdata.Histogram[int64])
	if !ok {
		t.Fatalf("expected Histogram[int64], got %T", foundMetric.Data)
	}

	if len(histogram.DataPoints) != 1 {
		t.Fatalf("expected 1 data point, got %d", len(histogram.DataPoints))
	}

	dp := histogram.DataPoints[0]
	// We added 3 leaves:
	// Leaf 1: 1 key
	// Leaf 2: 2 keys
	// Leaf 3: 0 keys
	// Total count should be 3.
	if dp.Count != 3 {
		t.Errorf("expected count 3, got %d", dp.Count)
	}
	// Sum should be 1 + 2 + 0 = 3.
	if dp.Sum != 3 {
		t.Errorf("expected sum 3, got %d", dp.Sum)
	}

	// Verify buckets
	expectedBounds := []float64{0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}
	if !slices.Equal(dp.Bounds, expectedBounds) {
		t.Errorf("expected bounds %v, got %v", expectedBounds, dp.Bounds)
	}

	expectedBuckets := []uint64{1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if !slices.Equal(dp.BucketCounts, expectedBuckets) {
		t.Errorf("expected bucket counts %v, got %v", expectedBuckets, dp.BucketCounts)
	}

	verifyFloat64Histogram(t, rm, "vindex.sync.fetch.duration", 3)
	verifyFloat64Histogram(t, rm, "vindex.sync.map_fn.duration", 3)
	verifyFloat64Histogram(t, rm, "vindex.sync.process.duration", 3)

	verifyFloat64Histogram(t, rm, "vindex.build.wal.duration", 1)
	verifyFloat64Histogram(t, rm, "vindex.build.vindex.duration", 1)
	verifyFloat64Histogram(t, rm, "vindex.build.publish.duration", 1)
	verifyFloat64Histogram(t, rm, "vindex.build.total.duration", 1)
}

func verifyFloat64Histogram(t *testing.T, rm metricdata.ResourceMetrics, name string, expectedCount int64) {
	t.Helper()
	var foundMetric *metricdata.Metrics
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				foundMetric = &m
				break
			}
		}
	}

	if foundMetric == nil {
		t.Fatalf("metric %s not found", name)
	}

	histogram, ok := foundMetric.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", foundMetric.Data)
	}

	if len(histogram.DataPoints) != 1 {
		t.Fatalf("expected 1 data point, got %d", len(histogram.DataPoints))
	}

	dp := histogram.DataPoints[0]
	if dp.Count != uint64(expectedCount) {
		t.Errorf("%s: expected count %d, got %d", name, expectedCount, dp.Count)
	}
	if dp.Sum < 0 {
		t.Errorf("%s: expected non-negative sum, got %f", name, dp.Sum)
	}
}
