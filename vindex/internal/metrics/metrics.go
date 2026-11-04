// Copyright 2026 The Transparency Authors. All Rights Reserved.
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

// Package metrics defines the Prometheus observability metrics for VIndex.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Checkpoint Progression Gauges (Monotonic Sizes)
	InputTreeSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vindex_input_tree_size",
		Help: "Latest discovered size of the upstream Input Log checkpoint.",
	})

	KVCommittedSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vindex_kv_committed_size",
		Help: "Highest leaf index + 1 durably committed to the Pebble KV store (m_kv_size).",
	})

	OutputTreeSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vindex_output_tree_size",
		Help: "Total committed size of the Output Log.",
	})

	ServingTreeSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vindex_serving_tree_size",
		Help: "Input Log size covered by the active serving state exposed to readers.",
	})

	// Stage Throughput Monotonic Counters
	LeavesDownloadedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vindex_leaves_downloaded_total",
		Help: "Cumulative number of raw input log leaves downloaded from upstream.",
	})

	LeavesMappedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vindex_leaves_mapped_total",
		Help: "Cumulative number of input log leaves executed through the MapFn.",
	})

	LeavesIndexedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vindex_leaves_indexed_total",
		Help: "Cumulative number of input log leaves committed into Pebble inverted chunks.",
	})

	KeysMappedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vindex_keys_mapped_total",
		Help: "Cumulative number of search key entries produced by the MapFn.",
	})

	// Pipeline Health & Subsystem Metrics
	InputFetchErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vindex_input_fetch_errors_total",
		Help: "Total number of network or HTTP errors encountered while polling/fetching from the upstream log.",
	})

	WitnessSignaturesCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vindex_witness_signatures_count",
		Help: "Number of valid witness signatures attached to the latest active Output Log checkpoint.",
	})

	WitnessErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vindex_witness_errors_total",
		Help: "Total number of failed witness signing attempts.",
	})

	TileCacheBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vindex_tile_cache_bytes",
		Help: "Estimated total bytes stored in the local managed tile cache directory.",
	})

	// Ingestion Metrics
	IngestionLag = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vindex_ingestion_lag",
		Help: "Difference between Input Log size and last indexed leaf index (m_kv_size).",
	})

	MapDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vindex_map_duration_seconds",
		Help:    "Time spent executing the WASM MapFn per leaf bundle in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	MapErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vindex_map_errors_total",
		Help: "Rate of mapping failures labeled by policy.",
	}, []string{"policy"})

	// Indexing & Commit Metrics
	IndexingLag = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vindex_indexing_lag",
		Help: "Difference between m_kv_size and Output_Size.",
	})

	WitnessWaitSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vindex_witness_wait_seconds",
		Help:    "Latency waiting for remote Output Log witness signatures in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	MPTLockWaitSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vindex_mpt_lock_wait_seconds",
		Help:    "Wait duration to acquire mpt_lock.Lock() in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	MPTPredictDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vindex_mpt_predict_duration_seconds",
		Help:    "Time spent predicting MPT root hash without lock in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	MPTWriteDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vindex_mpt_write_duration_seconds",
		Help:    "Critical section duration applying MPT mutations in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	OutputLogAppendDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vindex_output_log_append_duration_seconds",
		Help:    "Time spent appending leaf and fetching proof from Output Log in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	PebbleApplyDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vindex_pebble_apply_duration_seconds",
		Help:    "Time spent committing atomic batch to Pebble in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	// Lookup Metrics
	LookupLatencySeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vindex_lookup_latency_seconds",
		Help:    "Latency of the Lookup API endpoint in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	LookupResultsReturned = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vindex_lookup_results_returned",
		Help:    "Count of index pointers returned per lookup.",
		Buckets: prometheus.ExponentialBuckets(1, 2, 16),
	})

	// Storage Metrics
	MPTMMapBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vindex_mpt_mmap_bytes",
		Help: "Virtual memory size of the MPT mmap allocation.",
	})

	// Independent Auditor Metrics
	AuditorRootMismatchesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vindex_auditor_root_mismatches_total",
		Help: "Cumulative number of detected root hash mismatches between local MPT calculation and OutputLog leaf commitments.",
	})

	AuditorRootMismatch = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vindex_auditor_root_mismatch",
		Help: "Current root mismatch status (0 = no mismatch / healthy, 1 = root mismatch detected).",
	})
)

// RecordAuditorRootMismatch records a root hash mismatch event by incrementing
// AuditorRootMismatchesTotal and setting AuditorRootMismatch to 1.
func RecordAuditorRootMismatch() {
	AuditorRootMismatchesTotal.Inc()
	AuditorRootMismatch.Set(1)
}

// ResetAuditorRootMismatch resets the AuditorRootMismatch gauge to 0 (healthy).
func ResetAuditorRootMismatch() {
	AuditorRootMismatch.Set(0)
}

// SetAuditorRootMismatch sets the AuditorRootMismatch gauge to val.
func SetAuditorRootMismatch(val float64) {
	AuditorRootMismatch.Set(val)
}
