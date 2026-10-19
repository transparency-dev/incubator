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

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics_RegistrationAndMutation(t *testing.T) {
	// 1. Checkpoint Progression Gauges
	InputTreeSize.Set(100)
	if v := testutil.ToFloat64(InputTreeSize); v != 100 {
		t.Fatalf("InputTreeSize = %v, want 100", v)
	}

	KVCommittedSize.Set(80)
	if v := testutil.ToFloat64(KVCommittedSize); v != 80 {
		t.Fatalf("KVCommittedSize = %v, want 80", v)
	}

	OutputTreeSize.Set(75)
	if v := testutil.ToFloat64(OutputTreeSize); v != 75 {
		t.Fatalf("OutputTreeSize = %v, want 75", v)
	}

	ServingTreeSize.Set(70)
	if v := testutil.ToFloat64(ServingTreeSize); v != 70 {
		t.Fatalf("ServingTreeSize = %v, want 70", v)
	}

	// 2. Stage Throughput Counters
	LeavesDownloadedTotal.Add(1000)
	if v := testutil.ToFloat64(LeavesDownloadedTotal); v < 1000 {
		t.Fatalf("LeavesDownloadedTotal = %v, want >= 1000", v)
	}

	LeavesMappedTotal.Add(500)
	if v := testutil.ToFloat64(LeavesMappedTotal); v < 500 {
		t.Fatalf("LeavesMappedTotal = %v, want >= 500", v)
	}

	LeavesIndexedTotal.Add(400)
	if v := testutil.ToFloat64(LeavesIndexedTotal); v < 400 {
		t.Fatalf("LeavesIndexedTotal = %v, want >= 400", v)
	}

	KeysMappedTotal.Add(1200)
	if v := testutil.ToFloat64(KeysMappedTotal); v < 1200 {
		t.Fatalf("KeysMappedTotal = %v, want >= 1200", v)
	}

	// 3. Pipeline Health & Subsystem Metrics
	InputFetchErrorsTotal.Inc()
	if v := testutil.ToFloat64(InputFetchErrorsTotal); v < 1 {
		t.Fatalf("InputFetchErrorsTotal = %v, want >= 1", v)
	}

	WitnessSignaturesCount.Set(3)
	if v := testutil.ToFloat64(WitnessSignaturesCount); v != 3 {
		t.Fatalf("WitnessSignaturesCount = %v, want 3", v)
	}

	WitnessErrorsTotal.Inc()
	if v := testutil.ToFloat64(WitnessErrorsTotal); v < 1 {
		t.Fatalf("WitnessErrorsTotal = %v, want >= 1", v)
	}

	TileCacheBytes.Set(1048576)
	if v := testutil.ToFloat64(TileCacheBytes); v != 1048576 {
		t.Fatalf("TileCacheBytes = %v, want 1048576", v)
	}

	MPTPredictDurationSeconds.Observe(0.123)
	OutputLogAppendDurationSeconds.Observe(0.045)

	MapErrorsTotal.WithLabelValues("skip").Inc()
	if v := testutil.ToFloat64(MapErrorsTotal.WithLabelValues("skip")); v < 1 {
		t.Fatalf("MapErrorsTotal(skip) = %v, want >= 1", v)
	}

	LookupResultsReturned.Observe(4)

	IngestionLag.Set(20)
	if v := testutil.ToFloat64(IngestionLag); v != 20 {
		t.Fatalf("IngestionLag = %v, want 20", v)
	}

	IndexingLag.Set(5)
	if v := testutil.ToFloat64(IndexingLag); v != 5 {
		t.Fatalf("IndexingLag = %v, want 5", v)
	}

	MapDurationSeconds.Observe(0.002)
	WitnessWaitSeconds.Observe(0.25)
	MPTLockWaitSeconds.Observe(0.001)
	MPTWriteDurationSeconds.Observe(0.015)
	PebbleApplyDurationSeconds.Observe(0.03)
	LookupLatencySeconds.Observe(0.005)

	MPTMMapBytes.Set(65536)
	if v := testutil.ToFloat64(MPTMMapBytes); v != 65536 {
		t.Fatalf("MPTMMapBytes = %v, want 65536", v)
	}

	ResetAuditorRootMismatch()
	if v := testutil.ToFloat64(AuditorRootMismatch); v != 0 {
		t.Fatalf("AuditorRootMismatch after reset = %v, want 0", v)
	}
	beforeMismatches := testutil.ToFloat64(AuditorRootMismatchesTotal)
	RecordAuditorRootMismatch()
	if v := testutil.ToFloat64(AuditorRootMismatch); v != 1 {
		t.Fatalf("AuditorRootMismatch after record = %v, want 1", v)
	}
	if v := testutil.ToFloat64(AuditorRootMismatchesTotal); v != beforeMismatches+1 {
		t.Fatalf("AuditorRootMismatchesTotal = %v, want %v", v, beforeMismatches+1)
	}
	SetAuditorRootMismatch(0)
	if v := testutil.ToFloat64(AuditorRootMismatch); v != 0 {
		t.Fatalf("AuditorRootMismatch after SetAuditorRootMismatch(0) = %v, want 0", v)
	}
}
