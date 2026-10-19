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

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

func TestHammerCLI_ValidationAndWriteGoalTimeout(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	_, outVKey, err := note.GenerateKey(rand.Reader, "example.com/out")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		args    []string
		wantSub string
	}{
		{
			name:    "missing_storage_dir",
			args:    []string{},
			wantSub: "--storage_dir",
		},
		{
			name:    "nan_write_rate",
			args:    []string{"--storage_dir", t.TempDir(), "--write_rate", "NaN"},
			wantSub: "--write_rate",
		},
		{
			name:    "prefix_ratio_out_of_range",
			args:    []string{"--storage_dir", t.TempDir(), "--prefix_ratio", "1.5"},
			wantSub: "--prefix_ratio",
		},
		{
			name:    "readers_without_policy_or_pubkey",
			args:    []string{"--storage_dir", t.TempDir(), "--num_readers", "2"},
			wantSub: "--output_log_policy or --output_log_pubkey",
		},
		{
			name:    "write_goal_without_policy_or_pubkey",
			args:    []string{"--storage_dir", t.TempDir(), "--num_readers", "0", "--write_goal", "5"},
			wantSub: "--output_log_policy or --output_log_pubkey",
		},
		{
			name:    "output_log_url_without_policy_or_pubkey",
			args:    []string{"--storage_dir", t.TempDir(), "--num_readers", "0", "--output_log_url", "http://localhost:8080"},
			wantSub: "--output_log_policy or --output_log_pubkey",
		},
		{
			name:    "invalid_zipf_s",
			args:    []string{"--storage_dir", t.TempDir(), "--zipf_s", "0.9"},
			wantSub: "--zipf_s must be > 1.0",
		},
		{
			name:    "invalid_ct_domain_bounds",
			args:    []string{"--storage_dir", t.TempDir(), "--ct_min_domains", "10", "--ct_max_domains", "5"},
			wantSub: "invalid CT domain bounds",
		},
	} {
		err := run(ctx, tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: run(%v) err = %v, want substring %q", tc.name, tc.args, err, tc.wantSub)
		}
	}

	// Verify --write_goal timeout under --runtime returns a non-DeadlineExceeded error so main() exits non-zero.
	err = run(ctx, []string{
		"--storage_dir", t.TempDir(),
		"--listen_addr", "127.0.0.1:0",
		"--vindex_url", "http://127.0.0.1:1",
		"--output_log_pubkey", outVKey,
		"--num_readers", "0",
		"--write_goal", "10",
		"--runtime", "150ms",
	})
	if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "write_goal") {
		t.Fatalf("expected non-DeadlineExceeded write_goal timeout error, got: %v", err)
	}
}

func TestHammerCLI_WriteOnlyContinuousStopsCleanlyOnRuntime(t *testing.T) {
	t.Parallel()
	inSKey, _, err := note.GenerateKey(rand.Reader, "corp.example/custom-inlog")
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	err = run(t.Context(), []string{
		"--storage_dir", t.TempDir(),
		"--listen_addr", "127.0.0.1:0",
		"--input_log_signer_key", inSKey,
		"--num_readers", "0",
		"--write_rate", "50",
		"--runtime", "120ms",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected clean context.DeadlineExceeded on continuous --runtime expiry, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("expected fast shutdown on --runtime expiry, took %v", elapsed)
	}
}
