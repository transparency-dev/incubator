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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/ingest"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

func collectTileJobs(treeSize uint64, levelFlag int) []tileJob {
	var jobs []tileJob
	_ = streamTileJobs(context.Background(), treeSize, levelFlag, func(j tileJob) error {
		jobs = append(jobs, j)
		return nil
	})
	return jobs
}

func TestClonelog_FlagValidationAndFallbackSafety(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	// Missing --input_log_url and missing verification key must fail closed by default.
	if err := run(ctx, []string{"--out_dir=" + t.TempDir()}); err == nil || !strings.Contains(err.Error(), "--input_log_url") {
		t.Fatalf("expected missing --input_log_url error, got: %v", err)
	}
	if err := run(ctx, []string{"--input_log_url=http://127.0.0.1:1/", "--out_dir=" + t.TempDir()}); err == nil || !strings.Contains(err.Error(), "--input_log_policy or --input_log_pubkey is required") {
		t.Fatalf("expected missing verification policy error without --insecure_skip_verify, got: %v", err)
	}

	const treeSize uint64 = 600 // 3 entry bundles (256, 256, 88), 3 level-0 hash tiles, 1 level-1 hash tile
	if gotCount := countTileJobs(treeSize, -2); gotCount != 7 {
		t.Fatalf("countTileJobs(600, -2) = %d, want 7", gotCount)
	}

	var transientFails atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/checkpoint", func(w http.ResponseWriter, _ *http.Request) {
		cpContent := fmt.Sprintf("example.com/log\n%d\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— example.com/log sig\n", treeSize)
		_, _ = w.Write([]byte(cpContent))
	})

	for bIdx := range uint64(2) {
		relPath := "/" + layout.EntriesPath(bIdx, 0)
		bIdxCopy := bIdx
		mux.HandleFunc(relPath, func(w http.ResponseWriter, _ *http.Request) {
			if bIdxCopy == 1 && transientFails.Add(1) == 1 {
				http.Error(w, "temporary error", http.StatusInternalServerError)
				return
			}
			_, _ = fmt.Fprintf(w, "tile_data_bundle_%d", bIdxCopy)
		})
	}
	mux.HandleFunc("/"+layout.EntriesPath(2, 0), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("full_256_bundle_2"))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	tempDir := t.TempDir()
	u, _ := url.Parse(ts.URL + "/")

	var stats cloneStats
	client := ts.Client()

	cpData, parsedSize, _, err := fetchCheckpoint(ctx, client, u, nil, "example.com/log", 3)
	if err != nil {
		t.Fatalf("fetchCheckpoint failed: %v", err)
	}
	if parsedSize != treeSize || len(cpData) == 0 {
		t.Fatalf("parsed treeSize = %d, len=%d", parsedSize, len(cpData))
	}

	entryJobs := collectTileJobs(treeSize, -1)
	for _, job := range entryJobs {
		if err := downloadTileJob(ctx, client, u, tempDir, false, job, treeSize, 3, &stats); err != nil {
			t.Fatalf("downloadTileJob(%+v) failed: %v", job, err)
		}
	}

	// Fallback on bundle 2 MUST write ONLY the full path (/002) and NOT corrupt .p/88!
	if _, err := os.Stat(filepath.Join(tempDir, layout.EntriesPath(2, 88))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected partial path .p/88 NOT to be written when fallback full bundle was used, stat err=%v", err)
	}
	if gotFull, err := os.ReadFile(filepath.Join(tempDir, layout.EntriesPath(2, 0))); err != nil || string(gotFull) != "full_256_bundle_2" {
		t.Fatalf("expected full fallback bundle at /002, got %q (err=%v)", gotFull, err)
	}

	// Restart skip check (including skipping partial job 2 because full /002 exists)
	var statsRestart cloneStats
	for _, job := range entryJobs {
		if err := downloadTileJob(ctx, client, u, tempDir, false, job, treeSize, 3, &statsRestart); err != nil {
			t.Fatalf("restart downloadTileJob(%+v) failed: %v", job, err)
		}
	}
	if statsRestart.downloadedTiles.Load() != 0 || statsRestart.skippedTiles.Load() != 3 {
		t.Fatalf("restart stats: downloaded=%d skipped=%d, want 0 and 3", statsRestart.downloadedTiles.Load(), statsRestart.skippedTiles.Load())
	}
}

func TestClonelog_RealTesseraCloneVerifiedByTiledFetcher(t *testing.T) {
	ctx := t.Context()
	srcDir := filepath.Join(t.TempDir(), "src")
	dstDir := filepath.Join(t.TempDir(), "dst")

	skey, vkey, err := note.GenerateKey(rand.Reader, "test.clonelog.origin")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := note.NewSigner(skey)
	verifier, _ := note.NewVerifier(vkey)

	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	drv, err := posix.New(appCtx, posix.Config{Path: srcDir})
	if err != nil {
		t.Fatal(err)
	}
	app, shutdown, reader, err := tessera.NewAppender(appCtx, drv, tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(64, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		sCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer sCancel()
		_ = shutdown(sCtx)
	}()

	awaiter := tessera.NewPublicationAwaiter(appCtx, reader.ReadCheckpoint, 5*time.Millisecond)
	const nLeaves = 300 // Spans >1 bundle (requires level 0 and level 1 hash tiles)
	futs := make([]tessera.IndexFuture, nLeaves)
	for i := range nLeaves {
		futs[i] = app.Add(ctx, tessera.NewEntry(fmt.Appendf(nil, "entry-%d", i)))
	}
	for i, f := range futs {
		if _, _, err := awaiter.Await(ctx, f); err != nil {
			t.Fatalf("await(%d) failed: %v", i, err)
		}
	}

	ts := httptest.NewServer(http.FileServer(http.Dir(srcDir)))
	defer ts.Close()

	// Omit --input_log_origin to verify origin auto-derivation from --input_log_pubkey.
	if err := run(ctx, []string{
		"--input_log_url=" + ts.URL,
		"--input_log_pubkey=" + vkey,
		"--out_dir=" + dstDir,
		"--workers=4",
	}); err != nil {
		t.Fatalf("clonelog run() failed: %v", err)
	}

	// Verify TiledFetcher over file://<dstDir> authenticates checkpoint AND all 300 leaves via cloned hash tiles!
	tf, err := ingest.NewTiledFetcher(&url.URL{Scheme: "file", Path: dstDir}, verifier, "test.clonelog.origin", nil)
	if err != nil {
		t.Fatalf("NewTiledFetcher(file://dstDir) failed: %v", err)
	}
	cp, err := tf.Checkpoint(ctx)
	if err != nil || cp.Size != nLeaves {
		t.Fatalf("tf.Checkpoint = %+v, err=%v, want size %d", cp, err, nLeaves)
	}
	tf.SetTreeState(cp.Size, cp.Hash)
	bundles, err := tf.FetchTiles(ctx, 0, cp.Size)
	if err != nil {
		t.Fatalf("tf.FetchTiles failed against cloned directory: %v", err)
	}
	var count int
	for _, b := range bundles {
		count += len(b.Leaves)
		b.Release()
	}
	if count != nLeaves {
		t.Fatalf("fetched %d verified leaves from cloned dir, want %d", count, nLeaves)
	}
}
