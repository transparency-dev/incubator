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

// clonelog mirrors a tlog-tiles log to local disk with high concurrency.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

const (
	maxHashTileLevel      = 7
	maxCheckpointRespSize = 1 << 20  // 1 MiB
	maxTileRespSize       = 64 << 20 // 64 MiB
)

type tileJob struct {
	level int // -1 for entry bundles, >= 0 for hash tiles
	index uint64
}

type cloneStats struct {
	downloadedTiles atomic.Uint64
	skippedTiles    atomic.Uint64
	downloadedBytes atomic.Uint64
	downloadedCerts atomic.Uint64
}

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) {
		klog.Exitf("clonelog failed: %v", err)
	}
}

func ceilDiv(n, d uint64) uint64 {
	if n == 0 {
		return 0
	}
	return 1 + (n-1)/d
}

func countTileJobs(treeSize uint64, levelFlag int) uint64 {
	if treeSize == 0 {
		return 0
	}
	bundleWidth := max(uint64(layout.EntryBundleWidth), 256)
	var total uint64
	if levelFlag == -2 || levelFlag == -1 {
		total += ceilDiv(treeSize, bundleWidth)
	}
	startLvl, endLvl := 0, -1
	if levelFlag == -2 {
		endLvl = maxHashTileLevel
	} else if levelFlag >= 0 {
		startLvl, endLvl = levelFlag, levelFlag
	}
	for lvl := startLvl; lvl <= endLvl; lvl++ {
		levelHashes := treeSize >> (uint(lvl) * 8)
		if levelHashes == 0 {
			break
		}
		total += ceilDiv(levelHashes, 256)
	}
	return total
}

func streamTileJobs(ctx context.Context, treeSize uint64, levelFlag int, emit func(tileJob) error) error {
	if treeSize == 0 {
		return nil
	}
	bundleWidth := max(uint64(layout.EntryBundleWidth), 256)
	if levelFlag == -2 || levelFlag == -1 {
		numEntries := ceilDiv(treeSize, bundleWidth)
		for idx := range numEntries {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := emit(tileJob{level: -1, index: idx}); err != nil {
				return err
			}
		}
	}
	startLvl, endLvl := 0, -1
	if levelFlag == -2 {
		endLvl = maxHashTileLevel
	} else if levelFlag >= 0 {
		startLvl, endLvl = levelFlag, levelFlag
	}
	for lvl := startLvl; lvl <= endLvl; lvl++ {
		levelHashes := treeSize >> (uint(lvl) * 8)
		if levelHashes == 0 {
			break
		}
		numTiles := ceilDiv(levelHashes, 256)
		for idx := range numTiles {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := emit(tileJob{level: lvl, index: idx}); err != nil {
				return err
			}
		}
	}
	return nil
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("clonelog", flag.ContinueOnError)
	inputLogURL := fs.String("input_log_url", "", "Base URL of the remote tlog-tiles Input Log (required).")
	inputLogOrigin := fs.String("input_log_origin", "", "Expected origin string for Input Log checkpoint verification.")
	inputLogPubKey := fs.String("input_log_pubkey", "", "Public key or key file to verify the checkpoint before cloning.")
	inputLogPolicy := fs.String("input_log_policy", "", "Path to C2SP tlog-policy file to verify the checkpoint before cloning.")
	insecureSkipVerify := fs.Bool("insecure_skip_verify", false, "Allow cloning unverified checkpoints without --input_log_policy or --input_log_pubkey (for local testing only).")
	inputLogType := fs.String("input_log_type", "auto", "Input log layout type: 'auto', 'tessera', or 'static-ct'.")
	outDir := fs.String("out_dir", "", "Local directory to store mirrored log tiles (required).")
	numWorkers := fs.Int("workers", 64, "Number of concurrent download workers.")
	maxRetries := fs.Int("max_retries", 10, "Maximum retry attempts per tile on transient network/server errors.")
	progressInterval := fs.Duration("progress_interval", 5*time.Second, "Interval for logging periodic progress.")
	tileLevel := fs.Int("tile_level", -2, "Tile level to clone (-2 for entry bundles + all hash tile levels, -1 for entry bundles only, 0..7 for a single hash tile level).")
	useLocalCheckpoint := fs.Bool("use_local_checkpoint", false, "Use existing local checkpoint file to determine tree size without overwriting it.")

	if err := fs.Parse(args); err != nil {
		return err
	}

	rawURL := strings.TrimSpace(*inputLogURL)
	if rawURL == "" {
		return errors.New("--input_log_url must be specified")
	}
	targetOutDir := strings.TrimSpace(*outDir)
	if targetOutDir == "" {
		return errors.New("--out_dir must be specified")
	}
	if *numWorkers <= 0 {
		return errors.New("--workers must be > 0")
	}
	if *progressInterval <= 0 {
		return errors.New("--progress_interval must be > 0")
	}
	if *tileLevel < -2 || *tileLevel > maxHashTileLevel {
		return fmt.Errorf("--tile_level must be between -2 and %d, got %d", maxHashTileLevel, *tileLevel)
	}

	baseURL, err := url.Parse(rawURL)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return fmt.Errorf("invalid --input_log_url %q: expected http(s) URL", rawURL)
	}
	if !strings.HasSuffix(baseURL.Path, "/") {
		baseURL.Path += "/"
	}

	var isStaticCT bool
	switch strings.ToLower(strings.TrimSpace(*inputLogType)) {
	case "tessera":
		isStaticCT = false
	case "static-ct", "ct":
		isStaticCT = true
	case "", "auto":
		isStaticCT = strings.Contains(baseURL.Host, "certificate.transparency") || strings.Contains(baseURL.Path, "static-ct")
	default:
		return fmt.Errorf("unknown --input_log_type %q: expected 'auto', 'tessera', or 'static-ct'", *inputLogType)
	}

	polPath := strings.TrimSpace(*inputLogPolicy)
	pubKey := strings.TrimSpace(*inputLogPubKey)
	if polPath != "" && pubKey != "" {
		return errors.New("cannot specify both --input_log_policy and --input_log_pubkey")
	}
	expectedOrigin := strings.TrimSpace(*inputLogOrigin)
	var cpPolicy wire.Policy
	if polPath != "" || pubKey != "" {
		cpPolicy, err = wire.ParsePolicyOrVerifier(polPath, pubKey, expectedOrigin, nil, 0)
		if err != nil {
			return fmt.Errorf("invalid input log checkpoint policy/pubkey: %w", err)
		}
		if expectedOrigin == "" {
			expectedOrigin = wire.PolicyOrigin(cpPolicy)
		}
		if expectedOrigin == "" {
			return errors.New("--input_log_origin is required when --input_log_policy does not specify a single log")
		}
	} else if !*insecureSkipVerify {
		return errors.New("--input_log_policy or --input_log_pubkey is required (or pass --insecure_skip_verify for local testing)")
	}

	if err := os.MkdirAll(targetOutDir, 0o755); err != nil {
		return fmt.Errorf("failed to create out_dir %q: %w", targetOutDir, err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        *numWorkers * 4,
			MaxIdleConnsPerHost: *numWorkers * 2,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		Timeout: 60 * time.Second,
	}

	cpPath := filepath.Join(targetOutDir, "checkpoint")
	var cpBytes []byte
	var treeSize uint64
	if *useLocalCheckpoint {
		cpBytes, err = os.ReadFile(cpPath)
		if err != nil {
			return fmt.Errorf("failed to read local checkpoint %q: %w", cpPath, err)
		}
		var vErr error
		treeSize, _, vErr = parseAndVerifyCheckpoint(cpBytes, cpPolicy, expectedOrigin)
		if vErr != nil {
			return fmt.Errorf("invalid local checkpoint: %w", vErr)
		}
		klog.Infof("Using local checkpoint: treeSize = %d", treeSize)
	} else {
		var remoteHash [sha256.Size]byte
		cpBytes, treeSize, remoteHash, err = fetchCheckpoint(ctx, httpClient, baseURL, cpPolicy, expectedOrigin, *maxRetries)
		if err != nil {
			return fmt.Errorf("failed to fetch checkpoint: %w", err)
		}
		// Prevent overwriting a newer local checkpoint with a regressed or split-view CDN response.
		if existingCP, rErr := os.ReadFile(cpPath); rErr == nil {
			existingSize, existingHash, pErr := parseAndVerifyCheckpoint(existingCP, cpPolicy, expectedOrigin)
			if pErr != nil {
				return fmt.Errorf("existing local checkpoint %q failed verification: %w", cpPath, pErr)
			}
			if treeSize < existingSize {
				return fmt.Errorf("remote checkpoint regressed: remote size %d < existing local size %d", treeSize, existingSize)
			}
			if treeSize == existingSize && remoteHash != existingHash {
				return fmt.Errorf("checkpoint split-view at size %d: remote hash %x != existing local hash %x", treeSize, remoteHash, existingHash)
			}
		}
		klog.Infof("Fetched checkpoint: treeSize = %d (%d bytes)", treeSize, len(cpBytes))
	}

	totalJobs := countTileJobs(treeSize, *tileLevel)

	var stats cloneStats
	startTime := time.Now()
	stopProgress := make(chan struct{})
	var wgProgress sync.WaitGroup
	wgProgress.Add(1)
	go func() {
		defer wgProgress.Done()
		logProgressLoop(ctx, stopProgress, startTime, *progressInterval, totalJobs, &stats)
	}()

	g, gCtx := errgroup.WithContext(ctx)
	jobs := make(chan tileJob, *numWorkers*4)
	g.Go(func() error {
		defer close(jobs)
		return streamTileJobs(gCtx, treeSize, *tileLevel, func(job tileJob) error {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			case jobs <- job:
				return nil
			}
		})
	})
	for range *numWorkers {
		g.Go(func() error {
			for job := range jobs {
				if err := downloadTileJob(gCtx, httpClient, baseURL, targetOutDir, isStaticCT, job, treeSize, *maxRetries, &stats); err != nil {
					return fmt.Errorf("failed on level %d tile %d: %w", job.level, job.index, err)
				}
			}
			return nil
		})
	}

	workErr := g.Wait()
	close(stopProgress)
	wgProgress.Wait()
	if workErr != nil {
		return workErr
	}

	if !*useLocalCheckpoint {
		if err := atomicWriteFile(cpPath, cpBytes); err != nil {
			return fmt.Errorf("failed to persist checkpoint after clone: %w", err)
		}
	}

	elapsed := time.Since(startTime)
	dlTiles := stats.downloadedTiles.Load()
	skTiles := stats.skippedTiles.Load()
	totalMB := float64(stats.downloadedBytes.Load()) / (1024 * 1024)
	klog.Infof("Clone completed in %s: %d tiles (%d downloaded, %d skipped), %d entries, %.2f MB",
		elapsed.Truncate(time.Second), dlTiles+skTiles, dlTiles, skTiles, stats.downloadedCerts.Load(), totalMB)
	return nil
}

func logProgressLoop(ctx context.Context, stop <-chan struct{}, startTime time.Time, interval time.Duration, numBundles uint64, stats *cloneStats) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastBytes, lastCerts uint64
	lastTime := startTime
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			dlTiles := stats.downloadedTiles.Load()
			skTiles := stats.skippedTiles.Load()
			dlBytes := stats.downloadedBytes.Load()
			dlCerts := stats.downloadedCerts.Load()
			deltaSec := max(now.Sub(lastTime).Seconds(), 1e-3)

			pct := 0.0
			if numBundles > 0 {
				pct = float64(dlTiles+skTiles) / float64(numBundles) * 100.0
			}
			rateMB := float64(dlBytes-lastBytes) / (1024 * 1024 * deltaSec)
			rateItems := float64(dlCerts-lastCerts) / deltaSec
			klog.Infof("[Progress %5.1f%%] %d/%d tiles (%d downloaded, %d skipped) | %.1f MB | %.2f MB/s, %.0f items/s | %s",
				pct, dlTiles+skTiles, numBundles, dlTiles, skTiles, float64(dlBytes)/(1024*1024), rateMB, rateItems, time.Since(startTime).Truncate(time.Second))

			lastBytes, lastCerts, lastTime = dlBytes, dlCerts, now
		}
	}
}

func fetchWithRetry(ctx context.Context, client *http.Client, reqURL, fallbackURL string, maxBytes int64, retries int) ([]byte, bool, error) {
	var lastErr error
	attempts := max(retries, 1)
	for attempt := range attempts {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if attempt > 0 {
			shift := min(attempt, 7)
			backoff := min(time.Duration(100*(1<<shift))*time.Millisecond+time.Duration(rand.IntN(100))*time.Millisecond, 10*time.Second)
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-time.After(backoff):
			}
		}

		data, status, err := httpGetStatus(ctx, client, reqURL, maxBytes)
		if err == nil && status == http.StatusOK {
			return data, false, nil
		}
		if status == http.StatusNotFound && fallbackURL != "" {
			if fbData, fbStatus, fbErr := httpGetStatus(ctx, client, fallbackURL, maxBytes); fbErr == nil && fbStatus == http.StatusOK {
				return fbData, true, nil
			}
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("HTTP %d from %s", status, reqURL)
		}
	}
	return nil, false, fmt.Errorf("failed after %d attempts: %w", attempts, lastErr)
}

func httpGetStatus(ctx context.Context, client *http.Client, reqURL string, maxBytes int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, resp.StatusCode, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(data)) > maxBytes {
		return nil, resp.StatusCode, fmt.Errorf("response from %s exceeded %d bytes", reqURL, maxBytes)
	}
	return data, resp.StatusCode, nil
}

func atomicWriteFile(destPath string, data []byte) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(destPath)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func parseAndVerifyCheckpoint(rawData []byte, pol wire.Policy, expectedOrigin string) (uint64, [sha256.Size]byte, error) {
	var outHash [sha256.Size]byte
	if pol != nil {
		cp, err := pol.Verify(rawData)
		if err != nil {
			return 0, outHash, fmt.Errorf("checkpoint verification failed: %w", err)
		}
		if expectedOrigin != "" && cp.Origin != expectedOrigin {
			return 0, outHash, fmt.Errorf("checkpoint origin %q != expected %q", cp.Origin, expectedOrigin)
		}
		if len(cp.Hash) != sha256.Size {
			return 0, outHash, fmt.Errorf("invalid checkpoint hash length %d", len(cp.Hash))
		}
		copy(outHash[:], cp.Hash)
		return cp.Size, outHash, nil
	}
	hdrRaw, _, _ := bytes.Cut(rawData, []byte("\n\n"))
	cp, err := wire.ParseCheckpointHeader(hdrRaw)
	if err != nil {
		return 0, outHash, fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	if expectedOrigin != "" && cp.Origin != expectedOrigin {
		return 0, outHash, fmt.Errorf("checkpoint origin %q != expected %q", cp.Origin, expectedOrigin)
	}
	copy(outHash[:], cp.Hash)
	return cp.Size, outHash, nil
}

func fetchCheckpoint(ctx context.Context, client *http.Client, baseURL *url.URL, pol wire.Policy, expectedOrigin string, retries int) ([]byte, uint64, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	rawData, _, err := fetchWithRetry(ctx, client, baseURL.JoinPath("checkpoint").String(), "", maxCheckpointRespSize, retries)
	if err != nil {
		return nil, 0, zero, err
	}
	size, rootHash, err := parseAndVerifyCheckpoint(rawData, pol, expectedOrigin)
	if err != nil {
		return nil, 0, zero, err
	}
	return rawData, size, rootHash, nil
}

func bundleCertsCount(bIdx, treeSize uint64) uint64 {
	bundleWidth := max(uint64(layout.EntryBundleWidth), 256)
	if bIdx > treeSize/bundleWidth {
		return 0
	}
	start := bIdx * bundleWidth
	if start >= treeSize {
		return 0
	}
	return min(bundleWidth, treeSize-start)
}

func validTileByteLen(level int, p uint8, usedFallback bool, size int64) bool {
	if level >= 0 {
		if !usedFallback && p != 0 {
			return size == int64(p)*sha256.Size
		}
		return size == 256*sha256.Size
	}
	return size > 0
}

func downloadTileJob(ctx context.Context, client *http.Client, baseURL *url.URL, outDir string, isStaticCT bool, job tileJob, treeSize uint64, retries int, stats *cloneStats) error {
	bIdx := job.index
	var p uint8
	var relPath, fullRelPath string
	var certsInBundle uint64
	if job.level >= 0 {
		lvl := uint64(job.level)
		p = layout.PartialTileSize(lvl, bIdx, treeSize)
		relPath = layout.TilePath(lvl, bIdx, p)
		fullRelPath = layout.TilePath(lvl, bIdx, 0)
	} else if isStaticCT {
		p = layout.PartialTileSize(0, bIdx, treeSize)
		relPath = "tile/data/" + layout.TilePath(0, bIdx, p)[7:]
		fullRelPath = "tile/data/" + layout.TilePath(0, bIdx, 0)[7:]
		certsInBundle = bundleCertsCount(bIdx, treeSize)
	} else {
		p = layout.PartialTileSize(0, bIdx, treeSize)
		relPath = layout.EntriesPath(bIdx, p)
		fullRelPath = layout.EntriesPath(bIdx, 0)
		certsInBundle = bundleCertsCount(bIdx, treeSize)
	}

	destPath := filepath.Join(outDir, relPath)
	if info, err := os.Stat(destPath); err == nil && validTileByteLen(job.level, p, false, info.Size()) {
		stats.skippedTiles.Add(1)
		return nil
	}
	if p != 0 {
		if info, err := os.Stat(filepath.Join(outDir, fullRelPath)); err == nil && validTileByteLen(job.level, p, true, info.Size()) {
			stats.skippedTiles.Add(1)
			return nil
		}
	}

	var fallbackURL string
	if p != 0 {
		fallbackURL = baseURL.JoinPath(fullRelPath).String()
	}
	data, usedFallback, err := fetchWithRetry(ctx, client, baseURL.JoinPath(relPath).String(), fallbackURL, maxTileRespSize, retries)
	if err != nil {
		return err
	}
	if !validTileByteLen(job.level, p, usedFallback, int64(len(data))) {
		return fmt.Errorf("invalid tile byte length %d for level %d index %d (partial=%d, fallback=%v)", len(data), job.level, bIdx, p, usedFallback)
	}

	targetPath := destPath
	if usedFallback {
		targetPath = filepath.Join(outDir, fullRelPath)
	}
	if err := atomicWriteFile(targetPath, data); err != nil {
		return err
	}

	stats.downloadedTiles.Add(1)
	stats.downloadedBytes.Add(uint64(len(data)))
	stats.downloadedCerts.Add(certsInBundle)
	return nil
}
