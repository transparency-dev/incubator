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

// vindexd is the Verifiable Index indexing and HTTP serving daemon.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/internal/server"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	err := run(ctx, os.Args[1:], nil)
	if err == nil || errors.Is(err, flag.ErrHelp) || errors.Is(err, context.Canceled) {
		return
	}
	klog.Exitf("vindexd failed: %v", err)
}

func parseSigner(rawOrPath string) (note.Signer, error) {
	keyStr := strings.TrimSpace(rawOrPath)
	if keyStr == "" {
		return nil, errors.New("signer key is empty")
	}
	isFilePath := strings.Count(keyStr, "+") < 2
	if !isFilePath {
		if info, err := os.Stat(keyStr); err == nil && !info.IsDir() {
			isFilePath = true
		}
	}
	if isFilePath {
		data, err := os.ReadFile(keyStr)
		if err != nil {
			return nil, fmt.Errorf("failed to read signer key file: %w", err)
		}
		keyStr = string(bytes.TrimSpace(data))
		if keyStr == "" {
			return nil, errors.New("signer key file is empty")
		}
	}
	return fnote.NewSigner(keyStr)
}

func startHTTPListener(addr, label string, handler http.Handler) (string, func(), error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, fmt.Errorf("failed to bind %s %q: %w", label, addr, err)
	}
	boundAddr := ln.Addr().String()
	srv := server.NewHTTPServer(boundAddr, handler)
	done := make(chan struct{})
	go func() {
		defer close(done)
		klog.Infof("Serving %s at http://%s", label, boundAddr)
		if sErr := srv.Serve(ln); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			klog.Errorf("%s error: %v", label, sErr)
		}
	}()
	shutdown := func() {
		sCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer sCancel()
		if sErr := srv.Shutdown(sCtx); sErr != nil {
			_ = srv.Close()
		}
		<-done
	}
	return boundAddr, shutdown, nil
}

func run(ctx context.Context, args []string, onStarted func(listenAddr, metricsAddr string)) (retErr error) {
	var storage vindex.StorageConfig
	var tuning vindex.TuningOptions
	serve := vindex.ServeOptions{ServeOutputTiles: true}

	fs := flag.NewFlagSet("vindexd", flag.ContinueOnError)
	inputLogURL := fs.String("input_log_url", "", "Base URL of the Input Log (required).")
	inputLogOrigin := fs.String("input_log_origin", "", "Expected origin string for Input Log checkpoints.")
	inputLogPubKey := fs.String("input_log_pubkey", "", "Public key or key file for Input Log checkpoint verification (standard note or mtc+<name>+<cosignerID>+<logID>+<pubKeyBase64>).")
	inputLogPolicy := fs.String("input_log_policy", "", "Path to C2SP tlog-policy file for Input Log checkpoint verification.")
	insecureSkipVerify := fs.Bool("insecure_skip_verify", false, "Allow unverified Input Log checkpoints when --input_log_policy and --input_log_pubkey are unset (for local testing only).")
	inputLogType := fs.String("input_log_type", "auto", "Input Log layout type: 'auto', 'tessera', or 'static-ct'.")
	fromVal := fs.Uint64("from", 0, "Starting Input Log leaf index (from) for Output Log commitments.")

	fs.StringVar(&storage.OutputLogDir, "output_log_dir", "", "Directory path for local Output Log storage (required).")
	outputLogSignerKey := fs.String("output_log_signer_key", "", "Note signer string or path to private key for signing Output Log checkpoints (required).")
	outputLogPolicy := fs.String("output_log_policy", "", "Path to C2SP tlog-policy file configuring Output Log witness quorum cosigning and verification.")

	fs.StringVar(&storage.DBPath, "db_path", "", "Directory path for Pebble KV store (required).")
	fs.StringVar(&storage.MPTDir, "mpt_dir", "", "Directory path for MPT persistence files (required).")
	fs.StringVar(&storage.TileCacheDir, "tile_cache_dir", "", "Directory path for local Input Log bundle cache.")

	wasmPath := fs.String("wasm_path", "", "Path to compiled MapFn WASM binary (required).")
	fs.IntVar(&tuning.Workers, "wasm_workers", 0, "Number of concurrent WASM worker instances (0 = auto).")
	fs.IntVar(&tuning.FetchWorkers, "fetch_workers", 0, "Number of concurrent tile fetch workers (0 = auto).")
	fs.Uint64Var(&tuning.CommitBatchSize, "commit_batch_size", 0, "Number of leaves accumulated per batch commit (0 = default 4096).")
	fs.DurationVar(&tuning.PollInterval, "poll_interval", 0, "Ingestion polling interval (0 = default 10s).")
	fs.IntVar(&tuning.DBCacheSizeMB, "db_cache_size_mb", 0, "Pebble block cache size in megabytes (0 = default 512).")
	fs.IntVar(&tuning.DBMaxOpenFiles, "db_max_open_files", 0, "Maximum open files for Pebble DB (0 = auto).")

	listenAddr := fs.String("listen_addr", ":8080", "Public HTTP Read Server address.")
	metricsAddr := fs.String("metrics_addr", ":9090", "Internal operational listener address for /metrics, /healthz, /readyz, and pprof.")
	fs.StringVar(&serve.PathPrefix, "path_prefix", "", "Base URL path prefix to host vindex endpoints under (defaults to root).")
	enableUI := fs.Bool("enable_ui", true, "Serve the raw wire inspector HTML UI at / and /index.html.")
	prefixPolicyName := fs.String("prefix_policy", "allow", "Prefix query policy for /keys?prefix=<prefix>: 'allow' (default), 'reversed-dns' ('domain'), or 'none'.")
	fs.IntVar(&serve.MaxPrefixKeys, "max_prefix_keys", 0, "Maximum matching keys returned by a single /keys?prefix=<prefix> query before HTTP 413 (0 = default 10000).")
	oneShot := fs.Bool("oneshot", false, "Run synchronization once against log tip and exit.")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	if *oneShot {
		// Ensure an interrupted --oneshot run exits non-zero rather than being
		// treated as a graceful daemon shutdown in main() regardless of stage.
		defer func() {
			if errors.Is(retErr, context.Canceled) {
				retErr = fmt.Errorf("oneshot interrupted: %v", retErr)
			}
		}()
	}

	if strings.TrimSpace(storage.DBPath) == "" {
		return errors.New("--db_path flag is required")
	}
	if strings.TrimSpace(storage.MPTDir) == "" {
		return errors.New("--mpt_dir flag is required")
	}
	if strings.TrimSpace(*wasmPath) == "" {
		return errors.New("--wasm_path flag is required")
	}
	if strings.TrimSpace(storage.OutputLogDir) == "" {
		return errors.New("--output_log_dir flag is required")
	}
	if strings.TrimSpace(*outputLogSignerKey) == "" {
		return errors.New("--output_log_signer_key flag is required")
	}

	inPolSet := strings.TrimSpace(*inputLogPolicy) != ""
	inKeySet := strings.TrimSpace(*inputLogPubKey) != ""
	if inPolSet && inKeySet {
		return errors.New("cannot specify both --input_log_policy and --input_log_pubkey")
	}
	inURL := strings.TrimSpace(*inputLogURL)
	if inURL == "" {
		return errors.New("--input_log_url flag is required")
	}
	if *insecureSkipVerify && (inPolSet || inKeySet) {
		return errors.New("cannot combine --insecure_skip_verify with --input_log_policy or --input_log_pubkey")
	}
	if !inPolSet && !inKeySet && !*insecureSkipVerify {
		return errors.New("--input_log_policy or --input_log_pubkey is required (or pass --insecure_skip_verify)")
	}

	var fromSet, listenSet, metricsSet bool
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "from":
			fromSet = true
		case "listen_addr":
			listenSet = true
		case "metrics_addr":
			metricsSet = true
		}
	})

	effListenAddr := strings.TrimSpace(*listenAddr)
	effMetricsAddr := strings.TrimSpace(*metricsAddr)
	if *oneShot {
		if !listenSet {
			effListenAddr = ""
		}
		if !metricsSet {
			effMetricsAddr = ""
		}
	}
	if effListenAddr != "" {
		if _, _, err := net.SplitHostPort(effListenAddr); err != nil {
			return fmt.Errorf("invalid --listen_addr %q: %w", effListenAddr, err)
		}
	}
	if effMetricsAddr != "" {
		if _, _, err := net.SplitHostPort(effMetricsAddr); err != nil {
			return fmt.Errorf("invalid --metrics_addr %q: %w", effMetricsAddr, err)
		}
	}

	prefixFn, err := vindex.ParsePrefixPolicy(*prefixPolicyName)
	if err != nil {
		return err
	}
	serve.PrefixPolicyFunc = prefixFn
	serve.DisableUI = !*enableUI

	outSigner, err := parseSigner(*outputLogSignerKey)
	if err != nil {
		return fmt.Errorf("failed to parse --output_log_signer_key: %w", err)
	}

	var opts []vindex.Option
	if outPolPath := strings.TrimSpace(*outputLogPolicy); outPolPath != "" {
		polBytes, rErr := os.ReadFile(outPolPath)
		if rErr != nil {
			return fmt.Errorf("failed to read --output_log_policy %q: %w", outPolPath, rErr)
		}
		opts = append(opts, vindex.WithOutputWitnessPolicy(polBytes))
	}

	switch strings.ToLower(strings.TrimSpace(*inputLogType)) {
	case "", "auto":
	case "static-ct", "ct":
		opts = append(opts, vindex.WithStaticCT(true))
	case "tessera":
		opts = append(opts, vindex.WithStaticCT(false))
	default:
		return fmt.Errorf("unknown --input_log_type %q: expected 'auto', 'tessera', or 'static-ct'", *inputLogType)
	}

	inOrigin := strings.TrimSpace(*inputLogOrigin)
	var inPolicy vindex.CheckpointPolicy
	if !*insecureSkipVerify {
		pol, pErr := wire.ParsePolicyOrVerifier(*inputLogPolicy, *inputLogPubKey, inOrigin, nil, 0)
		if pErr != nil {
			return fmt.Errorf("invalid input log policy/pubkey: %w", pErr)
		}
		inPolicy = pol
	}

	wasmBytes, err := os.ReadFile(strings.TrimSpace(*wasmPath))
	if err != nil {
		return fmt.Errorf("failed to read WASM binary %q: %w", *wasmPath, err)
	}
	wasmHost, err := vindex.NewWASMHost(ctx, wasmBytes, tuning.Workers)
	if err != nil {
		return fmt.Errorf("failed to initialize WASM host from %q: %w", *wasmPath, err)
	}
	defer func() {
		retErr = errors.Join(retErr, wasmHost.Close(context.Background()))
	}()

	if *insecureSkipVerify {
		opts = append(opts, vindex.WithUnverifiedInputLog(inURL, inOrigin, wasmHost))
	} else {
		opts = append(opts, vindex.WithInputLog(inURL, inPolicy, wasmHost))
		if inOrigin != "" {
			opts = append(opts, vindex.WithInputOrigin(inOrigin))
		}
	}
	if fromSet || *fromVal > 0 {
		opts = append(opts, vindex.WithFrom(*fromVal))
	}
	opts = append(opts, vindex.WithServing(serve), vindex.WithTuning(tuning))

	if strings.TrimSpace(storage.TileCacheDir) == "" {
		klog.Warning("--tile_cache_dir is not set; local disk tile caching is disabled.")
	}

	engine, err := vindex.New(storage, outSigner, opts...)
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, engine.Close())
	}()

	var boundMetrics, boundListen string
	if effMetricsAddr != "" {
		bound, shutdownMetrics, lErr := startHTTPListener(effMetricsAddr, "operational endpoints (/metrics, /healthz, /readyz, pprof)", engine.AdminHandler())
		if lErr != nil {
			return lErr
		}
		defer shutdownMetrics()
		boundMetrics = bound
	}
	if effListenAddr != "" {
		bound, shutdownPublic, lErr := startHTTPListener(effListenAddr, "VIndex Read API", engine.Handler())
		if lErr != nil {
			return lErr
		}
		defer shutdownPublic()
		boundListen = bound
	}

	if onStarted != nil {
		onStarted(boundListen, boundMetrics)
	}

	if *oneShot {
		klog.Info("Running oneshot synchronization...")
		syncStart := time.Now()
		// Format with %v rather than %w so an interrupted oneshot exits non-zero instead of being suppressed as graceful shutdown.
		if err := engine.SyncOnce(ctx); err != nil {
			return fmt.Errorf("oneshot sync failed: %v", err)
		}
		klog.Infof("Oneshot sync completed in %v.", time.Since(syncStart))
		return nil
	}

	return engine.Run(ctx)
}
