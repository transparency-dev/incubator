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

// vindex-auditor is the dedicated standalone Verifiable Index auditor and verifier.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/transparency-dev/incubator/vindex/internal/auditor"
	"github.com/transparency-dev/incubator/vindex/internal/wasmhost"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
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
	klog.Exitf("vindex-auditor failed: %v", err)
}

func run(ctx context.Context, args []string, onInit func(*auditor.Verifier)) (retErr error) {
	fs := flag.NewFlagSet("vindex-auditor", flag.ContinueOnError)
	outputLogURL := fs.String("output_log_url", "", "Base URL of Output Log to verify (required).")
	outputLogPolicy := fs.String("output_log_policy", "", "Path to C2SP tlog-policy file for Output Log checkpoint verification.")
	outputLogPubKey := fs.String("output_log_pubkey", "", "Public key or key file for Output Log checkpoint verification.")
	outputLogOrigin := fs.String("output_log_origin", "", "Expected origin string for Output Log (inferred from --output_log_policy or --output_log_pubkey when unset).")

	inputLogURL := fs.String("input_log_url", "", "Base URL of the Input Log (required).")
	inputLogPolicy := fs.String("input_log_policy", "", "Path to C2SP tlog-policy file for Input Log checkpoint verification.")
	inputLogPubKey := fs.String("input_log_pubkey", "", "Public key or key file for Input Log checkpoint verification (standard note or mtc+<name>+<cosignerID>+<logID>+<pubKeyBase64>).")
	inputLogOrigin := fs.String("input_log_origin", "", "Expected origin string for Input Log checkpoints (inferred from --input_log_policy or --input_log_pubkey when unset).")
	inputLogType := fs.String("input_log_type", "auto", "Input Log layout type: 'auto', 'tessera', or 'static-ct'.")
	fromFlag := fs.Uint64("from", 0, "Expected starting Input Log leaf index (from) in Output Log leaves.")

	dbPath := fs.String("db_path", "", "Directory path for Pebble KV store (required).")
	mptDir := fs.String("mpt_dir", "", "Directory path for MPT persistence files (required).")
	tileCacheDir := fs.String("tile_cache_dir", "", "Directory path for local Input Log bundle cache.")

	wasmPath := fs.String("wasm_path", "", "Path to compiled MapFn WASM binary (required).")
	wasmWorkers := fs.Int("wasm_workers", 0, "Number of concurrent WASM worker instances (0 = auto).")
	fetchWorkers := fs.Int("fetch_workers", 0, "Number of concurrent tile fetch workers (0 = auto).")
	commitBatchSize := fs.Uint64("commit_batch_size", 0, "Number of leaves accumulated per batch commit (0 = default 4096).")
	pollInterval := fs.Duration("poll_interval", 0, "Polling interval for new Output Log checkpoints (0 = default 10s).")
	dbCacheSizeMB := fs.Int("db_cache_size_mb", 0, "Pebble block cache size in megabytes (0 = default 512).")
	dbMaxOpenFiles := fs.Int("db_max_open_files", 0, "Maximum open files for Pebble DB (0 = auto).")

	metricsAddr := fs.String("metrics_addr", "127.0.0.1:9090", "Internal operational listener address for /metrics, /healthz, /readyz, and pprof.")
	oneShot := fs.Bool("oneshot", false, "Run verification once against log tip and exit.")

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

	outURL, err := parseLogURL(*outputLogURL, "output_log_url")
	if err != nil {
		return err
	}
	inURL, err := parseLogURL(*inputLogURL, "input_log_url")
	if err != nil {
		return err
	}
	cleanDBPath := strings.TrimSpace(*dbPath)
	if cleanDBPath == "" {
		return errors.New("--db_path flag is required")
	}
	cleanMPTDir := strings.TrimSpace(*mptDir)
	if cleanMPTDir == "" {
		return errors.New("--mpt_dir flag is required")
	}
	cleanWASMPath := strings.TrimSpace(*wasmPath)
	if cleanWASMPath == "" {
		return errors.New("--wasm_path flag is required")
	}

	cleanLogType := strings.ToLower(strings.TrimSpace(*inputLogType))
	switch cleanLogType {
	case "", "auto", "tessera", "static-ct", "ct":
	default:
		return fmt.Errorf("unknown --input_log_type %q: expected 'auto', 'tessera', or 'static-ct'", *inputLogType)
	}

	inPolicy, inOrigin, err := buildLogPolicy(*inputLogPolicy, *inputLogPubKey, *inputLogOrigin, "input_log")
	if err != nil {
		return err
	}
	outPolicy, outOrigin, err := buildLogPolicy(*outputLogPolicy, *outputLogPubKey, *outputLogOrigin, "output_log")
	if err != nil {
		return err
	}

	var metricsSet bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "metrics_addr" {
			metricsSet = true
		}
	})
	effMetricsAddr := strings.TrimSpace(*metricsAddr)
	if *oneShot && !metricsSet {
		effMetricsAddr = ""
	}
	if effMetricsAddr != "" {
		if _, _, err := net.SplitHostPort(effMetricsAddr); err != nil {
			return fmt.Errorf("invalid --metrics_addr %q: %w", effMetricsAddr, err)
		}
	}

	wasmBytes, err := os.ReadFile(cleanWASMPath)
	if err != nil {
		return fmt.Errorf("failed to read WASM binary %q: %w", cleanWASMPath, err)
	}
	wasmHost, err := wasmhost.NewWASMHost(ctx, wasmBytes, *wasmWorkers)
	if err != nil {
		return fmt.Errorf("failed to initialize WASM host from %q: %w", cleanWASMPath, err)
	}
	defer func() {
		retErr = errors.Join(retErr, wasmHost.Close(context.Background()))
	}()

	fromVal := *fromFlag
	v, err := auditor.New(auditor.Config{
		InputLogURL:     inURL,
		InputLogOrigin:  inOrigin,
		InputLogPolicy:  inPolicy,
		InputLogType:    cleanLogType,
		OutputLogURL:    outURL,
		OutputLogOrigin: outOrigin,
		OutputLogPolicy: outPolicy,
		WASMHost:        wasmHost,
		ExpectedFrom:    &fromVal,
		DBPath:          cleanDBPath,
		DBCacheSizeMB:   *dbCacheSizeMB,
		DBMaxOpenFiles:  *dbMaxOpenFiles,
		MPTDir:          cleanMPTDir,
		TileCacheDir:    strings.TrimSpace(*tileCacheDir),
		MetricsAddr:     effMetricsAddr,
		PollInterval:    *pollInterval,
		CommitBatchSize: *commitBatchSize,
		WASMWorkers:     *wasmWorkers,
		FetchWorkers:    *fetchWorkers,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize auditor engine: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, v.Close())
	}()

	if onInit != nil {
		onInit(v)
	}

	if *oneShot {
		klog.Info("Running oneshot verification...")
		if err := v.VerifyOnce(ctx); err != nil {
			return fmt.Errorf("oneshot verification failed: %w", err)
		}
		klog.Info("Oneshot verification succeeded.")
		return nil
	}

	klog.Info("Starting auditor daemon...")
	return v.Run(ctx)
}

func parseLogURL(raw, flagName string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("--%s flag is required", flagName)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid --%s %q: %w", flagName, raw, err)
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return "", fmt.Errorf("invalid --%s %q: host is required", flagName, raw)
		}
		if !strings.HasSuffix(u.Path, "/") {
			u.Path += "/"
		}
	case "file":
		if (u.Host != "" && u.Host != "localhost") || u.Path == "" {
			return "", fmt.Errorf("invalid --%s %q: expected file:///path", flagName, raw)
		}
	default:
		return "", fmt.Errorf("invalid --%s %q: scheme must be http, https, or file", flagName, raw)
	}
	return u.String(), nil
}

func buildLogPolicy(policyPath, pubKey, origin, label string) (wire.Policy, string, error) {
	policyPath = strings.TrimSpace(policyPath)
	pubKey = strings.TrimSpace(pubKey)
	origin = strings.TrimSpace(origin)
	if policyPath != "" && pubKey != "" {
		return nil, "", fmt.Errorf("cannot specify both --%s_policy and --%s_pubkey", label, label)
	}
	if policyPath == "" && pubKey == "" {
		return nil, "", fmt.Errorf("--%s_policy or --%s_pubkey is required", label, label)
	}
	pol, err := wire.ParsePolicyOrVerifier(policyPath, pubKey, origin, nil, 0)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build %s policy: %w", label, err)
	}
	if origin == "" {
		origin = wire.PolicyOrigin(pol)
	}
	if origin == "" {
		return nil, "", fmt.Errorf("--%s_origin is required when --%s_policy does not specify a single log", label, label)
	}
	return pol, origin, nil
}
