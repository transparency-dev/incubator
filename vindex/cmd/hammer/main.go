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

// hammer is the implementation-agnostic C2SP tlog-vindex conformance checker and load-testing harness.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/incubator/vindex/internal/hammer"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		klog.Exitf("Hammer failed: %v", err)
	}
}

func checkFiniteNonNeg(name string, v float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return fmt.Errorf("--%s must be a finite number >= 0, got %v", name, v)
	}
	return nil
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("hammer", flag.ContinueOnError)
	var (
		storageDir        = fs.String("storage_dir", "", "Path for local Tessera POSIX Input Log storage.")
		vindexURL         = fs.String("vindex_url", "http://localhost:8080", "Base <index-url> of the target tlog-vindex server.")
		outputLogURL      = fs.String("output_log_url", "", "Optional <output-log-url> to verify Output Log tlog-tiles (/checkpoint and /tile/entries/...) conformance.")
		listenAddr        = fs.String("listen_addr", ":8085", "HTTP address to host hammer tlog-tiles Input Log and drip checkpoints.")
		numReaders        = fs.Int("num_readers", 8, "Number of concurrent verifying reader workers.")
		maxReadQPS        = fs.Float64("max_read_qps", 200, "Maximum total read queries per second (0 = unconstrained).")
		writeRate         = fs.Float64("write_rate", 500, "Target write rate (leaves/sec) into the local Input Log (0 = unconstrained).")
		writeGoal         = fs.Uint64("write_goal", 0, "Target number of leaves to write and verify before stopping (0 = continuous).")
		dripRate          = fs.Float64("drip_rate", 2.0, "Checkpoint drip-feed rate (CP/sec) released to the target VIndex.")
		burstInterval     = fs.Duration("burst_interval", 0, "Interval between burst checkpoint releases (0 = steady drip).")
		initialPause      = fs.Duration("initial_pause", 0, "Initial pause duration before drip-feeding checkpoints begins.")
		prefixRatio       = fs.Float64("prefix_ratio", 0.10, "Fraction of read queries that perform prefix scans [0.0, 1.0] (set 0 if target disables prefix queries).")
		checkConformance  = fs.Bool("conformance", true, "Run tlog-vindex HTTP status-code and parameter conformance probes.")
		keyDistribution   = fs.String("key_distribution", "zipf", "Key distribution: zipf, pareto, or uniform.")
		numKeys           = fs.Uint64("num_keys", 10000, "Number of unique keys in the active working set.")
		zipfS             = fs.Float64("zipf_s", 1.2, "Zipfian skew parameter (s > 1.0).")
		zipfV             = fs.Float64("zipf_v", 1.0, "Zipfian scale parameter (v >= 1.0).")
		runDuration       = fs.Duration("runtime", 0, "Test duration (e.g. 30s, 2m; 0 = run until interrupted).")
		statsInterval     = fs.Duration("stats_interval", 1*time.Second, "Terminal stats dashboard refresh interval.")
		inputLogOrigin    = fs.String("input_log_origin", "", "Input Log origin string (inferred from --input_log_signer_key or defaults to example.com/hammer/inputlog).")
		inputLogSignerKey = fs.String("input_log_signer_key", "", "Optional private note signer key (or file path) for Input Log checkpoints.")
		outputLogOrigin   = fs.String("output_log_origin", "", "Expected Output Log origin string (inferred from --output_log_policy or --output_log_pubkey when unset).")
		outputLogPubKey   = fs.String("output_log_pubkey", "", "Public key or key file for verifying Output Log checkpoint signatures.")
		outputLogPolicy   = fs.String("output_log_policy", "", "Path to C2SP tlog-policy file for verifying Output Log checkpoints.")
		leafFormat        = fs.String("leaf_format", "raw", "Synthetic leaf format and pure-Go MapFn profile: raw, sumdb, or ct.")
		ctMinDomains      = fs.Int("ct_min_domains", 1, "Minimum number of domains per CT leaf.")
		ctMaxDomains      = fs.Int("ct_max_domains", 50, "Maximum number of domains per CT leaf.")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	if strings.TrimSpace(*storageDir) == "" {
		return errors.New("--storage_dir flag is required")
	}
	if *numReaders < 0 {
		return errors.New("--num_readers must be >= 0")
	}
	if *numKeys == 0 {
		return errors.New("--num_keys must be >= 1")
	}
	for _, fc := range []struct {
		name string
		val  float64
	}{
		{"max_read_qps", *maxReadQPS},
		{"write_rate", *writeRate},
		{"drip_rate", *dripRate},
		{"prefix_ratio", *prefixRatio},
		{"zipf_s", *zipfS},
		{"zipf_v", *zipfV},
	} {
		if err := checkFiniteNonNeg(fc.name, fc.val); err != nil {
			return err
		}
	}
	if *prefixRatio > 1.0 {
		return fmt.Errorf("--prefix_ratio must be in [0.0, 1.0], got %v", *prefixRatio)
	}
	if (*keyDistribution == "zipf" || *keyDistribution == "pareto") && (*zipfS <= 1.0 || *zipfV < 1.0) {
		return fmt.Errorf("--zipf_s must be > 1.0 and --zipf_v must be >= 1.0 (got s=%v, v=%v)", *zipfS, *zipfV)
	}
	if *ctMinDomains < 1 || *ctMaxDomains < *ctMinDomains || *ctMaxDomains > 500 {
		return fmt.Errorf("invalid CT domain bounds: require 1 <= --ct_min_domains (%d) <= --ct_max_domains (%d) <= 500", *ctMinDomains, *ctMaxDomains)
	}
	if strings.TrimSpace(*outputLogPolicy) != "" && strings.TrimSpace(*outputLogPubKey) != "" {
		return errors.New("cannot specify both --output_log_policy and --output_log_pubkey")
	}

	var dist hammer.Distribution
	switch *keyDistribution {
	case "uniform":
		dist = hammer.DistUniform
	case "pareto", "zipf":
		dist = hammer.DistZipf
	default:
		return fmt.Errorf("unknown key_distribution %q (expected zipf, pareto, uniform)", *keyDistribution)
	}

	var lFormat hammer.LeafFormat
	switch *leafFormat {
	case "raw", "":
		lFormat = hammer.FormatRaw
	case "sumdb":
		lFormat = hammer.FormatSumDB
	case "ct":
		lFormat = hammer.FormatCT
	default:
		return fmt.Errorf("unknown leaf_format %q (expected raw, sumdb, ct)", *leafFormat)
	}

	if *runDuration > 0 {
		var runtimeCancel context.CancelFunc
		ctx, runtimeCancel = context.WithTimeout(ctx, *runDuration)
		defer runtimeCancel()
	}

	generator := hammer.NewGenerator(hammer.GeneratorConfig{
		Distribution: dist,
		NumKeys:      *numKeys,
		ZipfS:        *zipfS,
		ZipfV:        *zipfV,
		Seed:         time.Now().UnixNano(),
		LeafFormat:   lFormat,
		CTMinDomains: *ctMinDomains,
		CTMaxDomains: *ctMaxDomains,
	})

	sequencer, err := hammer.NewSequencer(ctx, hammer.SequencerConfig{
		StorageDir: *storageDir,
		Origin:     *inputLogOrigin,
		SignerKey:  *inputLogSignerKey,
		WriteRate:  *writeRate,
		WriteGoal:  *writeGoal,
	}, generator)
	if err != nil {
		return fmt.Errorf("failed to initialize sequencer: %w", err)
	}
	defer func() { _ = sequencer.Close(context.Background()) }()
	initialTreeSize := sequencer.Stats().LatestTreeSize

	dripServer := hammer.NewDripServer(hammer.ServerConfig{
		ListenAddr:    *listenAddr,
		StorageDir:    *storageDir,
		DripRate:      *dripRate,
		BurstInterval: *burstInterval,
		InitialPause:  *initialPause,
	}, sequencer.ReadCheckpoint)
	if err := dripServer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start drip server: %w", err)
	}
	defer func() { _ = dripServer.Close(context.Background()) }()

	analyzer := hammer.NewAnalyzer(sequencer)

	var outPolicy client.CheckpointPolicy
	outOrigin := strings.TrimSpace(*outputLogOrigin)
	needsVerification := *numReaders > 0 || *writeGoal > 0 || strings.TrimSpace(*outputLogURL) != ""
	if strings.TrimSpace(*outputLogPolicy) != "" || strings.TrimSpace(*outputLogPubKey) != "" {
		pol, pErr := wire.ParsePolicyOrVerifier(*outputLogPolicy, *outputLogPubKey, outOrigin, nil, 0)
		if pErr != nil {
			return fmt.Errorf("failed to parse output log policy/verifier: %w", pErr)
		}
		outPolicy = pol
	} else if needsVerification {
		return errors.New("--output_log_policy or --output_log_pubkey is required when --num_readers > 0, --write_goal > 0, or --output_log_url is set")
	}

	var dripWait time.Duration
	if *burstInterval > 0 {
		dripWait = *burstInterval
	} else if *dripRate > 0 {
		ns := float64(time.Second) / *dripRate
		if ns < float64(math.MaxInt64) {
			dripWait = time.Duration(ns)
		}
	}
	readinessWindow := max(15*time.Second, max(*initialPause, 0)+dripWait+15*time.Second)

	var readers *hammer.ReaderPool
	var standaloneOutVerifier *hammer.OutputLogVerifier
	if *numReaders > 0 {
		readers, err = hammer.NewReaderPool(hammer.ReaderConfig{
			VIndexURL:        *vindexURL,
			OutputLogURL:     *outputLogURL,
			NumWorkers:       *numReaders,
			MaxReadQPS:       *maxReadQPS,
			OutputLogOrigin:  outOrigin,
			OutputLogPolicy:  outPolicy,
			InputLogOrigin:   sequencer.Origin(),
			Oracle:           sequencer.Oracle(),
			CheckConformance: *checkConformance,
			PrefixRatio:      *prefixRatio,
			PageSize:         100,
			ReadinessTimeout: readinessWindow,
		}, generator, analyzer)
		if err != nil {
			return fmt.Errorf("failed to create reader pool: %w", err)
		}
	} else if strings.TrimSpace(*outputLogURL) != "" {
		standaloneOutVerifier, err = hammer.NewOutputLogVerifier(
			*outputLogURL,
			outOrigin,
			outPolicy,
			sequencer.Origin(),
			sequencer.Oracle(),
			5*time.Second,
			analyzer,
		)
		if err != nil {
			return fmt.Errorf("failed to create output log verifier: %w", err)
		}
	}

	fmt.Println("========================================================================")
	fmt.Printf("Starting tlog-vindex Conformance & Load Hammer\n")
	fmt.Printf("Input Log Server:   %s\n", dripServer.URL())
	fmt.Printf("Target VIndex URL:  %s\n", *vindexURL)
	if strings.TrimSpace(*outputLogURL) != "" {
		fmt.Printf("Output Log URL:     %s\n", *outputLogURL)
	}
	if *writeGoal > 0 {
		fmt.Printf("Write Goal:         %d leaves\n", *writeGoal)
	}
	fmt.Printf("Write Target:       %.1f leaves/sec | Drip Rate: %.1f CP/sec\n", *writeRate, *dripRate)
	fmt.Printf("Reader Workers:     %d (Max Read QPS: %.1f, Prefix Ratio: %.2f)\n", *numReaders, *maxReadQPS, *prefixRatio)
	fmt.Printf("Keyspace & Profile: %d keys (%s distribution, %s pure-Go MapFn)\n", *numKeys, *keyDistribution, lFormat)
	fmt.Printf("Input Log Origin:   %s\n", sequencer.Origin())
	fmt.Printf("Input Verifier Key: %s\n", sequencer.VerifierKey())
	fmt.Println("========================================================================")

	runCtx, cancelRun := context.WithCancel(ctx)
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		if sErr := sequencer.RunLoop(runCtx); sErr != nil && !errors.Is(sErr, context.Canceled) && !errors.Is(sErr, context.DeadlineExceeded) {
			errCh <- fmt.Errorf("sequencer failed: %v", sErr)
			cancelRun()
		}
	}()
	go func() {
		defer wg.Done()
		analyzer.RunDashboard(runCtx, *statsInterval)
	}()
	if readers != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rErr := readers.Start(runCtx); rErr != nil && runCtx.Err() == nil {
				errCh <- fmt.Errorf("reader pool failed: %v", rErr)
				cancelRun()
			}
		}()
	} else if standaloneOutVerifier != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			standaloneOutVerifier.Run(runCtx, 250*time.Millisecond)
		}()
	}

	var runErr error
	if *writeGoal > 0 {
		runErr = waitForWriteGoal(runCtx, *vindexURL, outOrigin, sequencer.Origin(), outPolicy, sequencer.Oracle(), readers, analyzer, initialTreeSize+*writeGoal)
	} else {
		<-runCtx.Done()
		runErr = ctx.Err()
	}

	cancelRun()
	wg.Wait()
	close(errCh)

	fmt.Println("\nStopping hammer load generation...")
	stats := analyzer.PrintSummary()

	if stats.InvariantViolations > 0 {
		return fmt.Errorf("hammer finished with %d invariant violations", stats.InvariantViolations)
	}
	for bgErr := range errCh {
		if bgErr != nil {
			return bgErr
		}
	}
	if readers != nil && stats.ReadSuccesses == 0 {
		return fmt.Errorf("hammer finished with 0 successful verified reads (failures: %d)", stats.ReadFailures)
	}
	if standaloneOutVerifier != nil && standaloneOutVerifier.VerifiedSize() == 0 {
		return errors.New("hammer finished with 0 verified output log checkpoints from --output_log_url")
	}
	return runErr
}

func waitForWriteGoal(
	ctx context.Context,
	vindexURL, outOrigin, inOrigin string,
	outPolicy client.CheckpointPolicy,
	oracle *hammer.Oracle,
	readers *hammer.ReaderPool,
	analyzer *hammer.Analyzer,
	targetSize uint64,
) error {
	var probeClient *client.Client
	if readers == nil {
		var err error
		probeClient, err = client.New(vindexURL, client.Config{
			ExpectedOutputLogOrigin: outOrigin,
			OutputLogPolicy:         outPolicy,
			ExpectedInputLogOrigin:  inOrigin,
		}, client.WithHTTPClient(&http.Client{Timeout: 3 * time.Second}))
		if err != nil {
			return fmt.Errorf("failed to create write-goal probe client: %w", err)
		}
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var lastSize, verifiedFrom uint64
	hasFrom := false
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("aborted before reaching write_goal %d (last indexed size: %d): %v", targetSize, lastSize, ctx.Err())
		case <-ticker.C:
			if readers != nil {
				st := analyzer.ExportStats()
				lastSize = st.ServingTreeSize
				if lastSize >= targetSize && st.ReadSuccesses > 0 {
					klog.Infof("Target write goal reached: %d / %d indexed by target VIndex", lastSize, targetSize)
					return nil
				}
				continue
			}
			probeStart := time.Now()
			kr, err := probeClient.LookupKey(ctx, "__hammer_probe__")
			if err != nil {
				if errors.Is(err, client.ErrVerificationFailed) {
					analyzer.RecordInvariantViolation(fmt.Sprintf("WriteGoalProbeVerificationError: %v", err))
					return fmt.Errorf("write-goal probe failed cryptographic verification: %w", err)
				}
				continue
			}
			if !hasFrom {
				hasFrom = true
				verifiedFrom = kr.From
			} else if kr.From != verifiedFrom {
				analyzer.RecordInvariantViolation(fmt.Sprintf("HorizonViolation: index start horizon changed from %d to %d", verifiedFrom, kr.From))
				return fmt.Errorf("write-goal probe horizon changed from %d to %d", verifiedFrom, kr.From)
			}
			if oracle != nil {
				if vErr := oracle.VerifyInputState(ctx, kr.InputSize, kr.InputRoot); vErr != nil {
					analyzer.RecordInvariantViolation(fmt.Sprintf("WriteGoalProbeInputStateError: %v", vErr))
					return fmt.Errorf("write-goal probe failed input state check: %w", vErr)
				}
			}
			analyzer.RecordReadSuccess(time.Since(probeStart), kr.InputSize)
			lastSize = kr.InputSize
			if lastSize >= targetSize {
				klog.Infof("Target write goal reached: %d / %d indexed by target VIndex", lastSize, targetSize)
				return nil
			}
		}
	}
}
