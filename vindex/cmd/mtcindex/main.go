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

// mtcindex brings up a verifiable index for the MTC log.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/internal/mtc"
	"github.com/transparency-dev/incubator/vindex/internal/web"
	"go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	logURL       = flag.String("log_url", "https://bootstrap-mtca-shard3.cloudflareresearch.com/", "Base URL of the MTC log")
	keyName      = flag.String("key_name", "oid/1.3.6.1.4.1.44363.47.1.44363.48.8", "The key name used in the checkpoint signature")
	logPublicKey = flag.String("log_public_key", "teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU=", "The log's public key, base64 encoded raw 32-byte Ed25519 key")
	cosignerID   = flag.String("cosigner_id", "44363.48.9", "The relative OID of the cosigner")
	logID        = flag.String("log_id", "44363.48.8", "The relative OID of the log")
	origin       = flag.String("origin", "bootstrap-mtca.cloudflareresearch.com/logs/shard3", "The expected origin string in the checkpoint")
	storageDir   = flag.String("storage_dir", "", "Root directory for storage (required)")
	listen       = flag.String("listen", ":8088", "Address to listen on")
	persistIndex = flag.Bool("persist_index", true, "Whether to persist the index")
	oneShot      = flag.Bool("oneshot", false, "Run once and exit")

	outputLogPrivKeyFile = flag.String("output_log_private_key_path", "", "Location of private key file. If unset, uses the contents of the OUTPUT_LOG_PRIVATE_KEY environment variable.")
	inputLogReaders      = flag.Uint("input_log_readers", 10, "Number of parallel readers for the input log")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		klog.Exitf("Run failed: %v", err)
	}
}

func run(ctx context.Context) error {
	if *storageDir == "" {
		return errors.New("storage_dir must be set")
	}

	exporter, err := prometheus.New()
	if err != nil {
		return fmt.Errorf("failed to create prometheus exporter: %v", err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := provider.Shutdown(shutdownCtx); err != nil {
			klog.Errorf("failed to shutdown meter provider: %v", err)
		}
	}()

	outputLogDir := path.Join(*storageDir, "outputlog")
	mapRoot := path.Join(*storageDir, "vindex")

	if err := os.MkdirAll(outputLogDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output log directory: %v", err)
	}
	if err := os.MkdirAll(mapRoot, 0o755); err != nil {
		return fmt.Errorf("failed to create vindex directory: %v", err)
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(*logPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode log_public_key: %v", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid log_public_key size: %d, expected %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	mtcVerifier, err := mtc.NewMTCVerifier(*keyName, pubKey, *cosignerID, *logID)
	if err != nil {
		return fmt.Errorf("failed to create MTCVerifier: %v", err)
	}

	parsedLogURL, err := url.Parse(*logURL)
	if err != nil {
		return fmt.Errorf("failed to parse log_url: %v", err)
	}

	inputLog, err := vindex.NewTiledInputLog(parsedLogURL, mtcVerifier, vindex.InputLogOpts{
		HttpClient: http.DefaultClient,
		Origin:     *origin,
		NumReaders: *inputLogReaders,
	})
	if err != nil {
		return fmt.Errorf("failed to create InputLog: %v", err)
	}

	outputLog, outputCloser := outputLogOrDie(ctx, outputLogDir)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		outputCloser(shutdownCtx)
	}()

	vi, err := vindex.NewVerifiableIndex(ctx, inputLog, mapFn, outputLog, mapRoot, vindex.Options{
		PersistIndex:  *persistIndex,
		MeterProvider: provider,
	})
	if err != nil {
		return fmt.Errorf("failed to create vindex: %v", err)
	}
	defer func() {
		if err := vi.Close(); err != nil {
			klog.Errorf("failed to close vindex: %v", err)
		}
	}()

	webShutdown, err := runWebServer(vi, outputLogDir)
	if err != nil {
		return fmt.Errorf("failed to start web server: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := webShutdown(shutdownCtx); err != nil {
			klog.Errorf("failed to shutdown web server: %v", err)
		}
	}()

	if *oneShot {
		if err := vi.Update(ctx); err != nil {
			return fmt.Errorf("failed to Update index: %v", err)
		}
		return nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		maintainMap(ctx, vi)
	}()

	<-ctx.Done()
	klog.Info("Stopping indexer, waiting for pending updates to complete...")
	wg.Wait()
	return nil
}

func outputLogOrDie(ctx context.Context, outputLogDir string) (log vindex.OutputLog, closer func(context.Context)) {
	s, v := getOutputLogSignerVerifierOrDie()
	l, c, err := vindex.NewOutputLog(ctx, outputLogDir, s, v, vindex.OutputLogOpts{})
	if err != nil {
		klog.Exitf("Failed to create Output Log: %v", err)
	}
	return l, c
}

func maintainMap(ctx context.Context, vi *vindex.VerifiableIndex) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		if err := vi.Update(ctx); err != nil {
			klog.Warningf("Failed to Update index: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func runWebServer(vi *vindex.VerifiableIndex, outLogDir string) (func(context.Context) error, error) {
	srv := web.NewServer(vi.Lookup)

	olfs := http.FileServer(http.Dir(outLogDir))
	r := mux.NewRouter()
	r.PathPrefix("/outputlog/").Handler(http.StripPrefix("/outputlog/", olfs))
	srv.RegisterHandlers(r)

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return nil, err
	}

	hServer := &http.Server{
		Handler: r,
	}
	go func() {
		if err := hServer.Serve(listener); err != http.ErrServerClosed {
			klog.Warningf("Error from HTTP server: %v", err)
		}
	}()
	klog.Infof("Started HTTP server listening on %s", *listen)

	return hServer.Shutdown, nil
}

func getOutputLogSignerVerifierOrDie() (note.Signer, note.Verifier) {
	var privKey string
	var err error
	if len(*outputLogPrivKeyFile) > 0 {
		privKey, err = getKeyFile(*outputLogPrivKeyFile)
		if err != nil {
			klog.Exitf("Unable to get private key: %v", err)
		}
	} else {
		privKey = os.Getenv("OUTPUT_LOG_PRIVATE_KEY")
		if len(privKey) == 0 {
			klog.Exit("Supply private key file path using --output_log_private_key_path or set OUTPUT_LOG_PRIVATE_KEY environment variable")
		}
	}
	s, v, err := fnote.NewEd25519SignerVerifier(privKey)
	if err != nil {
		klog.Exitf("Failed to get signer/verifier: %v", err)
	}
	return s, v
}

func getKeyFile(path string) (string, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}
	return string(k), nil
}

func mapFn(data []byte) [][32]byte {
	if len(data) < 2 {
		return nil
	}
	entryType := binary.BigEndian.Uint16(data[:2])
	if entryType != 1 {
		return nil
	}
	entry, err := mtc.ParseTBSCertificateLogEntry(data[2:])
	if err != nil {
		klog.Warningf("Failed to parse TBSCertificateLogEntry: %v", err)
		return nil
	}
	dnsNames := mtc.ExtractDNSNames(entry)
	uniqueNames := make(map[string]bool)
	for _, cn := range dnsNames {
		cn = strings.ToLower(cn)
		if strings.HasPrefix(cn, "*.") {
			cn = cn[2:]
		} else if strings.HasPrefix(cn, "*") {
			cn = cn[1:]
		}
		if cn == "" {
			continue
		}
		uniqueNames[cn] = true

		etld1, err := publicsuffix.EffectiveTLDPlusOne(cn)
		if err != nil {
			continue
		}
		if cn == etld1 {
			continue
		}
		curr := cn
		for {
			idx := strings.Index(curr, ".")
			if idx == -1 {
				break
			}
			curr = curr[idx+1:]
			if len(curr) < len(etld1) {
				break
			}
			uniqueNames[curr] = true
			if curr == etld1 {
				break
			}
		}
	}
	var hashes [][32]byte
	for name := range uniqueNames {
		hashes = append(hashes, sha256.Sum256([]byte(name)))
	}
	return hashes
}
