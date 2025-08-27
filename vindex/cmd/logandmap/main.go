// Copyright 2025 Google LLC. All Rights Reserved.
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

// logandmap is a binary that serves as a demo of how to run a log and a map in the
// same process.
// The log is a Tessera POSIX log, and the map is an in-memory verifiable index.
// A web server is hosted that allows lookups in the map to be performed.
// The log is updated periodically with entries of type LogEntry, and the map keys
// each of the module names from that struct to each of the indices in the log where
// an entry for that module is stored.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"iter"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	inputLogPrivKeyFile  = flag.String("input_log_private_key", "", "Location of private key file. If unset, uses the contents of the INPUT_LOG_PRIVATE_KEY environment variable.")
	outputLogPrivKeyFile = flag.String("output_log_private_key", "", "Location of private key file. If unset, uses the contents of the OUTPUT_LOG_PRIVATE_KEY environment variable.")
	storageDir           = flag.String("storage_dir", "", "Root directory in which to store the data for the demo. This will create subdirectories for the Input Log, Output Log, and allocate space to store the verifiable map persistence.")
	listen               = flag.String("listen", ":8088", "Address to set up HTTP server listening on")
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

type LogEntry struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Hash    []byte `json:"hash"`
}

func run(ctx context.Context) error {
	// Set up storage for the input log, index, and output log.
	if *storageDir == "" {
		return errors.New("storage_dir must be set")
	}
	inputLogDir := path.Join(*storageDir, "inputlog")
	outputLogDir := path.Join(*storageDir, "outputlog")
	mapRoot := path.Join(*storageDir, "vindex")

	if err := os.MkdirAll(inputLogDir, 0o755); err != nil {
		return fmt.Errorf("failed to create input log directory: %v", err)
	}
	if err := os.MkdirAll(outputLogDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output log directory: %v", err)
	}
	if err := os.MkdirAll(mapRoot, 0o755); err != nil {
		return fmt.Errorf("failed to create vindex directory: %v", err)
	}

	// Create the input log, output log, and verifiable index.
	// The input log is continuously getting new leaves written to it.
	inputLog, inputCloser := inputLogOrDie(ctx, inputLogDir)
	defer inputCloser()

	outputLog, outputCloser := outputLogOrDie(ctx, outputLogDir)
	defer outputCloser()

	vi, err := vindex.NewVerifiableIndex(ctx, inputLog, mapFnFromFlags(), outputLog, mapRoot)
	if err != nil {
		return fmt.Errorf("failed to create vindex: %v", err)
	}

	// Keeps the map synced with the latest published input log state.
	go maintainMap(ctx, vi)

	// Run a web server to serve the input log, index, and output log.
	go runWebServer(vi, inputLogDir, outputLogDir)
	<-ctx.Done()
	return nil
}

// inputLogOrDie returns an input log that is being updated periodically.
func inputLogOrDie(ctx context.Context, inputLogDir string) (log logReaderSource, closer func()) {
	// Gather the info needed for reading/writing checkpoints
	ils, ilv := getInputLogSignerVerifierOrDie()

	// Set up a Tessera POSIX log
	ild, err := posix.New(ctx, posix.Config{Path: inputLogDir})
	if err != nil {
		klog.Exit(fmt.Errorf("failed to create input log: %v", err))
	}

	inputAppender, inputShutdown, inputReader, err := tessera.NewAppender(ctx, ild, tessera.NewAppendOptions().
		WithCheckpointSigner(ils).
		WithCheckpointInterval(5*time.Second).
		WithBatching(256, time.Second))
	if err != nil {
		klog.Exit(fmt.Errorf("failed to get appender: %v", err))
	}

	inputLog := logReaderSource{
		r: inputReader,
		v: ilv,
	}

	// Submits new entries to the log in the background.
	go submitEntries(ctx, inputAppender)

	return inputLog, func() {
		_ = inputShutdown(ctx)
	}
}

// logReaderSource adapts a tessera.LogReader to a vindex.InputLog.
type logReaderSource struct {
	r tessera.LogReader
	v note.Verifier
}

func (s logReaderSource) Checkpoint(ctx context.Context) (checkpoint []byte, err error) {
	return s.r.ReadCheckpoint(ctx)
}

func (s logReaderSource) Parse(cpRaw []byte) (*log.Checkpoint, error) {
	cp, _, _, err := log.ParseCheckpoint(cpRaw, s.v.Name(), s.v)
	return cp, err
}

func (s logReaderSource) Leaves(ctx context.Context, start, end uint64) iter.Seq2[[]byte, error] {
	tsf := func(ctx context.Context) (uint64, error) {
		return end, nil
	}
	bi := client.EntryBundles(ctx, 2, tsf, s.r.ReadEntryBundle, start, end-start)
	unbundleFn := func(bundle []byte) ([][]byte, error) {
		eb := &api.EntryBundle{}
		if err := eb.UnmarshalText(bundle); err != nil {
			return nil, err
		}
		return eb.Entries, nil
	}

	return func(yield func([]byte, error) bool) {
		// Unwrap the client.Entry type to return an iterator of []byte only.
		for entry, err := range client.Entries(bi, unbundleFn) {
			if err != nil {
				if !yield(nil, err) {
					return
				}
				continue
			}
			if !yield(entry.Entry, nil) {
				return
			}
		}
	}
}

// outputLogOrDie returns an output log using a POSIX log in the given directory.
func outputLogOrDie(ctx context.Context, outputLogDir string) (log vindex.OutputLog, closer func()) {
	s, v := getOutputLogSignerVerifierOrDie()

	l, c, err := vindex.NewOutputLog(ctx, outputLogDir, s, v)
	if err != nil {
		klog.Exit(err)
	}
	return l, c
}

// maintainMap reads entries from the log and sync them to the vindex.
func maintainMap(ctx context.Context, vi *vindex.VerifiableIndex) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		if err := vi.Update(ctx); err != nil {
			klog.Warning(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// submitEntries continually creates new log entries and submits them to the log.
// Entries are json-encoded LogEntry structs. The module are randomly pulled from a
// list of [foo, bar, baz, splat]. The version is the current timestamp, as a string.
// The hash is set to the sha256 of the module+version.
func submitEntries(ctx context.Context, appender *tessera.Appender) {
	modules := []string{"foo", "bar", "baz", "splat"}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			klog.Info("Context cancelled, stopping log appender")
			return
		case <-ticker.C:
			module := modules[r.Intn(len(modules))]
			version := time.Now().Format(time.RFC3339Nano)
			h := sha256.Sum256([]byte(module + version))
			entry := LogEntry{
				Module:  module,
				Version: version,
				Hash:    h[:],
			}
			data, err := json.Marshal(entry)
			if err != nil {
				klog.Errorf("Failed to marshal log entry: %v", err)
				continue
			}
			if idx, err := appender.Add(ctx, tessera.NewEntry(data))(); err != nil {
				klog.Errorf("Failed to append to log: %v", err)
			} else {
				klog.V(2).Infof("Appended entry for %s@%s at index %d", module, version, idx.Index)
			}
		}
	}
}

func runWebServer(vi *vindex.VerifiableIndex, inLogDir, outLogDir string) {
	web := NewServer(vi.Lookup)

	ilfs := http.FileServer(http.Dir(inLogDir))
	olfs := http.FileServer(http.Dir(outLogDir))
	r := mux.NewRouter()
	r.PathPrefix("/inputlog/").Handler(http.StripPrefix("/inputlog/", ilfs))
	r.PathPrefix("/outputlog/").Handler(http.StripPrefix("/outputlog/", olfs))
	web.registerHandlers(r)
	hServer := &http.Server{
		Addr:    *listen,
		Handler: r,
	}
	go func() {
		_ = hServer.ListenAndServe()
	}()
	klog.Infof("Started HTTP server listening on %s", *listen)
}

// Read input log private key from file or environment variable and generate the
// note Signer and Verifier pair for it.
func getInputLogSignerVerifierOrDie() (note.Signer, note.Verifier) {
	var privKey string
	var err error
	if len(*inputLogPrivKeyFile) > 0 {
		privKey, err = getKeyFile(*inputLogPrivKeyFile)
		if err != nil {
			klog.Exitf("Unable to get private key: %v", err)
		}
	} else {
		privKey = os.Getenv("INPUT_LOG_PRIVATE_KEY")
		if len(privKey) == 0 {
			klog.Exit("Supply private key file path using --input_log_private_key or set INPUT_LOG_PRIVATE_KEY environment variable")
		}
	}
	s, v, err := fnote.NewEd25519SignerVerifier(privKey)
	if err != nil {
		klog.Exitf("Failed to get signer/verifier: %v", err)
	}
	return s, v
}

// Read output log private key from file or environment variable and generate the
// note Signer and Verifier pair for it.
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
			klog.Exit("Supply private key file path using --output_log_private_key or set OUTPUT_LOG_PRIVATE_KEY environment variable")
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

func mapFnFromFlags() vindex.MapFn {
	mapFn := func(data []byte) [][sha256.Size]byte {
		var entry LogEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			panic(fmt.Errorf("failed to unmarshal entry: %v", err))
		}

		// This returns a key which is simply the hash of the module name.
		// This could be changed to return something more complex, e.g. include
		// a static prefix of "module=", which would allow the same map to host
		// multiple queries in parallel.
		return [][sha256.Size]byte{sha256.Sum256([]byte(entry.Module))}
	}
	return mapFn
}
