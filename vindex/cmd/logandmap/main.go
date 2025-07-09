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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"iter"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	privKeyFile = flag.String("private_key", "", "Location of private key file. If unset, uses the contents of the LOG_PRIVATE_KEY environment variable.")
	inputLogDir = flag.String("input_log_dir", "", "Root directory in which to store the log for the POSIX-based Input Log")
	walPath     = flag.String("walPath", "", "Path to use for the Write Ahead Log. If empty, a temporary file will be used.")
	listen      = flag.String("listen", ":8088", "Address to set up HTTP server listening on")
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
	if *inputLogDir == "" {
		return errors.New("input_log_dir must be set")
	}

	// Gather the info needed for reading/writing checkpoints
	s, v := getSignerVerifierOrDie()

	// Set up a Tessera POSIX log
	driver, err := posix.New(ctx, posix.Config{Path: *inputLogDir})
	if err != nil {
		return fmt.Errorf("failed to create new log: %v", err)
	}

	// Get a Tessera appender
	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, tessera.NewAppendOptions().
		WithCheckpointSigner(s).
		WithCheckpointInterval(10*time.Second).
		WithBatching(256, time.Second))
	if err != nil {
		return fmt.Errorf("failed to get appender: %v", err)
	}
	defer func() {
		_ = shutdown(ctx)
	}()

	// Create the verifiable index connected to the LogReader.
	inputLog := logReaderSource{
		r: reader,
	}
	logCpParseFn := func(cpRaw []byte) (*log.Checkpoint, error) {
		// No witnesses required yet
		cp, _, _, err := log.ParseCheckpoint(cpRaw, v.Name(), v)
		return cp, err
	}
	vi, err := vindex.NewVerifiableIndex(ctx, inputLog, logCpParseFn, mapFnFromFlags(), walPathFromFlags())
	if err != nil {
		return fmt.Errorf("failed to create vindex: %v", err)
	}

	// Submits new entries to the log in the background.
	go submitEntries(ctx, appender)

	// Keeps the map synced with the latest published log state.
	go maintainMap(ctx, vi)

	// Run a web server to handle queries over the verifiable index.
	go runWebServer(vi)
	<-ctx.Done()
	return nil
}

// logReaderSource adapts a tessera.LogReader to a vindex.InputLog.
type logReaderSource struct {
	r tessera.LogReader
}

func (s logReaderSource) GetCheckpoint(ctx context.Context) (checkpoint []byte, err error) {
	return s.r.ReadCheckpoint(ctx)
}

func (s logReaderSource) StreamLeaves(ctx context.Context, start, end uint64) iter.Seq2[[]byte, error] {
	bi := client.EntryBundles(ctx, 2, s.r.IntegratedSize, s.r.ReadEntryBundle, start, end-start)
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

// maintainMap reads entries from the log and sync them to the vindex.
func maintainMap(ctx context.Context, vi *vindex.VerifiableIndex) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := vi.Update(ctx); err != nil {
				klog.Warning(err)
			}
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

func runWebServer(vi *vindex.VerifiableIndex) {
	web := NewServer(func(h [sha256.Size]byte) ([]uint64, error) {
		idxes, size := vi.Lookup(h)
		if size == 0 {
			return nil, errors.New("index not populated")
		}
		return idxes, nil
	})

	ilfs := http.FileServer(http.Dir(*inputLogDir))
	r := mux.NewRouter()
	r.PathPrefix("/inputlog/").Handler(http.StripPrefix("/inputlog/", ilfs))
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

// Read log private key from file or environment variable and generate the
// note Signer and Verifier pair for it.
func getSignerVerifierOrDie() (note.Signer, note.Verifier) {
	var privKey string
	var err error
	if len(*privKeyFile) > 0 {
		privKey, err = getKeyFile(*privKeyFile)
		if err != nil {
			klog.Exitf("Unable to get private key: %v", err)
		}
	} else {
		privKey = os.Getenv("LOG_PRIVATE_KEY")
		if len(privKey) == 0 {
			klog.Exit("Supply private key file path using --private_key or set LOG_PRIVATE_KEY environment variable")
		}
	}
	s, v, err := signerVerifierFromSkey(privKey)
	if err != nil {
		klog.Exitf("Failed to get signer/verifier: %v", err)
	}
	return s, v
}

// TODO(mhutchinson): move this into t-dev/formats.
func signerVerifierFromSkey(skey string) (note.Signer, note.Verifier, error) {
	const algEd25519 = 1
	s, err := note.NewSigner(skey)
	if err != nil {
		return nil, nil, err
	}
	_, skey, _ = strings.Cut(skey, "+")
	_, skey, _ = strings.Cut(skey, "+")
	_, skey, _ = strings.Cut(skey, "+")
	_, key64, _ := strings.Cut(skey, "+")
	key, err := base64.StdEncoding.DecodeString(key64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	alg, key := key[0], key[1:]
	switch alg {
	default:
		return nil, nil, errors.New("unsupported algorithm")

	case algEd25519:
		if len(key) != ed25519.SeedSize {
			return nil, nil, fmt.Errorf("expected key seed of size %d but got %d", ed25519.SeedSize, len(key))
		}
		key := ed25519.NewKeyFromSeed(key)
		publicKey := key.Public().(ed25519.PublicKey)
		vkey, err := note.NewEd25519VerifierKey(s.Name(), publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate verifier from key: %v", err)

		}
		v, err := note.NewVerifier(vkey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create verifier from vkey: %v", err)
		}
		return s, v, err
	}
}

func getKeyFile(path string) (string, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}
	return string(k), nil
}

func mapFnFromFlags() vindex.MapFn {
	mapFn := func(data []byte) [][32]byte {
		var entry LogEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			panic(fmt.Errorf("failed to unmarshal entry: %v", err))
		}

		// This returns a key which is simply the hash of the module name.
		// This could be changed to return something more complex, e.g. include
		// a static prefix of "module=", which would allow the same map to host
		// multiple queries in parallel.
		return [][32]byte{sha256.Sum256([]byte(entry.Module))}
	}
	return mapFn
}

func walPathFromFlags() string {
	if len(*walPath) > 0 {
		return *walPath
	}
	f, err := os.CreateTemp("", "walPath")
	if err != nil {
		klog.Exitf("Failed to create temporary path for WAL: %s", err)
	}
	klog.Infof("Created temporary WAL at %s", f.Name())
	return f.Name()
}
