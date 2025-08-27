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
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"iter"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"filippo.io/sunlight"
	"filippo.io/torchwood"
	"github.com/gorilla/mux"
	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"k8s.io/klog/v2"
)

var (
	inputLogUrl        = flag.String("monitoring_url", "", "Base URL of the static CT log to index")
	origin             = flag.String("origin", "", "Origin of the log to check")
	pubKey             = flag.String("public_key", "", "The log's public key in base64 encoded DER format")
	userAgentInfo      = flag.String("user_agent_info", "", "Optional string to append to the user agent (e.g. email address for Sunlight logs)")
	persistentCacheDir = flag.String("persistent_cache_dir", "", "Optional location of a directory to cache Input Log tiles")
	persistIndex       = flag.Bool("persist_index", false, "Set to true to use a disk-based implementation of the verifiable index. This can be slow, but useful in situations where memory is constrained.")

	outputLogPrivKeyFile = flag.String("output_log_private_key", "", "Location of private key file. If unset, uses the contents of the OUTPUT_LOG_PRIVATE_KEY environment variable.")
	storageDir           = flag.String("storage_dir", "", "Root directory in which to store the data for the demo. This will create subdirectories for the Input Log, Output Log, and allocate space to store the verifiable map persistence.")
	listen               = flag.String("listen", ":8088", "Address to set up HTTP server listening on")
)

const (
	userAgent = "TrustFabric VerifiableIndex"
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
	// Set up storage for the input log, index, and output log.
	if *storageDir == "" {
		return errors.New("storage_dir must be set")
	}
	outputLogDir := path.Join(*storageDir, "outputlog")
	mapRoot := path.Join(*storageDir, "vindex")

	if err := os.MkdirAll(outputLogDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output log directory: %v", err)
	}
	if err := os.MkdirAll(mapRoot, 0o755); err != nil {
		return fmt.Errorf("failed to create vindex directory: %v", err)
	}

	outputLog, outputCloser := outputLogOrDie(ctx, outputLogDir)
	defer outputCloser()

	inputLog := newStaticCTInputLogFromFlags()

	vi, err := vindex.NewVerifiableIndex(ctx, inputLog, mapFn, outputLog, mapRoot, vindex.Options{PersistIndex: *persistIndex})
	if err != nil {
		return fmt.Errorf("failed to create vindex: %v", err)
	}
	klog.Info("Created verifiable index")

	// Keeps the map synced with the latest published input log state.
	go maintainMap(ctx, vi)

	// Run a web server to serve the input log, index, and output log.
	go runWebServer(vi, outputLogDir)
	<-ctx.Done()
	return nil
}

func cutEntry(tile []byte) (entry []byte, rh tlog.Hash, rest []byte, err error) {
	// This implementation is terribly inefficient, parsing the whole entry just
	// to re-serialize and throw it away. If this function shows up in profiles,
	// let me know and I'll improve it.
	e, rest, err := sunlight.ReadTileLeaf(tile)
	if err != nil {
		return nil, tlog.Hash{}, nil, err
	}
	rh = tlog.RecordHash(e.MerkleTreeLeaf())
	entry = tile[:len(tile)-len(rest)]
	return entry, rh, rest, nil
}

func newStaticCTInputLogFromFlags() *staticCTInputLog {
	ua := userAgent
	if *userAgentInfo != "" {
		ua = fmt.Sprintf("%s (%s)", userAgent, *userAgentInfo)
	}
	fetcher, err := torchwood.NewTileFetcher(*inputLogUrl,
		torchwood.WithTilePath(sunlight.TilePath),
		torchwood.WithUserAgent(ua))
	if err != nil {
		klog.Exitf("failed to create client: %v", err)
	}
	var tileReader torchwood.TileReaderWithContext = fetcher
	if *persistentCacheDir != "" {
		tileReader, err = torchwood.NewPermanentCache(fetcher, *persistentCacheDir)
		if err != nil {
			klog.Exitf("failed to create permanent cache: %v", err)
		}
	}
	client, err := torchwood.NewClient(tileReader, torchwood.WithCutEntry(cutEntry))
	if err != nil {
		klog.Exitf("failed to create client: %v", err)
	}
	return &staticCTInputLog{
		c: client,
		f: fetcher,
		v: verifierFromFlags(),
	}
}

type staticCTInputLog struct {
	c *torchwood.Client
	f *torchwood.TileFetcher
	v note.Verifier

	lastCheckpoint log.Checkpoint
}

func (l *staticCTInputLog) Checkpoint(ctx context.Context) (checkpoint []byte, err error) {
	return l.f.ReadEndpoint(ctx, "checkpoint")
}

// Parse unmarshals and verifies a checkpoint obtained from GetCheckpoint.
func (l *staticCTInputLog) Parse(checkpoint []byte) (*log.Checkpoint, error) {
	cp, _, _, err := log.ParseCheckpoint(checkpoint, l.v.Name(), l.v)
	if err != nil {
		return nil, err
	}
	l.lastCheckpoint = *cp
	return cp, err
}

// Leaves returns all the leaves in the range [start, end), outputting them via
// the returned iterator.
func (l *staticCTInputLog) Leaves(ctx context.Context, start, end uint64) iter.Seq2[[]byte, error] {
	tree := tlog.Tree{
		N:    int64(end),
		Hash: tlog.Hash(l.lastCheckpoint.Hash),
	}
	return func(yield func([]byte, error) bool) {
		for _, entry := range l.c.Entries(ctx, tree, int64(start)) {
			e, _, err := sunlight.ReadTileLeaf(entry)
			if err != nil {
				if !yield(nil, err) {
					return
				}
			}
			if !yield(e.MerkleTreeLeaf(), nil) {
				return
			}
		}
		if err := l.c.Err(); err != nil {
			yield(nil, l.c.Err())
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

func verifierFromFlags() note.Verifier {
	if *origin == "" {
		klog.Exitf("Must provide the --origin flag")
	}
	if *pubKey == "" {
		klog.Exitf("Must provide the --pub_key flag")
	}
	derBytes, err := base64.StdEncoding.DecodeString(*pubKey)
	if err != nil {
		klog.Exitf("Error decoding public key: %s", err)
	}
	pub, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		klog.Exitf("Error parsing public key: %v", err)
	}

	verifierKey, err := fnote.RFC6962VerifierString(*origin, pub)
	if err != nil {
		klog.Exitf("Error creating RFC6962 verifier string: %v", err)
	}
	logSigV, err := fnote.NewVerifier(verifierKey)
	if err != nil {
		klog.Exitf("Error creating verifier: %v", err)
	}

	klog.Infof("Using verifier string: %v", verifierKey)

	return logSigV
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

func runWebServer(vi *vindex.VerifiableIndex, outLogDir string) {
	web := NewServer(vi.Lookup)

	olfs := http.FileServer(http.Dir(outLogDir))
	r := mux.NewRouter()
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

func mapFn(data []byte) [][sha256.Size]byte {
	s := cryptobyte.String(data)

	var version, leafType uint8
	var timestamp uint64
	var certType uint16
	if !s.ReadUint8(&version) || !s.ReadUint8(&leafType) || !s.ReadUint64(&timestamp) || !s.ReadUint16(&certType) {
		klog.Warningf("Failed to unmarshal headers")
		// This should return a sentinel value (e.g. all zero hash) so unprocessable entries can be found
		return nil
	}
	var isPreCert bool
	var cert cryptobyte.String
	switch certType {
	case 0:
		// x509
		isPreCert = false
		s.ReadUint24LengthPrefixed(&cert)
	case 1:
		if true {
			// Need to support parsing TBS certs
			return nil
		}
		// precert
		isPreCert = true
		var ikh []byte
		s.ReadBytes(&ikh, sha256.Size)
		s.ReadUint24LengthPrefixed(&cert)
	default:
		panic("unknown cert type")
	}

	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		klog.Warningf("failed to parse x509 cert (preCert=%t): %v", isPreCert, err)
		// This should return a sentinel value (e.g. all zero hash) so unprocessable entries can be found
		return nil
	}
	if klog.V(2).Enabled() {
		klog.V(2).Info(parsedCert.DNSNames)
	}
	hashes := make([][sha256.Size]byte, 0, len(parsedCert.DNSNames))
	for _, cn := range parsedCert.DNSNames {
		// This filtering is simply to make the index manageable for current CT logs
		// https://github.com/transparency-dev/incubator/issues/64
		if strings.HasSuffix(cn, ".co.uk") {
			// This should output keys for various levels up to the TLD, e.g.
			// maps.google.co.uk should have google.co.uk as a secondary key.
			h := sha256.Sum256([]byte(cn))
			hashes = append(hashes, h)
		}
	}
	return hashes
}
