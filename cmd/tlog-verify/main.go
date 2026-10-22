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

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/proof"
	merkleproof "github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

var (
	logKey   = flag.String("log-key", "", "Log verifier key (required).")
	origin   = flag.String("origin", "", "Expected log origin in checkpoint (optional, defaults to name in log-key).")
	leafHash = flag.String("leaf-hash", "", "Pre-computed leaf hash (hex or base64).")
	leaf     = flag.String("leaf", "", "Raw leaf data string.")
	leafFile = flag.String("leaf-file", "", "Path to file containing raw leaf data.")
)

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}

func run() error {
	if *logKey == "" {
		return fmt.Errorf("--log-key is required")
	}

	// Validate leaf inputs
	leafInputs := 0
	if *leafHash != "" {
		leafInputs++
	}
	if *leaf != "" {
		leafInputs++
	}
	if *leafFile != "" {
		leafInputs++
	}

	if leafInputs != 1 {
		return fmt.Errorf("exactly one of --leaf-hash, --leaf, or --leaf-file must be provided")
	}

	// Determine leaf hash
	var computedLeafHash []byte
	var err error

	if *leafHash != "" {
		computedLeafHash, err = decodeLeafHash(*leafHash)
		if err != nil {
			return fmt.Errorf("invalid --leaf-hash: %w", err)
		}
	} else {
		var leafData []byte
		if *leaf != "" {
			leafData = []byte(*leaf)
		} else {
			leafData, err = os.ReadFile(*leafFile)
			if err != nil {
				return fmt.Errorf("failed to read leaf file: %w", err)
			}
		}
		// Apply RFC6962 leaf hashing: SHA256(0x00 || data)
		h := rfc6962.DefaultHasher.HashLeaf(leafData)
		computedLeafHash = h
	}

	// Read proof
	var proofBytes []byte
	args := flag.Args()
	if len(args) > 1 {
		return fmt.Errorf("too many arguments; expected at most one proof file")
	}

	if len(args) == 1 {
		proofBytes, err = os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("failed to read proof file: %w", err)
		}
	} else {
		proofBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read proof from stdin: %w", err)
		}
	}

	return verifyProof(*logKey, *origin, proofBytes, computedLeafHash)
}

func decodeLeafHash(s string) ([]byte, error) {
	// Try hex first (64 chars for SHA256)
	if len(s) == 64 {
		h, err := hex.DecodeString(s)
		if err == nil && len(h) == 32 {
			return h, nil
		}
	}

	// Try base64
	h, err := base64.StdEncoding.DecodeString(s)
	if err == nil && len(h) == 32 {
		return h, nil
	}

	// Try base64 raw (unpadded)
	h, err = base64.RawStdEncoding.DecodeString(s)
	if err == nil && len(h) == 32 {
		return h, nil
	}

	return nil, fmt.Errorf("must be 32-byte hex or base64 encoded string")
}

func verifyProof(logKeyStr, originStr string, proofBytes []byte, leafHash []byte) error {
	// 1. Parse log key
	verifier, err := note.NewVerifier(strings.TrimSpace(logKeyStr))
	if err != nil {
		return fmt.Errorf("failed to parse log key: %w", err)
	}

	// 2. Unmarshal proof
	var p proof.TLogProof
	if err := p.Unmarshal(proofBytes); err != nil {
		return fmt.Errorf("failed to unmarshal proof: %w", err)
	}

	expectedOrigin := originStr
	if expectedOrigin == "" {
		expectedOrigin = verifier.Name()
	}

	// 3. Verify checkpoint signature
	// note.Open is strict about trailing newlines. Clean them up.
	cpBytes := bytes.TrimRight(p.Checkpoint, "\r\n ")
	cpBytes = append(cpBytes, '\n')

	checkpoint, _, _, err := log.ParseCheckpoint(cpBytes, expectedOrigin, verifier)
	if err != nil {
		return fmt.Errorf("failed to verify checkpoint: %w", err)
	}

	// 4. Verify inclusion proof
	hashes := make([][]byte, len(p.Hashes))
	for i, h := range p.Hashes {
		hashes[i] = h[:]
	}

	// Convert root hash to slice
	rootHash := checkpoint.Hash

	err = merkleproof.VerifyInclusion(rfc6962.DefaultHasher, p.Index, checkpoint.Size, leafHash, hashes, rootHash)
	if err != nil {
		return fmt.Errorf("inclusion proof verification failed: %w", err)
	}

	return nil
}
