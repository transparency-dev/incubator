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
	"os"
	"path/filepath"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	testLogKey = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"
	testOrigin = "go.sum database tree"
	// RFC6962 leaf hash for tessera@v1.0.0
	testLeafHashHex = "0fa57c511c3b2ffcc0a05ad63172568d265aaf9844e9b636a0978795396f2ab1"
)

func TestVerifyProof(t *testing.T) {
	proofPath := filepath.Join("testdata", "go.sum-database-tree-43930254.tlog-proof")
	proofBytes, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("failed to read test proof file: %v", err)
	}

	leafHash, err := decodeLeafHash(testLeafHashHex)
	if err != nil {
		t.Fatalf("failed to decode leaf hash: %v", err)
	}

	wrongLeafHash := make([]byte, len(leafHash))
	copy(wrongLeafHash, leafHash)
	wrongLeafHash[0] ^= 0xFF

	wrongLogKey := "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn9"

	corruptedProof := make([]byte, len(proofBytes))
	copy(corruptedProof, proofBytes)
	corruptedProof = corruptedProof[:len(corruptedProof)-50]

	proofWithNewlines := append(proofBytes, []byte("\n\n\n")...)

	tests := []struct {
		name     string
		logKey   string
		origin   string
		proof    []byte
		leafHash []byte
		wantErr  bool
	}{
		{
			name:     "success",
			logKey:   testLogKey,
			origin:   testOrigin,
			proof:    proofBytes,
			leafHash: leafHash,
			wantErr:  false,
		},
		{
			name:     "wrong leaf hash",
			logKey:   testLogKey,
			origin:   testOrigin,
			proof:    proofBytes,
			leafHash: wrongLeafHash,
			wantErr:  true,
		},
		{
			name:     "wrong log key",
			logKey:   wrongLogKey,
			origin:   testOrigin,
			proof:    proofBytes,
			leafHash: leafHash,
			wantErr:  true,
		},
		{
			name:     "corrupted proof",
			logKey:   testLogKey,
			origin:   testOrigin,
			proof:    corruptedProof,
			leafHash: leafHash,
			wantErr:  true,
		},
		{
			name:     "success with trailing newlines",
			logKey:   testLogKey,
			origin:   testOrigin,
			proof:    proofWithNewlines,
			leafHash: leafHash,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyProof(tt.logKey, tt.origin, tt.proof, tt.leafHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyProof() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeLeafHash(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid hex",
			input:   testLeafHashHex,
			wantErr: false,
		},
		{
			name:    "valid base64 padded",
			input:   "D6V8URw7L/zAoFrWMXJWjSZar5hE6bY2oJeHlTlvKrE=",
			wantErr: false,
		},
		{
			name:    "valid base64 unpadded",
			input:   "D6V8URw7L/zAoFrWMXJWjSZar5hE6bY2oJeHlTlvKrE",
			wantErr: false,
		},
		{
			name:    "invalid length hex",
			input:   testLeafHashHex + "00",
			wantErr: true,
		},
		{
			name:    "invalid chars hex",
			input:   testLeafHashHex[:63] + "g",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			input:   "invalid-base64-string!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeLeafHash(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeLeafHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != 32 {
				t.Errorf("decodeLeafHash() got length = %d, want 32", len(got))
			}
		})
	}
}

func TestVerifyProofWithRawLeaf(t *testing.T) {
	rawLeafPath := filepath.Join("testdata", "go.sum-database-tree-43930254.raw")
	rawLeaf, err := os.ReadFile(rawLeafPath)
	if err != nil {
		t.Fatalf("failed to read test raw leaf file: %v", err)
	}
	computedHash := rfc6962.DefaultHasher.HashLeaf(rawLeaf)

	proofPath := filepath.Join("testdata", "go.sum-database-tree-43930254.tlog-proof")
	proofBytes, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("failed to read test proof file: %v", err)
	}

	err = verifyProof(testLogKey, testOrigin, proofBytes, computedHash)
	if err != nil {
		t.Errorf("expected verification with computed leaf hash to succeed, got: %v", err)
	}
}
