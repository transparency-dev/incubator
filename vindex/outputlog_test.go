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

// vindex contains a prototype of an in-memory verifiable index.
// This version uses the clone tool DB as the log source.
package vindex_test

import (
	"bytes"
	"crypto/sha256"
	"os"
	"testing"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

func TestOutputLog_Lookup(t *testing.T) {
	s, v, err := fnote.NewEd25519SignerVerifier(skey)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []struct {
		desc      string
		leaves    []string
		lookupIdx uint64
		wantErr   bool
	}{
		{
			desc:      "single entry log",
			leaves:    []string{"foo"},
			lookupIdx: 0,
			wantErr:   false,
		},
		{
			desc:      "two entry log",
			leaves:    []string{"foo", "bar"},
			lookupIdx: 1,
			wantErr:   false,
		},
		{
			desc:      "multi entry log: last",
			leaves:    []string{"foo", "bar", "baz"},
			lookupIdx: 2,
			wantErr:   false,
		}, {
			desc:      "multi entry log: penultimate",
			leaves:    []string{"foo", "bar", "baz"},
			lookupIdx: 1,
			wantErr:   false,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "testOutputLog")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = os.RemoveAll(dir)
			}()

			log, closer, err := vindex.NewOutputLog(t.Context(), dir, s, v, vindex.OutputLogOpts{})
			if err != nil {
				t.Fatal(err)
			}
			defer closer()

			for _, l := range tC.leaves {
				if _, _, err := log.Append(t.Context(), []byte(l)); err != nil {
					t.Fatal(err)
				}
			}
			rawCp, err := log.Checkpoint(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			cp, err := log.Parse(rawCp)
			if err != nil {
				t.Fatal(err)
			}

			data, incProof, err := log.Lookup(t.Context(), tC.lookupIdx, cp.Size)
			if err != nil {
				t.Fatal(err)
			}

			hash := rfc6962.DefaultHasher.HashLeaf(data)
			incProof2 := make([][]byte, len(incProof))
			for i := range incProof {
				incProof2[i] = incProof[i][:]
			}
			if err := proof.VerifyInclusion(rfc6962.DefaultHasher, tC.lookupIdx, cp.Size, hash, incProof2, cp.Hash); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOutpuLogLeafRoundtrip(t *testing.T) {
	inH := sha256.Sum256([]byte("test123"))
	inCp := []byte("example.com/test\n123\ndeadbeef")

	leaf := vindex.MarshalLeaf(inH, inCp)

	outH, outCp, err := vindex.UnmarshalLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(outCp, inCp) {
		t.Errorf("expected %x but got %x", inCp, outCp)
	}
	if !bytes.Equal(inH[:], outH[:]) {
		t.Errorf("expected %x but got %x", inH, outH)
	}
}
