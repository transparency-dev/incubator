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
package vindex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"iter"
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
	"golang.org/x/mod/sumdb/note"
)

const (
	skey = "PRIVATE+KEY+logandmap+38581672+AXJ0FKWOcO2ch6WC8kP705Ed3Gxu7pVtZLhfHAQwp+FE"
	vkey = "logandmap+38581672+Ab/PCr1eCclRPRMBqw/r5An1xO71MCnImLiospEq6b4l"
)

func TestVerifiableIndex(t *testing.T) {
	ctx := t.Context()
	s, v, err := fnote.NewEd25519SignerVerifier(skey)
	if err != nil {
		t.Fatal(err)
	}
	inputLog := &inMemoryTreeSource{
		t:      testonly.New(rfc6962.DefaultHasher),
		leaves: make([][]byte, 0),
		s:      s,
		v:      v,
	}
	for _, str := range []string{"foo: 2", "bar: 5", "bar: 10", "foo: 8"} {
		inputLog.Append(str)
	}

	mapFn := func(leaf []byte) [][sha256.Size]byte {
		key, _, found := bytes.Cut(leaf, []byte(":"))
		if !found {
			panic("colon not found")
		}
		return [][sha256.Size]byte{sha256.Sum256(key)}
	}
	f, err := os.CreateTemp("", "vindexTestDir")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.Name()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.Name(), 0o755); err != nil {
		t.Fatal(err)
	}

	old := path.Join(f.Name(), "outputlog")
	outputLog, closer, err := NewOutputLog(ctx, old, s, v)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	vi, err := NewVerifiableIndex(ctx, inputLog, mapFn, outputLog, f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if err := vi.Update(ctx); err != nil {
		t.Fatal(err)
	}

	resp, err := vi.Lookup(t.Context(), sha256.Sum256([]byte("foo")))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := resp.IndexValue, []uint64{0, 3}; !cmp.Equal(got, want) {
		t.Errorf("expected %v but got %v", want, got)
	}

	resp, err = vi.Lookup(t.Context(), sha256.Sum256([]byte("bar")))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := resp.IndexValue, []uint64{1, 2}; !cmp.Equal(got, want) {
		t.Errorf("expected %v but got %v", want, got)
	}

	resp, err = vi.Lookup(t.Context(), sha256.Sum256([]byte("banana")))
	if err != nil {
		t.Fatal(err)
	}
	if resp.IndexValue != nil {
		t.Errorf("expected no results but got %+v", resp.IndexValue)
	}
}

type inMemoryTreeSource struct {
	t      *testonly.Tree
	leaves [][]byte
	s      note.Signer
	v      note.Verifier
}

func (s *inMemoryTreeSource) Checkpoint(ctx context.Context) (checkpoint []byte, err error) {
	rootHash := s.t.Hash()
	size := uint64(len(s.leaves))

	cp := log.Checkpoint{
		Origin: s.s.Name(),
		Size:   size,
		Hash:   rootHash,
	}
	n := &note.Note{Text: string(cp.Marshal())}
	return note.Sign(n, s.s)
}

func (s *inMemoryTreeSource) Parse(cpRaw []byte) (*log.Checkpoint, error) {
	cp, _, _, err := log.ParseCheckpoint(cpRaw, s.v.Name(), s.v)
	return cp, err
}

func (s *inMemoryTreeSource) Leaves(ctx context.Context, start, end uint64) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, entry := range s.leaves {
			if !yield(entry, nil) {
				return
			}
		}
	}
}

func (s *inMemoryTreeSource) Append(leafStr string) {
	leaf := []byte(leafStr)
	s.leaves = append(s.leaves, leaf)
	s.t.Append(rfc6962.DefaultHasher.HashLeaf(leaf))
}

func mustHashEncode(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}
