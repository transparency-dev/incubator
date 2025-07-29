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
	ctx := context.Background()
	s, v, err := fnote.NewEd25519SignerVerifier(skey)
	if err != nil {
		t.Fatal(err)
	}
	inputLog := &inMemoryTreeSource{
		t:      testonly.New(rfc6962.DefaultHasher),
		leaves: make([][]byte, 0),
		s:      s,
	}
	for _, str := range []string{"foo: 2", "bar: 5", "bar: 10", "foo: 8"} {
		inputLog.Append(str)
	}

	inputLogCpParseFn := func(cpRaw []byte) (*log.Checkpoint, error) {
		cp, _, _, err := log.ParseCheckpoint(cpRaw, v.Name(), v)
		return cp, err
	}
	mapFn := func(leaf []byte) [][32]byte {
		key, _, found := bytes.Cut(leaf, []byte(":"))
		if !found {
			panic("colon not found")
		}
		return [][32]byte{sha256.Sum256(key)}
	}
	f, err := os.CreateTemp("", "testWal")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	vi, err := NewVerifiableIndex(ctx, inputLog, inputLogCpParseFn, mapFn, f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if err := vi.Update(ctx); err != nil {
		t.Fatal(err)
	}

	idxes, size := vi.Lookup(sha256.Sum256([]byte("foo")))
	if size != 4 {
		t.Errorf("expected size 4 but got %d", size)
	}
	if want := []uint64{0, 3}; !cmp.Equal(idxes, want) {
		t.Errorf("expected %v but got %v", want, idxes)
	}

	idxes, size = vi.Lookup(sha256.Sum256([]byte("bar")))
	if size != 4 {
		t.Errorf("expected size 4 but got %d", size)
	}
	if want := []uint64{1, 2}; !cmp.Equal(idxes, want) {
		t.Errorf("expected %v but got %v", want, idxes)
	}

	idxes, size = vi.Lookup(sha256.Sum256([]byte("banana")))
	if size != 4 {
		t.Errorf("expected size 4 but got %d", size)
	}
	if idxes != nil {
		t.Errorf("expected no results but got %+v", idxes)
	}
}

type inMemoryTreeSource struct {
	t      *testonly.Tree
	leaves [][]byte
	s      note.Signer
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
	s.t.Append(leaf)
}

func mustHashEncode(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}
