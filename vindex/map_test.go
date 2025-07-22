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
	"fmt"
	"io"
	"iter"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
)

const (
	skey = "PRIVATE+KEY+logandmap+38581672+AXJ0FKWOcO2ch6WC8kP705Ed3Gxu7pVtZLhfHAQwp+FE"
	vkey = "logandmap+38581672+Ab/PCr1eCclRPRMBqw/r5An1xO71MCnImLiospEq6b4l"
)

func TestWriteAheadLog_init(t *testing.T) {
	testCases := []struct {
		desc         string
		fileContents string
		wantIdx      uint64
		wantErr      bool
	}{
		{
			desc:         "empty file",
			fileContents: "",
			wantIdx:      0,
			wantErr:      false,
		}, {
			desc:         "0 file",
			fileContents: "0\n",
			wantIdx:      1,
			wantErr:      false,
		}, {
			desc:         "just indexes",
			fileContents: "0\n1\n2\n",
			wantIdx:      3,
			wantErr:      false,
		}, {
			desc:         "indexes and hashes",
			fileContents: fmt.Sprintf("1 %s %s\n", mustHashEncode("1a"), mustHashEncode("1b")),
			wantIdx:      2,
			wantErr:      false,
		}, {
			desc:         "trailing corruption",
			fileContents: "1\n2 fdfxx",
			wantErr:      true,
		}, {
			desc:         "lots of newlines",
			fileContents: "1\n2\n3\n\n",
			wantErr:      true,
		}, {
			desc:         "no trailing newlines",
			fileContents: "1\n2\n3",
			wantErr:      true,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			f, err := os.CreateTemp("", "testWal")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(tC.fileContents); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			wal := &walWriter{
				walPath: f.Name(),
			}
			idx, err := wal.init()
			if gotErr := err != nil; gotErr != tC.wantErr {
				t.Fatalf("wantErr != gotErr (%t != %t) %v", tC.wantErr, gotErr, err)
			}
			defer func() {
				_ = wal.close()
			}()
			if tC.wantErr {
				return
			}
			if idx != tC.wantIdx {
				t.Errorf("want idx %v but got %v", tC.wantIdx, idx)
			}
		})
	}
}

func TestWriteAheadLog_roundtrip(t *testing.T) {
	f, err := os.CreateTemp("", "testWal")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.Name()); err != nil {
		t.Fatal(err)
	}

	wal := &walWriter{
		walPath: f.Name(),
	}
	idx, err := wal.init()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := idx, uint64(0); got != want {
		t.Fatalf("expected index %d, got %d", want, got)
	}

	for i := range 33 {
		hash := sha256.Sum256([]byte{byte(i)})
		if err := wal.append(uint64(i), [][32]byte{hash}); err != nil {
			t.Error(err)
		}
	}

	if err := wal.close(); err != nil {
		t.Error(err)
	}

	idx, err = wal.init()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := idx, uint64(33); got != want {
		t.Fatalf("expected index %d, got %d", want, got)
	}

	if err := wal.close(); err != nil {
		t.Error(err)
	}
}

func TestWriteAndWriteLog(t *testing.T) {
	f, err := os.CreateTemp("", "testWal")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.Name()); err != nil {
		t.Fatal(err)
	}

	wal := &walWriter{
		walPath: f.Name(),
	}
	idx, err := wal.init()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := idx, uint64(0); got != want {
		t.Fatalf("expected index %d, got %d", want, got)
	}

	reader, err := newWalReader(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	const count = 2056
	var eg errgroup.Group
	eg.Go(func() error {
		for i := range count {
			hash := sha256.Sum256([]byte{byte(i)})
			if err := wal.append(uint64(i), [][32]byte{hash}); err != nil {
				return err
			}
		}
		return nil
	})
	eg.Go(func() error {
		var expect uint64
		for expect < count {
			idx, _, err := reader.next()
			if err != nil {
				if err != io.EOF {
					return err
				}
				// Wait a small amount of time for more data to become available
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if got, want := idx, expect; got != want {
				return fmt.Errorf("expected index %d, got %d", want, got)
			}
			expect++
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		t.Fatal(err)
	}

	if err := wal.close(); err != nil {
		t.Error(err)
	}
	if err := reader.close(); err != nil {
		t.Error(err)
	}
}

func TestUnmarshal(t *testing.T) {
	testCases := []struct {
		desc       string
		entry      string
		wantErr    bool
		wantIdx    uint64
		wantHashes int
	}{
		{
			desc:       "just index",
			entry:      "1",
			wantErr:    false,
			wantIdx:    1,
			wantHashes: 0,
		}, {
			desc:       "index and hashes",
			entry:      fmt.Sprintf("1 %s %s", mustHashEncode("1a"), mustHashEncode("1b")),
			wantErr:    false,
			wantIdx:    1,
			wantHashes: 2,
		}, {
			desc:    "corruption at the end",
			entry:   "1 deadbeef feed01xxx",
			wantErr: true,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			idx, hashes, err := unmarshalWalEntry(tC.entry)
			if gotErr := err != nil; gotErr != tC.wantErr {
				t.Fatalf("wantErr != gotErr (%t != %t) %v", tC.wantErr, gotErr, err)
			}
			if tC.wantErr {
				return
			}
			if idx != tC.wantIdx {
				t.Errorf("want idx %v but got %v", tC.wantIdx, idx)
			}
			if got, want := len(hashes), tC.wantHashes; got != want {
				t.Errorf("want %v hashes but got %v: %q", want, got, hashes)
			}
		})
	}
}

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
