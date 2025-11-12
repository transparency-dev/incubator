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
	"context"
	"crypto/sha256"
	"fmt"
	"iter"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/incubator/vindex"
	"github.com/transparency-dev/incubator/vindex/api"
	"github.com/transparency-dev/incubator/vindex/client"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
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
	outputLog, closer, err := vindex.NewOutputLog(ctx, old, s, v, vindex.OutputLogOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	vi, err := vindex.NewVerifiableIndex(ctx, inputLog, mapFn, outputLog, f.Name(), vindex.Options{})
	if err != nil {
		t.Fatal(err)
	}

	if err := vi.Update(ctx); err != nil {
		t.Fatal(err)
	}

	kh := sha256.Sum256([]byte("foo"))
	resp, err := vi.Lookup(t.Context(), kh)
	if err != nil {
		t.Fatal(err)
	}
	indices, _, err := client.VerifyLookupResponse(kh, resp, v)
	if err != nil {
		t.Fatalf("failed to verify vindex response: %v", err)
	}
	if got, want := indices, []uint64{0, 3}; !cmp.Equal(got, want) {
		t.Errorf("expected %v but got %v", want, got)
	}

	kh = sha256.Sum256([]byte("bar"))
	resp, err = vi.Lookup(t.Context(), kh)
	if err != nil {
		t.Fatal(err)
	}
	indices, _, err = client.VerifyLookupResponse(kh, resp, v)
	if err != nil {
		t.Fatalf("failed to verify vindex response: %v", err)
	}
	if got, want := indices, []uint64{1, 2}; !cmp.Equal(got, want) {
		t.Errorf("expected %v but got %v", want, got)
	}

	kh = sha256.Sum256([]byte("banana"))
	resp, err = vi.Lookup(t.Context(), kh)
	if err != nil {
		t.Fatal(err)
	}
	indices, _, err = client.VerifyLookupResponse(kh, resp, v)
	if err != nil {
		t.Fatalf("failed to verify vindex response: %v", err)
	}
	if indices != nil {
		t.Errorf("expected no results but got %+v", resp.IndexValue)
	}
}

func TestVerifiableIndex_concurrency(t *testing.T) {
	testCases := []struct {
		desc    string
		persist bool
	}{
		{
			desc:    "in memory",
			persist: false,
		},
		{
			desc:    "on disk",
			persist: true,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
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
			outputLog, closer, err := vindex.NewOutputLog(ctx, old, s, v, vindex.OutputLogOpts{})
			if err != nil {
				t.Fatal(err)
			}
			defer closer()
			vi, err := vindex.NewVerifiableIndex(ctx, inputLog, mapFn, outputLog, f.Name(), vindex.Options{PersistIndex: tC.persist})
			if err != nil {
				t.Fatal(err)
			}
			if err := vi.Update(ctx); err != nil {
				t.Fatal(err)
			}

			var eg errgroup.Group

			// Constantly add entries to the input log.
			eg.Go(func() error {
				i := 101

				for {
					inputLog.Append(fmt.Sprintf("key%d: %d", i, i))
					i++
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(2 * time.Millisecond):
					}
				}
			})

			// Periodically update the map from the input log.
			eg.Go(func() error {
				for {
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(100 * time.Millisecond):
						if err := vi.Update(ctx); err != nil {
							if ctx.Err() != nil {
								return nil
							}
							return err
						}
					}
				}
			})

			// Regularly perform lookups in the index.
			eg.Go(func() error {
				var kh [sha256.Size]byte
				var resp api.LookupResponse
				var indices []uint64

				kh = sha256.Sum256([]byte("bar"))
				resp, err = vi.Lookup(t.Context(), kh)
				if err != nil {
					return err
				}
				indices, _, err = client.VerifyLookupResponse(kh, resp, v)
				if err != nil {
					return fmt.Errorf("failed to verify vindex response: %v", err)
				}
				if got, want := indices, []uint64{1, 2}; !cmp.Equal(got, want) {
					return fmt.Errorf("expected %v but got %v", want, got)
				}

				kh = sha256.Sum256([]byte("banana"))
				resp, err = vi.Lookup(t.Context(), kh)
				if err != nil {
					return err
				}
				indices, _, err = client.VerifyLookupResponse(kh, resp, v)
				if err != nil {
					return fmt.Errorf("failed to verify vindex response: %v", err)
				}
				if indices != nil {
					return fmt.Errorf("expected no results but got %+v", resp.IndexValue)
				}

				for {
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(8 * time.Millisecond):
					}
				}
			})

			<-time.After(4 * time.Second)
			cancel()
			if err := eg.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type inMemoryTreeSource struct {
	t      *testonly.Tree
	leaves [][]byte
	s      note.Signer
	v      note.Verifier

	mu sync.RWMutex
}

func (s *inMemoryTreeSource) Checkpoint(ctx context.Context) (checkpoint []byte, err error) {
	var rootHash []byte
	var size uint64
	rootHash, size = func() ([]byte, uint64) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.t.Hash(), uint64(len(s.leaves))
	}()

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
		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, entry := range s.leaves[start:end] {
			if !yield(entry, nil) {
				return
			}
		}
	}
}

func (s *inMemoryTreeSource) Append(leafStr string) {
	leaf := []byte(leafStr)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaves = append(s.leaves, leaf)
	s.t.Append(rfc6962.DefaultHasher.HashLeaf(leaf))
}
