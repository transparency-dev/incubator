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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
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
			wantIdx:      2,
			wantErr:      false,
		}, {
			desc:         "lots of newlines",
			fileContents: "1\n2\n3\n\n",
			wantErr:      true,
		}, {
			desc:         "no trailing newlines",
			fileContents: "1\n2\n3",
			wantIdx:      3,
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
			wal, err := newWalWriter(f.Name(), 0)
			if gotErr := err != nil; gotErr != tC.wantErr {
				t.Fatalf("wantErr != gotErr (%t != %t) %v", tC.wantErr, gotErr, err)
			}
			if tC.wantErr {
				return
			}
			defer func() {
				_ = wal.close()
			}()
		})
	}
}

func TestWriteAheadLog_truncate(t *testing.T) {
	f, err := os.CreateTemp("", "testWal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("0\n2\n5 xxabcdeadbeef"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	wal, err := newWalWriter(f.Name(), 3)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = wal.close()
	}()

	contents, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := contents, []byte("0\n2\n"); !bytes.Equal(got, want) {
		t.Errorf("expected %v but got %v", want, got)
	}
}

func TestWriteAheadLog_roundtrip(t *testing.T) {
	testCases := []struct {
		desc           string
		entriesToWrite uint64
		treeSizeNeeded uint64
		wantErr        bool
	}{
		{
			desc:           "write 2, read 2",
			entriesToWrite: 2,
			treeSizeNeeded: 2,
			wantErr:        false,
		}, {
			desc:           "write 200, read 200",
			entriesToWrite: 200,
			treeSizeNeeded: 200,
			wantErr:        false,
		}, {
			desc:           "write 50, read 20",
			entriesToWrite: 50,
			treeSizeNeeded: 20,
			wantErr:        false,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
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

			wal, err := newWalWriter(f.Name(), 0)
			if err != nil {
				t.Fatal(err)
			}

			for i := range tC.entriesToWrite {
				hash := sha256.Sum256([]byte{byte(i)})
				if err := wal.append(uint64(i), [][sha256.Size]byte{hash}); err != nil {
					t.Error(err)
				}
			}

			if err := wal.close(); err != nil {
				t.Error(err)
			}

			wal, err = newWalWriter(f.Name(), tC.treeSizeNeeded)
			if err != nil {
				t.Fatal(err)
			}

			if err := wal.close(); err != nil {
				t.Error(err)
			}

			wr, err := newWalReader(f.Name())
			if err != nil {
				t.Fatal(err)
			}

			var lastIdx uint64
			for {
				if idx, _, err := wr.next(); err != nil {
					break
				} else {
					lastIdx = idx
				}
			}
			if got, want := lastIdx, tC.treeSizeNeeded-1; got != want {
				t.Errorf("expected reader to have last index of %d, but found %d", want, got)
			}
		})
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

	wal, err := newWalWriter(f.Name(), 0)
	if err != nil {
		t.Fatal(err)
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
			if err := wal.append(uint64(i), [][sha256.Size]byte{hash}); err != nil {
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

func mustHashEncode(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}
