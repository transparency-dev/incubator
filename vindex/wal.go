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

package vindex

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

// newWalWriter creates a WAL writer that uses the file at the given path.
// This will verify that the tail of the WAL file is well-formed, and truncate the file
// if there is any trailing corruption. It will ensure that the file is truncated so that
// the last index there is treeSize-1. This allows the WAL to be
// flushed ahead of storing state about the input log merkle tree, and then slightly
// truncated if the WAL ends up being ahead due to process termination.
// If no entry for treeSize-1 can be found, then this returns an error.
func newWalWriter(walPath string, treeSize uint64) (*walWriter, error) {
	w := &walWriter{
		walPath: walPath,
	}
	ffs := os.O_WRONLY | os.O_APPEND

	var lastIndex uint64
	if treeSize > 0 {
		lastIndex = treeSize - 1
	}
	err := validate(walPath, lastIndex)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		ffs |= os.O_CREATE | os.O_EXCL
	}
	// Open the file for writing in append-only, creating it if needed
	w.f, err = os.OpenFile(walPath, ffs, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open file for writing: %s", err)
	}
	return w, err
}

// walWriter provides the methods needed by the processor of the Input Log when interacting
// with the WAL. init provides the index that this processor should start from, and append
// allows new mapped entries to be added to the WAL.
type walWriter struct {
	walPath string
	f       *os.File
}

func (l *walWriter) close() error {
	return l.f.Close()
}

// validate reads the file and determines what the last mapped log index was, and returns it.
// The assumption is that all lines ending with a newline were written correctly.
// If there are any errors in the file then this throws an error.
func validate(walPath string, lastIdx uint64) error {
	f, err := os.OpenFile(walPath, os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()
	fi, err := f.Stat()
	if err != nil {
		return err
	}

	// Handle trivial case of empty file
	fileSize := fi.Size()
	if fileSize == 0 {
		if err := os.Remove(walPath); err != nil {
			return fmt.Errorf("failed to delete empty file: %s", err)
		}
		return os.ErrNotExist
	}

	// Read from the end of the file in stripes, terminating when we either:
	// a) find another newline; or
	// b) we have read from the beginning of the file
	var buffer string
	const stripeSize = 1024
	readStripe := make([]byte, stripeSize)
	seekPos := fileSize - stripeSize
	droppedTail := false

	for {
		if seekPos < 0 {
			// If the stripe is bigger than the remaining file contents, adjust the offset
			// and scale down what we'll read to avoid reading duplicates.
			readStripe = readStripe[:stripeSize+seekPos]
			seekPos = 0
		}
		if _, err := f.ReadAt(readStripe, seekPos); err != nil {
			return err
		}
		buffer = string(readStripe) + buffer

		var truncFrom int64 = -1
		defer func() {
			if truncFrom >= 0 {
				klog.Warningf("Dropping trailing %d bytes from WAL", fileSize-truncFrom)
				if err := f.Truncate(truncFrom); err != nil {
					panic(fmt.Errorf("failed to truncate WAL: %v", err))
				}
			}
		}()

		for i := strings.LastIndex(buffer, "\n"); i > 0; i = strings.LastIndex(buffer, "\n") {
			p := buffer[i+1:]
			buffer = buffer[:i]
			if !droppedTail {
				droppedTail = true
				if len(p) > 0 {
					truncFrom = seekPos + int64(i) + 1
				}
				continue
			}
			idx, _, err := unmarshalWalEntry(p)
			if err != nil {
				return err
			}
			switch {
			case idx > lastIdx:
				truncFrom = seekPos + int64(i) + 1
			case idx == lastIdx:
				return nil
			case idx < lastIdx:
				return fmt.Errorf("failed to find index %d (terminated after rewinding to %d)", lastIdx, idx)
			}
		}
		if seekPos == 0 {
			_, _, err := unmarshalWalEntry(buffer)
			return err
		}
		seekPos = seekPos - stripeSize
	}
}

func (l *walWriter) flush() error {
	return l.f.Sync()
}

func (l *walWriter) append(idx uint64, hashes [][32]byte) error {
	e, err := marshalWalEntry(idx, hashes)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %v", err)
	}
	_, err = fmt.Fprintf(l.f, "%s\n", e)
	return err
}

func newWalReader(path string) (*walReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &walReader{
		f: f,
		r: bufio.NewReader(f),
	}, nil
}

type walReader struct {
	f       *os.File
	r       *bufio.Reader
	partial string
}

// next returns the next index, hashes, and any error.
// TODO(mhutchinson): change this as it's inconvenient with EOF handling,
// which should be common when reader hits the end of the file but more is
// to be written.
func (r *walReader) next() (uint64, [][32]byte, error) {
	line, err := r.r.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			r.partial = line
		}
		return 0, nil, err
	}

	// Make sure any partial lines are prepended, and drop the final newline
	line = r.partial + line[:len(line)-1]
	r.partial = ""
	return unmarshalWalEntry(line)
}

func (r *walReader) close() error {
	return r.f.Close()
}

// unmarshalWalEntry parses a line from the WAL.
// This is the reverse of marshalWalEntry.
func unmarshalWalEntry(e string) (uint64, [][32]byte, error) {
	tokens := strings.Split(e, " ")
	idx, err := strconv.ParseUint(tokens[0], 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse idx from %q", e)
	}

	hashes := make([][32]byte, 0, len(tokens)-1)
	for i, h := range tokens[1:] {
		parsed, err := hex.DecodeString(h)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to parse hex token %d from %q", i, e)
		}
		if got, want := len(parsed), 32; got != want {
			return 0, nil, fmt.Errorf("expected 32 byte hash but got %d bytes at idx %d", got, i)
		}
		hashes = append(hashes, [32]byte(parsed))
	}

	return idx, hashes, nil
}

// unmarshalWalEntry converts an index and the hashes it affects into a line for the WAL.
// This is the reverse of unmarshalWalEntry.
func marshalWalEntry(idx uint64, hashes [][32]byte) (string, error) {
	sb := strings.Builder{}
	if _, err := sb.WriteString(strconv.FormatUint(idx, 10)); err != nil {
		return "", err
	}
	for _, h := range hashes {
		if _, err := sb.WriteString(" " + hex.EncodeToString(h[:])); err != nil {
			return "", err
		}
	}
	return sb.String(), nil
}
