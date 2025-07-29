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
)

// walWriter provides the methods needed by the processor of the Input Log when interacting
// with the WAL. init provides the index that this processor should start from, and append
// allows new mapped entries to be added to the WAL.
type walWriter struct {
	walPath string
	f       *os.File
}

// init verifies that the log is in good shape, and returns the index that is expected next.
// It also opens the log for appending to.
//
// Note that it returns the next expected index to avoid awkwardness with the meaning of 0,
// which could mean 0 was successfully read from a previous run, or that there was no log.
func (l *walWriter) init() (uint64, error) {
	ffs := os.O_WRONLY | os.O_APPEND

	idx, err := l.validate()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return idx, err
		}
		ffs |= os.O_CREATE | os.O_EXCL
	} else {
		// If the file exists, then we expect the next index to be returned
		idx++
	}
	// Open the file for writing in append-only, creating it if needed
	l.f, err = os.OpenFile(l.walPath, ffs, 0o644)
	if err != nil {
		return 0, fmt.Errorf("failed to open file for writing: %s", err)
	}
	return idx, err
}

func (l *walWriter) close() error {
	return l.f.Close()
}

// validate reads the file and determines what the last mapped log index was, and returns it.
// The assumption is that all lines ending with a newline were written correctly.
// If there are any errors in the file then this throws an error.
func (l *walWriter) validate() (uint64, error) {
	f, err := os.Open(l.walPath)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = f.Close()
	}()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}

	// Handle trivial case of empty file
	size := fi.Size()
	if size == 0 {
		if err := os.Remove(l.walPath); err != nil {
			return 0, fmt.Errorf("failed to delete empty file: %s", err)
		}
		return 0, os.ErrNotExist
	}

	// Confirm last character is a newline
	// TODO(mhutchinson): support ignoring incomplete lines
	lastChar := make([]byte, 1)
	if _, err := f.ReadAt(lastChar, size-1); err != nil {
		return 0, err
	}
	if lastChar[0] != '\n' {
		return 0, fmt.Errorf("expected final newline but got '%x'", lastChar[0])
	}

	// Read from the end of the file in stripes, terminating when we either:
	// a) find another newline; or
	// b) we have read from the beginning of the file
	var lastLine string
	const stripeSize = 1024
	readStripe := make([]byte, stripeSize)
	// Set it up so we read all but the last character (we know it's a newline)
	currOffset := size - 1 - stripeSize

	for {
		if currOffset < 0 {
			// If the stripe is bigger than the remaining file contents, adjust the offset
			// and scale down what we'll read to avoid reading duplicates.
			readStripe = readStripe[:stripeSize+currOffset]
			currOffset = 0
		}
		if _, err := f.ReadAt(readStripe, currOffset); err != nil {
			return 0, err
		}
		lastLine = string(readStripe) + lastLine
		if idx := strings.LastIndexByte(lastLine, '\n'); idx > 0 {
			lastLine = lastLine[idx+1:]
			break
		}
		if currOffset == 0 {
			// We read from the start of the file so lastLine is full
			break
		}
		currOffset = currOffset - stripeSize
	}

	idx, _, err := unmarshalWalEntry(lastLine)

	return idx, err
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
