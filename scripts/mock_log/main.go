// Copyright 2026 The Transparency Authors. All Rights Reserved.
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
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

func validOrigin(s string) bool {
	if s == "" || s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

func run(dir, origin string) (retErr error) {
	if !validOrigin(origin) {
		return fmt.Errorf("invalid origin %q: must be printable ASCII without leading/trailing spaces", origin)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("MkdirAll failed: %w", err)
	}

	skeyPath := filepath.Join(dir, "signer.key")
	vkeyPath := filepath.Join(dir, "verifier.vkey")
	var skey, vkey string
	if rawSKey, err := os.ReadFile(skeyPath); err == nil {
		skey = string(bytes.TrimSpace(rawSKey))
	} else {
		var gErr error
		skey, vkey, gErr = note.GenerateKey(rand.Reader, origin)
		if gErr != nil {
			return fmt.Errorf("GenerateKey failed: %w", gErr)
		}
		if err := os.WriteFile(skeyPath, []byte(skey), 0o600); err != nil {
			return fmt.Errorf("writing signer.key: %w", err)
		}
		if err := os.WriteFile(vkeyPath, []byte(vkey), 0o644); err != nil {
			return fmt.Errorf("writing verifier.vkey: %w", err)
		}
	}

	signer, err := note.NewSigner(skey)
	if err != nil {
		return fmt.Errorf("NewSigner failed: %w", err)
	}
	if signer.Name() != origin {
		return fmt.Errorf("existing log signer origin %q does not match requested origin %q", signer.Name(), origin)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	driver, err := posix.New(ctx, posix.Config{Path: dir})
	if err != nil {
		return fmt.Errorf("posix.New failed: %w", err)
	}
	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(16, time.Millisecond).
		WithCheckpointInterval(100*time.Millisecond))
	if err != nil {
		return fmt.Errorf("NewAppender failed: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, shutdown(context.Background()))
	}()

	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 5*time.Millisecond)
	var lastFut tessera.IndexFuture
	for _, e := range []string{"apple", "banana", "cherry", "apple"} {
		lastFut = appender.Add(ctx, tessera.NewEntry([]byte(e)))
	}
	if _, _, err := awaiter.Await(ctx, lastFut); err != nil {
		return fmt.Errorf("awaiter.Await failed: %w", err)
	}
	return nil
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Fprintf(os.Stderr, "Usage: go run ./scripts/mock_log <dir> [origin]\n")
		if len(os.Args) < 2 {
			os.Exit(1)
		}
		return
	}

	dir := os.Args[1]
	origin := "mock.log.local"
	if len(os.Args) > 2 && strings.TrimSpace(os.Args[2]) != "" {
		origin = strings.TrimSpace(os.Args[2])
	}

	if err := run(dir, origin); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
