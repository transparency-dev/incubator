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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

// outputLogOrDie returns an output log using a POSIX log in the given directory.
func NewOutputLog(ctx context.Context, outputLogDir string, s note.Signer, v note.Verifier) (log OutputLog, closer func(), err error) {
	driver, err := posix.New(ctx, posix.Config{Path: outputLogDir})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create input log: %v", err)
	}

	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, tessera.NewAppendOptions().
		WithCheckpointSigner(s).
		WithCheckpointInterval(1*time.Second).
		WithBatching(1, time.Second))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get appender: %v", err)
	}
	awaiter := tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 100*time.Millisecond)

	outputLog := posixOutputLog{
		a: appender,
		w: awaiter,
		r: reader,
		v: v,
	}

	return outputLog, func() {
		_ = shutdown(ctx)
	}, nil
}

type posixOutputLog struct {
	a *tessera.Appender
	w *tessera.PublicationAwaiter
	r tessera.LogReader
	v note.Verifier
}

func (l posixOutputLog) Checkpoint(ctx context.Context) (checkpoint []byte, err error) {
	return l.r.ReadCheckpoint(ctx)
}

func (l posixOutputLog) Parse(cpRaw []byte) (*log.Checkpoint, error) {
	cp, _, _, err := log.ParseCheckpoint(cpRaw, l.v.Name(), l.v)
	return cp, err
}

func (l posixOutputLog) Append(ctx context.Context, data []byte) (idx uint64, checkpoint []byte, err error) {
	index, cp, err := l.w.Await(ctx, l.a.Add(ctx, tessera.NewEntry(data)))
	return index.Index, cp, err
}

func (l posixOutputLog) Lookup(ctx context.Context, idx, size uint64) ([]byte, [][sha256.Size]byte, error) {
	pb, err := client.NewProofBuilder(ctx, size, l.r.ReadTile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create proof builder: %v", err)
	}
	proof, err := pb.InclusionProof(ctx, idx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create proof: %v", err)
	}
	sizeFn := func(_ context.Context) (uint64, error) {
		return size, nil
	}

	var data []byte
	var done bool
	for b := range client.EntryBundles(ctx, 1, sizeFn, l.r.ReadEntryBundle, idx, 1) {
		if done {
			panic(errors.New("got 2 entries, expected 1"))
		}
		var eb api.EntryBundle
		if err := eb.UnmarshalText(b.Data); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal bundle: %v", err)
		}
		data = eb.Entries[b.RangeInfo.First]
		done = true
	}

	proofRes := make([][sha256.Size]byte, len(proof))
	for i, p := range proof {
		proofRes[i] = [sha256.Size]byte(p)
	}
	return data, proofRes, nil
}

// MarshalLeaf creates the leaf to be committed to the Output Log given the root hash
// of the verifiable index, and the checkpoint from the Input Log.
func MarshalLeaf(vindexRootHash [sha256.Size]byte, inLogCp []byte) []byte {
	m := append(hex.AppendEncode(nil, vindexRootHash[:]), '\n')
	m = append(m, inLogCp...)
	return m
}

// UnmarshalLeaf returns the root hash of the Verifiable Index and the checkpoint from the
// Input Log by unmarshalling a leaf from the Output Log, previously marshalled with
// MarshalLeaf.
func UnmarshalLeaf(leaf []byte) ([sha256.Size]byte, []byte, error) {
	split := hex.EncodedLen(sha256.Size)
	if split > len(leaf) {
		return [sha256.Size]byte{}, nil, fmt.Errorf("failed to parse output log leaf: %q", leaf)
	}
	mapRoot, err := hex.AppendDecode(nil, leaf[:split])
	if err != nil {
		return [sha256.Size]byte{}, nil, fmt.Errorf("failed to decode map root: %v", err)
	}
	return [32]byte(mapRoot), leaf[split+1:], nil
}
