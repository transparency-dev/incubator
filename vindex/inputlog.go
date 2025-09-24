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
	"iter"
	"net/http"
	"net/url"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

type InputLogOpts struct {
	HttpClient *http.Client
	Origin     string
}

func NewTiledInputLog(base *url.URL, v note.Verifier, o InputLogOpts) (InputLog, error) {
	// Set any missing optional values to their defaults
	if o.HttpClient == nil {
		o.HttpClient = http.DefaultClient
	}
	if len(o.Origin) == 0 {
		o.Origin = v.Name()
	}

	f, err := client.NewHTTPFetcher(base, o.HttpClient)
	if err != nil {
		return nil, err
	}
	return logReaderSource{
		f:    f,
		v:    v,
		opts: o,
	}, nil
}

// logReaderSource adapts a tessera.LogReader to a vindex.InputLog.
type logReaderSource struct {
	f    *client.HTTPFetcher
	v    note.Verifier
	opts InputLogOpts
}

func (s logReaderSource) Checkpoint(ctx context.Context) (checkpoint []byte, err error) {
	return s.f.ReadCheckpoint(ctx)
}

func (s logReaderSource) Parse(cpRaw []byte) (*log.Checkpoint, error) {
	cp, _, _, err := log.ParseCheckpoint(cpRaw, s.opts.Origin, s.v)
	return cp, err
}

func (s logReaderSource) Leaves(ctx context.Context, start, end uint64) iter.Seq2[[]byte, error] {
	tsf := func(ctx context.Context) (uint64, error) {
		return end, nil
	}
	bi := client.EntryBundles(ctx, 2, tsf, s.f.ReadEntryBundle, start, end-start)
	unbundleFn := func(bundle []byte) ([][]byte, error) {
		eb := &api.EntryBundle{}
		if err := eb.UnmarshalText(bundle); err != nil {
			return nil, err
		}
		return eb.Entries, nil
	}

	return func(yield func([]byte, error) bool) {
		// Unwrap the client.Entry type to return an iterator of []byte only.
		for entry, err := range client.Entries(bi, unbundleFn) {
			if err != nil {
				if !yield(nil, err) {
					return
				}
				continue
			}
			if !yield(entry.Entry, nil) {
				return
			}
		}
	}
}
