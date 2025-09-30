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

package sumdb

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"testing"
)

func TestRewrite(t *testing.T) {
	testCases := []struct {
		desc       string
		pathPrefix string
		inPath     string
		outPath    string
	}{
		{
			desc:       "checkpoint no prefix",
			pathPrefix: "",
			inPath:     "/checkpoint",
			outPath:    "/latest",
		}, {
			desc:       "checkpoint with prefix",
			pathPrefix: "/customprefix",
			inPath:     "/customprefix/checkpoint",
			outPath:    "/latest",
		}, {
			desc:       "entries no prefix",
			pathPrefix: "",
			inPath:     "/tile/entries/000",
			outPath:    "/tile/8/data/000",
		}, {
			desc:       "entries with prefix",
			pathPrefix: "/customprefix",
			inPath:     "/customprefix/tile/entries/000",
			outPath:    "/tile/8/data/000",
		}, {
			desc:       "internal tile no prefix",
			pathPrefix: "",
			inPath:     "/tile/0/000",
			outPath:    "/tile/8/0/000",
		}, {
			desc:       "internal tile with prefix",
			pathPrefix: "/customprefix",
			inPath:     "/customprefix/tile/0/000",
			outPath:    "/tile/8/0/000",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			proxy := NewProxy(ProxyOpts{PathPrefix: tC.pathPrefix})
			req := &httputil.ProxyRequest{
				In: &http.Request{
					URL: mustParseURL(t, fmt.Sprintf("http://example.com%s", tC.inPath)),
				},
			}
			out := *req.In
			req.Out = &out
			proxy.Rewrite(req)

			if got, want := req.Out.URL.Path, tC.outPath; got != want {
				t.Errorf("expected path to be %s but was %s", want, got)
			}
		})
	}
}

func TestModifyResponse(t *testing.T) {
	testCases := []struct {
		desc string
		path string
		body []byte
		want []byte
	}{
		{
			desc: "checkpoint not changed",
			path: "/latest",
			body: []byte("moose\n42\ndeadbeef"),
			want: []byte("moose\n42\ndeadbeef"),
		},
		{
			desc: "entries body modified",
			path: "/tile/8/data/000",
			body: []byte("foo\nfoo1\n\nmoose\nmoose1\n"),
			want: append(append(append([]byte{0, 9}, []byte("foo\nfoo1\n")...), []byte{0, 13}...), []byte("moose\nmoose1\n")...),
		},
		{
			desc: "internal tiles not modified",
			path: "/tile/8/0/000",
			body: []byte("foo\nfoo1\n\nmoose\nmoose1\n"),
			want: []byte("foo\nfoo1\n\nmoose\nmoose1\n"),
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			proxy := NewProxy(ProxyOpts{})
			resp := &http.Response{
				Request: &http.Request{
					URL: mustParseURL(t, fmt.Sprintf("http://example.com%s", tC.path)),
				},
				Header: http.Header{},
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(tC.body))
			if err := proxy.ModifyResponse(resp); err != nil {
				t.Fatal(err)
			}
			if got, want := mustReadAll(t, resp.Body), tC.want; !bytes.Equal(got, want) {
				t.Errorf("expected body %v but got %v", want, got)
			}
		})
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func mustReadAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	bs, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}
	return bs
}
