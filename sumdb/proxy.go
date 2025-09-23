// Copyright 2025 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// sumdb is a command that launches a local proxy that allows clients to query
// using the tlog-tiles API, and retrieve results from SumDB.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"

	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"io"

	"k8s.io/klog/v2"
)

var (
	listen = flag.String("listen", ":8089", "Address to set up HTTP server listening on")
)

const (
	upstreamBase = "https://sum.golang.org"
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	upstream, err := url.Parse(upstreamBase)
	if err != nil {
		klog.Fatalf("Failed to parse upstream URL %q: %v", upstreamBase, err)
	}

	const tlogEntriesPrefix = "/tile/entries/"
	const tlogTilePrefix = "/tile/"

	const sumDBTileDataPrefix = "/tile/8/data/"
	const sumDBTilePrefix = "/tile/8/"
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			klog.V(2).Infof("Request for %s", r.In.URL.Path)
			if r.In.URL.Path == "/checkpoint" {
				r.Out.URL.Path = "/latest"
			} else if strings.HasPrefix(r.In.URL.Path, tlogEntriesPrefix) {
				o := strings.TrimPrefix(r.In.URL.Path, tlogEntriesPrefix)
				r.Out.URL.Path = fmt.Sprintf("%s%s", sumDBTileDataPrefix, o)
			} else if strings.HasPrefix(r.In.URL.Path, tlogTilePrefix) {
				o := strings.TrimPrefix(r.In.URL.Path, tlogTilePrefix)
				r.Out.URL.Path = fmt.Sprintf("%s%s", sumDBTilePrefix, o)
			}
		},
		ModifyResponse: func(r *http.Response) error {
			if strings.HasPrefix(r.Request.URL.Path, sumDBTileDataPrefix) {
				// Leaf data requires splitting into individual records, and then
				// reassembling with the record size prepended to each record.
				data, err := io.ReadAll(r.Body)
				if err != nil {
					return err
				}
				leaves := bytes.Split(data, []byte{'\n', '\n'})
				buf := bytes.Buffer{}
				for _, l := range leaves {
					r := append(bytes.TrimSpace(l), '\n')
					size := binary.BigEndian.AppendUint16(nil, uint16(len(r)))
					buf.Write(size)
					buf.Write(r)
				}
				r.Body = io.NopCloser(&buf)
				r.Header["Content-Length"] = []string{fmt.Sprint(buf.Len())}
			}
			return nil
		},
	}

	klog.Infof("Proxying tlog-tiles API to %s on %s", upstreamBase, *listen)
	if err := http.ListenAndServe(*listen, proxy); err != nil {
		klog.Fatalf("ListenAndServe: %v", err)
	}
}

