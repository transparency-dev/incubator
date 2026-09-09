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
	"flag"

	"net/http"

	"github.com/transparency-dev/incubator/sumdb"
	"k8s.io/klog/v2"
)

var (
	listen      = flag.String("listen", ":8089", "Address to set up HTTP server listening on")
	witnessSigs = flag.Uint("witnesses", 0, "Number of witness signatures required on a checkpoint. Setting this will pull checkpoints from the transparency-dev prod distributor.")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	proxy := sumdb.NewProxy(sumdb.ProxyOpts{
		WitnessSigs: *witnessSigs,
	})
	klog.Infof("tlog-tiles API listening on %s", *listen)
	if err := http.ListenAndServe(*listen, proxy); err != nil {
		klog.Fatalf("ListenAndServe: %v", err)
	}
}
