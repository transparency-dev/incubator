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

// api contains the API definitions for the prototype VIndex API.
package api

import "crypto/sha256"

const (
	// PathLookup defines the path from the vindex base URL where the lookup
	// operation will be served. This takes a single key as a GET request
	// parameter, and returns a marshalled LookupResponse.
	PathLookup = "/lookup/"
)

// LookupResponse describes the result from a lookup operation.
type LookupResponse struct {
	// These values represent the proof that the state of the index is committed
	// to in the output log. These fields are a checkpoint, the encoded leaf in
	// this log (which can be parsed as an OutputLogLeaf), and a proof that the leaf
	// is committeed to by the checkpoint.
	//
	// TODO(mhutchinson): Revisit these fields when implementing the output log.
	// A more modern approach is to return only an index into the output log, and then
	// have the client look up the latest checkpoint, leaf value, and inclusion proof.
	// This puts more work on the client, but saves work for the server and provides
	// more flexibility.
	OutputLogCP    []byte              `json:"output_log_cp"`
	OutputLogLeaf  []byte              `json:"output_log_leaf"`
	OutputLogProof [][sha256.Size]byte `json:"output_log_proof"`

	// These values represent the lookup operation in the index at the root hash
	// committed to by OutputLogLeaf. The values contain all indices for the given
	// key, and the proof binds these values at this key at the index root hash.
	IndexKey   [sha256.Size]byte   `json:"index_key"`
	IndexValue []uint64            `json:"index_value"`
	IndexProof [][sha256.Size]byte `json:"index_proof"`
}

// OutputLogLeaf describes a leaf in the output log.
//
// This leaf is a statement that commits to the result of generating a map from a
// given input log size. To do this, it binds the Input Log state (in the form of
// a checkpoint), to a single hash, which is the Merkle Tree root hash for the index.
type OutputLogLeaf struct {
	// InputLogCP is the checkpoint from the input log that commits to
	// the state of the log that the index was derived from.
	InputLogCP []byte `json:"input_log_cp"`
	// IndexRoot is the root hash of the Merkle Tree for the verifiable index.
	IndexRoot [sha256.Size]byte `json:"index_root"`
}
