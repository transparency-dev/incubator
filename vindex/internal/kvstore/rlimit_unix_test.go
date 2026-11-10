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

//go:build unix

package kvstore

import (
	"math"
	"testing"
)

func TestClampOpenFilesFromCurLimit(t *testing.T) {
	if got := clampOpenFilesFromCurLimit(math.MaxUint64); got != 50000 {
		t.Errorf("clampOpenFilesFromCurLimit(RLIM_INFINITY) = %d, want 50000", got)
	}
	if got := clampOpenFilesFromCurLimit(256); got != 500 {
		t.Errorf("clampOpenFilesFromCurLimit(256) = %d, want 500", got)
	}
	if got := clampOpenFilesFromCurLimit(4096); got != 3584 {
		t.Errorf("clampOpenFilesFromCurLimit(4096) = %d, want 3584", got)
	}
}
