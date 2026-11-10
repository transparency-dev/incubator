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
	"syscall"

	"k8s.io/klog/v2"
)

func clampOpenFilesFromCurLimit(cur uint64) int {
	const reservedFDs = 512
	var limit uint64
	if cur > reservedFDs {
		limit = min(cur-reservedFDs, 50000)
	} else {
		limit = cur / 2
	}
	return max(int(limit), 500)
}

// autoTuneMaxOpenFiles inspects and optionally raises the process rlimit to determine a safe,
// high-performance MaxOpenFiles limit for Pebble, avoiding SSTable file descriptor churn at scale.
func autoTuneMaxOpenFiles() int {
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		klog.V(2).Infof("kvstore: failed to query RLIMIT_NOFILE: %v; defaulting MaxOpenFiles to 1000", err)
		return 1000
	}

	const desiredLimit = 65536
	cur := uint64(rlim.Cur)
	maxLim := uint64(rlim.Max)
	if cur < desiredLimit && maxLim > cur {
		setLim := rlim
		if maxLim > desiredLimit {
			setLim.Cur = desiredLimit
		} else {
			setLim.Cur = rlim.Max
		}
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &setLim); err == nil {
			cur = uint64(setLim.Cur)
			klog.V(2).Infof("kvstore: elevated RLIMIT_NOFILE soft limit to %d", cur)
		}
	}

	autoLimit := clampOpenFilesFromCurLimit(cur)
	if cur < 2048 {
		klog.Warningf("kvstore: system file descriptor limit is low (ulimit -n = %d). Pebble MaxOpenFiles constrained to %d. Run 'ulimit -n 65536' for optimal performance with large transparency logs.", cur, autoLimit)
	} else {
		klog.V(2).Infof("kvstore: auto-configured Pebble MaxOpenFiles to %d (system ulimit -n = %d)", autoLimit, cur)
	}

	return autoLimit
}
