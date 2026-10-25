// Package filelock preserves the internal import path while delegating to the
// public package. Lock state and the contention sentinel are shared by both paths.
package filelock

import publiclock "github.com/ishizakahiroshi/heartpost/filelock"

// ErrLocked identifies a lock held by another caller.
var ErrLocked = publiclock.ErrLocked

// Acquire acquires a nonblocking exclusive lock.
func Acquire(path string) (func(), error) { return publiclock.Acquire(path) }

// TryAcquire is an alias of Acquire.
func TryAcquire(path string) (func(), error) { return publiclock.TryAcquire(path) }
