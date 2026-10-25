// Package agent provides the shared collection, licensing and delivery runtime.
// Command-line parsing and product-specific collectors belong to its caller.
package agent

import (
	"context"
	license "github.com/ishizakahiroshi/heartpost/agentlicense"
	"log"
	"time"
)

type Identity struct{ ID, Label, Type string }
type Task struct {
	Name, Group string
	Always      bool
	Collect     func(context.Context) (any, error)
}
type RunMode uint8

const (
	Once RunMode = iota
	Intervals
)

type CancelPolicy uint8

const (
	ReportCanceled CancelPolicy = iota
	FailCanceled
	DropCanceled
)

type FailurePolicy uint8

const (
	// ReturnFailure returns an error when every configured target failed. In
	// Intervals mode the first failed cycle cancels and joins all worker groups.
	ReturnFailure FailurePolicy = iota
	// WarnFailure logs target errors and permits the next scheduled invocation.
	WarnFailure
)

type Encoding uint8

const (
	TypedIndented Encoding = iota
	SortedIndented
	SortedCompact
)

type LicenseOptions struct {
	Verifier                                                        license.Verifier
	Key, PrimaryEndpoint, OfflineFile, CachePath, PrimaryTargetName string
	Relaxed, RefreshPrimary401                                      bool
	VerifyTimeout, HeartbeatInterval                                time.Duration
}

// BackgroundService is started only by Run and stopped before Run returns.
type BackgroundService func(context.Context) (func(context.Context) error, error)
type Options struct {
	Identity                  Identity
	Mode                      RunMode
	Tasks                     []Task
	Jobs                      map[string]bool
	Intervals                 map[string]time.Duration
	UnknownInterval, Timeout  time.Duration
	Targets                   []Target
	License                   *LicenseOptions
	LockPath                  string
	CreateLockDirectory       bool
	Location                  *time.Location
	Logger                    *log.Logger
	CancelPolicy              CancelPolicy
	SendFailurePolicy         FailurePolicy
	Encoding                  Encoding
	MarshalFailureEmptyObject bool
	DryRun                    bool
	// Initialize runs after the process-wide active guard has been acquired.
	// It connects legacy collectors' cancellation channel without overlapping runs.
	Initialize func(context.Context)
	Services   []BackgroundService
}
