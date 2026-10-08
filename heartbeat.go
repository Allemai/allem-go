package allem

// Run lifecycle and heartbeats. Makes silence mean something specific.
//
// Non-Negotiable Rule 5: *"at any moment we must be able to distinguish 'the
// agent did nothing' from 'the agent was not reporting.'"*
//
// Without a heartbeat those two are the same observation -- an absence of events
// -- and the difference between them is the difference between a quiet Tuesday
// and an outage nobody noticed. The heartbeat splits them:
//
//   - events arriving, no actions      -> the agent did nothing
//   - no events at all past the grace  -> we were not receiving, and the server
//     opens a **blackout window** recording
//     exactly when visibility was lost
//
// A heartbeat consumes a client_seq like any other event. That is deliberate and
// is the whole trick: **a missing heartbeat is itself a detectable gap**, so the
// mechanism that detects lost actions also detects lost heartbeats, and there is
// no second mechanism to keep honest.
//
// Three event types travel on this path:
//
//	run_start  first event of every run, always client_seq = 1
//	heartbeat  every 60s while the agent lives
//	run_end    on graceful shutdown
//
// They are emitted lowercase because `normalize_event` canonicalizes identifiers
// to lowercase on arrival anyway; sending the canonical form means what you see
// in the console is what the SDK sent. An uppercase sender still works.
//
// **Volume.** ~1,440 heartbeats per agent per day. They are excluded by default
// from console event lists, the SSE stream, thread evaluation, and activity
// stats -- see `docs/completeness-blackouts.md`. They are still in the chain,
// because they are evidence of coverage.
//
// # What Go does differently, and why
//
// The Python SDK installs an `atexit` hook and chains onto SIGTERM so that
// RUN_END is emitted on a clean exit. **Go has neither.** There is no `atexit`,
// and a library that installs a `signal.Notify` handler changes the host
// program's signal disposition without being asked -- the exact objection the
// Python module raises against REPLACING a SIGTERM handler, except Go gives a
// library no way to chain onto one.
//
// So this SDK does not install a signal handler, and `Client.Close()` is how a
// run ends. A Go program that exits without calling it reports UNCLOSED_RUN,
// which is accurate: nothing observed the shutdown. That is the honest
// behaviour and it is the one divergence from the Python SDK that a customer
// has to do something about, so it is in the README, in
// `docs/go-sdk-report.md`, and in the doc comment of every constructor.

import (
	"sync"
	"time"
)

// HeartbeatInterval is how often a live agent beats.
const HeartbeatInterval = 60 * time.Second

// HeartbeatGrace is how long the server waits before declaring a blackout.
//
// Three missed beats, not one: a single missed beat is a hiccup -- a slow GC
// pause, a network blip, a container rescheduling -- and a product that opened a
// blackout window for every one of those would produce a compliance artifact
// nobody reads.
const HeartbeatGrace = 180 * time.Second

// The three lifecycle event types.
const (
	EventRunStart  = "run_start"
	EventHeartbeat = "heartbeat"
	EventRunEnd    = "run_end"
)

// LifecycleEventTypes is the closed set, for a caller that filters on it.
var LifecycleEventTypes = []string{EventRunStart, EventHeartbeat, EventRunEnd}

// emitFunc emits one lifecycle event for one agent.
type emitFunc func(agentID, eventType string) error

// heartbeat is a goroutine emitting one beat per interval for one agent.
//
// It stops when the RunLifecycle that owns it ends, and it cannot keep a
// finished process alive -- Go exits when main returns regardless of what any
// goroutine is doing. An abruptly killed agent SHOULD stop beating, and the
// resulting blackout window is the record we want.
type heartbeat struct {
	emit     emitFunc
	agentID  string
	interval time.Duration
	logf     Logf

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	started  bool
}

func newHeartbeat(emit emitFunc, agentID string, interval time.Duration, logf Logf) *heartbeat {
	if interval <= 0 {
		interval = HeartbeatInterval
	}
	if logf == nil {
		logf = discardLogf
	}
	return &heartbeat{
		emit:     emit,
		agentID:  agentID,
		interval: interval,
		logf:     logf,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (h *heartbeat) start() {
	if h.started {
		return
	}
	h.started = true
	go h.run()
}

func (h *heartbeat) run() {
	defer close(h.done)
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-ticker.C:
			if err := h.emit(h.agentID, EventHeartbeat); err != nil {
				// Losing one beat is survivable; losing the goroutine is not --
				// it would look exactly like the agent dying, and would
				// manufacture a blackout window for an agent that is fine.
				h.logf(LevelWarning,
					"heartbeat for %q could not be emitted (%v). The next beat "+
						"will be attempted normally; if beats keep failing the "+
						"server will open a blackout window, which is the "+
						"correct record.", h.agentID, err)
			}
		}
	}
}

func (h *heartbeat) Stop(timeout time.Duration) {
	h.stopOnce.Do(func() { close(h.stop) })
	if !h.started {
		return
	}
	select {
	case <-h.done:
	case <-time.After(timeout):
	}
}

// RunLifecycle owns one agent's run: RUN_START, the beat goroutine, and RUN_END.
//
// RUN_START is emitted synchronously at construction, before the beat goroutine
// starts, so it always takes client_seq = 1. Nothing else may consume a number
// for this agent first -- that is why starting a run is an explicit call rather
// than something that happens lazily on the first action.
type RunLifecycle struct {
	agentID   string
	heartbeat *heartbeat
	emit      emitFunc
	logf      Logf

	endOnce sync.Once
}

func newRunLifecycle(emit emitFunc, agentID string, interval time.Duration, logf Logf) (*RunLifecycle, error) {
	if logf == nil {
		logf = discardLogf
	}
	if err := emit(agentID, EventRunStart); err != nil {
		return nil, err
	}
	run := &RunLifecycle{
		agentID:   agentID,
		emit:      emit,
		logf:      logf,
		heartbeat: newHeartbeat(emit, agentID, interval, logf),
	}
	run.heartbeat.start()
	return run, nil
}

// AgentID is whose run this is.
func (r *RunLifecycle) AgentID() string { return r.agentID }

// End emits RUN_END and stops beating. Safe to call more than once.
//
// Go has no `atexit`, so nothing calls this for you. `Client.Close()` does, and
// a program that exits without calling `Close` reports UNCLOSED_RUN -- which is
// accurate rather than a defect, because nothing observed the shutdown.
func (r *RunLifecycle) End() {
	r.endOnce.Do(func() {
		r.heartbeat.Stop(2 * time.Second)
		if err := r.emit(r.agentID, EventRunEnd); err != nil {
			r.logf(LevelWarning,
				"run_end for %q could not be emitted (%v). The run will report "+
					"as unclosed, which is the honest record.", r.agentID, err)
		}
	})
}
