package allem

// Background delivery worker for the spool.
//
// A single goroutine drains the spool oldest-first and posts each event to
// POST /api/v1/events. It never blocks the agent's code, and it never gives up:
// backoff runs 1s, 2s, 4s, 8s, 16s, 32s, then every 60s indefinitely. A spool
// that empties itself on failure is worse than no spool.
//
// One row is taken out of the queue rather than retried: one the platform
// ANSWERED and permanently refused (PlatformRefused.Permanent -- a 4xx that is
// about the bytes, not the moment), **after PermanentRefusalAttempts of them**,
// because one refusal is a moment and several are a property of the bytes. It is
// set aside, not deleted, and Spool.UnsentCount still counts it.
//
// Left in the queue such a row is retried until the end of time, so
// PendingCount never reaches zero and the queue can never be shown to have
// drained. It does not block the rest of its own batch -- drainOnce attempts
// every row it selected -- but Pending is `LIMIT 100` ordered by age, so a
// hundred of them at the head mean row 101 is never selected at all.
//
// On startup the worker replays whatever the spool already holds -- including
// rows left over from a previous process that crashed or exited while Allem was
// unreachable (acceptance test 2).
//
// Replay always targets /events, even for events first attempted via
// /events/check: after fail-open let the action proceed, the verdict is moot --
// what must survive is the record. The server dedupes replays on
// (run_id, client_seq) and on the deterministic external_event_id, so a retry
// can never create a duplicate.

import (
	"sync"
	"time"
)

var backoffSeconds = []time.Duration{
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	32 * time.Second,
}

const steadyRetry = 60 * time.Second

// batchRows is one batch, matching Spool.Pending's default.
const batchRows = 100

// PermanentRefusalAttempts is how many times the platform has to permanently
// refuse ONE row before it is set aside.
//
// One refusal is a moment -- an auth blip, a key rotation, a WAF event, a
// rollout that 404s for a second. Several, across the backoff ladder, are a
// property of the bytes. Measured on the Python side: with a threshold of one,
// an endpoint answering 401 for a single second set a 1,049-row backlog aside
// in 1.36 s.
const PermanentRefusalAttempts = 3

// sendFunc posts one payload and returns an error on failure.
type sendFunc func(payload []byte) error

// sender drains the spool through send.
type sender struct {
	spool     *Spool
	send      sendFunc
	logf      Logf
	retention time.Duration

	wake chan struct{}
	stop chan struct{}

	startOnce sync.Once
	stopOnce  sync.Once
	done      chan struct{}
	running   bool

	// Where the next batch is read from; see drainOnce.
	window int
	// The retention rule the spool's own documentation states, enforced. It had
	// no caller anywhere in the shipped Python SDK, so a delivered row was kept
	// for ever and a long-running agent's spool grew without bound until it
	// crossed the size limit and began logging that events were NOT being
	// delivered -- about rows that all were.
	purged   bool
	failures int
}

// newSender builds the worker. start=false builds it without running it.
//
// For one caller: a process whose delivery is somebody else's job. Nothing is
// lost by not starting it -- every row is already durable on disk before this
// object is consulted.
func newSender(spool *Spool, send sendFunc, logf Logf, retention time.Duration, start bool) *sender {
	if logf == nil {
		logf = discardLogf
	}
	if retention <= 0 {
		retention = DefaultRetention
	}
	s := &sender{
		spool:     spool,
		send:      send,
		logf:      logf,
		retention: retention,
		// Buffered by one: Wake must never block the agent's call path, and a
		// wake that arrives while the worker is already awake is redundant
		// rather than lost.
		wake: make(chan struct{}, 1),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	if start {
		s.start()
	}
	return s
}

func (s *sender) start() {
	s.startOnce.Do(func() {
		s.running = true
		go s.run()
	})
}

// Running reports whether the worker goroutine was started.
func (s *sender) Running() bool { return s.running }

// Wake signals that new work was spooled. Non-blocking, always.
func (s *sender) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Stop stops the worker, giving it a short window to drain first.
//
// Whatever is still unsent stays in the spool and is replayed by the next
// process -- stopping never loses evidence.
func (s *sender) Stop(drainTimeout time.Duration) {
	s.stopOnce.Do(func() {
		if !s.running {
			close(s.stop)
			close(s.done)
			return
		}
		deadline := time.Now().Add(drainTimeout)
		for time.Now().Before(deadline) {
			pending, err := s.spool.PendingCount()
			if err != nil || pending == 0 {
				break
			}
			s.Wake()
			time.Sleep(50 * time.Millisecond)
		}
		close(s.stop)
		s.Wake()
		select {
		case <-s.done:
		case <-time.After(time.Second):
			// The worker is mid-request against an endpoint that is not
			// answering. It is a goroutine on a daemon path holding nothing the
			// caller needs; the rows it was sending are still on disk. Waiting
			// longer would make every process exit hang behind an outage.
		}
	})
}

func (s *sender) run() {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			return
		default:
		}

		delivered := s.drainOnce()

		select {
		case <-s.stop:
			return
		default:
		}

		if delivered {
			s.failures = 0
			continue // keep draining while work is flowing
		}

		pending, err := s.spool.PendingCount()
		if err == nil && pending > 0 {
			// Sends are failing -- back off, but never give up.
			delay := steadyRetry
			if s.failures < len(backoffSeconds) {
				delay = backoffSeconds[s.failures]
			}
			s.failures++
			s.waitFor(delay)
			continue
		}

		if !s.purged {
			s.purged = true
			if removed, err := s.spool.PurgeSent(s.retention); err != nil {
				// Retention never stops delivery.
				s.logf(LevelDebug, "spool retention pass failed: %v", err)
			} else if removed > 0 {
				s.logf(LevelInfo,
					"removed %d delivered event(s) past the spool's retention window",
					removed)
			}
		}
		s.waitForever()
	}
}

// waitFor sleeps until the delay elapses, a wake arrives, or we are stopping.
func (s *sender) waitFor(delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-s.stop:
	case <-s.wake:
	case <-timer.C:
	}
}

// waitForever idles until new work arrives or we are stopping.
func (s *sender) waitForever() {
	select {
	case <-s.stop:
	case <-s.wake:
	}
}

// drainOnce attempts every pending row once. Returns true if anything sent.
//
// Reads through a moving window: Pending is `LIMIT n ORDER BY created_at`, so a
// hundred rows at the head that the platform refuses with a status that is not
// permanent -- any 5xx -- are re-selected on every pass and row 101 is never
// attempted at all.
func (s *sender) drainOnce() bool {
	delivered := false

	batch, err := s.spool.Pending(batchRows, s.window)
	if err != nil {
		s.logf(LevelWarning,
			"could not read the spool (%v). Nothing is lost -- the rows are on "+
				"disk and the next pass reads them again.", err)
		return false
	}
	if len(batch) == 0 && s.window > 0 {
		s.window = 0
		batch, err = s.spool.Pending(batchRows, 0)
		if err != nil {
			return false
		}
	}

	for _, row := range batch {
		select {
		case <-s.stop:
			return delivered
		default:
		}

		err := s.send(row.Payload)
		if err == nil {
			_ = s.spool.MarkSent(row.ID)
			delivered = true
			continue
		}

		// Recorded, never swallowed (Non-Negotiable Rule 2): the failure lands
		// on the row and the retry loop continues.
		_ = s.spool.MarkFailed(row.ID, err.Error())

		if refused, ok := asRefused(err); ok {
			// The platform answered. Taken out of the queue only when no retry
			// of these bytes could ever succeed AND it has said so more than
			// once.
			if refused.Permanent() && row.Attempts+1 >= PermanentRefusalAttempts {
				_ = s.spool.MarkUndeliverable(row.ID, refused.Error())
				s.logf(LevelWarning,
					"the platform refused a spooled event and will refuse it "+
						"again (%s). It is kept on disk and counted as "+
						"undelivered; it is no longer retried.", refused.Error())
				continue
			}
		}
		s.logf(LevelDebug, "event delivery failed, will retry: %v", err)
	}

	if delivered {
		s.window = 0
	} else if len(batch) == batchRows {
		s.window += batchRows
	}
	return delivered
}
