package allem

// Draining: in order, for ever, and what is taken out of the queue.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// recordingSender captures what the drain attempted, in order, and can be told
// how to fail.
type recordingSender struct {
	mu   sync.Mutex
	seen []string
	err  func(attempt int, payload []byte) error
	n    int
}

func (r *recordingSender) send(payload []byte) error {
	r.mu.Lock()
	r.n++
	attempt := r.n
	fail := r.err
	r.mu.Unlock()

	if fail != nil {
		if err := fail(attempt, payload); err != nil {
			return err
		}
	}
	r.mu.Lock()
	r.seen = append(r.seen, string(payload))
	r.mu.Unlock()
	return nil
}

func (r *recordingSender) delivered() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.seen))
	copy(out, r.seen)
	return out
}

func (r *recordingSender) attempts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func TestTheDrainIsInOrder(t *testing.T) {
	spool := newTestSpool(t)
	for i := int64(1); i <= 10; i++ {
		write(t, spool, "run-1", i)
		spool.mu.Lock()
		_, _ = spool.db.Exec(`UPDATE spooled_events SET created_at = ? WHERE client_seq = ?`,
			float64(1000+i), i)
		spool.mu.Unlock()
	}

	recorder := &recordingSender{}
	worker := newSender(spool, recorder.send, nil, 0, false)
	worker.drainOnce()

	got := recorder.delivered()
	if len(got) != 10 {
		t.Fatalf("delivered %d of 10", len(got))
	}
	for i, payload := range got {
		want := fmt.Sprintf(`{"run":"run-1","seq":%d}`, i+1)
		if payload != want {
			t.Fatalf("row %d was %s, want %s -- the drain is oldest-first", i, payload, want)
		}
	}
	if n, _ := spool.PendingCount(); n != 0 {
		t.Fatalf("pending after a clean drain = %d", n)
	}
}

func TestOneRefusalDoesNotSetARowAside(t *testing.T) {
	// A one-second 401 during a key rotation would otherwise set a whole backlog
	// aside before the platform recovered. Measured on the Python side: with a
	// threshold of one, an endpoint answering 401 for a single second set a
	// 1,049-row backlog aside in 1.36 s.
	spool := newTestSpool(t)
	write(t, spool, "run-1", 1)

	recorder := &recordingSender{err: func(int, []byte) error {
		return &PlatformRefused{StatusCode: 401}
	}}
	worker := newSender(spool, recorder.send, nil, 0, false)

	for pass := 1; pass < PermanentRefusalAttempts; pass++ {
		worker.drainOnce()
		if aside, _ := spool.UndeliverableCount(); aside != 0 {
			t.Fatalf("a row was set aside after %d refusal(s); the threshold is %d",
				pass, PermanentRefusalAttempts)
		}
	}
	worker.drainOnce()
	if aside, _ := spool.UndeliverableCount(); aside != 1 {
		t.Fatalf("a row that was permanently refused %d times is still in the "+
			"queue, so the queue can never be shown to have drained",
			PermanentRefusalAttempts)
	}
	if unsent, _ := spool.UnsentCount(); unsent != 1 {
		t.Fatal("setting aside deleted the row. It is kept on disk and still counted as owed.")
	}
}

func TestANonPermanentRefusalIsRetriedForEver(t *testing.T) {
	spool := newTestSpool(t)
	write(t, spool, "run-1", 1)

	recorder := &recordingSender{err: func(int, []byte) error {
		return &PlatformRefused{StatusCode: 503}
	}}
	worker := newSender(spool, recorder.send, nil, 0, false)
	for i := 0; i < 10; i++ {
		worker.drainOnce()
	}
	if aside, _ := spool.UndeliverableCount(); aside != 0 {
		t.Fatal("a 503 set a row aside. A 503 is the platform saying it is " +
			"overloaded, which is about the moment and not about the bytes.")
	}
	if recorder.attempts() != 10 {
		t.Fatalf("attempted %d times, want 10 -- a spool that gives up is worse "+
			"than no spool", recorder.attempts())
	}
}

func TestAFullBatchOfRefusalsIsNotAWall(t *testing.T) {
	// `Pending` is `LIMIT 100 ORDER BY created_at`, so a hundred rows at the head
	// that the platform refuses with a status that is NOT permanent are
	// re-selected on every pass and row 101 is never attempted at all.
	spool := newTestSpool(t)
	total := int64(batchRows + 5)
	for i := int64(1); i <= total; i++ {
		write(t, spool, "run-1", i)
		spool.mu.Lock()
		_, _ = spool.db.Exec(`UPDATE spooled_events SET created_at = ? WHERE client_seq = ?`,
			float64(1000+i), i)
		spool.mu.Unlock()
	}

	// Every row in the first batch is refused with a 503; everything past it
	// would deliver.
	recorder := &recordingSender{err: func(_ int, payload []byte) error {
		var row struct{ Seq int64 }
		_ = json.Unmarshal(payload, &row)
		if row.Seq <= int64(batchRows) {
			return &PlatformRefused{StatusCode: 503}
		}
		return nil
	}}
	worker := newSender(spool, recorder.send, nil, 0, false)

	worker.drainOnce() // the wall: 100 rows, none delivered
	if len(recorder.delivered()) != 0 {
		t.Fatalf("the fixture is wrong: %d rows delivered on the first pass",
			len(recorder.delivered()))
	}
	worker.drainOnce() // the window moves past it
	if len(recorder.delivered()) != 5 {
		t.Fatalf("delivered %d rows past the wall, want 5. Without the moving "+
			"window row 101 is never attempted at all.", len(recorder.delivered()))
	}
}

func TestTheWindowResetsWhenSomethingDelivers(t *testing.T) {
	spool := newTestSpool(t)
	write(t, spool, "run-1", 1)
	recorder := &recordingSender{}
	worker := newSender(spool, recorder.send, nil, 0, false)
	worker.window = batchRows * 3

	worker.drainOnce() // empty batch at that offset -> falls back to offset 0
	if len(recorder.delivered()) != 1 {
		t.Fatalf("a non-empty spool looked empty at offset %d and nothing "+
			"recovered", batchRows*3)
	}
	if worker.window != 0 {
		t.Fatalf("window = %d after a delivery, want 0", worker.window)
	}
}

func TestStartupReplaysWhatAPreviousProcessLeftBehind(t *testing.T) {
	// Acceptance test 2: rows left over from a process that crashed or exited
	// while Allem was unreachable.
	dir := isolate(t)
	first, err := OpenSpool(dir+"/spool.db", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 3; i++ {
		write(t, first, "previous-run", i)
	}
	_ = first.Close()

	second, err := OpenSpool(dir+"/spool.db", 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	recorder := &recordingSender{}
	worker := newSender(second, recorder.send, nil, 0, true)
	// The worker is stopped BEFORE the spool it reads from is closed. Written
	// the other way round first, which is how `ErrSpoolClosed` was found: every
	// Spool read dereferenced the handle with no nil check, so a drain racing a
	// Close was a segmentation fault in the host process.
	t.Cleanup(func() { _ = second.Close() })
	t.Cleanup(func() { worker.Stop(time.Second) })

	eventually(t, 3*time.Second, "the previous process's rows to be replayed", func() bool {
		return len(recorder.delivered()) == 3
	})
}

func TestTheRetentionPassRunsOnlyWhenTheQueueIsEmpty(t *testing.T) {
	// It had no caller anywhere in the shipped Python SDK, so a delivered row was
	// kept for ever and a long-running agent's spool grew without bound until it
	// crossed the size limit and began logging that events were NOT being
	// delivered -- about rows that all were.
	dir := isolate(t)
	spool, err := OpenSpool(dir+"/spool.db", 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	id := write(t, spool, "run-1", 1)
	_ = spool.MarkSent(id)
	spool.mu.Lock()
	_, _ = spool.db.Exec(`UPDATE spooled_events SET sent_at = ? WHERE id = ?`,
		nowFloat()-30*24*3600, id)
	spool.mu.Unlock()

	recorder := &recordingSender{}
	worker := newSender(spool, recorder.send, nil, 0, true)
	t.Cleanup(func() { _ = spool.Close() })
	t.Cleanup(func() { worker.Stop(time.Second) })

	eventually(t, 3*time.Second, "the retention pass to remove the delivered row", func() bool {
		var n int
		spool.mu.Lock()
		_ = spool.db.QueryRow(`SELECT COUNT(*) FROM spooled_events`).Scan(&n)
		spool.mu.Unlock()
		return n == 0
	})
}

func TestStoppingNeverLosesEvidence(t *testing.T) {
	spool := newTestSpool(t)
	for i := int64(1); i <= 5; i++ {
		write(t, spool, "run-1", i)
	}
	recorder := &recordingSender{err: func(int, []byte) error {
		return &PlatformRefused{StatusCode: 503}
	}}
	worker := newSender(spool, recorder.send, nil, 0, true)
	worker.Stop(100 * time.Millisecond)

	if n, _ := spool.UnsentCount(); n != 5 {
		t.Fatalf("unsent after stopping = %d, want 5 -- stopping never loses evidence", n)
	}
}

func TestBackoffIsBoundedAndThenSteady(t *testing.T) {
	// 1, 2, 4, 8, 16, 32, then every 60s indefinitely. Asserted over the table
	// rather than over the clock: a test that actually waited 32 seconds is a
	// test nobody runs.
	if len(backoffSeconds) != 6 {
		t.Fatalf("the backoff ladder has %d rungs, want 6", len(backoffSeconds))
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second, 16 * time.Second, 32 * time.Second}
	for i, d := range want {
		if backoffSeconds[i] != d {
			t.Errorf("rung %d = %v, want %v", i, backoffSeconds[i], d)
		}
	}
	if steadyRetry != 60*time.Second {
		t.Errorf("steady retry = %v, want 60s", steadyRetry)
	}
}

func TestWakeNeverBlocksTheCaller(t *testing.T) {
	// Wake is called from the agent's own call path. A blocking Wake would put
	// the sender's scheduling on the customer's latency budget.
	spool := newTestSpool(t)
	worker := newSender(spool, func([]byte) error { return nil }, nil, 0, false)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			worker.Wake()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wake blocked")
	}
}

func TestReadingAClosedSpoolIsAnErrorNotAPanic(t *testing.T) {
	// This SDK runs inside the customer's process. A monitoring goroutine that
	// asks for a queue depth one moment after shutdown must get an error, not a
	// segmentation fault in a program that has nothing to do with governance.
	//
	// Found by the ordering mistake in `TestStartupReplaysWhatAPreviousProcessLeftBehind`
	// above: every read dereferenced the handle with no nil check.
	dir := isolate(t)
	spool, err := OpenSpool(dir+"/spool.db", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	write(t, spool, "run-1", 1)
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("a closed spool PANICKED (%v). This package is linked into "+
				"somebody else's program.", recovered)
		}
	}()

	checks := map[string]func() error{
		"PendingCount":         func() error { _, err := spool.PendingCount(); return err },
		"UnsentCount":          func() error { _, err := spool.UnsentCount(); return err },
		"UndeliverableCount":   func() error { _, err := spool.UndeliverableCount(); return err },
		"Pending":              func() error { _, err := spool.Pending(10, 0); return err },
		"Write":                func() error { _, err := spool.Write("r", 9, []byte("{}"), true); return err },
		"Amend":                func() error { return spool.Amend(1, []byte("{}")) },
		"MarkSent":             func() error { return spool.MarkSent(1) },
		"MarkFailed":           func() error { return spool.MarkFailed(1, "x") },
		"MarkUndeliverable":    func() error { return spool.MarkUndeliverable(1, "x") },
		"RequeueUndeliverable": func() error { _, err := spool.RequeueUndeliverable(); return err },
		"UndeliverableReasons": func() error { _, err := spool.UndeliverableReasons(5); return err },
		"LastSentAt":           func() error { _, err := spool.LastSentAt(); return err },
		"OldestUnsentAt":       func() error { _, err := spool.OldestUnsentAt(); return err },
		"OldestPendingAt":      func() error { _, err := spool.OldestPendingAt(); return err },
		"PurgeSent":            func() error { _, err := spool.PurgeSent(time.Hour); return err },
		"sizeBytes":            func() error { _, err := spool.sizeBytes(); return err },
	}
	for name, call := range checks {
		if err := call(); !errors.Is(err, ErrSpoolClosed) {
			t.Errorf("%s on a closed spool returned %v, want ErrSpoolClosed", name, err)
		}
	}
	if err := spool.Close(); err != nil {
		t.Errorf("a second Close returned %v; it must be safe to call twice", err)
	}
}
