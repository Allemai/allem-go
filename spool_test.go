package allem

// The write-ahead spool: what may be deleted, what may not, and what is set
// aside.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func newTestSpool(t *testing.T) *Spool {
	t.Helper()
	dir := isolate(t)
	spool, err := OpenSpool(filepath.Join(dir, "spool.db"), 0, nil)
	if err != nil {
		t.Fatalf("OpenSpool: %v", err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	return spool
}

func write(t *testing.T, s *Spool, runID string, seq int64) int64 {
	t.Helper()
	id, err := s.Write(runID, seq, []byte(fmt.Sprintf(`{"run":%q,"seq":%d}`, runID, seq)), true)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return id
}

func TestAnUnsentRowIsUndeletableEvidence(t *testing.T) {
	// The durability contract in one test: the retention pass exists and it
	// cannot reach anything that has not been delivered, however old.
	spool := newTestSpool(t)
	id := write(t, spool, "run-1", 1)

	// Backdate it far past any retention window.
	spool.mu.Lock()
	_, err := spool.db.Exec(`UPDATE spooled_events SET created_at = ? WHERE id = ?`,
		nowFloat()-10*365*24*3600, id)
	spool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	removed, err := spool.PurgeSent(time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("the retention pass deleted %d UNSENT row(s). `sent_at IS NOT "+
			"NULL` is the whole durability contract.", removed)
	}
	if n, _ := spool.UnsentCount(); n != 1 {
		t.Fatalf("unsent count = %d, want 1", n)
	}
}

func TestADeliveredRowIsRemovedOnlyAfterTheRetentionWindow(t *testing.T) {
	spool := newTestSpool(t)
	id := write(t, spool, "run-1", 1)
	if err := spool.MarkSent(id); err != nil {
		t.Fatal(err)
	}

	if removed, _ := spool.PurgeSent(time.Hour); removed != 0 {
		t.Fatalf("a row delivered a moment ago was purged under a one-hour window")
	}

	spool.mu.Lock()
	_, err := spool.db.Exec(`UPDATE spooled_events SET sent_at = ? WHERE id = ?`,
		nowFloat()-8*24*3600, id)
	spool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if removed, _ := spool.PurgeSent(DefaultRetention); removed != 1 {
		t.Fatalf("a row delivered eight days ago survived a seven-day window")
	}
}

func TestSetAsideIsNotDeleteAndHasAWayBack(t *testing.T) {
	// A row the platform permanently refuses is taken out of the delivery queue
	// so the queue can reach zero. It is still on disk, `sent_at` is still NULL,
	// UnsentCount still counts it, and RequeueUndeliverable puts it back.
	spool := newTestSpool(t)
	id := write(t, spool, "run-1", 1)
	write(t, spool, "run-1", 2)

	if err := spool.MarkUndeliverable(id, "POST /api/v1/events returned 422"); err != nil {
		t.Fatal(err)
	}

	pending, _ := spool.PendingCount()
	unsent, _ := spool.UnsentCount()
	aside, _ := spool.UndeliverableCount()
	if pending != 1 || unsent != 2 || aside != 1 {
		t.Fatalf("pending=%d unsent=%d set-aside=%d; want 1/2/1. The three counts "+
			"answer three different questions and collapsing any two is how a "+
			"customer is told nothing is owed.", pending, unsent, aside)
	}

	reasons, err := spool.UndeliverableReasons(5)
	if err != nil || len(reasons) != 1 || reasons[0].Count != 1 {
		t.Fatalf("the platform's own reason is not reportable: %v (%v)", reasons, err)
	}

	back, err := spool.RequeueUndeliverable()
	if err != nil || back != 1 {
		t.Fatalf("requeued %d (%v), want 1 -- setting aside must never be a one-way door", back, err)
	}
	if pending, _ := spool.PendingCount(); pending != 2 {
		t.Fatalf("pending after requeue = %d, want 2", pending)
	}
}

func TestSetAsideNeverTouchesADeliveredRow(t *testing.T) {
	spool := newTestSpool(t)
	id := write(t, spool, "run-1", 1)
	_ = spool.MarkSent(id)
	_ = spool.MarkUndeliverable(id, "should not apply")
	if aside, _ := spool.UndeliverableCount(); aside != 0 {
		t.Fatal("a delivered row was set aside, which would count it as owed for ever")
	}
}

func TestAmendOnlyWidensAPendingRowAndNeverMarksItDelivered(t *testing.T) {
	spool := newTestSpool(t)
	id := write(t, spool, "run-1", 1)

	if err := spool.Amend(id, []byte(`{"amended":true}`)); err != nil {
		t.Fatal(err)
	}
	rows, _ := spool.Pending(10, 0)
	if len(rows) != 1 || string(rows[0].Payload) != `{"amended":true}` {
		t.Fatalf("amend did not widen the pending row: %v", rows)
	}

	_ = spool.MarkSent(id)
	if err := spool.Amend(id, []byte(`{"too":"late"}`)); err != nil {
		t.Fatal(err)
	}
	spool.mu.Lock()
	var payload string
	err := spool.db.QueryRow(`SELECT payload FROM spooled_events WHERE id = ?`, id).Scan(&payload)
	spool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if payload == `{"too":"late"}` {
		t.Fatal("amend rewrote a DELIVERED row. Allem already holds those bytes; " +
			"changing them locally makes the two records disagree silently.")
	}
}

func TestPendingIsOldestFirstAndPagesPastAWall(t *testing.T) {
	// `Pending` is `LIMIT n ORDER BY created_at`, so a full batch the platform
	// keeps refusing with a non-permanent status is re-selected on every pass and
	// row n+1 is never attempted. The offset is how the caller gets past it.
	spool := newTestSpool(t)
	for i := int64(1); i <= 5; i++ {
		write(t, spool, "run-1", i)
		// Distinct created_at values, so "oldest first" is a real order rather
		// than whatever the rowid happens to be.
		spool.mu.Lock()
		_, _ = spool.db.Exec(`UPDATE spooled_events SET created_at = ? WHERE client_seq = ?`,
			float64(1000+i), i)
		spool.mu.Unlock()
	}

	rows, err := spool.Pending(2, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("Pending(2,0) = %d rows (%v)", len(rows), err)
	}
	if string(rows[0].Payload) != `{"run":"run-1","seq":1}` {
		t.Fatalf("first row is %s, want seq 1 -- the drain is in order", rows[0].Payload)
	}

	past, err := spool.Pending(2, 2)
	if err != nil || len(past) != 2 {
		t.Fatalf("Pending(2,2) = %d rows (%v)", len(past), err)
	}
	if string(past[0].Payload) != `{"run":"run-1","seq":3}` {
		t.Fatalf("offset 2 gave %s, want seq 3", past[0].Payload)
	}
}

func TestAttemptsAreReturnedBecauseSomethingHasToReadThem(t *testing.T) {
	// The column was incremented on every failure and consulted by nobody, so a
	// row could be set aside on its first refusal -- and a one-second 401 during
	// a key rotation could set an entire backlog aside before the platform
	// recovered.
	spool := newTestSpool(t)
	id := write(t, spool, "run-1", 1)
	for i := 0; i < 2; i++ {
		if err := spool.MarkFailed(id, "401"); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := spool.Pending(10, 0)
	if len(rows) != 1 || rows[0].Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", rows[0].Attempts)
	}
}

func TestADuplicateWriteReturnsTheExistingRow(t *testing.T) {
	// SQLite's last_insert_rowid() is unchanged by an ignored INSERT, so it names
	// whatever row was inserted last -- a DIFFERENT row. A caller that went on to
	// mark that id sent would mark somebody else's event delivered.
	spool := newTestSpool(t)
	first := write(t, spool, "run-1", 1)
	write(t, spool, "run-1", 2)
	again, err := spool.Write("run-1", 1, []byte(`{"replay":true}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatalf("a duplicate (run_id, client_seq) returned id %d, want the "+
			"existing row %d", again, first)
	}
	if n, _ := spool.PendingCount(); n != 2 {
		t.Fatalf("a duplicate created a row: pending = %d, want 2", n)
	}
}

func TestPermissionsAreOwnerOnly(t *testing.T) {
	// Gate C, confirmed 27 July. The spool holds action parameters and lives on
	// the customer's machine.
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := isolate(t)
	path := filepath.Join(dir, "nested", "spool.db")
	spool, err := OpenSpool(path, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fileInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("spool file is mode %o, want 600", mode)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Errorf("spool directory is mode %o, want 700", mode)
	}
}

func TestTheSizeLimitMeasuresContentNotFileSize(t *testing.T) {
	// SQLite does not return freed pages to the filesystem, so after the
	// retention pass removes a hundred thousand delivered rows the file is
	// exactly as large as it was. Measuring the file kept the "events are NOT
	// being delivered" warning firing about rows that had all been delivered.
	dir := isolate(t)
	spool, err := OpenSpool(filepath.Join(dir, "spool.db"), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = 'x'
	}
	for i := int64(1); i <= 200; i++ {
		id, err := spool.Write("run-1", i, payload, true)
		if err != nil {
			t.Fatal(err)
		}
		_ = spool.MarkSent(id)
	}
	full, err := spool.sizeBytes()
	if err != nil {
		t.Fatal(err)
	}

	spool.mu.Lock()
	_, _ = spool.db.Exec(`UPDATE spooled_events SET sent_at = ?`, nowFloat()-30*24*3600)
	spool.mu.Unlock()
	if removed, _ := spool.PurgeSent(DefaultRetention); removed != 200 {
		t.Fatalf("purged %d, want 200", removed)
	}

	after, err := spool.sizeBytes()
	if err != nil {
		t.Fatal(err)
	}
	if after >= full {
		t.Fatalf("content size did not fall after deleting every row (%d -> %d). "+
			"That is what kept the over-limit warning firing about rows that had "+
			"all been delivered.", full, after)
	}

	fileInfo, err := os.Stat(spool.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("content %d bytes, file %d bytes -- the gap is the freed pages SQLite "+
		"keeps, and is a disk-usage question rather than a delivery one",
		after, fileInfo.Size())
}

func TestOverTheLimitRefusesNonCriticalAndStillRecordsEvidence(t *testing.T) {
	dir := isolate(t)
	logs := &capturedLog{}
	// One byte, so everything is over the limit.
	spool, err := OpenSpool(filepath.Join(dir, "spool.db"), 1, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()

	id, err := spool.Write("run-1", 1, []byte(`{"critical":true}`), true)
	if err != nil || id == 0 {
		t.Fatalf("action evidence was refused over the size limit (%v). Pending "+
			"rows are never deleted to make room and evidence is never dropped "+
			"to stay under it.", err)
	}
	skipped, err := spool.Write("run-1", 2, []byte(`{"critical":false}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Error("a non-critical write was accepted over the size limit")
	}
	if !logs.contains("Events are NOT being delivered") {
		t.Errorf("crossing the size limit was not announced: %v", logs.all())
	}
}

func TestTheThreeTimestampsAnswerThreeQuestions(t *testing.T) {
	spool := newTestSpool(t)
	if at, _ := spool.LastSentAt(); !at.IsZero() {
		t.Error("LastSentAt returned a date on a spool that has never delivered " +
			"anything. Never and 'not recently' are different facts.")
	}

	old := write(t, spool, "run-1", 1)
	recent := write(t, spool, "run-1", 2)
	spool.mu.Lock()
	_, _ = spool.db.Exec(`UPDATE spooled_events SET created_at = ? WHERE id = ?`, float64(1000), old)
	_, _ = spool.db.Exec(`UPDATE spooled_events SET created_at = ? WHERE id = ?`, float64(2000), recent)
	spool.mu.Unlock()
	_ = spool.MarkUndeliverable(old, "422")

	unsent, _ := spool.OldestUnsentAt()
	pending, _ := spool.OldestPendingAt()
	if unsent.Unix() != 1000 {
		t.Errorf("OldestUnsentAt = %v, want the set-aside row -- it is still owed", unsent)
	}
	if pending.Unix() != 2000 {
		t.Errorf("OldestPendingAt = %v, want the row that is actually waiting. "+
			"A set-aside row is not waiting for anything, and printing it as "+
			"'oldest waiting' describes a state this package says does not exist.",
			pending)
	}
}

func TestTheSpoolIsSafeUnderConcurrentWriters(t *testing.T) {
	// Agents are frequently concurrent. A spool that corrupted or lost a row
	// under two goroutines would lose evidence in exactly the deployment this
	// SDK is for.
	spool := newTestSpool(t)
	const writers, each = 8, 25

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if _, err := spool.Write(fmt.Sprintf("run-%d", w), int64(i+1),
					[]byte(`{"x":1}`), true); err != nil {
					t.Errorf("concurrent write failed: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if n, _ := spool.PendingCount(); n != writers*each {
		t.Fatalf("pending = %d, want %d -- a concurrent write was lost", n, writers*each)
	}
}

func TestAnOlderSpoolIsMigratedInPlace(t *testing.T) {
	// A customer's spool is months old and holds undelivered evidence. It is
	// migrated, never recreated.
	dir := isolate(t)
	path := filepath.Join(dir, "spool.db")

	spool, err := OpenSpool(path, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Reduce it to the v1 schema, with a row in it.
	write(t, spool, "run-1", 1)
	spool.mu.Lock()
	for _, column := range []string{"undeliverable_at", "undeliverable_reason"} {
		if _, err := spool.db.Exec(`ALTER TABLE spooled_events DROP COLUMN ` + column); err != nil {
			spool.mu.Unlock()
			t.Skipf("this SQLite build cannot DROP COLUMN (%v), so the v1 schema "+
				"cannot be reconstructed here", err)
		}
	}
	spool.mu.Unlock()
	_ = spool.Close()

	migrated, err := OpenSpool(path, 0, nil)
	if err != nil {
		t.Fatalf("an older spool could not be opened: %v", err)
	}
	defer migrated.Close()
	if n, _ := migrated.PendingCount(); n != 1 {
		t.Fatalf("the migration lost the row already on disk: pending = %d", n)
	}
}
