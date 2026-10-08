package allem

// Local write-ahead spool.
//
// Every event is written here BEFORE we attempt to send it. If the process
// crashes, the network fails, or Allem is down, the record survives and is
// retried. This is what makes fail-open safe: the agent proceeds, and the
// evidence is not lost.
//
// SQLite, with the same schema and the same semantics as
// `sdk/allem-python/allem/spool.py`, through `modernc.org/sqlite` -- a pure-Go
// translation of SQLite with no cgo, so this package cross-compiles and needs
// no C toolchain. It is the SDK's one dependency and it is a large one; the
// report says so rather than leaving a Go reader to discover it.
//
// Durability rules (completeness spec, Task 2):
//
//   - A row is only ever deleted after it was successfully sent AND the
//     retention window has passed. An unsent row is un-deletable evidence.
//   - A row the platform permanently refuses, repeatedly, is SET ASIDE, never
//     deleted: `undeliverable_at` takes it out of the delivery queue so the
//     queue can reach zero, and `UnsentCount` still counts it as owed. See
//     MarkUndeliverable, and RequeueUndeliverable for the way back. The
//     repetition matters -- a single refusal is not evidence of a permanent
//     one, and a one-second 401 during a key rotation would otherwise set aside
//     a whole backlog before the platform recovered.
//   - The spool file lives on the customer's machine and may contain sensitive
//     action parameters. v1 ships unencrypted with restrictive permissions
//     (0700 directory / 0600 file -- Gate C, confirmed July 27); encryption at
//     rest is documented in the README and revisited for regulated customers.

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // the pure-Go SQLite driver; registered as "sqlite"
)

// DefaultMaxBytes is the size above which new non-critical writes are refused
// and the spool logs loudly -- something is badly wrong (weeks of outage or
// runaway volume). Pending rows are NEVER deleted to make room: an unsent row
// is evidence.
const DefaultMaxBytes int64 = 500 * 1024 * 1024

// DefaultRetention is how long a DELIVERED row is kept before the retention
// pass removes it. Seven days, matching the Python spool's `purge_sent`.
const DefaultRetention = 7 * 24 * time.Hour

// ErrSpoolClosed is returned by every Spool method after Close.
//
// **Not a panic.** This SDK runs inside the customer's process, and a governance
// tool that takes down a host program because a monitoring goroutine asked for a
// queue depth one moment after shutdown is a governance tool that gets removed.
// Found by `TestReadingAClosedSpoolIsAnErrorNotAPanic`, which was written for a
// test-ordering problem and turned up this instead: every read dereferenced the
// handle with no nil check, so `PendingCount()` after `Close()` was a
// segmentation fault in the host process.
var ErrSpoolClosed = errors.New("allem: the spool is closed")

// SpoolRow is one pending event as the sender sees it.
type SpoolRow struct {
	ID       int64
	Payload  []byte
	Attempts int
}

// Spool is the durable write-ahead log.
type Spool struct {
	path     string
	maxBytes int64
	logf     Logf

	mu sync.Mutex
	db *sql.DB

	overLimitWarned bool
}

// DefaultSpoolPath is where the spool lives when the caller names no path.
//
// Resolved at call time (not at package init) so an ALLEM_SPOOL_DIR set by the
// host application before constructing the client is honoured -- the same rule
// the Python spool follows, and the same environment variable, so one setting
// moves both packages' state together.
func DefaultSpoolPath() string {
	base := os.Getenv("ALLEM_SPOOL_DIR")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			// No home directory is a real state -- a scratch container, a
			// daemon with no passwd entry. The working directory is a worse
			// place for a spool but it is a place, and the alternative is
			// refusing to record anything at all.
			home = "."
		}
		base = filepath.Join(home, ".allem")
	}
	return filepath.Join(base, "spool.db")
}

// OpenSpool opens (and creates) the spool at path.
//
// An empty path means DefaultSpoolPath.
func OpenSpool(path string, maxBytes int64, logf Logf) (*Spool, error) {
	if path == "" {
		path = DefaultSpoolPath()
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if logf == nil {
		logf = discardLogf
	}

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("allem: could not create the spool directory %s: %w", parent, err)
	}
	// Gate C: restrictive permissions. MkdirAll applies the umask, so the mode
	// is set explicitly afterwards -- a directory created 0755 under a
	// permissive umask holds the same action parameters.
	if err := os.Chmod(parent, 0o700); err != nil {
		return nil, fmt.Errorf("allem: could not restrict permissions on %s: %w", parent, err)
	}

	// `_pragma` is how modernc.org/sqlite takes PRAGMAs on the DSN, applied to
	// every connection in the pool. Setting them with Exec would apply them to
	// whichever pooled connection happened to serve that call, which for
	// `synchronous` -- the durability guarantee -- is the difference between
	// this spool being a write-ahead log and it being a cache.
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" + // one writer and many readers, no blocking
		"&_pragma=synchronous(FULL)" + // the OS must actually flush before we call it written
		"&_pragma=busy_timeout(10000)" // the Python spool's `timeout=10.0`

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("allem: could not open the spool at %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("allem: could not open the spool at %s: %w", path, err)
	}

	s := &Spool{path: path, maxBytes: maxBytes, logf: logf, db: db}
	if err := s.initDB(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("allem: could not restrict permissions on %s: %w", path, err)
	}
	return s, nil
}

// Path is where this spool lives. `allem status`-shaped tooling prints it.
func (s *Spool) Path() string { return s.path }

// Close releases the database handle. It does not delete anything: whatever is
// unsent stays on disk and is replayed by the next process.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// handle returns the database, or ErrSpoolClosed. The caller must already hold
// s.mu when it needs the handle to stay valid across the call.
func (s *Spool) handle() (*sql.DB, error) {
	if s.db == nil {
		return nil, ErrSpoolClosed
	}
	return s.db, nil
}

func (s *Spool) initDB() error {
	// Byte-for-byte the Python spool's schema. A Go agent and a Python agent
	// on one machine with one ALLEM_SPOOL_DIR would otherwise each find a file
	// the other wrote and disagree about its shape.
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS spooled_events (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id       TEXT NOT NULL,
			client_seq   INTEGER NOT NULL,
			payload      TEXT NOT NULL,
			created_at   REAL NOT NULL,
			sent_at      REAL,
			attempts     INTEGER NOT NULL DEFAULT 0,
			last_error   TEXT,
			UNIQUE(run_id, client_seq)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_unsent
			ON spooled_events (sent_at, created_at)
			WHERE sent_at IS NULL`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("allem: could not initialise the spool: %w", err)
		}
	}
	return s.addMissingColumns()
}

// addMissingColumns applies columns added after v1 to spools that already
// exist.
//
// A customer's spool is months old and holds undelivered evidence; it is
// migrated in place, never recreated. `ALTER TABLE ... ADD COLUMN` on SQLite is
// a metadata-only change and cannot touch a row.
func (s *Spool) addMissingColumns() error {
	rows, err := s.db.Query(`PRAGMA table_info(spooled_events)`)
	if err != nil {
		return fmt.Errorf("allem: could not read the spool's schema: %w", err)
	}
	existing := map[string]bool{}
	for rows.Next() {
		var (
			cid        int
			name, typ  string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultVal, &pk); err != nil {
			_ = rows.Close()
			return fmt.Errorf("allem: could not read the spool's schema: %w", err)
		}
		existing[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("allem: could not read the spool's schema: %w", err)
	}
	_ = rows.Close()

	for _, column := range []struct{ name, ddl string }{
		{"undeliverable_at", "REAL"},
		{"undeliverable_reason", "TEXT"},
	} {
		if existing[column.name] {
			continue
		}
		if _, err := s.db.Exec(
			`ALTER TABLE spooled_events ADD COLUMN ` + column.name + ` ` + column.ddl,
		); err != nil {
			return fmt.Errorf("allem: could not migrate the spool: %w", err)
		}
	}
	return nil
}

// now is the spool's clock, as a Unix float -- the representation Python's
// `time.time()` writes, so the two packages' rows are comparable.
func nowFloat() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// Write durably records an event before any send attempt.
//
// MUST complete before the agent's action proceeds. This is the only blocking
// call in the SDK, and it is a local disk write.
//
// Over the size limit: non-critical events are refused; action evidence is
// still written, and we log loudly either way -- a spool this size means
// something is badly wrong. Pending rows are never deleted to make room.
//
// Returns the row id. A duplicate (run_id, client_seq) returns the EXISTING
// row's id rather than zero, so a caller that goes on to amend or mark the row
// operates on the row that is actually there.
func (s *Spool) Write(runID string, clientSeq int64, payload []byte, critical bool) (int64, error) {
	if size, err := s.sizeBytes(); err == nil && size > s.maxBytes {
		s.mu.Lock()
		warn := !s.overLimitWarned
		s.overLimitWarned = true
		s.mu.Unlock()
		if warn {
			s.logf(LevelCritical,
				"Allem spool at %s exceeds %d bytes. Events are NOT being "+
					"delivered -- investigate connectivity to Allem now. "+
					"Pending evidence is never deleted.",
				s.path, s.maxBytes)
		}
		if !critical {
			return 0, nil
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return 0, err
	}
	result, err := db.Exec(
		`INSERT OR IGNORE INTO spooled_events (run_id, client_seq, payload, created_at)
		 VALUES (?, ?, ?, ?)`,
		runID, clientSeq, string(payload), nowFloat(),
	)
	if err != nil {
		return 0, fmt.Errorf("allem: could not write to the spool: %w", err)
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		// The row was already there -- an idempotent replay of a
		// (run_id, client_seq) this process already reserved. SQLite's
		// last_insert_rowid() is unchanged by an ignored INSERT, so it would
		// name whatever row was inserted last, which is a different row. Look
		// the real one up.
		var id int64
		if err := db.QueryRow(
			`SELECT id FROM spooled_events WHERE run_id = ? AND client_seq = ?`,
			runID, clientSeq,
		).Scan(&id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, nil
			}
			return 0, fmt.Errorf("allem: could not read back the spooled row: %w", err)
		}
		return id, nil
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("allem: could not read the spooled row id: %w", err)
	}
	return id, nil
}

// Amend widens a still-pending row's payload.
//
// Exists for one case: a local hard-gate denial. The row is written BEFORE the
// network is touched -- that ordering is the durability guarantee and is not
// negotiable -- so at write time we cannot yet know that the action will be
// denied locally. This is how that fact reaches the record without weakening
// the write-first rule.
//
// Only ever adds to the evidence, and only while the row is unsent. It never
// touches `sent_at`: this is not a delivery-state change, and an amended row is
// still un-deletable until it has been delivered.
func (s *Spool) Amend(spoolID int64, payload []byte) error {
	if spoolID == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`UPDATE spooled_events SET payload = ? WHERE id = ? AND sent_at IS NULL`,
		string(payload), spoolID,
	)
	return err
}

// MarkSent records a successful delivery.
func (s *Spool) MarkSent(spoolID int64) error {
	if spoolID == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE spooled_events SET sent_at = ? WHERE id = ?`, nowFloat(), spoolID)
	return err
}

// MarkFailed records one failed attempt and its reason.
func (s *Spool) MarkFailed(spoolID int64, reason string) error {
	if spoolID == 0 {
		return nil
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`UPDATE spooled_events SET attempts = attempts + 1, last_error = ? WHERE id = ?`,
		reason, spoolID,
	)
	return err
}

// Pending is the delivery queue: unsent, not set aside, oldest first.
//
// `Attempts` is returned because nothing read it in the first version of the
// Python spool -- the column was incremented on every failure and consulted by
// no one, so a row could be taken out of the queue on its first refusal, and a
// one-second 401 during a key rotation could set an entire backlog aside before
// the platform recovered.
//
// `offset` exists because a full batch that delivers nothing is a wall: the
// window is `ORDER BY created_at ASC LIMIT n`, so 100 rows at the head that the
// platform refuses with a status that is NOT permanent -- any 5xx -- are
// re-selected on every pass and row 101 is never attempted at all. The caller
// pages past them.
func (s *Spool) Pending(limit, offset int) ([]SpoolRow, error) {
	if limit <= 0 {
		limit = batchRows
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(
		`SELECT id, payload, attempts FROM spooled_events
		 WHERE sent_at IS NULL AND undeliverable_at IS NULL
		 ORDER BY created_at ASC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("allem: could not read the spool: %w", err)
	}
	defer rows.Close()

	var out []SpoolRow
	for rows.Next() {
		var (
			id       int64
			payload  string
			attempts int
		)
		if err := rows.Scan(&id, &payload, &attempts); err != nil {
			return nil, fmt.Errorf("allem: could not read a spooled row: %w", err)
		}
		out = append(out, SpoolRow{ID: id, Payload: []byte(payload), Attempts: attempts})
	}
	return out, rows.Err()
}

func (s *Spool) countWhere(where string) (int, error) {
	var n int
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return 0, err
	}
	err = db.QueryRow(`SELECT COUNT(*) FROM spooled_events WHERE ` + where).Scan(&n)
	return n, err
}

// PendingCount is how many events are queued for delivery.
//
// **Not the same as how many are owed to the customer.** A row the platform
// permanently refuses is set aside so that this count can reach zero -- left in
// the queue it is retried until the end of time, and a hundred of them at the
// head fill a batch and hide everything past row 100. It is still on disk, still
// undeleted, and counted by UndeliverableCount. UnsentCount is the one that
// answers "how much has not reached Allem".
//
// It is a local SQLite count, no network. It says nothing about whether the
// platform is reachable -- that question has exactly one answer and it lives on
// Reachability.
func (s *Spool) PendingCount() (int, error) {
	return s.countWhere(`sent_at IS NULL AND undeliverable_at IS NULL`)
}

// UnsentCount is everything that has not reached Allem, set aside or not.
func (s *Spool) UnsentCount() (int, error) {
	return s.countWhere(`sent_at IS NULL`)
}

// UndeliverableCount is how many rows are set aside.
func (s *Spool) UndeliverableCount() (int, error) {
	return s.countWhere(`sent_at IS NULL AND undeliverable_at IS NOT NULL`)
}

// MarkUndeliverable takes a row out of the delivery queue, keeping the row.
//
// For one case: the platform ANSWERED and refused this exact payload in a way
// no retry can change (see PlatformRefused.Permanent), and said so
// PermanentRefusalAttempts times -- one refusal is a moment, several are a
// property of the bytes.
//
// It is NOT a delete and it is not a quiet one. The row keeps its payload,
// `sent_at` stays NULL, UnsentCount still counts it, UndeliverableReasons
// prints it with the platform's own reason, and RequeueUndeliverable puts every
// one of them back.
func (s *Spool) MarkUndeliverable(spoolID int64, reason string) error {
	if len(reason) > 500 {
		reason = reason[:500]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`UPDATE spooled_events SET undeliverable_at = ?, undeliverable_reason = ?
		 WHERE id = ? AND sent_at IS NULL`,
		nowFloat(), reason, spoolID,
	)
	return err
}

// RequeueUndeliverable puts every set-aside row back in the delivery queue and
// returns how many. The way back from MarkUndeliverable, so setting aside is
// never a one-way door.
func (s *Spool) RequeueUndeliverable() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return 0, err
	}
	result, err := db.Exec(
		`UPDATE spooled_events SET undeliverable_at = NULL, undeliverable_reason = NULL
		 WHERE sent_at IS NULL AND undeliverable_at IS NOT NULL`,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// UndeliverableReason is one reason and how many rows carry it.
type UndeliverableReason struct {
	Reason string
	Count  int
}

// UndeliverableReasons is (reason, count), commonest first.
func (s *Spool) UndeliverableReasons(limit int) ([]UndeliverableReason, error) {
	if limit <= 0 {
		limit = 5
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(
		`SELECT undeliverable_reason, COUNT(*) FROM spooled_events
		 WHERE sent_at IS NULL AND undeliverable_at IS NOT NULL
		 GROUP BY undeliverable_reason ORDER BY 2 DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UndeliverableReason
	for rows.Next() {
		var (
			reason sql.NullString
			count  int
		)
		if err := rows.Scan(&reason, &count); err != nil {
			return nil, err
		}
		text := reason.String
		if !reason.Valid || text == "" {
			text = "(no reason recorded)"
		}
		out = append(out, UndeliverableReason{Reason: text, Count: count})
	}
	return out, rows.Err()
}

func (s *Spool) timeQuery(query string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return time.Time{}, err
	}
	var at sql.NullFloat64
	if err := db.QueryRow(query).Scan(&at); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	if !at.Valid {
		return time.Time{}, nil
	}
	sec, frac := int64(at.Float64), at.Float64-float64(int64(at.Float64))
	return time.Unix(sec, int64(frac*1e9)), nil
}

// LastSentAt is when an event was last delivered. The zero Time means one never
// has been -- which is a different fact from "none recently", and the caller
// must not print it as a date.
func (s *Spool) LastSentAt() (time.Time, error) {
	return s.timeQuery(`SELECT MAX(sent_at) FROM spooled_events WHERE sent_at IS NOT NULL`)
}

// OldestUnsentAt is when the oldest thing still owed to the customer was
// recorded -- set-aside rows included.
func (s *Spool) OldestUnsentAt() (time.Time, error) {
	return s.timeQuery(`SELECT MIN(created_at) FROM spooled_events WHERE sent_at IS NULL`)
}

// OldestPendingAt is when the oldest row still IN THE QUEUE was recorded.
//
// Distinct from OldestUnsentAt, and the distinction is a sentence on a
// customer's screen: with ten permanently-refused rows from five weeks ago set
// aside, "waiting to be delivered: 1, oldest recorded 39 days ago" describes a
// row that by this package's own definition is not waiting for anything.
func (s *Spool) OldestPendingAt() (time.Time, error) {
	return s.timeQuery(
		`SELECT MIN(created_at) FROM spooled_events
		 WHERE sent_at IS NULL AND undeliverable_at IS NULL`)
}

// PurgeSent deletes successfully-sent rows older than the retention window.
//
// The `sent_at IS NOT NULL` predicate is the whole durability contract -- never
// add a purge path without it.
func (s *Spool) PurgeSent(olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		olderThan = DefaultRetention
	}
	cutoff := nowFloat() - olderThan.Seconds()
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return 0, err
	}
	result, err := db.Exec(
		`DELETE FROM spooled_events WHERE sent_at IS NOT NULL AND sent_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// sizeBytes is how much of the spool is CONTENT, not how large the file is.
//
// SQLite does not return freed pages to the filesystem -- no `auto_vacuum`, no
// `VACUUM` anywhere in this package -- so after the retention pass removes a
// hundred thousand delivered rows the file is exactly as large as it was.
// Measuring the file size therefore kept the "events are NOT being delivered"
// warning firing about rows that had all been delivered and then deleted.
//
// `(page_count - freelist_count) * page_size` is what the data actually
// occupies. It costs three pragmas, all O(1).
func (s *Spool) sizeBytes() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.handle()
	if err != nil {
		return 0, err
	}
	var pages, free, pageSize int64
	for _, q := range []struct {
		sql  string
		into *int64
	}{
		{`PRAGMA page_count`, &pages},
		{`PRAGMA freelist_count`, &free},
		{`PRAGMA page_size`, &pageSize},
	} {
		if err := db.QueryRow(q.sql).Scan(q.into); err != nil {
			// Fall back to the file, never to zero: a zero here silently turns
			// the size limit off.
			info, statErr := os.Stat(s.path)
			if statErr != nil {
				return 0, err
			}
			return info.Size(), nil
		}
	}
	if pages < free {
		return 0, nil
	}
	return (pages - free) * pageSize, nil
}

// marshalPayload is the one place a payload becomes spool bytes, and the same
// bytes go on the wire.
//
// **CanonicalJSON, not `encoding/json`, and the difference is a signature that
// does not verify.**
//
// The server recomputes the content digest from the body *exactly as received*:
// it parses the JSON and canonicalizes the result. So the requirement is
// `canonical(parse(wire)) == canonical(what the client digested)`. With
// `encoding/json` on the wire that is false for a whole-valued float --
// `json.Marshal(float64(4200))` emits `4200`, the server's JSON parser reads an
// INTEGER, and canonicalizing an integer gives `4200` where the client digested
// the float and got `4200.0`. Every signed event carrying a round monetary
// value, a whole rate or a count-as-float would have arrived with
// `signature_verified: false`, on the Go SDK only, intermittently, depending on
// whether a customer's number happened to have a fractional part.
//
// Canonicalizing here removes the class rather than the instance: the bytes the
// digest covers, the bytes on disk and the bytes on the wire are one string.
// Found by building the cross-SDK parity harness, before it was ever run.
func marshalPayload(payload map[string]any) ([]byte, error) {
	body, err := CanonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("allem: could not encode the event: %w", err)
	}
	return body, nil
}
