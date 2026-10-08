package allem

// Posting one event, and the one question every caller actually asks.
//
// A transliteration of `sdk/allem-python/allem/delivery.py`, including the
// reason it exists: "offline" had two meanings in one connector and the wrong
// one governed everything. One path asked *did the platform answer?* -- a
// reachability test. The other asked *is the queue empty after 0.75 seconds?*
// -- a queue-depth test wearing the same word. Against a remote endpoint the
// second is almost always false, and the connector that believed it stopped
// flushing, which made it truer, which is a loop with no exit
// (`docs/queue-report.md`).
//
// So the question is asked in exactly one place, from the only evidence that
// can answer it: an HTTP attempt that was actually made.
//
// Three outcomes, and the middle one is the one that gets collapsed by accident:
//
//	delivered       the platform answered, and accepted the event
//	refused         the platform ANSWERED, and would not take it (any status
//	                >= 300 -- a 401 from a revoked key, a 422 from a payload it
//	                will never accept, a 503 from an overloaded instance)
//	did not answer  no response at all: DNS, a refused connection, a TLS
//	                failure, a read timeout
//
// Only the third is *offline*. A 401 is an answer, and a connector that marks
// the platform down because its key was revoked would spool forever against a
// platform that is up and would keep telling it so.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The three reachability states. Named rather than booleans because two of the
// three are "not delivered" and collapsing them is the defect this file is for.
const (
	Answered     = "answered"
	DidNotAnswer = "did_not_answer"
	NoAttempt    = "no_attempt"
)

// PlatformDidNotAnswer means no response at all. This -- and only this -- is
// *offline*.
type PlatformDidNotAnswer struct {
	Cause error
}

func (e *PlatformDidNotAnswer) Error() string {
	return fmt.Sprintf("allem: the platform did not answer: %v", e.Cause)
}

func (e *PlatformDidNotAnswer) Unwrap() error { return e.Cause }

// PlatformRefused means the platform answered and would not take the event.
//
// Carries the status so a caller can tell a refusal that retrying might fix
// (503, 429) from one that it never will (401, 422). It is still an answer, so
// it never sets the offline marker.
type PlatformRefused struct {
	StatusCode int
	Detail     string
	Path       string
}

func (e *PlatformRefused) Error() string {
	path := e.Path
	if path == "" {
		path = EventsPath
	}
	msg := fmt.Sprintf("POST %s returned %d", path, e.StatusCode)
	if e.Detail != "" {
		detail := e.Detail
		if len(detail) > 200 {
			detail = detail[:200]
		}
		msg += ": " + detail
	}
	return msg
}

// Permanent reports whether retrying this exact payload can never succeed.
//
// A 4xx is the platform saying *this body is wrong* -- a payload the server
// refuses today it refuses forever, because nothing about the bytes changes on
// a retry. The two exceptions are the 4xx codes that are about the moment
// rather than the body: 408 (the request timed out) and 429 (too many, come
// back later).
//
// A 401/403 is deliberately on the permanent side. The credential could be
// replaced tomorrow, but nothing the SENDER does changes it, and a connector
// retrying a revoked key at 60-second intervals forever is how a spool grows to
// a gigabyte in silence.
//
// **Permanent does not mean deletable.** Nothing in this package ever deletes an
// unsent row. It means: stop spending the queue's time on it, count it
// separately, and say so out loud.
func (e *PlatformRefused) Permanent() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500 &&
		e.StatusCode != http.StatusRequestTimeout &&
		e.StatusCode != http.StatusTooManyRequests
}

// Wire paths. Written down once so the check path and the delivery path cannot
// end up pointing at different versions of the API.
const (
	// EventsPath is the fire-and-forget audit log.
	EventsPath = "/api/v1/events"
	// CheckPath is the pre-flight gate.
	CheckPath = "/api/v1/events/check"
)

// httpDoer is the seam the tests drive. `*http.Client` satisfies it.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// post POSTs and hands back the response, or returns *PlatformDidNotAnswer.
//
// **The line between "answered" and "did not answer" is drawn here and nowhere
// else in this package.** Everything that stops us obtaining a response is a
// non-answer; every response, whatever its status, is an answer. Both call
// sites that talk to Allem -- the pre-flight check and the spool delivery --
// come through this function so the two cannot drift apart again.
func post(ctx context.Context, doer httpDoer, apiKey, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		// A URL this process built and cannot turn into a request is not
		// evidence about the platform, so it is not a non-answer. It is a
		// programming error and it is returned as one.
		return nil, fmt.Errorf("allem: could not build the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The Allem backend authenticates via X-API-Key
	// (backend/app/api/deps.py:get_current_org_id).
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("User-Agent", userAgent())

	resp, err := doer.Do(req)
	if err != nil {
		// Anything that yields no response is a non-answer. Including a
		// cancelled context: the caller stopped waiting, so no verdict was
		// obtained, and the only honest reading is that we did not get an
		// answer.
		return nil, &PlatformDidNotAnswer{Cause: err}
	}
	return resp, nil
}

// deliverEvent POSTs one event. Returns *PlatformDidNotAnswer or *PlatformRefused.
func deliverEvent(ctx context.Context, doer httpDoer, apiKey, endpoint string, body []byte, path string) error {
	if path == "" {
		path = EventsPath
	}
	resp, err := post(ctx, doer, apiKey, strings.TrimRight(endpoint, "/")+path, body)
	if err != nil {
		return err
	}
	defer drainAndClose(resp)

	if resp.StatusCode >= 300 {
		// A body we cannot read does not change the status we got.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return &PlatformRefused{StatusCode: resp.StatusCode, Detail: string(detail), Path: path}
	}
	return nil
}

// drainAndClose returns the connection to the pool.
//
// Go will not reuse a keep-alive connection whose body was not read to EOF, so
// a connector that closed without draining would open a new TCP connection per
// event -- on the latency path of a pre-flight check, forever. Bounded, because
// draining an unbounded error body is a second way to hang.
func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

// attempt is what the last HTTP attempt found, and when.
type attempt struct {
	at       time.Time
	answered bool
	note     string
}

// Reachability records what the last HTTP attempt found and **when**.
//
// This is the ONLY thing the connector is allowed to call "offline". It is not
// a queue depth, not a pending count, not a flush that ran out of time.
//
// Safe for concurrent use: the sender writes from its own goroutine while the
// caller reads from another.
type Reachability struct {
	mu   sync.Mutex
	last *attempt
}

func (r *Reachability) recordAnswered(note string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = &attempt{at: time.Now(), answered: true, note: note}
}

func (r *Reachability) recordDidNotAnswer(note string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = &attempt{at: time.Now(), answered: false, note: note}
}

// State is Answered, DidNotAnswer, or NoAttempt.
//
// NoAttempt is a real answer to a real question and must not be folded into
// either of the others. A process that never touched the network learned
// nothing about the platform, and a caller acting on that ignorance is how a
// queue depth became a reachability claim.
func (r *Reachability) State() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		return NoAttempt
	}
	if r.last.answered {
		return Answered
	}
	return DidNotAnswer
}

// Note is what the last attempt reported, or "" if there has been none.
func (r *Reachability) Note() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		return ""
	}
	return r.last.note
}

// At is when the last attempt was made. The zero Time means no attempt has been
// made in this process, which is not the same as the platform being fine.
func (r *Reachability) At() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		return time.Time{}
	}
	return r.last.at
}

// asRefused unwraps a *PlatformRefused from an error chain, if there is one.
func asRefused(err error) (*PlatformRefused, bool) {
	var refused *PlatformRefused
	ok := errors.As(err, &refused)
	return refused, ok
}

// asDidNotAnswer unwraps a *PlatformDidNotAnswer from an error chain.
func asDidNotAnswer(err error) (*PlatformDidNotAnswer, bool) {
	var silent *PlatformDidNotAnswer
	ok := errors.As(err, &silent)
	return silent, ok
}
