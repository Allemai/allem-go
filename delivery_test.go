package allem

// Three outcomes, and the middle one is the one that gets collapsed by accident.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestA401IsAnAnswerAndNotAnOutage(t *testing.T) {
	// The defect this whole file exists to prevent: a connector that marks the
	// platform down because its own key was revoked spools for ever against a
	// platform that is up and is telling it so.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"invalid api key"}`))
	}))
	defer server.Close()

	err := deliverEvent(context.Background(), server.Client(), "k", server.URL, []byte(`{}`), EventsPath)
	refused, ok := asRefused(err)
	if !ok {
		t.Fatalf("a 401 produced %T, want *PlatformRefused", err)
	}
	if _, isSilent := asDidNotAnswer(err); isSilent {
		t.Fatal("a 401 was classed as the platform not answering. It is an answer.")
	}
	if refused.StatusCode != 401 {
		t.Fatalf("status = %d", refused.StatusCode)
	}
}

func TestNoResponseAtAllIsTheOnlyOfflineState(t *testing.T) {
	err := deliverEvent(context.Background(), &http.Client{Timeout: time.Second},
		"k", "http://127.0.0.1:1", []byte(`{}`), EventsPath)
	if _, ok := asDidNotAnswer(err); !ok {
		t.Fatalf("a refused connection produced %T, want *PlatformDidNotAnswer", err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Errorf("the underlying cause is not reachable through the error chain: %v", err)
	}
}

func TestPermanentIsAboutTheBytesNotTheMoment(t *testing.T) {
	// A 4xx is the platform saying *this body is wrong*, and nothing about the
	// bytes changes on a retry. The two exceptions are the 4xx codes that are
	// about the moment: 408 and 429.
	//
	// 401/403 are deliberately permanent. The credential could be replaced
	// tomorrow, but nothing the SENDER does changes it, and a connector retrying
	// a revoked key at 60-second intervals for ever is how a spool grows to a
	// gigabyte in silence.
	for status, want := range map[int]bool{
		400: true, 401: true, 403: true, 404: true, 422: true,
		408: false, 429: false,
		500: false, 502: false, 503: false, 504: false,
		300: false, 301: false,
	} {
		refused := &PlatformRefused{StatusCode: status}
		if got := refused.Permanent(); got != want {
			t.Errorf("HTTP %d: Permanent() = %v, want %v", status, got, want)
		}
	}
}

func TestReachabilityStartsAtNoAttempt(t *testing.T) {
	// The absence of an attempt is not evidence of anything, and a caller that
	// made no attempt in this process must leave the offline marker exactly as it
	// found it. Folding `no_attempt` into either of the others is how a queue
	// depth became a reachability claim.
	var r Reachability
	if got := r.State(); got != NoAttempt {
		t.Fatalf("a fresh Reachability reports %q, want %q", got, NoAttempt)
	}
	if !r.At().IsZero() {
		t.Error("a fresh Reachability has a timestamp, which reads as an attempt " +
			"that was made")
	}

	r.recordAnswered("check returned 200")
	if r.State() != Answered || r.Note() != "check returned 200" || r.At().IsZero() {
		t.Fatalf("after an answer: %q / %q / %v", r.State(), r.Note(), r.At())
	}

	r.recordDidNotAnswer("dial tcp: refused")
	if r.State() != DidNotAnswer {
		t.Fatalf("after a non-answer: %q", r.State())
	}
}

func TestReachabilityIsSafeUnderConcurrentUse(t *testing.T) {
	// The sender writes from its own goroutine while the caller reads from
	// another. Exercised under `-race` in CI.
	var r Reachability
	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			r.recordAnswered("a")
		}
		close(done)
	}()
	for i := 0; i < 500; i++ {
		_ = r.State()
		_ = r.Note()
		_ = r.At()
	}
	<-done
}

func TestARefusalRecordsThePlatformAsReachable(t *testing.T) {
	// A refusal is an ANSWER: it records the platform as reachable and still
	// returns an error, so the row stays pending and the sender retries it.
	isolate(t)
	platform := newFakePlatform(t)
	platform.mu.Lock()
	platform.eventsStatus = http.StatusServiceUnavailable
	platform.mu.Unlock()

	client, err := New("alm_sk_test_key", WithEndpoint(platform.URL()),
		WithLogger(nil), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := client.deliver([]byte(`{"a":1}`)); err == nil {
		t.Fatal("a 503 delivered successfully")
	}
	if got := client.Reachability.State(); got != Answered {
		t.Fatalf("a 503 left reachability at %q. The platform ANSWERED -- it said "+
			"it was overloaded.", got)
	}
}

func TestTheUserAgentIsNotEvidence(t *testing.T) {
	// The one header this SDK sets that the Python SDK does not. No code under
	// `backend/app/` reads a User-Agent and no field on `AgentEvent` holds one,
	// so it is an operational aid in a proxy log and not part of the row an
	// auditor compares. It must also never name a connection tier: the tier is
	// read off the authenticated credential at ingestion, and an agent naming its
	// own tier is the credential rule inverted.
	agent := userAgent()
	if agent == "" {
		t.Fatal("no User-Agent at all")
	}
	for _, forbidden := range []string{"tier", "sdk_tier", "connector", "tier1", "tier 1"} {
		if containsFold(agent, forbidden) {
			t.Errorf("the User-Agent (%q) contains %q. The tier is not this "+
				"package's to declare.", agent, forbidden)
		}
	}
}

func TestEveryRequestCarriesTheKeyAndNothingThatNamesATier(t *testing.T) {
	var seen http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	if err := deliverEvent(context.Background(), server.Client(), "alm_sk_live_abc",
		server.URL, []byte(`{}`), EventsPath); err != nil {
		t.Fatal(err)
	}
	if seen.Get("X-API-Key") != "alm_sk_live_abc" {
		t.Fatalf("X-API-Key = %q", seen.Get("X-API-Key"))
	}
	if seen.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", seen.Get("Content-Type"))
	}
	for header := range seen {
		for _, forbidden := range []string{"tier", "connector"} {
			if containsFold(header, forbidden) {
				t.Errorf("request carries header %q, which names something only "+
					"the credential may establish", header)
			}
		}
	}
}

func TestACancelledContextIsANonAnswerAndNotADenial(t *testing.T) {
	// The caller stopped waiting, so no verdict was obtained. The only honest
	// reading is that we did not get an answer -- and the fail-open rule then
	// applies, or the local gate does.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := post(ctx, server.Client(), "k", server.URL, []byte(`{}`))
	if _, ok := asDidNotAnswer(err); !ok {
		t.Fatalf("a cancelled context produced %T, want *PlatformDidNotAnswer", err)
	}
}
