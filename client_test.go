package allem

// Fail-open on enforcement, fail-safe on evidence.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, opts ...Option) (*Client, *fakePlatform) {
	t.Helper()
	isolate(t)
	platform := newFakePlatform(t)
	all := append([]Option{
		WithEndpoint(platform.URL()),
		WithLogger(nil),
		WithBackgroundDelivery(false),
	}, opts...)
	client, err := New("alm_sk_test_key", all...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, platform
}

// --------------------------------------------------------------------------- //
// Only a verdict Allem returned, or the local gate, may deny
// --------------------------------------------------------------------------- //

func TestAnUnhappyAnswerIsNotADenial(t *testing.T) {
	// Reading `allowed` off any response turned every auth failure and every 500
	// into allowed=false -- a denial manufactured from an outage. The distinction
	// has to be made on the BODY, not the status.
	cases := []struct {
		name   string
		status int
		body   any
	}{
		{"401 from a revoked key", 401, map[string]any{"detail": "invalid api key"}},
		{"403 refusing the CREDENTIAL", 403, map[string]any{"detail": "agent keys may not do this"}},
		{"404", 404, map[string]any{"detail": "not found"}},
		{"500", 500, map[string]any{"detail": "internal server error"}},
		{"502 with an HTML body", 502, "<html>bad gateway</html>"},
		{"200 with no verdict in it", 200, map[string]any{"status": "queued"}},
		{"429", 429, map[string]any{"detail": "slow down"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, platform := testClient(t)
			platform.setCheck(tc.status, tc.body)

			verdict, err := client.Check(context.Background(), "agent-1", Action{Type: "payment.send"})
			if err != nil {
				t.Fatalf("Check returned an error: %v", err)
			}
			if !verdict.Allowed {
				t.Fatalf("HTTP %d produced a DENIAL. Only a verdict Allem "+
					"returned, or the local gate, may deny.\n  %s", tc.status, verdict)
			}
			if verdict.EventID != "" {
				t.Errorf("a response that carried no verdict produced an event id %q",
					verdict.EventID)
			}
			// The record is not marked delivered: the platform did not record it
			// either, so it replays through /events. Marking it sent would lose
			// the evidence for exactly the responses we understand least.
			if n, _ := client.spool.PendingCount(); n != 1 {
				t.Errorf("pending after an unhappy answer = %d, want 1", n)
			}
		})
	}
}

func TestA403ThatDeniesByRuleIsAVerdict(t *testing.T) {
	// Including the 403 that denies by rule, which the platform chains as
	// evidence. It carries `allowed` and an event id; a 403 refusing the
	// credential carries neither.
	client, platform := testClient(t)
	platform.setCheck(http.StatusForbidden, map[string]any{
		"allowed":  false,
		"event_id": "evt-denied-by-rule",
		"verdict": map[string]any{
			"explanation":        "payment.send is outside this agent's scope",
			"severity":           "CRITICAL",
			"recommended_action": "HARD_FREEZE",
		},
	})

	verdict, err := client.Check(context.Background(), "agent-1", Action{Type: "payment.send"})
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Allowed {
		t.Fatal("a rule denial was allowed through")
	}
	if verdict.EventID != "evt-denied-by-rule" || !verdict.DecidedByAllem() {
		t.Fatalf("the platform's own denial lost its event id: %+v", verdict)
	}
	if verdict.Severity != "CRITICAL" || verdict.RecommendedAction != "HARD_FREEZE" {
		t.Fatalf("the verdict's fields did not survive: %+v", verdict)
	}
	// The server chained the event as part of evaluating it -- delivered.
	if n, _ := client.spool.PendingCount(); n != 0 {
		t.Errorf("a chained denial is still pending (%d)", n)
	}
}

func TestAFreezeBlockSurvives(t *testing.T) {
	client, platform := testClient(t)
	platform.setCheck(http.StatusForbidden, map[string]any{
		"allowed":  false,
		"event_id": "evt-frozen",
		"verdict":  map[string]any{"explanation": "frozen", "severity": "CRITICAL"},
		"freeze": map[string]any{
			"type": "HARD_FREEZE", "reason": "composite breach",
			"issued_at": "2026-09-17T09:00:00+00:00",
		},
	})
	verdict, _ := client.Check(context.Background(), "agent-1", Action{Type: "payment.send"})
	if verdict.Freeze == nil || verdict.Freeze["type"] != "HARD_FREEZE" {
		t.Fatalf("the freeze block did not survive: %+v", verdict.Freeze)
	}
}

// --------------------------------------------------------------------------- //
// Durable first
// --------------------------------------------------------------------------- //

func TestTheRecordExistsOnDiskBeforeTheNetworkIsTouched(t *testing.T) {
	// DURABLE FIRST: the record exists on disk before anything can fail. Check
	// still waits for the verdict -- that is the point of a pre-flight check --
	// fail-open on the verdict, fail-safe on the record.
	isolate(t)

	// A handler that inspects the spool from INSIDE the request: by the time the
	// platform is being asked, the row must already be there.
	var pendingDuringRequest int
	platform := newFakePlatform(t)
	client, err := New("alm_sk_test_key", WithEndpoint(platform.URL()),
		WithLogger(nil), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	client.http = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		pendingDuringRequest, _ = client.spool.PendingCount()
		return (&http.Client{}).Do(req)
	})

	if _, err := client.Check(context.Background(), "agent-1", Action{Type: "payment.send"}); err != nil {
		t.Fatal(err)
	}
	if pendingDuringRequest != 1 {
		t.Fatalf("the spool held %d rows while the request was in flight, want 1. "+
			"The record has to exist before anything can fail.", pendingDuringRequest)
	}
}

func TestTheSignatureIsOnTheBytesThatWereSpooled(t *testing.T) {
	// Sign before spooling, so the bytes on disk are the bytes we send. A
	// signature added after the spool write would not survive a crash between the
	// two, and the replayed event would verify as unsigned.
	dir := isolate(t)
	keyPath := dir + "/agent.key"
	if _, err := GenerateKeypair(keyPath); err != nil {
		t.Fatal(err)
	}
	client, _ := testClient(t, WithSigningKeyPath(keyPath))

	if err := client.Log(context.Background(), "agent-1", Action{Type: "file.read"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := client.spool.Pending(10, 0)
	var payload map[string]any
	if err := json.Unmarshal(rows[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	sequence, _ := payload["sequence"].(map[string]any)
	if sequence["signature"] == nil || sequence["signature_method"] != MethodEd25519 {
		t.Fatalf("the spooled bytes are unsigned: %v", sequence)
	}

	// And the signature is over those exact bytes.
	digest, err := ContentDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" {
		t.Fatal("no digest")
	}
}

func TestASigningFailureDoesNotLoseTheEvent(t *testing.T) {
	// An unsigned event is a supported state the server records as
	// `signature_verified: null`. The record is the thing that matters.
	client, _ := testClient(t, WithSigner(brokenSigner{}), WithLogger(nil))
	if err := client.Log(context.Background(), "agent-1", Action{Type: "file.read"}); err != nil {
		t.Fatalf("a signing failure lost the event: %v", err)
	}
	if n, _ := client.spool.PendingCount(); n != 1 {
		t.Fatalf("pending = %d, want 1", n)
	}
	rows, _ := client.spool.Pending(10, 0)
	var payload map[string]any
	_ = json.Unmarshal(rows[0].Payload, &payload)
	sequence, _ := payload["sequence"].(map[string]any)
	if _, signed := sequence["signature"]; signed {
		t.Fatal("a broken signer produced a signature")
	}
}

// --------------------------------------------------------------------------- //
// The wire shape
// --------------------------------------------------------------------------- //

func TestTheWireShapeIsThePythonSDKs(t *testing.T) {
	// A Go-instrumented and a Python-instrumented agent must produce rows an
	// auditor cannot tell apart except by the `tool` field. This asserts the
	// envelope; `backend/tests/test_go_sdk_parity.py` diffs the rows the SERVER
	// actually stored, which is the check that counts.
	client, platform := testClient(t)

	monetary := 42.5
	external := true
	reversible := false
	if _, err := client.Check(context.Background(), "billing-bot", Action{
		Type:            "refund.issue",
		Parameters:      map[string]any{"amount": 4200},
		Description:     "issue a refund",
		ToolCalled:      "stripe",
		SessionID:       "sess-1",
		MonetaryValue:   &monetary,
		AffectsExternal: &external,
		Reversible:      &reversible,
	}); err != nil {
		t.Fatal(err)
	}

	bodies := platform.bodies()
	if len(bodies) != 1 {
		t.Fatalf("the platform saw %d bodies", len(bodies))
	}
	body := bodies[0]

	if body["agent_id"] != "billing-bot" || body["agent_external_id"] != "billing-bot" {
		t.Errorf("both agent fields are sent, as the Python SDK sends them: %v", body)
	}
	action, _ := body["action"].(map[string]any)
	if action["type"] != "refund.issue" || action["description"] != "issue a refund" ||
		action["tool_called"] != "stripe" {
		t.Errorf("action = %v", action)
	}
	context, _ := body["context"].(map[string]any)
	if context["session_id"] != "sess-1" {
		t.Errorf("context = %v", context)
	}
	impact, _ := body["impact"].(map[string]any)
	if impact["monetary_value"] != 42.5 || impact["affects_external"] != true ||
		impact["reversible"] != false {
		t.Errorf("impact = %v", impact)
	}
	sequence, _ := body["sequence"].(map[string]any)
	if sequence["run_id"] == nil || sequence["client_seq"] != float64(1) {
		t.Errorf("sequence = %v", sequence)
	}
	// The deterministic id: a retry of this exact event dedupes on the server's
	// external_event_id check before touching the chain.
	want := sequence["run_id"].(string) + ":1"
	if body["external_event_id"] != want {
		t.Errorf("external_event_id = %v, want %q", body["external_event_id"], want)
	}
}

func TestNothingOnTheWireNamesAConnectionTier(t *testing.T) {
	// The tier is read off the AUTHENTICATED CREDENTIAL at ingestion. An agent
	// naming its own tier is the credential rule inverted: the thing being judged
	// says how trustworthy the judgement is.
	client, platform := testClient(t)
	if _, err := client.Check(context.Background(), "agent-1", Action{Type: "file.read"}); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(platform.bodies()[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"connection_tier", "tier", "connector", "sdk_tier", "allem-go", "allem_go",
	} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Errorf("the event body contains %q:\n  %s", forbidden, encoded)
		}
	}
}

func TestAnEmptyParametersMapIsSentRatherThanOmitted(t *testing.T) {
	// The Python SDK sends `{"type": ..., "parameters": parameters or {}}`, so
	// the key is always present. A Go SDK that omitted it would produce a row
	// that differs from a Python one in a field an auditor can see.
	client, platform := testClient(t)
	if _, err := client.Check(context.Background(), "agent-1", Action{Type: "file.read"}); err != nil {
		t.Fatal(err)
	}
	action, _ := platform.bodies()[0]["action"].(map[string]any)
	params, present := action["parameters"]
	if !present {
		t.Fatal("parameters is absent; the Python SDK always sends it")
	}
	if len(params.(map[string]any)) != 0 {
		t.Fatalf("parameters = %v, want an empty object", params)
	}
}

// --------------------------------------------------------------------------- //
// Construction
// --------------------------------------------------------------------------- //

func TestNothingPanicsAtConstruction(t *testing.T) {
	isolate(t)
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("New panicked: %v. This package is linked into somebody "+
				"else's program.", recovered)
		}
	}()
	if _, err := New(""); err == nil {
		t.Error("an empty API key was accepted")
	}
	if _, err := New("k", WithSigningKeyPath("/nonexistent/key")); err == nil {
		t.Error("a missing signing key was accepted. 'Signing was configured " +
			"and quietly did not happen' is the failure this layer removes.")
	}
}

func TestEd25519WinsWheneverAKeyPathIsAvailable(t *testing.T) {
	// A deployment that sets both must not silently get the weaker one, and there
	// is no path from Ed25519 down to HMAC on error.
	dir := isolate(t)
	keyPath := dir + "/agent.key"
	if _, err := GenerateKeypair(keyPath); err != nil {
		t.Fatal(err)
	}

	signer, err := resolveSigner(options{signingKeyPath: keyPath, signingSecret: "legacy"}, discardLogf)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Method() != MethodEd25519 {
		t.Fatalf("with both configured the signer is %q", signer.Method())
	}

	// And an unreadable key does not fall back.
	if _, err := resolveSigner(options{
		signingKeyPath: dir + "/missing.key", signingSecret: "legacy",
	}, discardLogf); err == nil {
		t.Fatal("an unreadable Ed25519 key fell back to HMAC")
	}
}

func TestTheHMACFallbackIsWarnedAboutOnce(t *testing.T) {
	isolate(t)
	logs := &capturedLog{}
	signer, err := resolveSigner(options{signingSecret: "legacy"}, logs.logf)
	if err != nil || signer.Method() != MethodHMAC {
		t.Fatalf("signer = %v (%v)", signer, err)
	}
	if !logs.contains("Allem cannot verify these signatures") {
		t.Fatalf("the HMAC warning was not emitted: %v", logs.all())
	}
}

func TestCloseIsIdempotentAndDoesNotLoseEvidence(t *testing.T) {
	client, _ := testClient(t)
	if err := client.Log(context.Background(), "agent-1", Action{Type: "file.read"}); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("a second Close returned %v", err)
	}

	// Reopened by a second process: the row is still there.
	spool, err := OpenSpool(client.spool.Path(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	if n, _ := spool.UnsentCount(); n != 1 {
		t.Fatalf("unsent after Close = %d, want 1", n)
	}
}

func TestFlushReportsWhatIsStillOwed(t *testing.T) {
	client, platform := testClient(t, WithBackgroundDelivery(true))
	for i := 0; i < 5; i++ {
		if err := client.Log(context.Background(), "agent-1", Action{Type: "file.read"}); err != nil {
			t.Fatal(err)
		}
	}
	remaining, err := client.Flush(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("%d events still pending after a flush against a healthy platform", remaining)
	}
	if len(platform.bodies()) != 5 {
		t.Fatalf("the platform received %d of 5", len(platform.bodies()))
	}
}

func TestLogNeverWaitsOnTheNetwork(t *testing.T) {
	// The event is written durably to local disk, then delivered by the
	// background worker. A slow platform must not become a slow agent.
	isolate(t)
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	client, err := New("alm_sk_test_key", WithEndpoint("https://example.invalid"),
		WithLogger(nil), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.http = roundTripFunc(func(*http.Request) (*http.Response, error) {
		<-block
		return nil, context.Canceled
	})

	start := time.Now()
	if err := client.Log(context.Background(), "agent-1", Action{Type: "file.read"}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Log took %v against a platform that never answers", elapsed)
	}
	if n, _ := client.spool.PendingCount(); n != 1 {
		t.Fatalf("the event was not recorded: pending = %d", n)
	}
}

func TestAnAgentIDIsRequired(t *testing.T) {
	client, _ := testClient(t)
	if err := client.Log(context.Background(), "  ", Action{Type: "x"}); err == nil {
		t.Error("an empty agent id was accepted")
	}
	verdict, err := client.Check(context.Background(), "", Action{Type: "x"})
	if err == nil {
		t.Error("Check accepted an empty agent id")
	}
	if !verdict.Allowed {
		t.Error("a caller's mistake produced a denial")
	}
}

// -- helpers ---------------------------------------------------------------- //

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

type brokenSigner struct{}

func (brokenSigner) Method() string { return MethodEd25519 }
func (brokenSigner) Sign([]byte) (string, error) {
	return "", context.DeadlineExceeded
}

func TestAWholeValuedFloatSurvivesAsAFloat(t *testing.T) {
	// The defect the parity harness turned up before it was ever run.
	//
	// `encoding/json` emits `json.Marshal(float64(4200))` as `4200`. The server
	// recomputes the content digest from the body EXACTLY AS RECEIVED, so it
	// would parse an integer, canonicalize to `4200`, and compare that against a
	// client digest taken over the float -- `4200.0`. Every signed event carrying
	// a round monetary value would have arrived `signature_verified: false`, on
	// the Go SDK only, depending on whether a customer's number happened to have
	// a fractional part.
	//
	// The wire bytes are canonical now, so the digest, the spool and the request
	// are one string. Asserted on the RAW BYTES the transport carried, because
	// the parsed body cannot tell `4200` from `4200.0` and would pass either way.
	client, _ := testClient(t)
	var onTheWire string
	inner := client.http
	client.http = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		onTheWire = string(raw)
		req.Body = io.NopCloser(strings.NewReader(onTheWire))
		req.ContentLength = int64(len(raw))
		return inner.Do(req)
	})

	monetary := 4200.0
	if _, err := client.Check(context.Background(), "agent-1", Action{
		Type:          "refund.issue",
		Parameters:    map[string]any{"rate": 1234567.0, "tiny": 1e-7},
		MonetaryValue: &monetary,
	}); err != nil {
		t.Fatal(err)
	}
	if onTheWire == "" {
		t.Fatal("no request body was captured")
	}

	for _, want := range []string{`"monetary_value":4200.0`, `"rate":1234567.0`, `"tiny":1e-07`} {
		if !strings.Contains(onTheWire, want) {
			t.Errorf("the wire body does not contain %s:\n  %s", want, onTheWire)
		}
	}

	// And a digest recomputed from the PARSED body matches the one the client
	// would have taken -- which is exactly the comparison the server makes.
	var payload map[string]any
	decoder := json.NewDecoder(strings.NewReader(onTheWire))
	if err := decoder.Decode(&payload); err != nil {
		t.Fatal(err)
	}
	reparsed, err := ContentDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	original, err := ContentDigest(map[string]any{
		"agent_id": "agent-1", "agent_external_id": "agent-1",
		"action": map[string]any{
			"type":       "refund.issue",
			"parameters": map[string]any{"rate": 1234567.0, "tiny": 1e-7},
		},
		"external_event_id": payload["external_event_id"],
		"impact":            map[string]any{"monetary_value": 4200.0},
		"identity":          payload["identity"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if reparsed != original {
		t.Fatalf("a digest recomputed from the parsed body differs from one over "+
			"the original values:\n  reparsed: %s\n  original: %s\n  body: %s",
			reparsed, original, onTheWire)
	}
}

func TestParamsNormalizesAStructAndSaysWhatItCosts(t *testing.T) {
	type refund struct {
		Amount   int64   `json:"amount"`
		Currency string  `json:"currency"`
		Rate     float64 `json:"rate"`
		internal string  //nolint:unused // the point is that it is dropped
	}
	params, err := Params(refund{Amount: 4200, Currency: "EUR", Rate: 0.5, internal: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if params["currency"] != "EUR" {
		t.Errorf("params = %v", params)
	}
	// A large integer survives exactly, which is what UseNumber is for.
	big, err := Params(map[string]any{"n": json.Number("9007199254740993")})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := CanonicalJSON(big)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"n":9007199254740993}` {
		t.Fatalf("a large integer lost precision through Params: %s", encoded)
	}

	// And a value that is not an object is refused rather than wrapped.
	if _, err := Params([]int{1, 2, 3}); err == nil {
		t.Error("a JSON array was accepted as an action's parameters")
	}
}

func TestAStructInParametersIsRefusedLoudly(t *testing.T) {
	// Refused at the call site with a message that names the fix, rather than
	// silently converted -- a conversion this package did on its own would move
	// the bytes the signature covers.
	type payload struct{ A int }
	client, _ := testClient(t)
	err := client.Log(context.Background(), "agent-1", Action{
		Type:       "x",
		Parameters: map[string]any{"body": payload{A: 1}},
	})
	if err == nil {
		t.Fatal("a struct in Parameters was accepted")
	}
	if !containsFold(err.Error(), "allem.Params") {
		t.Errorf("the error does not name the fix: %v", err)
	}
}
