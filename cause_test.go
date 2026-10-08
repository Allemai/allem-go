package allem

// The field the SDK must never fill in.

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestTheSDKNeverInventsACause(t *testing.T) {
	// Not from the previous call in this process, not from the run id, not from
	// anything this package happens to know. The temptation is specific: the
	// Client holds a run id and a monotonic sequence, so "the previous event in
	// this run" is one field away and would look right almost all the time. It
	// would also be a guess written into the hash recipe, under the agent's name,
	// in the one field a reader treats as the agent's own account of itself.
	isolate(t)
	platform := newFakePlatform(t)
	client, err := New("alm_sk_test_key", WithEndpoint(platform.URL()),
		WithLogger(nil), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	for i := 0; i < 3; i++ {
		if err := client.Log(context.Background(), "agent-1", Action{Type: "file.read"}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := client.spool.Pending(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("spooled %d events, want 3", len(rows))
	}
	for i, row := range rows {
		var payload map[string]any
		if err := json.Unmarshal(row.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if _, present := payload["cause"]; present {
			t.Fatalf("event %d carries a cause nobody passed: %v. An absent cause "+
				"is a true record; a plausible one is not.", i, payload["cause"])
		}
	}
}

func TestACauseIsSentOnlyWhenThePassedOneIsValid(t *testing.T) {
	block, err := causeBlock(&Cause{Kind: CausePriorEvent, Ref: "evt-123", Note: " why "})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"kind": "prior_event", "ref": "evt-123", "note": "why"}
	if !reflect.DeepEqual(block, want) {
		t.Fatalf("cause block = %v, want %v", block, want)
	}

	empty, err := causeBlock(&Cause{Kind: CauseUnknown, Ref: "   ", Note: ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 1 || empty["kind"] != CauseUnknown {
		t.Fatalf("a whitespace-only ref was sent as a value: %v. Omitting says "+
			"'not known' in the shape that cannot be mistaken for one.", empty)
	}

	if block, err := causeBlock(nil); block != nil || err != nil {
		t.Fatalf("no cause produced %v / %v", block, err)
	}
}

func TestTheKindSetIsClosed(t *testing.T) {
	// Allem refuses an unrecognised kind rather than storing it, because an
	// append-only evidence field cannot be tidied up later.
	if len(CauseKinds) != 6 {
		t.Fatalf("the cause set has %d kinds, want 6", len(CauseKinds))
	}
	for _, kind := range CauseKinds {
		if _, err := causeBlock(&Cause{Kind: kind}); err != nil {
			t.Errorf("a documented kind %q was refused: %v", kind, err)
		}
	}
	for _, bad := range []string{"", "HUMAN_INSTRUCTION", "human instruction", "retry", "prior-event"} {
		if _, err := causeBlock(&Cause{Kind: bad}); err == nil {
			t.Errorf("an unrecognised kind %q was accepted", bad)
		}
	}
}

func TestTheLengthBoundsAreMirroredFromTheServer(t *testing.T) {
	// A value the server refuses is a 422 the CALLER never sees -- the row is
	// already on the spool, the sender retries a deterministic refusal for ever,
	// and the client_seq it consumed is a permanent gap in the completeness
	// record. The most likely over-length value is a whole prompt pasted into
	// Note.
	if MaxCauseRefLength != 512 || MaxCauseNoteLength != 2000 {
		t.Fatalf("the bounds moved: ref=%d note=%d", MaxCauseRefLength, MaxCauseNoteLength)
	}
	if _, err := causeBlock(&Cause{
		Kind: CauseHumanInstruction, Ref: strings.Repeat("r", MaxCauseRefLength),
	}); err != nil {
		t.Errorf("a ref exactly at the bound was refused: %v", err)
	}
	if _, err := causeBlock(&Cause{
		Kind: CauseHumanInstruction, Ref: strings.Repeat("r", MaxCauseRefLength+1),
	}); err == nil {
		t.Error("a ref one character over the bound was accepted, so the server " +
			"would 422 an event the caller can no longer see")
	}
	if _, err := causeBlock(&Cause{
		Kind: CauseHumanInstruction, Note: strings.Repeat("n", MaxCauseNoteLength+1),
	}); err == nil {
		t.Error("an over-length note was accepted")
	}
}

func TestTheBoundsCountCharactersNotBytes(t *testing.T) {
	// The server's bound is Python's `len()` over a `str`. A byte count would
	// refuse locally what the server accepts, which is the same disagreement in
	// the other direction.
	note := strings.Repeat("é", MaxCauseNoteLength) // 2000 characters, 4000 bytes
	if len([]rune(note)) != MaxCauseNoteLength {
		t.Fatalf("the fixture is %d characters", len([]rune(note)))
	}
	if len(note) <= MaxCauseNoteLength {
		t.Fatal("the fixture is not longer in bytes than in characters, so it " +
			"cannot distinguish the two rules")
	}
	if _, err := causeBlock(&Cause{Kind: CauseHumanInstruction, Note: note}); err != nil {
		t.Fatalf("a note the server would accept was refused locally: %v", err)
	}
}

func TestAnInvalidCauseBurnsNoSequenceNumber(t *testing.T) {
	// Validated BEFORE Next() consumes a client_seq. A failure afterwards burns a
	// number on an event that is never sent, manufacturing a permanent gap in the
	// completeness record out of a caller's typo.
	isolate(t)
	platform := newFakePlatform(t)
	client, err := New("alm_sk_test_key", WithEndpoint(platform.URL()),
		WithLogger(nil), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	bad := Action{Type: "payment.send", Cause: &Cause{Kind: "made-up"}}
	if err := client.Log(context.Background(), "agent-1", bad); err == nil {
		t.Fatal("an invalid cause was accepted")
	}
	verdict, err := client.Check(context.Background(), "agent-1", bad)
	if err == nil {
		t.Fatal("Check accepted an invalid cause")
	}
	if !verdict.Allowed {
		t.Fatal("a caller's typo produced a DENIAL. Only a verdict Allem " +
			"returned, or the local hard gate, may deny.")
	}

	gen, _ := client.sequenceFor("agent-1")
	if gen.Current() != 0 {
		t.Fatalf("%d sequence number(s) were burned by two refused calls. Their "+
			"absence on the server is indistinguishable from a lost event.",
			gen.Current())
	}

	// And a valid call afterwards still starts at 1.
	if err := client.Log(context.Background(), "agent-1", Action{Type: "file.read"}); err != nil {
		t.Fatal(err)
	}
	if gen.Current() != 1 {
		t.Fatalf("the first successful event took client_seq %d", gen.Current())
	}
}

func TestThereIsNoWayToSetABasis(t *testing.T) {
	// `basis` is Allem's word for how Allem came to hold a cause. An agent that
	// could set it could stamp `observed` on its own claim -- the credential rule
	// inverted, inside the one field the governed thing writes about its own
	// reasons. The server declares `extra="forbid"` on CauseSection, so a
	// caller-supplied basis is a 422.
	//
	// In a typed language the strongest form of that rule is that the field does
	// not exist, so this asserts over the type rather than over a value.
	typ := reflect.TypeOf(Cause{})
	for i := 0; i < typ.NumField(); i++ {
		if containsFold(typ.Field(i).Name, "basis") {
			t.Fatalf("Cause has a %q field. How Allem came to hold a cause is "+
				"Allem's statement, not the caller's.", typ.Field(i).Name)
		}
	}
	if typ.NumField() != 3 {
		t.Fatalf("Cause has %d fields; the wire shape is {kind, ref, note}", typ.NumField())
	}

	// And nothing this package can emit contains the key.
	block, err := causeBlock(&Cause{Kind: CausePriorEvent, Ref: "evt-1", Note: "n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := block["basis"]; present {
		t.Fatal("a basis reached the wire")
	}
}

func TestACauseTravelsWhenOneIsPassed(t *testing.T) {
	isolate(t)
	platform := newFakePlatform(t)
	client, err := New("alm_sk_test_key", WithEndpoint(platform.URL()),
		WithLogger(nil), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Check(context.Background(), "agent-1", Action{
		Type:  "payment.send",
		Cause: &Cause{Kind: CauseHumanInstruction, Note: "the operator asked for it"},
	}); err != nil {
		t.Fatal(err)
	}

	bodies := platform.bodies()
	if len(bodies) != 1 {
		t.Fatalf("the platform saw %d bodies", len(bodies))
	}
	cause, _ := bodies[0]["cause"].(map[string]any)
	if cause == nil || cause["kind"] != CauseHumanInstruction {
		t.Fatalf("the cause did not travel: %v", bodies[0]["cause"])
	}
	if cause["note"] != "the operator asked for it" {
		t.Fatalf("note = %v", cause["note"])
	}
}
