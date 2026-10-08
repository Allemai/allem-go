package allem

// The run lifecycle: RUN_START at one, beats that consume numbers, and the
// ending Go cannot do for you.

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"
)

func spooledEvents(t *testing.T, client *Client) []map[string]any {
	t.Helper()
	rows, err := client.spool.Pending(1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		var payload map[string]any
		if err := json.Unmarshal(row.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		out = append(out, payload)
	}
	return out
}

func seqOf(t *testing.T, event map[string]any) float64 {
	t.Helper()
	sequence, _ := event["sequence"].(map[string]any)
	seq, ok := sequence["client_seq"].(float64)
	if !ok {
		t.Fatalf("no client_seq on %v", event)
	}
	return seq
}

func TestRunStartAlwaysTakesClientSeqOne(t *testing.T) {
	// Nothing else may consume a number for this agent first -- that is why
	// starting a run is an explicit call rather than something that happens
	// lazily on the first action.
	client, _ := testClient(t)
	if _, err := client.StartRun("agent-1", time.Hour); err != nil {
		t.Fatal(err)
	}
	events := spooledEvents(t, client)
	if len(events) != 1 {
		t.Fatalf("StartRun spooled %d events, want 1", len(events))
	}
	if events[0]["event_type"] != EventRunStart {
		t.Fatalf("event_type = %v, want %q", events[0]["event_type"], EventRunStart)
	}
	if seq := seqOf(t, events[0]); seq != 1 {
		t.Fatalf("run_start took client_seq %v, want 1", seq)
	}
}

func TestAHeartbeatConsumesASequenceNumber(t *testing.T) {
	// That is the whole trick: a MISSING heartbeat is itself a detectable gap, so
	// the mechanism that detects lost actions detects lost heartbeats too, and
	// there is no second mechanism to keep honest.
	client, _ := testClient(t)
	if _, err := client.StartRun("agent-1", 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "two heartbeats", func() bool {
		beats := 0
		for _, event := range spooledEvents(t, client) {
			if event["event_type"] == EventHeartbeat {
				beats++
			}
		}
		return beats >= 2
	})

	client.EndRun("agent-1")

	events := spooledEvents(t, client)
	seen := map[float64]bool{}
	for _, event := range events {
		seq := seqOf(t, event)
		if seen[seq] {
			t.Fatalf("client_seq %v was used twice", seq)
		}
		seen[seq] = true
	}
	for i := float64(1); i <= float64(len(events)); i++ {
		if !seen[i] {
			t.Fatalf("client_seq %v is missing from a run nothing lost, so the "+
				"completeness signal would report a gap that never happened", i)
		}
	}
}

func TestEndRunEmitsRunEndAndStopsBeating(t *testing.T) {
	client, _ := testClient(t)
	if _, err := client.StartRun("agent-1", 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	eventually(t, 2*time.Second, "at least one beat", func() bool {
		for _, event := range spooledEvents(t, client) {
			if event["event_type"] == EventHeartbeat {
				return true
			}
		}
		return false
	})

	client.EndRun("agent-1")
	after := len(spooledEvents(t, client))

	last := spooledEvents(t, client)
	if last[len(last)-1]["event_type"] != EventRunEnd {
		t.Fatalf("the last event is %v, want %q", last[len(last)-1]["event_type"], EventRunEnd)
	}

	time.Sleep(150 * time.Millisecond)
	if now := len(spooledEvents(t, client)); now != after {
		t.Fatalf("beats kept arriving after run_end: %d -> %d", after, now)
	}
}

func TestCloseEndsEveryRunBeforeDraining(t *testing.T) {
	// RUN_END first, so the closing events are spooled before the sender is asked
	// to drain. Reversing this would leave every clean shutdown reporting as an
	// unclosed run.
	client, platform := testClient(t, WithBackgroundDelivery(true))
	if _, err := client.StartRun("agent-1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := client.StartRun("agent-2", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	ends := map[string]bool{}
	for _, body := range platform.bodies() {
		if body["event_type"] == EventRunEnd {
			ends[body["agent_external_id"].(string)] = true
		}
	}
	if !ends["agent-1"] || !ends["agent-2"] {
		t.Fatalf("Close did not end both runs; delivered run_end for %v", ends)
	}
}

func TestStartRunIsIdempotentPerAgent(t *testing.T) {
	// A second call returns the existing run rather than starting a second beat
	// goroutine or burning another RUN_START.
	client, _ := testClient(t)
	first, err := client.StartRun("agent-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.StartRun("agent-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("a second StartRun produced a second run")
	}
	starts := 0
	for _, event := range spooledEvents(t, client) {
		if event["event_type"] == EventRunStart {
			starts++
		}
	}
	if starts != 1 {
		t.Fatalf("%d run_start events, want 1", starts)
	}
}

func TestEndIsSafeToCallMoreThanOnce(t *testing.T) {
	client, _ := testClient(t)
	run, err := client.StartRun("agent-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	run.End()
	run.End()
	client.EndRun("agent-1")
	client.EndRun("agent-1")

	ends := 0
	for _, event := range spooledEvents(t, client) {
		if event["event_type"] == EventRunEnd {
			ends++
		}
	}
	if ends != 1 {
		t.Fatalf("%d run_end events, want 1", ends)
	}
}

func TestABeatThatFailsDoesNotKillTheBeatGoroutine(t *testing.T) {
	// Losing one beat is survivable; losing the goroutine is not -- it would look
	// exactly like the agent dying, and would manufacture a blackout window for
	// an agent that is fine.
	logs := &capturedLog{}
	// Atomic: the beat runs on its own goroutine and the assertion runs on the
	// test's. Exercised under `-race` in CI, which is where the first version of
	// this counter was caught.
	var failures atomic.Int64
	emit := func(agentID, eventType string) error {
		if eventType == EventHeartbeat {
			if failures.Add(1) <= 2 {
				return context.DeadlineExceeded
			}
		}
		return nil
	}
	run, err := newRunLifecycle(emit, "agent-1", 10*time.Millisecond, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer run.End()

	eventually(t, 3*time.Second, "beats to continue past two failures", func() bool {
		return failures.Load() >= 4
	})
	if !logs.contains("blackout window, which is the correct record") {
		t.Errorf("a failed beat was not explained: %v", logs.all())
	}
}

func TestTheLifecycleConstantsMatchTheServersExpectations(t *testing.T) {
	if HeartbeatInterval != 60*time.Second {
		t.Errorf("interval = %v, want 60s", HeartbeatInterval)
	}
	// Three missed beats, not one: a single missed beat is a hiccup, and a
	// product that opened a blackout window for every one of those would produce
	// a compliance artifact nobody reads.
	if HeartbeatGrace != 180*time.Second {
		t.Errorf("grace = %v, want 180s", HeartbeatGrace)
	}
	if HeartbeatGrace != 3*HeartbeatInterval {
		t.Errorf("the grace is not three intervals")
	}
	// Lowercase, because `normalize_event` canonicalizes identifiers to lowercase
	// on arrival anyway; sending the canonical form means what you see in the
	// console is what the SDK sent.
	for _, eventType := range LifecycleEventTypes {
		if eventType != lower(eventType) {
			t.Errorf("%q is not the canonical lowercase form", eventType)
		}
	}
}

func TestThisPackageInstallsNoSignalHandler(t *testing.T) {
	// Go has no `atexit`, and a library that installs a `signal.Notify` handler
	// changes the host program's signal disposition without being asked -- the
	// exact objection the Python module raises against REPLACING a SIGTERM
	// handler, except Go gives a library no way to chain onto one.
	//
	// So the consequence is documented rather than hidden: a program that exits
	// without calling Close reports UNCLOSED_RUN, which is accurate because
	// nothing observed the shutdown.
	//
	// **Asserted over the parsed IMPORTS, not over the text.** The first version
	// of this test grepped the source for "signal.Notify" and failed on its own
	// explanatory comment -- which is this repository's own finding about its own
	// guards, reproduced inside a test written to state a rule. A comment naming
	// a defect is not the defect; an import is.
	imports := packageImports(t)
	for _, forbidden := range []string{"os/signal", "os/exec", "syscall"} {
		if imports[forbidden] {
			t.Errorf("this package imports %q. A library that takes over the "+
				"host program's signals, or shells out from inside it, is a "+
				"library that gets removed -- and Go offers no way to chain onto "+
				"an existing signal handler, so the honest answer is Close() and "+
				"a documented UNCLOSED_RUN.", forbidden)
		}
	}
	if len(imports) == 0 {
		t.Fatal("no imports were parsed, so this assertion is vacuous")
	}
}

func lower(s string) string {
	out := []byte(s)
	for i := range out {
		if 'A' <= out[i] && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}
