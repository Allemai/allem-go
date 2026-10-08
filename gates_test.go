package allem

// The hard gate, driven rather than read.
//
// `run-go-sdk.sh` says it out loud: *"a build that gets this backwards still
// compiles and still passes a suite that never unplugs the network."* So every
// test in this file unplugs the network -- `deadEndpoint` is a real closed port,
// so every request to it is a refused connection and a genuine
// PlatformDidNotAnswer rather than a mocked one.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// warmedClient fetches a hard-gate list from a live platform, then hands back a
// switch that takes the network away -- exactly the sequence a real outage
// produces, and WITHOUT changing the endpoint.
//
// Changing the endpoint would also change the cache file's name, because it is
// keyed on SHA-256("{endpoint}|{external_id}"). The first version of this helper
// did that, and every test in this file then passed through the in-memory copy
// of the list while proving nothing at all about the file on disk.
func warmedClient(t *testing.T, gated []string, armed bool) (*Client, *fakePlatform, *capturedLog, *switchableDoer) {
	t.Helper()
	isolate(t)
	platform := newFakePlatform(t)
	platform.setHardGates(gated, 7, armed)

	doer := newSwitchableDoer()
	logs := &capturedLog{}
	client, err := New("alm_sk_test_key",
		WithEndpoint(platform.URL()),
		WithLogger(logs.logf),
		WithBackgroundDelivery(false),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Swapped in after construction so the client and its gate cache share one
	// transport and one endpoint.
	client.http = doer
	client.gates.doer = doer
	t.Cleanup(func() { _ = client.Close() })

	// Warm the cache the way a running agent does: synchronously, so the test is
	// not racing a background refresh.
	gates := client.gates.Refresh("test-agent")
	if !gates.Available {
		t.Fatalf("the cache did not warm: %+v", gates)
	}
	return client, platform, logs, doer
}

// --------------------------------------------------------------------------- //
// THE RULE
// --------------------------------------------------------------------------- //

func TestAHardGatedActionIsDeniedLocallyWhenAllemDoesNotAnswer(t *testing.T) {
	client, _, logs, doer := warmedClient(t, []string{"payment.send"}, true)
	doer.goOffline()

	verdict, err := client.Check(context.Background(), "test-agent", Action{Type: "payment.send"})
	if err != nil {
		t.Fatalf("Check returned an error on the fail-open path: %v", err)
	}
	if verdict.Allowed {
		t.Fatalf("A HARD GATE FAILED OPEN. This is the defect the module exists "+
			"to prevent and revision 1 of the prompt asked for by mistake.\n"+
			"  verdict: %s\n  logs: %v", verdict, logs.all())
	}
	if verdict.Severity != "HIGH" || verdict.RecommendedAction != "REQUEST_APPROVAL" {
		t.Errorf("a local denial must carry the same severity and recommendation "+
			"the Python SDK sends: got %q / %q", verdict.Severity, verdict.RecommendedAction)
	}
}

func TestALocalDenialCarriesNoEventID(t *testing.T) {
	// The mechanical separation between Tier 1 and Tier 2. Tier 2 reads a
	// verdict without an id as "we never got an answer" rather than as a denial,
	// so adding one to make the shape tidier changes another package's
	// behaviour.
	client, _, _, doer := warmedClient(t, []string{"payment.send"}, true)
	doer.goOffline()

	verdict, _ := client.Check(context.Background(), "test-agent", Action{Type: "payment.send"})
	if verdict.EventID != "" {
		t.Fatalf("a local denial carried an event id (%q). The platform issues "+
			"one when IT records a denial; this one was decided here.", verdict.EventID)
	}
	if verdict.DecidedByAllem() {
		t.Fatal("DecidedByAllem() is true for a denial Allem never saw")
	}
}

func TestStalenessDoesNotRelaxTheGate(t *testing.T) {
	// THE ruling, and the row people get wrong. A cache older than the TTL keeps
	// blocking every action already on its list. Age makes the list less
	// COMPLETE -- a rule added during the outage is unknown to us -- never less
	// binding.
	client, _, _, doer := warmedClient(t, []string{"payment.send"}, true)

	// Age the cache well past any plausible bound.
	client.gates.mu.Lock()
	aged := client.gates.gates["test-agent"]
	aged.FetchedAt = time.Now().Add(-48 * time.Hour)
	client.gates.gates["test-agent"] = aged
	client.gates.mu.Unlock()

	if !aged.IsStale(client.gates.TTL(), time.Now()) {
		t.Fatal("the fixture did not actually make the cache stale, so this test " +
			"proves nothing")
	}

	doer.goOffline()
	verdict, _ := client.Check(context.Background(), "test-agent", Action{Type: "payment.send"})
	if verdict.Allowed {
		t.Fatal("a stale cache relaxed the gate. That 'silently converts the " +
			"hard gate back into fail-open after an outage of any length'.")
	}
}

func TestTheDenialSaysHowItWasDecided(t *testing.T) {
	// "Blocked alone does not distinguish a gate that worked from one that
	// guessed." Seven fields, named exactly as the Python SDK names them,
	// because the record travels in `metadata.allem_local_gate` and an auditor
	// reading two agents' events must not find two schemas.
	client, _, _, doer := warmedClient(t, []string{"payment.send"}, true)
	doer.goOffline()

	if _, err := client.Check(context.Background(), "test-agent", Action{Type: "payment.send"}); err != nil {
		t.Fatalf("Check: %v", err)
	}

	rows, err := client.spool.Pending(10, 0)
	if err != nil || len(rows) != 1 {
		t.Fatalf("expected one spooled row, got %d (%v)", len(rows), err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rows[0].Payload, &payload); err != nil {
		t.Fatalf("unreadable spooled payload: %v", err)
	}
	metadata, _ := payload["metadata"].(map[string]any)
	record, _ := metadata["allem_local_gate"].(map[string]any)
	if record == nil {
		t.Fatalf("the locally-denied event carries no gate record: %v", payload)
	}
	for _, field := range []string{
		"blocked_by", "scope_version", "cache_stale", "cache_age_s",
		"staleness_bound_s", "cache_source", "cache_in_memory_only",
	} {
		if _, ok := record[field]; !ok {
			t.Errorf("the denial record is missing %q; an auditor cannot tell a "+
				"gate that worked from one that guessed without it", field)
		}
	}
	if record["blocked_by"] != "local_hard_gate" {
		t.Errorf("blocked_by = %v, want local_hard_gate", record["blocked_by"])
	}
	if record["scope_version"] != float64(7) {
		t.Errorf("scope_version = %v, want 7", record["scope_version"])
	}
}

func TestAnActionNotOnTheListIsAllowed(t *testing.T) {
	client, _, _, doer := warmedClient(t, []string{"payment.send"}, true)
	doer.goOffline()

	verdict, _ := client.Check(context.Background(), "test-agent", Action{Type: "file.read"})
	if !verdict.Allowed {
		t.Fatalf("an action nobody gated was denied: %s", verdict)
	}
	if verdict.EventID != "" {
		t.Errorf("a fail-open verdict carried an event id (%q)", verdict.EventID)
	}
}

func TestAnUnarmedGateDoesNotStartBindingBecauseThePlatformWentDown(t *testing.T) {
	// Appendix A3. An organization that does not require agent keys has hard
	// gates that degrade to fail-open, because the acting agent on a check may
	// be named by a request body rather than proved by a credential. A gate that
	// was never in force while the platform was up cannot start being in force
	// because the platform went down.
	client, _, _, doer := warmedClient(t, []string{"payment.send"}, false)
	doer.goOffline()

	verdict, _ := client.Check(context.Background(), "test-agent", Action{Type: "payment.send"})
	if !verdict.Allowed {
		t.Fatal("an UNARMED hard gate blocked locally. It was not in force while " +
			"the platform was up, so it cannot be in force now.")
	}
}

func TestNoListEverFetchedFailsOpenAndSaysSoEveryTime(t *testing.T) {
	// The honest limit of the design, and `allem_cli/gates.py`'s built-in floor
	// is NOT the answer here -- that is a Tier 2 answer, and on Tier 1 the same
	// gap means failing open on a hard gate.
	isolate(t)
	logs := &capturedLog{}
	client, err := New("alm_sk_test_key",
		WithEndpoint(deadEndpoint(t)),
		WithLogger(logs.logf),
		WithBackgroundDelivery(false),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	for attempt := 1; attempt <= 3; attempt++ {
		verdict, _ := client.Check(context.Background(), "test-agent", Action{Type: "payment.send"})
		if !verdict.Allowed {
			t.Fatalf("attempt %d denied an action from a list that was never "+
				"fetched, which is a gate that guessed", attempt)
		}
	}
	// LOUD, and loud EVERY time. A connector that quietly stops enforcing is the
	// exact failure this package exists to avoid, and a warning that fires once
	// is a warning a long-running process never sees.
	warnings := 0
	for _, line := range logs.all() {
		if containsFold(line, "no hard-gate list has ever been fetched") {
			warnings++
		}
	}
	if warnings < 3 {
		t.Fatalf("the fail-open warning fired %d times across 3 checks; it has to "+
			"fire every time.\n  logs: %v", warnings, logs.all())
	}
}

func TestADirectoryWeCannotWriteIsNotNoGate(t *testing.T) {
	// The SDK runs inside the customer's process: a container, a Lambda, a
	// read-only root filesystem. A cache file that cannot be written degrades to
	// memory for the process lifetime and logs once. `Check` is NEVER failed
	// because a cache file could not be written -- the gate is the point, the
	// file is an optimisation.
	//
	// **The condition is created one directory up.** Sealing the state directory
	// itself does not work: `writeToDisk` chmods it back to 0700 before writing,
	// deliberately, and the owner of a 0500 directory may always chmod it. So the
	// PARENT is sealed and the state directory below it cannot be created at all
	// -- which is what a read-only root filesystem actually looks like.
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permissions; nothing in this package has been run on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can write into a 0500 directory, so this " +
			"test cannot create the condition it is about")
	}

	dir := isolate(t)
	sealed := filepath.Join(dir, "sealed")
	if err := os.MkdirAll(sealed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sealed, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sealed, 0o700) })
	// The spool keeps its own writable directory: this test is about the gate
	// cache, and a spool that could not open would fail construction for an
	// unrelated reason.
	t.Setenv(HomeEnvVar, filepath.Join(sealed, "home"))

	platform := newFakePlatform(t)
	platform.setHardGates([]string{"payment.send"}, 7, true)
	doer := newSwitchableDoer()
	logs := &capturedLog{}
	client, err := New("alm_sk_test_key",
		WithEndpoint(platform.URL()),
		WithSpoolPath(filepath.Join(dir, "spool.db")),
		WithLogger(logs.logf), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()
	client.http = doer
	client.gates.doer = doer

	gates := client.gates.Refresh("test-agent")
	if !gates.Available || !gates.Blocks("payment.send") {
		t.Fatalf("an unwritable cache directory became 'no gate': %+v", gates)
	}
	if _, err := os.Stat(client.gates.cachePath("test-agent")); err == nil {
		t.Fatal("the cache file was written after all, so this test is not " +
			"exercising the in-memory degradation it names")
	}
	if !logs.contains("cannot write the hard-gate cache") {
		t.Errorf("degrading to memory was not announced: %v", logs.all())
	}

	doer.goOffline()
	verdict, _ := client.Check(context.Background(), "test-agent", Action{Type: "payment.send"})
	if verdict.Allowed {
		t.Fatal("the gate stopped blocking because its cache file could not be written")
	}

	record := client.gates.DenialRecordFor(gates)
	if !record.CacheInMemoryOnly {
		t.Error("the denial record does not say the cache was in memory only, so " +
			"an auditor cannot tell this list will be gone on the next cold start")
	}
}

func TestAnUnresolvableAgentIDIsLoudAndHasNoBuiltInFloor(t *testing.T) {
	// `allem_cli/gates.py` falls back to a built-in floor when it cannot resolve
	// an id. That is a Tier 2 answer. Here the same gap means failing open on a
	// hard gate, so it is said out loud rather than papered over with a list
	// nobody configured.
	isolate(t)
	platform := newFakePlatform(t)
	platform.mu.Lock()
	platform.meStatus = 500
	platform.mu.Unlock()

	logs := &capturedLog{}
	client, err := New("alm_sk_test_key",
		WithEndpoint(platform.URL()), WithLogger(logs.logf), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	gates := client.gates.Refresh("test-agent")
	if gates.Available {
		t.Fatalf("a list appeared from nowhere: %+v", gates)
	}
	if len(gates.Actions) != 0 {
		t.Fatalf("a BUILT-IN FLOOR appeared (%v). That is the Tier 2 answer and "+
			"it is wrong here: it would enforce rules the customer never wrote.",
			gates.SortedActions())
	}
	if !logs.contains("hard gates will NOT block locally") {
		t.Fatalf("failing open on a hard gate was not announced: %v", logs.all())
	}
}

func TestOneAgentsGatesAreNeverCachedUnderAnothersName(t *testing.T) {
	// `/agents/me` answering with a different external id means the key belongs
	// to another agent. Using its id would silently enforce the wrong rules.
	isolate(t)
	platform := newFakePlatform(t)
	platform.setHardGates([]string{"payment.send"}, 7, true)

	logs := &capturedLog{}
	client, err := New("alm_sk_test_key",
		WithEndpoint(platform.URL()), WithLogger(logs.logf), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	// The platform's `/agents/me` answers "test-agent"; ask about a different one.
	gates := client.gates.Refresh("some-other-agent")
	if gates.Available {
		t.Fatalf("one agent's gates were cached under another's name: %+v", gates)
	}
	if !logs.contains("identifies as") {
		t.Errorf("the mismatch was not explained: %v", logs.all())
	}
}

func TestAFailedRefreshKeepsTheListWeAlreadyHold(t *testing.T) {
	// Losing a good list because one refresh failed would convert a working gate
	// into a fail-open gate, which is the bug this module exists to prevent.
	client, platform, _, _ := warmedClient(t, []string{"payment.send"}, true)

	platform.mu.Lock()
	platform.meStatus = 500
	platform.mu.Unlock()
	// Force the resolver back to the network by forgetting the id, then break it.
	client.gates.mu.Lock()
	client.gates.agentIDs = map[string]string{}
	client.gates.mu.Unlock()
	if err := os.RemoveAll(StateDir()); err != nil {
		t.Fatal(err)
	}

	after := client.gates.Refresh("test-agent")
	if !after.Available || !after.Blocks("payment.send") {
		t.Fatalf("a failed refresh emptied the cache: %+v", after)
	}
}

func TestTheCacheSurvivesAColdStart(t *testing.T) {
	// The whole point of the file: the list has to be on local disk BEFORE the
	// incident starts. A second process with no network must find it.
	//
	// **Same endpoint on both clients.** The cache file is keyed on
	// SHA-256("{endpoint}|{external_id}"), so a second client pointed at a
	// different URL looks for a different file and finds nothing -- correctly.
	// The outage is created by taking the transport away, not by moving the
	// address.
	dir := isolate(t)
	platform := newFakePlatform(t)
	platform.setHardGates([]string{"payment.send"}, 7, true)

	first, err := New("alm_sk_test_key", WithEndpoint(platform.URL()),
		WithSpoolPath(filepath.Join(dir, "first.db")),
		WithLogger(nil), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatal(err)
	}
	if gates := first.gates.Refresh("test-agent"); !gates.Available {
		t.Fatalf("the first process never fetched a list: %+v", gates)
	}
	_ = first.Close()

	// A second process: same ALLEM_HOME, same endpoint, nothing in memory, and
	// a transport that does not answer.
	offline := newSwitchableDoer()
	offline.goOffline()
	second, err := New("alm_sk_test_key", WithEndpoint(platform.URL()),
		WithSpoolPath(filepath.Join(dir, "second.db")),
		WithLogger(nil), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.http = offline
	second.gates.doer = offline

	if len(second.gates.gates) != 0 {
		t.Fatal("the second client started with something in memory, so this " +
			"test would pass without ever reading the file on disk")
	}

	verdict, _ := second.Check(context.Background(), "test-agent", Action{Type: "payment.send"})
	if verdict.Allowed {
		t.Fatal("a cold start with the list already on disk failed open. The list " +
			"is written down precisely so it is there before the incident starts.")
	}
	if source := second.gates.GatesFor("test-agent").Note; source != "loaded from cache on disk" {
		t.Errorf("the list came from %q rather than from disk, so the file was "+
			"not what enforced the gate", source)
	}
}

func TestTheCacheFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	client, _, _, _ := warmedClient(t, []string{"payment.send"}, true)

	path := client.gates.cachePath("test-agent")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no cache file was written: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("hard-gate cache is mode %o, want 600", mode)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Errorf("state directory is mode %o, want 700", mode)
	}
}

func TestTheCacheFileIsTheOneTheOtherPackagesWrite(t *testing.T) {
	// The three Allem connectors write `{StateDir}/hard-gates-{digest}.json` for
	// the same (endpoint, agent), where digest is the first 16 hex characters of
	// SHA-256 over "{endpoint}|{external_id}". That is a shared FILE FORMAT and
	// not shared code -- this package imports nothing from allem-cli and
	// allem-cli imports nothing from this.
	//
	// Pinned as a literal so a change to the derivation is visible here rather
	// than as a cache that silently stops being found.
	isolate(t)
	cache := newHardGateCache("https://api.allem.ai", "k", nil, 0, nil)
	got := filepath.Base(cache.cachePath("billing-bot"))
	// sha256("https://api.allem.ai|billing-bot")[:16]
	want := "hard-gates-101925302f5fff84.json"
	if got != want {
		t.Errorf("cache file name = %q, want %q. The Python SDK and the CLI "+
			"compute this the same way; a divergence means a list one of them "+
			"fetched is a list this one cannot find.", got, want)
	}
}

func TestBlocksIgnoresStalenessAndRespectsArmed(t *testing.T) {
	// The two lines of `Gates.Blocks`, isolated from everything else, because
	// this is the function the whole module reduces to.
	gates := Gates{
		Actions:   map[string]bool{"payment.send": true},
		Available: true,
		Armed:     true,
		FetchedAt: time.Now().Add(-1000 * time.Hour),
	}
	if !gates.Blocks("payment.send") {
		t.Error("a very stale list stopped blocking")
	}
	if gates.Blocks("file.read") {
		t.Error("an action not on the list was blocked")
	}

	unarmed := gates
	unarmed.Armed = false
	if unarmed.Blocks("payment.send") {
		t.Error("an unarmed gate blocked")
	}

	absent := gates
	absent.Available = false
	if absent.Blocks("payment.send") {
		t.Error("a list that was never fetched blocked")
	}
	if absent.IsStale(time.Second, time.Now()) {
		t.Error("an absent list reported as STALE. Absent and stale are " +
			"different facts and only one of them is about a list we hold.")
	}
}

func TestTTLIsReadAtCallTime(t *testing.T) {
	// So a host application can set the variable after this package is
	// initialised -- the same rule the Python SDK states.
	isolate(t)
	if got := ttlSeconds(); got != DefaultHardGateTTL {
		t.Fatalf("default TTL = %v, want %v", got, DefaultHardGateTTL)
	}
	t.Setenv(TTLEnvVar, "12.5")
	if got := ttlSeconds(); got != 12500*time.Millisecond {
		t.Errorf("TTL = %v, want 12.5s", got)
	}
	t.Setenv(TTLEnvVar, "not-a-number")
	if got := ttlSeconds(); got != DefaultHardGateTTL {
		t.Errorf("a malformed TTL = %v; it must fall back to the default rather "+
			"than to zero, which would make every list stale", got)
	}
	t.Setenv(TTLEnvVar, "-5")
	if got := ttlSeconds(); got != DefaultHardGateTTL {
		t.Errorf("a negative TTL = %v, want the default", got)
	}
}
