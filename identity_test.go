package allem

// Nothing is invented; nothing is laundered.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNothingIsInvented(t *testing.T) {
	// A value that is not known is OMITTED, never guessed. `project_id` above
	// all: a guessed one attributes one codebase's work to another, in an
	// append-only log where that cannot be repaired.
	// The agent id is DERIVED too (`a-...`), which is what a provisioned agent
	// has. Pairing a derived principal with a hand-chosen agent id is a
	// different case and is the subject of
	// `TestADerivedPrincipalIsNeverPairedWithANameBearingExternalID`.
	logs := &capturedLog{}
	block := Identity{PrincipalID: "p-" + zeros32}.block("a-"+zeros32, logs.logf)
	if block == nil {
		t.Fatal("a derived principal produced no identity block")
	}
	for _, field := range []string{"project_id", "host_id", "tool_id"} {
		if _, present := block[field]; present {
			t.Errorf("%s = %v was invented from nothing", field, block[field])
		}
	}
	if block["principal_id"] != "p-"+zeros32 {
		t.Errorf("principal_id = %v", block["principal_id"])
	}
}

func TestNothingIsLaundered(t *testing.T) {
	// The platform refuses `@` and whitespace because those are what an email, a
	// display name and a git author string look like. Rewriting such a value into
	// one that passes would carry the person straight through the check that
	// exists to stop exactly that.
	for _, value := range []string{
		"jane.doe@example.com", "Jane Doe", "a b", "x", "  ", "user\tname",
	} {
		if IsPseudonymous(value) {
			t.Errorf("%q passed the pseudonym rule", value)
		}
	}
	for _, value := range []string{
		"p-" + zeros32, "billing-bot", "claude-code", "a.b:c-d_e"[:9], "abc",
	} {
		if !IsPseudonymous(value) {
			t.Errorf("%q was refused and should not have been", value)
		}
	}

	logs := &capturedLog{}
	block := Identity{PrincipalID: "jane.doe@example.com"}.block("also@bad", logs.logf)
	if block != nil {
		t.Fatalf("a name-bearing principal produced an identity block: %v. "+
			"Dropping the block costs the project scope for this event and "+
			"nothing else; laundering it is permanent.", block)
	}
	if !logs.contains("not a pseudonym") {
		t.Errorf("dropping the block was not explained: %v", logs.all())
	}
}

func TestADerivedPrincipalIsNeverPairedWithANameBearingExternalID(t *testing.T) {
	// Two values from different installs in one chained event is a permanent,
	// unshreddable row mapping the pseudonym to the person's username -- the one
	// thing the derivation build exists to prevent, arriving through
	// configuration.
	logs := &capturedLog{}
	block := Identity{PrincipalID: "p-" + zeros32}.block("jdoe-laptop", logs.logf)
	if block == nil {
		t.Fatal("the whole block was dropped; only the derived principal should be")
	}
	if block["principal_id"] == "p-"+zeros32 {
		t.Fatal("a derived principal_id travelled beside a name-bearing " +
			"agent_external_id. That row maps the pseudonym to the person.")
	}
	if block["principal_id"] != "jdoe-laptop" {
		t.Fatalf("principal_id = %v; the external id wins, because it is what "+
			"the platform matches the credential against", block["principal_id"])
	}
	if !logs.contains("derived principal") {
		t.Errorf("the mismatch was not explained: %v", logs.all())
	}
}

func TestPrincipalCaseIsPreservedAndTheOthersAreLowercased(t *testing.T) {
	// Deliberately asymmetric. `project_id`, `host_id` and `tool_id` are GROUPING
	// keys and "Payments" vs "payments" silently splitting one project into two
	// is a reporting bug discovered late in an append-only log. `principal_id` is
	// stored verbatim: folding its case could MERGE two distinct principals, and
	// attributing one person's actions to another is strictly worse than
	// splitting a group.
	block := Identity{
		PrincipalID: "MixedCasePrincipal",
		ProjectID:   "Payments",
		HostID:      "Host-01",
		ToolID:      "MyService",
	}.block("MixedCasePrincipal", nil)

	if block["principal_id"] != "MixedCasePrincipal" {
		t.Errorf("principal_id = %v, want the value verbatim", block["principal_id"])
	}
	for key, want := range map[string]string{
		"project_id": "payments", "host_id": "host-01", "tool_id": "myservice",
	} {
		if block[key] != want {
			t.Errorf("%s = %v, want %q", key, block[key], want)
		}
	}
}

func TestAnUnusableGroupingKeyIsOmittedAndTheEventStillGoes(t *testing.T) {
	// The server's validation is on the REQUEST, not the field: one bad
	// `identity.host_id` is a 422 for the entire event, and the action it
	// described is then recorded nowhere.
	logs := &capturedLog{}
	block := Identity{
		PrincipalID: "p-" + zeros32,
		ProjectID:   "my project", // a space: the server refuses it
		ToolID:      "myservice",
	}.block("a-"+zeros32, logs.logf)

	if block == nil {
		t.Fatal("one bad grouping key dropped the whole identity")
	}
	if _, present := block["project_id"]; present {
		t.Error("a project id the server would refuse was sent anyway, which " +
			"would 422 the whole event")
	}
	if block["tool_id"] != "myservice" {
		t.Error("a usable field was dropped along with the unusable one")
	}
	if !logs.contains("omitted rather than rewritten") {
		t.Errorf("the omission was not explained: %v", logs.all())
	}
}

func TestProjectIDIsReadFromTheCommittedFile(t *testing.T) {
	// Read rather than derived. A project id is issued by Allem and never
	// computed from a git remote -- a repository can be renamed, forked or moved
	// and the governance unit cannot follow it.
	//
	// `[project].id`, because that is what the server writes. The CLI's reader
	// looked for a top-level `project_id` for a while, which no server has ever
	// emitted, so `allem project init` succeeded, wrote a file, and every event
	// still went out with no project id.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".allem"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Byte-for-byte the template in `backend/app/api/v1/projects.py`.
	content := `# Allem project identity. COMMIT THIS FILE.
#
# ` + "`project_id`" + ` is issued by Allem and is what makes this project's governance
# record survive a rename, a fork, an org move and a monorepo split.

[project]
id = "8f3c1d2e-4b5a-4c6d-8e9f-0a1b2c3d4e5f"
name = "payments"
issued_at = "2026-08-18T09:00:00+00:00"
issued_by = "allem"
`
	if err := os.WriteFile(filepath.Join(dir, ".allem", "project.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got := LoadProjectID(dir)
	if got != "8f3c1d2e-4b5a-4c6d-8e9f-0a1b2c3d4e5f" {
		t.Fatalf("LoadProjectID = %q", got)
	}
}

func TestATopLevelProjectIDKeyIsNotMistakenForOne(t *testing.T) {
	// The exact shape of the CLI's bug, asserted so this reader cannot acquire
	// it: a key outside `[project]` is not the one the server writes.
	if got := projectIDFromTOML("project_id = \"wrong\"\n"); got != "" {
		t.Fatalf("a top-level project_id was read as the project id: %q", got)
	}
	if got := projectIDFromTOML("[other]\nid = \"wrong\"\n"); got != "" {
		t.Fatalf("an id under another table was read: %q", got)
	}
	if got := projectIDFromTOML("[project]\nname = \"x\"\n"); got != "" {
		t.Fatalf("a table with no id produced %q", got)
	}
}

func TestAnAbsentOrBrokenProjectFileIsNotAnError(t *testing.T) {
	// Absent, unreadable and malformed alike: the caller can do nothing useful
	// with the difference and this must never fail an action.
	if got := LoadProjectID(t.TempDir()); got != "" {
		t.Fatalf("an absent file produced %q", got)
	}
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".allem"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, ".allem", "project.toml"),
		[]byte("this is not toml at all ]]]["), 0o644)
	if got := LoadProjectID(dir); got != "" {
		t.Fatalf("a malformed file produced %q", got)
	}
}

func TestIdentityReadsTheSameEnvironmentTheCLIWrites(t *testing.T) {
	// One `allem init` populates both connectors.
	t.Setenv(PrincipalIDEnvVar, "p-"+zeros32)
	t.Setenv(ProjectIDEnvVar, "8f3c1d2e")
	t.Setenv(HostIDEnvVar, "h-"+zeros32)
	t.Setenv(ToolIDEnvVar, "myservice")

	identity := LoadIdentityFromEnv()
	if identity.PrincipalID != "p-"+zeros32 || identity.ProjectID != "8f3c1d2e" ||
		identity.HostID != "h-"+zeros32 || identity.ToolID != "myservice" {
		t.Fatalf("LoadIdentityFromEnv = %+v", identity)
	}
	if identity.IsEmpty() {
		t.Error("a fully populated identity reports as empty")
	}
	if !(Identity{}).IsEmpty() {
		t.Error("an empty identity reports as populated")
	}
}

func TestTheIdentityReachesTheWire(t *testing.T) {
	isolate(t)
	platform := newFakePlatform(t)
	client, err := New("alm_sk_test_key",
		WithEndpoint(platform.URL()), WithLogger(nil), WithBackgroundDelivery(false),
		WithIdentity(Identity{
			PrincipalID: "p-" + zeros32,
			ProjectID:   "8f3c1d2e",
			HostID:      "h-" + zeros32,
			ToolID:      "myservice",
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// A provisioned agent: its external id is derived, like its principal.
	if err := client.Log(context.Background(), "a-"+zeros32, Action{Type: "file.read"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := client.spool.Pending(10, 0)
	var payload map[string]any
	if err := json.Unmarshal(rows[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	identity, _ := payload["identity"].(map[string]any)
	if identity == nil {
		t.Fatal("no identity section reached the event")
	}
	for key, want := range map[string]string{
		"principal_id": "p-" + zeros32,
		"project_id":   "8f3c1d2e",
		"host_id":      "h-" + zeros32,
		"tool_id":      "myservice",
	} {
		if identity[key] != want {
			t.Errorf("identity.%s = %v, want %q", key, identity[key], want)
		}
	}
}

func TestNoIdentityConfiguredSendsNoIdentitySection(t *testing.T) {
	// nil is an answer, not a failure: with no `identity` on the wire the
	// platform derives the one it has always derived, so the event is recorded
	// exactly as a Python SDK event is.
	isolate(t)
	platform := newFakePlatform(t)
	client, err := New("alm_sk_test_key", WithEndpoint(platform.URL()),
		WithLogger(nil), WithBackgroundDelivery(false))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// The agent id is a pseudonym, so it becomes the principal -- exactly the
	// CLI's fallback, and exactly what the server would derive anyway.
	if err := client.Log(context.Background(), "billing-bot", Action{Type: "file.read"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := client.spool.Pending(10, 0)
	var payload map[string]any
	_ = json.Unmarshal(rows[0].Payload, &payload)
	identity, _ := payload["identity"].(map[string]any)
	if identity == nil {
		t.Fatal("no identity at all; the agent id is a pseudonym and is the documented fallback")
	}
	if len(identity) != 1 || identity["principal_id"] != "billing-bot" {
		t.Fatalf("identity = %v, want only the fallback principal", identity)
	}
}

func TestIsDerivedIsAShapeTestAndNothingMore(t *testing.T) {
	// It cannot tell whose secret produced the digest, and it never decides that
	// a value is safe. It decides one thing: are these two values from the same
	// install?
	for _, value := range []string{"a-" + zeros32, "p-" + zeros32, "h-" + zeros32} {
		if !IsDerived(value) {
			t.Errorf("%q is the shape Allem's derivation produces", value)
		}
	}
	for _, value := range []string{
		"", "x-" + zeros32, "p-" + zeros32 + "0", "p-" + zeros32[:31],
		"p-" + "G" + zeros32[:31], "jdoe-laptop",
	} {
		if IsDerived(value) {
			t.Errorf("%q is not a derived id", value)
		}
	}
}

const zeros32 = "00000000000000000000000000000000"

func TestADerivedPrincipalSurvivesAProvisionedAgentID(t *testing.T) {
	// The other side of the mismatch rule, and the reason it is worth stating:
	// the rule fires on `derived principal + NOT-derived agent id`, and a
	// PROVISIONED agent has a derived external id (`a-...`), because
	// `POST /agents/provision` derives all three under the organisation's secret.
	//
	// So a correctly provisioned Go agent keeps its principal, and a derived
	// principal read from one machine's `allem init` paired by hand with a
	// service agent registered somewhere else does not -- which is right, because
	// those two values describe a person on a laptop and a server-side service,
	// and attaching one to the other is a false attribution in an append-only
	// log. That requirement is a documentation point for integrators and it is in
	// the README.
	logs := &capturedLog{}
	block := Identity{PrincipalID: "p-" + zeros32, ToolID: "myservice"}.block("a-"+zeros32, logs.logf)
	if block["principal_id"] != "p-"+zeros32 {
		t.Fatalf("a provisioned agent lost its derived principal: %v", block)
	}
	for _, line := range logs.all() {
		if containsFold(line, "derived principal") {
			t.Errorf("the mismatch warning fired on a correctly provisioned "+
				"agent: %q. It would then fire on every event of every correct "+
				"install, which is how a warning stops being read.", line)
		}
	}
}
