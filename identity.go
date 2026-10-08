package allem

// The identity tuple this SDK puts on every event it sends.
//
// `agent_id` bundles four separate jobs -- policy attachment, scoring subject,
// freeze scope, and chain key -- and only the chain key is irreversible. So
// Allem does not pick a granularity: every event records the full
// decomposition, and "agent" becomes a view over it (`docs/agent-identity.md`).
//
//	identity: { principal_id, project_id, host_id, tool_id }
//
// Four rules govern everything in this file. They are `allem_cli/identity.py`'s
// rules, restated rather than imported, because the two packages must not
// depend on each other.
//
// **Nothing is invented.** A value that is not known is OMITTED, never guessed.
// `project_id` above all: a guessed one attributes one codebase's work to
// another, in an append-only log where that cannot be repaired. This package
// mints nothing -- `backend/app/services/project_view.py` distinguishes a
// project Allem issued from a token that merely arrived, and a Go SDK that
// invented ids would fill that second category.
//
// **Nothing is laundered.** The platform refuses `@`, whitespace and anything
// outside an opaque charset (`backend/app/schemas/event_sections.py`,
// `reject_personal_data`) because those are what an email, a display name and a
// git author string look like. Rewriting such a value into one that passes --
// `jane.doe@example.com` becoming `jane.doe-example.com` -- would carry the person straight
// through the check that exists to stop exactly that. So a value here either
// passes as it stands or is omitted.
//
// **A refused value costs the whole event.** The server's validation is on the
// request, not the field: one bad `identity.host_id` is a 422 for the entire
// event, and the action it described is then recorded nowhere. That is why every
// value is checked here, against the same rule, before it is sent.
//
// **Nothing is derived on this machine.** `principal_id` is
// `HMAC-SHA256(org_secret, canonical(user, host, tool))`, computed by Allem at
// provisioning under a secret that never leaves Allem
// (`docs/derived-principal.md`). This package cannot recompute it and does not
// try: an unsalted digest of a hostname is a lookup, not a secret, and that
// exact mistake was deleted from the CLI. A missing value is a true answer.
//
// # Why this exists here and not in the Python SDK
//
// `sdk/allem-python/allem/client.py` sends NO identity block at all -- the
// platform then derives `principal_id = agent_external_id` with project, host
// and tool null, and every event from that SDK appears in no project view. That
// is a gap on the Python side, not a design. It matters more for Go than it did
// then, because the meter counts `governed_projects` alongside `active_agents`
// and `governed_principals` (`backend/app/models/usage_period.py`), and
// `allem-verify --usage` recomputes those from the customer's own export: an SDK
// that does not carry `project_id` meters differently from one that does, and
// the customer's own recomputation disagrees with their invoice.
//
// So this SDK carries it, and `TestTheGoSDKSendsAnIdentityTheServerAccepts`
// covers what it sends. **This is a deliberate divergence from Python SDK
// parity, in the direction of the documented contract**, and it is recorded as
// one in `docs/go-sdk-report.md`.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The environment variables the CLI already uses for these values, so one
// install populates both connectors.
const (
	PrincipalIDEnvVar = "ALLEM_PRINCIPAL_ID"
	ProjectIDEnvVar   = "ALLEM_PROJECT_ID"
	HostIDEnvVar      = "ALLEM_HOST_ID"
	ToolIDEnvVar      = "ALLEM_TOOL_ID"
)

// pseudonymRE is the platform's `_PSEUDONYM_RE`, restated.
//
// Deliberately a copy and not a shared constant: the backend is a separate
// deployment, this package ships to customers' binaries, and a connector that
// could only be trusted against one build of the server would be worse than one
// that carries the rule it was written against. If the server ever widens the
// charset the worst this does is omit a field that would have been accepted,
// which is the safe direction to be wrong in.
var pseudonymRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:\-]{2,127}$`)

// derivedRE is the shape Allem's derivation produces: `a-`, `p-` or `h-` and 32
// hex characters (`backend/app/services/principal_derivation.py`).
var derivedRE = regexp.MustCompile(`^[aph]-[0-9a-f]{32}$`)

// IsDerived reports whether a value looks like an id Allem derived.
//
// A shape test and nothing more. It cannot tell whose secret produced the digest,
// and it never decides that a value is safe. It decides one thing: are these two
// values from the same install?
func IsDerived(value string) bool { return derivedRE.MatchString(value) }

// IsPseudonymous reports whether the platform would accept this as an identity
// value.
//
// The `@` and whitespace tests are redundant against the regex -- neither can
// match -- and are kept because they are the two rules stated in prose in
// `docs/agent-identity.md`, and a reader checking this file against that
// document should find both of them here.
func IsPseudonymous(value string) bool {
	if value == "" {
		return false
	}
	if strings.ContainsRune(value, '@') || strings.ContainsAny(value, " \t\n\r\v\f") {
		return false
	}
	return pseudonymRE.MatchString(value)
}

// Identity is WHO acted, decomposed into the four things `agent_id` used to
// bundle.
//
// Only PrincipalID is required by the server. The rest are the axes a governance
// view may group on; a source that cannot supply one omits it rather than
// guessing, and the coverage attestation records the gap.
type Identity struct {
	// PrincipalID is the acting principal: a human developer OR a service
	// account (a background agent, a PR bot, a CI runner). "Governed principal"
	// deliberately covers both, because coding agents are becoming
	// non-interactive and any identity that assumes a seated human breaks
	// exactly there.
	//
	// Derived by Allem at provisioning. Read it out of your Allem config; do
	// not compute one.
	PrincipalID string

	// ProjectID is the governance unit. Rules, scopes and freeze bind here
	// (Pricing Model v6 Gate 05), and the meter counts `governed_projects`.
	//
	// Allem-ISSUED, from a committed `.allem/project.toml`. LoadProjectID reads
	// it. Never mint your own.
	ProjectID string

	// HostID is the machine. Derived by Allem at provisioning, for the same
	// reason PrincipalID is; this package will not digest a hostname.
	HostID string

	// ToolID is what is acting -- "ci-bot", "my-service". Free-form, and the
	// one field of the four a Go integrator writes themselves.
	ToolID string
}

// LoadIdentityFromEnv reads whatever the environment carries.
//
// Nothing is invented: a variable that is unset leaves its field empty, and an
// empty field is omitted from the event rather than sent as null. The variables
// are the CLI's, so a machine where `allem init` has run already has three of the
// four.
func LoadIdentityFromEnv() Identity {
	return Identity{
		PrincipalID: strings.TrimSpace(os.Getenv(PrincipalIDEnvVar)),
		ProjectID:   strings.TrimSpace(os.Getenv(ProjectIDEnvVar)),
		HostID:      strings.TrimSpace(os.Getenv(HostIDEnvVar)),
		ToolID:      strings.TrimSpace(os.Getenv(ToolIDEnvVar)),
	}
}

// LoadProjectID reads the Allem-issued project id from `<dir>/.allem/project.toml`.
//
// Read rather than derived. A project id is issued by Allem and never computed
// from a git remote -- a repository can be renamed, forked or moved and the
// governance unit cannot follow it (`docs/agent-identity.md`).
//
// Returns "" for absent, unreadable and malformed alike: the caller can do
// nothing useful with the difference, and this must never fail an action.
//
// `dir` empty means the current working directory.
func LoadProjectID(dir string) string {
	if dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return ""
		}
		dir = cwd
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".allem", "project.toml"))
	if err != nil {
		return ""
	}
	return projectIDFromTOML(string(raw))
}

// projectIDFromTOML reads `[project] id = "..."` and nothing else.
//
// **Deliberately not a TOML parser.** This package's dependency footprint is a
// thing a Go shop reads before it reads anything else, and the file's shape is
// fixed: it is rendered from `PROJECT_TOML_TEMPLATE` in
// `backend/app/api/v1/projects.py`, by Allem, with a project id the server
// validated. Reading one key out of one table is the whole job.
//
// `[project].id`, because that is what the server writes. The CLI's reader
// looked for a top-level `project_id` for a while -- which no server has ever
// emitted -- so `allem project init` succeeded, wrote a file, and every event
// still went out with no project id.
func projectIDFromTOML(text string) string {
	inProject := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inProject = line == "[project]"
			continue
		}
		if !inProject {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "id" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			return ""
		}
		unquoted := value[1 : len(value)-1]
		unquoted = strings.ReplaceAll(unquoted, `\"`, `"`)
		unquoted = strings.ReplaceAll(unquoted, `\\`, `\`)
		return strings.TrimSpace(unquoted)
	}
	return ""
}

// block is the identity section for one event, or nil to send none.
//
// nil is an answer, not a failure: with no `identity` on the wire the platform
// derives the one it has always derived, so the event is recorded exactly as the
// Python SDK's events are. What is never done is sending a principal that had to
// be rewritten to be acceptable.
//
// `agentExternalID` is the fallback principal, exactly as in the CLI -- for any
// agent provisioned since 2026-08-18 it is itself derived (`a-...`). The
// fallback is what keeps a pre-changeover install recording exactly what it
// recorded yesterday: those events are not pseudonymous, nothing here can make
// them so, and quietly relabelling them would make the old ones LOOK
// pseudonymised when they are not.
func (i Identity) block(agentExternalID string, logf Logf) map[string]any {
	if logf == nil {
		logf = discardLogf
	}
	external := strings.TrimSpace(agentExternalID)
	principal := strings.TrimSpace(i.PrincipalID)

	// **The two values have to come from the same install.**
	//
	// A derived principal beside a name-bearing external id means the config
	// was assembled from two installs, and both go into the same chained event
	// -- a permanent, unshreddable row mapping the pseudonym to the person's
	// username. That is the one thing the derivation build exists to prevent,
	// arriving through configuration. When they disagree the pairing is not
	// trusted: the external id wins, because it is what the platform matches
	// the credential against and what the event is attributed to either way.
	if principal != "" && IsDerived(principal) && external != "" && !IsDerived(external) {
		logf(LevelWarning,
			"a derived principal_id was found beside a non-derived "+
				"agent_external_id (%q). The derived principal was dropped -- "+
				"pairing them would write a permanent row mapping the pseudonym "+
				"to the name. Re-provision this agent.", external)
		principal = ""
	}

	if principal == "" {
		principal = external
	}
	if !IsPseudonymous(principal) {
		// `principal_id` is stored VERBATIM by design -- folding it could merge
		// two people into one identity, and attributing one person's actions to
		// another is worse than splitting a group. So there is nothing safe to
		// do with a value that does not already qualify: rewriting it would
		// launder a name into the chain, and digesting it would give this agent
		// a second principal that matches none of its own earlier events.
		// Dropping the block costs the project scope for this event and nothing
		// else.
		logf(LevelWarning,
			"no principal_id the platform would accept (%q is not a pseudonym "+
				"in its charset), so this event carries the identity the server "+
				"derives. Set ALLEM_PRINCIPAL_ID from your Allem config, or "+
				"give the client an agent id that qualifies.", principal)
		return nil
	}

	block := map[string]any{"principal_id": principal}
	// Lowercased because the server lowercases these three anyway, so this is
	// the string that will actually be stored -- and checking a different string
	// from the one that is stored is how a guard ends up protecting nothing.
	// `principal_id` is NOT lowercased, deliberately: folding its case could
	// MERGE two distinct principals.
	for _, field := range []struct{ key, value string }{
		{"project_id", strings.ToLower(strings.TrimSpace(i.ProjectID))},
		{"host_id", strings.ToLower(strings.TrimSpace(i.HostID))},
		{"tool_id", strings.ToLower(strings.TrimSpace(i.ToolID))},
	} {
		if field.value == "" {
			continue
		}
		if !IsPseudonymous(field.value) {
			logf(LevelWarning,
				"identity.%s (%q) is not a value the platform accepts, so it is "+
					"omitted rather than rewritten. Rewriting it could carry a "+
					"name into an append-only record.", field.key, field.value)
			continue
		}
		// Omitted, not sent as null. Both mean "not known" to the server;
		// omitting says it in the shape that cannot be mistaken for a value.
		block[field.key] = field.value
	}
	return block
}

// IsEmpty reports whether nothing at all was configured.
func (i Identity) IsEmpty() bool {
	return strings.TrimSpace(i.PrincipalID) == "" &&
		strings.TrimSpace(i.ProjectID) == "" &&
		strings.TrimSpace(i.HostID) == "" &&
		strings.TrimSpace(i.ToolID) == ""
}
