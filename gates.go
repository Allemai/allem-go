package allem

// The hard-gate list this agent must fail CLOSED on when Allem is unreachable.
//
// Tier 1. This SDK's promise is *enforcement* -- Check/Log in the customer's
// code, every action, before it happens. The 31 July approvals ruling spells
// out what that costs during an outage:
//
//	a gate that only holds while Allem is up is not a gate, it is a
//	gate-shaped thing that opens during exactly the incident it was bought for
//
// So the list has to be here already, on local disk, before the incident
// starts. This file holds it.
//
//	GET {endpoint}/api/v1/agents/me                       -> canonical agent id
//	GET {endpoint}/api/v1/agents/{id}/scopes/hard-gates   -> the list
//
// `/agents/me` exists because an agent key cannot read the roster and so could
// not previously resolve its own canonical id, which is what the hard-gates
// endpoint is keyed on. `allem_cli/gates.py` documents that gap and falls back
// to its built-in floor. **That fallback is a Tier 2 answer.** Here the same gap
// means failing open on a hard gate, which is the failure this file exists to
// prevent, so the SDK resolves its id properly or says loudly that it cannot.
//
// This mirrors `sdk/allem-python/allem/gates.py` and deliberately shares no
// code with `allem-cli`. The packages must not depend on each other in either
// direction: they ship separately, they make different promises, and shared
// code would let a Tier 2 change silently alter Tier 1 enforcement. Python
// keeps them apart by duplication on purpose; Go does too.
//
// **Staleness does not relax the gate.** A cache older than the TTL keeps
// blocking every action already on its list. From the ruling: *"the alternative
// silently converts the hard gate back into fail-open after an outage of any
// length."* Age makes the list less COMPLETE -- a rule added during the outage
// is unknown to us -- not less binding.
//
// Where the cache lives is a real question in this package, unlike in the CLI.
// The SDK runs inside the customer's process: a container, a Lambda, a
// read-only root filesystem. A directory we cannot write must not become "no
// gate", so it degrades to an in-memory cache for the process lifetime and logs
// once. That is a real cost -- the list must be refetched on every cold start --
// and an acceptable one. Check is never failed because a cache file could not be
// written; the gate is the point, the file is an optimisation.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// DefaultHardGateTTL is how long a cached list is used before a refresh is
// attempted, and the bound past which it counts as stale in the evidence.
//
// Same default and same environment variable as Tier 2 -- a customer tuning one
// should not find the other behaving differently.
const DefaultHardGateTTL = 300 * time.Second

// HardGateFetchTimeout bounds the two requests that build the list.
//
// **A divergence from the Python SDK, recorded rather than hidden.**
// `sdk/allem-python/allem/gates.py` declares `FETCH_TIMEOUT_S = 3.0` and never
// uses it -- its refresh runs on the client's own httpx instance and inherits
// the 5-second request timeout. `allem_cli/gates.py` declares the same constant
// and does pass it. This SDK uses it, because a background refresh that hangs
// for five seconds against an endpoint that is half-up is five seconds of a
// goroutine holding a connection, and because a declared bound that binds
// nothing is the shape of defect this repository keeps finding.
const HardGateFetchTimeout = 3 * time.Second

// TTLEnvVar is the environment variable that overrides DefaultHardGateTTL.
const TTLEnvVar = "ALLEM_HARD_GATE_TTL_S"

// HomeEnvVar names the per-user Allem directory. It matches the CLI's variable
// so one setting moves both packages' state together.
const HomeEnvVar = "ALLEM_HOME"

// ttlSeconds is read at call time so a host application can set the variable
// after this package is initialised.
func ttlSeconds() time.Duration {
	raw := os.Getenv(TTLEnvVar)
	if raw == "" {
		return DefaultHardGateTTL
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value <= 0 {
		return DefaultHardGateTTL
	}
	return time.Duration(value * float64(time.Second))
}

// AllemHome is the per-user Allem directory.
func AllemHome() string {
	if home := os.Getenv(HomeEnvVar); home != "" {
		return home
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return ".allem"
	}
	return filepath.Join(userHome, ".allem")
}

// StateDir is where the hard-gate cache lives.
func StateDir() string { return filepath.Join(AllemHome(), "state") }

// Gates is one agent's hard-gate list, and how much to trust its completeness.
//
// Available is the distinction everything turns on. False means no list has
// EVER been fetched -- we do not know what is gated, so nothing can be gated
// locally and the SDK must say so on every check. It does not mean "stale": a
// stale list is still Available and still blocks.
type Gates struct {
	Actions map[string]bool
	// ScopeVersion is nil when the agent has no active scope version. That is a
	// complete answer -- nothing is hard-gated -- and not an error.
	ScopeVersion *int64
	FetchedAt    time.Time
	Available    bool
	Note         string

	// Armed mirrors the endpoint's `armed` flag (appendix A3). An organization
	// that does not require agent keys has hard gates that degrade to
	// fail-open, because the acting agent on a check may be named by a request
	// body rather than proved by a credential. Recorded rather than hidden.
	Armed bool
}

// neverFetched is the honest limit of the design: nothing was ever fetched, so
// nothing is known to be gated. The SDK fails open here -- loudly, on every
// check.
func neverFetched() Gates {
	return Gates{
		Actions:   map[string]bool{},
		Available: false,
		Note:      "no hard-gate list has ever been fetched",
		Armed:     true,
	}
}

// Staleness is how long ago the list was fetched.
func (g Gates) Staleness(now time.Time) time.Duration {
	if !g.Available {
		return 0
	}
	if now.IsZero() {
		now = time.Now()
	}
	age := now.Sub(g.FetchedAt)
	if age < 0 {
		return 0
	}
	return age
}

// IsStale reports whether the list is older than the bound.
//
// A list that was never fetched is NOT stale -- it is absent, which is a
// different fact and is reported as one.
func (g Gates) IsStale(ttl time.Duration, now time.Time) bool {
	if !g.Available {
		return false
	}
	if ttl <= 0 {
		ttl = ttlSeconds()
	}
	return g.Staleness(now) > ttl
}

// Blocks reports whether this action must be denied locally when Allem is
// unreachable.
//
// Note what is NOT consulted: IsStale. That is the whole ruling in one line --
// an entry already on the list keeps blocking however old the list is. Note
// what IS consulted: Armed. An unarmed gate was never in force while the
// platform was up, so it cannot start being in force because the platform went
// down.
func (g Gates) Blocks(actionType string) bool {
	return g.Available && g.Armed && g.Actions[actionType]
}

// SortedActions is the gated action labels, in a stable order.
func (g Gates) SortedActions() []string {
	out := make([]string, 0, len(g.Actions))
	for action := range g.Actions {
		out = append(out, action)
	}
	sort.Strings(out)
	return out
}

// DenialRecord is what an auditor needs to tell a gate that worked from one
// that guessed.
//
// "Blocked" alone does not distinguish them. "Blocked locally, cache from scope
// version 7, 40 minutes stale" does. The field names are the Python SDK's,
// because the record travels in `metadata.allem_local_gate` and an auditor
// reading two agents' events must not find two schemas.
type DenialRecord struct {
	BlockedBy         string  `json:"blocked_by"`
	ScopeVersion      *int64  `json:"scope_version"`
	CacheStale        bool    `json:"cache_stale"`
	CacheAgeS         float64 `json:"cache_age_s"`
	StalenessBoundS   float64 `json:"staleness_bound_s"`
	CacheSource       string  `json:"cache_source"`
	CacheInMemoryOnly bool    `json:"cache_in_memory_only"`
}

// asMap is what actually travels on the wire, so the Go and Python rows are
// byte-comparable after JSON encoding.
func (r DenialRecord) asMap() map[string]any {
	return map[string]any{
		"blocked_by":           r.BlockedBy,
		"scope_version":        r.ScopeVersion,
		"cache_stale":          r.CacheStale,
		"cache_age_s":          r.CacheAgeS,
		"staleness_bound_s":    r.StalenessBoundS,
		"cache_source":         r.CacheSource,
		"cache_in_memory_only": r.CacheInMemoryOnly,
	}
}

// HardGateCache holds per-agent hard-gate lists for one client.
//
// One Client can check several agents (it already keeps a sequence generator
// per agent), so everything here is keyed by the agent's external id -- the
// identifier the caller passes to Check.
//
// Every method is safe to call from the fail path. Nothing panics, nothing
// blocks on the network, and nothing here can turn a transport failure into a
// denial.
type HardGateCache struct {
	endpoint    string
	apiKey      string
	doer        httpDoer
	ttlOverride time.Duration
	logf        Logf

	mu       sync.Mutex
	gates    map[string]Gates
	agentIDs map[string]string
	inFlight map[string]bool

	diskOK     bool
	diskWarned bool

	// Closed when the cache is shut down, so a refresh goroutine started just
	// before Close does not outlive the client it belongs to.
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func newHardGateCache(endpoint, apiKey string, doer httpDoer, ttl time.Duration, logf Logf) *HardGateCache {
	if logf == nil {
		logf = discardLogf
	}
	return &HardGateCache{
		endpoint:    trimEndpoint(endpoint),
		apiKey:      apiKey,
		doer:        doer,
		ttlOverride: ttl,
		logf:        logf,
		gates:       map[string]Gates{},
		agentIDs:    map[string]string{},
		inFlight:    map[string]bool{},
		diskOK:      true,
		stop:        make(chan struct{}),
	}
}

// TTL is the staleness bound in force.
func (c *HardGateCache) TTL() time.Duration {
	if c.ttlOverride > 0 {
		return c.ttlOverride
	}
	return ttlSeconds()
}

// GatesFor is the list we hold right now. No network, never fails.
//
// Called on the unreachable path, immediately after a request has already
// failed, so it must not attempt one itself.
func (c *HardGateCache) GatesFor(agentExternalID string) Gates {
	c.mu.Lock()
	cached, ok := c.gates[agentExternalID]
	c.mu.Unlock()
	if ok {
		return cached
	}

	loaded := c.loadFromDisk(agentExternalID)

	c.mu.Lock()
	defer c.mu.Unlock()
	// Another goroutine may have refreshed while we read the file; a live fetch
	// always beats a disk read.
	if existing, ok := c.gates[agentExternalID]; ok {
		return existing
	}
	c.gates[agentExternalID] = loaded
	return loaded
}

// MaybeRefresh is called after every successful Check, off the latency path.
//
// The ruling asks for a refresh on every successful check; the TTL decides
// whether that attempt reaches the network. Both are in the spec and this is the
// only reading where the TTL means anything -- otherwise every check would carry
// a second HTTP request. So: every check offers a refresh, a fresh cache
// declines it.
//
// Returns immediately. The caller has already returned its verdict; a refresh
// that mattered to THIS check would have been too late anyway.
func (c *HardGateCache) MaybeRefresh(agentExternalID string) {
	select {
	case <-c.stop:
		return
	default:
	}

	c.mu.Lock()
	if c.inFlight[agentExternalID] {
		c.mu.Unlock()
		return
	}
	current, ok := c.gates[agentExternalID]
	if ok && current.Available && !current.IsStale(c.TTL(), time.Now()) {
		c.mu.Unlock()
		return
	}
	c.inFlight[agentExternalID] = true
	c.wg.Add(1)
	c.mu.Unlock()

	go func() {
		defer c.wg.Done()
		defer func() {
			c.mu.Lock()
			delete(c.inFlight, agentExternalID)
			c.mu.Unlock()
		}()
		c.Refresh(agentExternalID)
	}()
}

// Refresh fetches and caches the list. It never returns an error to the caller.
//
// A failure leaves whatever we already hold in place -- it does not reset the
// cache to "never fetched". Losing a good list because one refresh failed would
// convert a working gate into a fail-open gate, which is the bug this file
// exists to prevent.
func (c *HardGateCache) Refresh(agentExternalID string) Gates {
	ctx, cancel := context.WithTimeout(context.Background(), HardGateFetchTimeout)
	defer cancel()

	gates, err := c.refreshInner(ctx, agentExternalID)
	if err != nil {
		c.logf(LevelWarning,
			"hard-gate refresh failed for agent %q: %v. Continuing on the list "+
				"already cached.", agentExternalID, err)
		return c.GatesFor(agentExternalID)
	}
	return gates
}

func (c *HardGateCache) refreshInner(ctx context.Context, agentExternalID string) (Gates, error) {
	agentID, how := c.resolveAgentID(ctx, agentExternalID)
	if agentID == "" {
		// **The loud failure.** `allem_cli/gates.py` falls back to a built-in
		// floor here; that is a Tier 2 answer. On Tier 1 the same gap means
		// failing OPEN on a hard gate, so it is said out loud rather than
		// papered over with a list nobody configured.
		c.logf(LevelWarning,
			"could not resolve a canonical agent id for %q (%s). The hard-gate "+
				"list cannot be fetched, so hard gates will NOT block locally "+
				"while Allem is unreachable.", agentExternalID, how)
		return c.GatesFor(agentExternalID), nil
	}

	resp, err := c.get(ctx, fmt.Sprintf("%s/api/v1/agents/%s/scopes/hard-gates", c.endpoint, agentID))
	if err != nil {
		return Gates{}, err
	}
	defer drainAndClose(resp)

	if resp.StatusCode >= 300 {
		c.logf(LevelWarning,
			"hard-gate list for %q returned HTTP %d. Continuing on the list "+
				"already cached.", agentExternalID, resp.StatusCode)
		return c.GatesFor(agentExternalID), nil
	}

	var body struct {
		ScopeVersion    *int64   `json:"scope_version"`
		HardGateActions []string `json:"hard_gate_actions"`
		Armed           *bool    `json:"armed"`
		AgentExternalID string   `json:"agent_external_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Gates{}, fmt.Errorf("hard-gate response was not an object: %w", err)
	}

	actions := make(map[string]bool, len(body.HardGateActions))
	for _, action := range body.HardGateActions {
		if action != "" {
			actions[action] = true
		}
	}
	armed := true
	if body.Armed != nil {
		armed = *body.Armed
	}
	gates := Gates{
		Actions:      actions,
		ScopeVersion: body.ScopeVersion,
		FetchedAt:    time.Now(),
		Available:    true,
		Note:         "fetched",
		Armed:        armed,
	}

	c.mu.Lock()
	c.gates[agentExternalID] = gates
	c.agentIDs[agentExternalID] = agentID
	c.mu.Unlock()

	c.writeToDisk(agentExternalID, agentID, gates)
	c.logf(LevelDebug, "hard gates for %q: %v (scope version %s, resolved via %s)",
		agentExternalID, gates.SortedActions(), formatScopeVersion(gates.ScopeVersion), how)
	return gates, nil
}

func formatScopeVersion(v *int64) string {
	if v == nil {
		return "none"
	}
	return strconv.FormatInt(*v, 10)
}

func (c *HardGateCache) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("User-Agent", userAgent())
	return c.doer.Do(req)
}

// resolveAgentID returns (agentID, how). Memory, then disk, then the platform.
//
// `/agents/me` is the agent-key path and the reason that endpoint exists. The
// roster is the org-key path: an org key is refused by `/agents/me` -- it is not
// any one agent -- but it may list agents, so it resolves the same id a
// different way.
func (c *HardGateCache) resolveAgentID(ctx context.Context, agentExternalID string) (string, string) {
	c.mu.Lock()
	known := c.agentIDs[agentExternalID]
	c.mu.Unlock()
	if known != "" {
		return known, "cache"
	}

	if cached := c.agentIDFromDisk(agentExternalID); cached != "" {
		c.mu.Lock()
		c.agentIDs[agentExternalID] = cached
		c.mu.Unlock()
		return cached, "disk"
	}

	resp, err := c.get(ctx, c.endpoint+"/api/v1/agents/me")
	if err != nil {
		// An unreachable endpoint returns no id and a reason, never a denial.
		return "", fmt.Sprintf("/agents/me unreachable (%v)", err)
	}
	defer drainAndClose(resp)

	switch {
	case resp.StatusCode == http.StatusOK:
		var body struct {
			AgentID         string `json:"agent_id"`
			AgentExternalID string `json:"agent_external_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return "", "/agents/me returned a malformed response"
		}
		if body.AgentID == "" {
			return "", "/agents/me returned no agent_id"
		}
		if body.AgentExternalID != "" && body.AgentExternalID != agentExternalID {
			// The key belongs to a different agent than the one being checked.
			// Using its id would cache one agent's gates under another's name
			// -- silently enforcing the wrong rules.
			return "", fmt.Sprintf(
				"this agent key identifies as %q, not %q", body.AgentExternalID, agentExternalID)
		}
		return body.AgentID, "/agents/me"

	case resp.StatusCode == http.StatusForbidden:
		// Not an agent key. An org key can still resolve it via the roster.
		return c.resolveViaRoster(ctx, agentExternalID)

	default:
		return "", fmt.Sprintf("/agents/me returned %d", resp.StatusCode)
	}
}

func (c *HardGateCache) resolveViaRoster(ctx context.Context, agentExternalID string) (string, string) {
	resp, err := c.get(ctx, c.endpoint+"/api/v1/agents?limit=2000")
	if err != nil {
		return "", fmt.Sprintf("roster unreachable (%v)", err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode >= 300 {
		return "", fmt.Sprintf("roster returned %d", resp.StatusCode)
	}
	var agents []struct {
		ID         string `json:"id"`
		ExternalID string `json:"external_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		return "", "roster returned a malformed response"
	}
	for _, agent := range agents {
		if agent.ExternalID == agentExternalID && agent.ID != "" {
			return agent.ID, "roster"
		}
	}
	return "", fmt.Sprintf("no agent registered as %q yet", agentExternalID)
}

// --------------------------------------------------------------------------- //
// Disk
// --------------------------------------------------------------------------- //

// diskRecord is the on-disk form. Field names match the Python SDK's and the
// CLI's, byte for byte: all three write `{StateDir}/hard-gates-{digest}.json`
// for the same (endpoint, agent), so a list one of them fetched is a list the
// others can read. That is a shared FILE FORMAT and not shared code -- the
// packages still import nothing from each other.
type diskRecord struct {
	AgentID         string   `json:"agent_id"`
	AgentExternalID string   `json:"agent_external_id"`
	ScopeVersion    *int64   `json:"scope_version"`
	HardGateActions []string `json:"hard_gate_actions"`
	Armed           *bool    `json:"armed"`
	FetchedAt       float64  `json:"fetched_at"`
}

// cachePath is one file per (endpoint, agent). Hashed so an endpoint or an
// identifier containing a slash cannot escape the state directory.
func (c *HardGateCache) cachePath(agentExternalID string) string {
	sum := sha256.Sum256([]byte(c.endpoint + "|" + agentExternalID))
	return filepath.Join(StateDir(), "hard-gates-"+hex.EncodeToString(sum[:])[:16]+".json")
}

// degradeToMemory: a read-only filesystem must not become "no gate".
func (c *HardGateCache) degradeToMemory(err error) {
	c.mu.Lock()
	c.diskOK = false
	warn := !c.diskWarned
	c.diskWarned = true
	c.mu.Unlock()
	if warn {
		c.logf(LevelWarning,
			"cannot write the hard-gate cache to %s (%v). Keeping the list in "+
				"memory for this process instead. Hard gates still block "+
				"locally; they must be refetched on each cold start.",
			StateDir(), err)
	}
}

func (c *HardGateCache) writeToDisk(agentExternalID, agentID string, gates Gates) {
	c.mu.Lock()
	ok := c.diskOK
	c.mu.Unlock()
	if !ok {
		return
	}

	armed := gates.Armed
	record := diskRecord{
		AgentID:         agentID,
		AgentExternalID: agentExternalID,
		ScopeVersion:    gates.ScopeVersion,
		HardGateActions: gates.SortedActions(),
		Armed:           &armed,
		FetchedAt:       float64(gates.FetchedAt.UnixNano()) / 1e9,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		c.degradeToMemory(err)
		return
	}

	path := c.cachePath(agentExternalID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		c.degradeToMemory(err)
		return
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		c.degradeToMemory(err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		c.degradeToMemory(err)
		return
	}
	// Atomic -- a half-written cache must never be read.
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		c.degradeToMemory(err)
		return
	}
	if err := os.Chmod(path, 0o600); err != nil {
		c.degradeToMemory(err)
	}
}

func (c *HardGateCache) readRecord(agentExternalID string) *diskRecord {
	raw, err := os.ReadFile(c.cachePath(agentExternalID))
	if err != nil {
		return nil
	}
	var record diskRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil
	}
	return &record
}

func (c *HardGateCache) loadFromDisk(agentExternalID string) Gates {
	record := c.readRecord(agentExternalID)
	if record == nil || record.HardGateActions == nil {
		return neverFetched()
	}
	actions := make(map[string]bool, len(record.HardGateActions))
	for _, action := range record.HardGateActions {
		if action != "" {
			actions[action] = true
		}
	}
	armed := true
	if record.Armed != nil {
		armed = *record.Armed
	}
	sec := int64(record.FetchedAt)
	return Gates{
		Actions:      actions,
		ScopeVersion: record.ScopeVersion,
		FetchedAt:    time.Unix(sec, int64((record.FetchedAt-float64(sec))*1e9)),
		Available:    true,
		Note:         "loaded from cache on disk",
		Armed:        armed,
	}
}

func (c *HardGateCache) agentIDFromDisk(agentExternalID string) string {
	record := c.readRecord(agentExternalID)
	if record == nil {
		return ""
	}
	return record.AgentID
}

// DenialRecordFor builds the evidence for one local denial.
func (c *HardGateCache) DenialRecordFor(gates Gates) DenialRecord {
	now := time.Now()
	c.mu.Lock()
	inMemoryOnly := !c.diskOK
	c.mu.Unlock()

	ttl := c.TTL()
	return DenialRecord{
		BlockedBy:         "local_hard_gate",
		ScopeVersion:      gates.ScopeVersion,
		CacheStale:        gates.IsStale(ttl, now),
		CacheAgeS:         roundTo(gates.Staleness(now).Seconds(), 3),
		StalenessBoundS:   ttl.Seconds(),
		CacheSource:       gates.Note,
		CacheInMemoryOnly: inMemoryOnly,
	}
}

// Close stops accepting refreshes and waits for the ones in flight.
func (c *HardGateCache) Close() {
	c.stopOnce.Do(func() { close(c.stop) })
	c.wg.Wait()
}

func roundTo(value float64, places int) float64 {
	shift := 1.0
	for i := 0; i < places; i++ {
		shift *= 10
	}
	rounded := float64(int64(value*shift + 0.5))
	if value < 0 {
		rounded = float64(int64(value*shift - 0.5))
	}
	return rounded / shift
}

func trimEndpoint(endpoint string) string {
	for len(endpoint) > 0 && endpoint[len(endpoint)-1] == '/' {
		endpoint = endpoint[:len(endpoint)-1]
	}
	return endpoint
}
