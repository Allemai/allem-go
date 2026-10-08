package allem

// The Allem client. Two operations, and one exception the customer turns on
// themselves.
//
//	Check -- pre-flight authorization check (POST /api/v1/events/check)
//	Log   -- fire-and-forget audit log     (POST /api/v1/events)
//
// **Fail-open by design**: if the platform is unreachable, Check returns a
// verdict that ALLOWS, so an Allem outage never breaks the customer's agent. The
// action proceeds and the event is logged when connectivity returns.
//
// **With one exception the customer turns on themselves.** A scope rule marked
// `hard_gate: true` fails CLOSED, and on this package it does so LOCALLY --
// without asking anyone -- because the ratified decision is that a gate which
// only holds while Allem is up *"is not a gate, it is a gate-shaped thing that
// opens during exactly the incident it was bought for"*. See gates.go for the
// cached list that makes that possible, and `docs/approvals.md` for what a
// customer is accepting when they set the flag.
//
// That is a **Tier 1 property**. The Tier 2 coding-agent hook (`allem-cli`) does
// not block during an outage, by design and by ratification. The two stay apart
// mechanically rather than by convention: a local denial carries no event id,
// and Tier 2 treats a verdict without one as "we never got an answer" rather
// than as a denial.
//
// # Errors, and why a failed call still allows
//
// Every method that can fail returns an error, and **every error path still
// returns an ALLOWING verdict**. That is not sloppiness about error handling; it
// is the same invariant stated in a language with multiple return values. Only
// a verdict Allem returned, or the local hard gate, may deny. A malformed cause,
// a spool that cannot be written, a signing key that has gone missing -- none of
// those is evidence about whether the action is permitted, and a Go zero value
// (`Verdict{}`, `Allowed: false`) read by a caller who forgot to check the error
// would manufacture a denial out of a typo.
//
// # The tier is not this package's to declare
//
// `backend/app/services/connection_tier.py` reads the tier off the
// AUTHENTICATED CREDENTIAL at ingestion: *"naming its own tier is the credential
// rule inverted: the thing being judged says how trustworthy the judgement is."*
// So this SDK sends no field naming its own tier, and there is a test asserting
// it never will. Registering `allem-go` as a connector is a provisioning change
// -- see `docs/go-sdk-report.md`, *What the tier needs*.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultEndpoint is the hosted service.
const DefaultEndpoint = "https://api.allem.ai"

// DefaultTimeout is the per-request timeout.
const DefaultTimeout = 5 * time.Second

// Environment variables this package reads, matching the Python SDK's.
const (
	SigningKeyPathEnvVar = "ALLEM_SIGNING_KEY_PATH"
	SigningSecretEnvVar  = "ALLEM_SIGNING_SECRET"
	SpoolDirEnvVar       = "ALLEM_SPOOL_DIR"
)

// Action is one thing an agent is about to do, or has done.
type Action struct {
	// Type is the action identifier -- the thing rules match against. Required.
	Type string

	// Parameters is what the action was called with. Anything JSON-encodable.
	Parameters map[string]any

	// Description is free text for a human reading the chain. It is NOT what
	// scope rules match on: the action *description* deciding scope matching is
	// the first recorded violation of the credential rule in this codebase
	// (`fix-scope-label`).
	Description string

	// ToolCalled is the underlying tool, if one was.
	ToolCalled string

	// SessionID groups actions. Travels in `context.session_id`.
	SessionID string

	// The impact block. Pointers, because "not stated" and "zero" are different
	// answers and only one of them is a claim.
	MonetaryValue   *float64
	AffectsExternal *bool
	Reversible      *bool

	// Cause is what YOU say provoked this action. Optional, never inferred, and
	// it changes nothing about the verdict -- see cause.go. Pass it only when
	// you actually know; omitting it is a true record and a guess is not.
	Cause *Cause
}

// Option configures a Client.
type Option func(*options)

type options struct {
	endpoint           string
	timeout            time.Duration
	httpClient         httpDoer
	signingKeyPath     string
	signingSecret      string
	signer             Signer
	spoolPath          string
	spoolMaxBytes      int64
	retention          time.Duration
	hardGateTTL        time.Duration
	backgroundDelivery bool
	logf               Logf
	logfSet            bool
	identity           Identity
}

// WithEndpoint sets the base URL of the Allem API.
func WithEndpoint(endpoint string) Option {
	return func(o *options) { o.endpoint = endpoint }
}

// WithTimeout sets the per-request timeout. Ignored when WithHTTPClient is used.
func WithTimeout(timeout time.Duration) Option {
	return func(o *options) { o.timeout = timeout }
}

// WithHTTPClient supplies the HTTP client. Use it to route through a proxy, add
// tracing, or pin a TLS configuration.
//
// **The client's own Timeout still applies to every request.** A client with no
// Timeout and no per-request deadline can hang forever against a half-open
// connection, and a pre-flight check that never returns is worse than one that
// fails open.
func WithHTTPClient(client *http.Client) Option {
	return func(o *options) { o.httpClient = client }
}

// WithSigningKeyPath points at an unencrypted PKCS#8 PEM Ed25519 private key --
// the file `python -m allem.sequence --out` writes, and the one
// GenerateKeypair writes.
func WithSigningKeyPath(path string) Option {
	return func(o *options) { o.signingKeyPath = path }
}

// WithSigningSecret configures the legacy HMAC signer.
//
// **Allem cannot verify these signatures** -- it has never held this secret --
// so events are recorded as unverified. Use WithSigningKeyPath.
func WithSigningSecret(secret string) Option {
	return func(o *options) { o.signingSecret = secret }
}

// WithSigner supplies a Signer directly, for a caller whose private key lives in
// an HSM, a KMS, or anywhere else this package should not know about.
func WithSigner(signer Signer) Option {
	return func(o *options) { o.signer = signer }
}

// WithSpoolPath sets where the durable spool lives.
func WithSpoolPath(path string) Option {
	return func(o *options) { o.spoolPath = path }
}

// WithSpoolMaxBytes sets the size above which non-critical writes are refused
// and the spool logs loudly. Pending rows are never deleted to make room.
func WithSpoolMaxBytes(maxBytes int64) Option {
	return func(o *options) { o.spoolMaxBytes = maxBytes }
}

// WithSpoolRetention sets how long a DELIVERED row is kept. Unsent rows are
// never subject to it.
func WithSpoolRetention(retention time.Duration) Option {
	return func(o *options) { o.retention = retention }
}

// WithHardGateTTL overrides the staleness bound on the hard-gate cache.
//
// It does NOT decide whether a stale list still blocks. It always does.
func WithHardGateTTL(ttl time.Duration) Option {
	return func(o *options) { o.hardGateTTL = ttl }
}

// WithBackgroundDelivery starts or does not start the background sender.
//
// false spools without delivering -- for a caller that hands the spool to
// another process. Every event is still written durably before this flag is
// consulted.
func WithBackgroundDelivery(on bool) Option {
	return func(o *options) { o.backgroundDelivery = on }
}

// WithLogger routes this package's output. WithLogger(nil) silences it.
//
// Silencing is a decision the caller makes rather than one this package makes
// for them -- three of this SDK's paths are degradations that are only safe
// because somebody finds out about them. See log.go.
func WithLogger(logf Logf) Option {
	return func(o *options) { o.logf = logf; o.logfSet = true }
}

// WithIdentity sets the identity block put on every event.
//
// Nothing here is invented: an empty field is omitted rather than guessed. See
// identity.go, and LoadIdentityFromEnv / LoadProjectID for the two things a
// caller usually wants.
func WithIdentity(identity Identity) Option {
	return func(o *options) { o.identity = identity }
}

// Client is the Allem SDK client. Safe for concurrent use.
type Client struct {
	apiKey   string
	endpoint string
	http     httpDoer
	logf     Logf
	identity Identity

	signer Signer

	// Reachability is what the last HTTP attempt this client made found, and
	// when. The one definition of offline -- see delivery.go. It is a queue
	// depth in no sense whatever.
	Reachability *Reachability

	spool  *Spool
	sender *sender
	gates  *HardGateCache

	generatorsMu sync.Mutex
	generators   map[string]*SequenceGenerator

	runsMu sync.Mutex
	runs   map[string]*RunLifecycle

	closeOnce sync.Once
}

// New builds a client.
//
// apiKey is an Allem API key (`alm_sk_live_...` or `alm_sk_test_...`).
//
// **Nothing here panics and nothing starts at package init.** An unreadable
// signing key, an unwritable spool directory and a malformed endpoint are all
// returned as errors, because a governance SDK that takes down the host process
// at startup is a governance SDK that gets removed.
//
// **Go has no `atexit`.** Call Close (or `defer client.Close()`) or the run
// reports as unclosed. See heartbeat.go.
func New(apiKey string, opts ...Option) (*Client, error) {
	settings := options{
		endpoint:           DefaultEndpoint,
		timeout:            DefaultTimeout,
		backgroundDelivery: true,
	}
	for _, opt := range opts {
		opt(&settings)
	}

	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New(
			"allem: an API key is required. Nothing here falls back to an " +
				"anonymous client: an event Allem cannot attribute is an event " +
				"it cannot chain")
	}
	endpoint := trimEndpoint(strings.TrimSpace(settings.endpoint))
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}

	logf := settings.logf
	if !settings.logfSet {
		logf = defaultLogf()
	}
	if logf == nil {
		logf = discardLogf
	}

	doer := settings.httpClient
	if doer == nil {
		doer = &http.Client{Timeout: settings.timeout}
	}

	signer, err := resolveSigner(settings, logf)
	if err != nil {
		return nil, err
	}

	spool, err := OpenSpool(settings.spoolPath, settings.spoolMaxBytes, logf)
	if err != nil {
		return nil, err
	}

	client := &Client{
		apiKey:       apiKey,
		endpoint:     endpoint,
		http:         doer,
		logf:         logf,
		identity:     settings.identity,
		signer:       signer,
		Reachability: &Reachability{},
		spool:        spool,
		generators:   map[string]*SequenceGenerator{},
		runs:         map[string]*RunLifecycle{},
	}

	// Which actions must fail CLOSED when the platform does not answer. Built
	// before the sender for the same reason the HTTP client is: the sender
	// starts draining immediately, and anything it touches has to exist.
	client.gates = newHardGateCache(endpoint, apiKey, doer, settings.hardGateTTL, logf)

	// The sender starts its goroutine inside newSender and immediately drains
	// whatever the spool already holds -- including rows left over from a
	// previous process that crashed or exited while Allem was unreachable.
	client.sender = newSender(spool, client.deliver, logf, settings.retention, settings.backgroundDelivery)

	return client, nil
}

// resolveSigner picks the signer, preferring Ed25519.
//
// Ed25519 wins whenever a key path is available, and the fallback runs only when
// no key path was given at all. A deployment that sets both must not silently
// get the weaker one, and there is no path from Ed25519 down to HMAC on error:
// an unreadable key file is an error, because "signing was configured and
// quietly did not happen" is precisely the failure this layer exists to remove.
func resolveSigner(settings options, logf Logf) (Signer, error) {
	if settings.signer != nil {
		return settings.signer, nil
	}

	keyPath := settings.signingKeyPath
	if keyPath == "" {
		keyPath = os.Getenv(SigningKeyPathEnvVar)
	}
	if keyPath != "" {
		return LoadEd25519Signer(keyPath)
	}

	secret := settings.signingSecret
	if secret == "" {
		secret = os.Getenv(SigningSecretEnvVar)
	}
	if secret != "" {
		// Legacy. The server has no HMAC secret registry, so these signatures
		// are recorded as unverified. Warned once, at construction, rather than
		// per event.
		logf(LevelWarning,
			"signing with HMAC-SHA256 (%s). Allem cannot verify these signatures "+
				"-- it has never held this secret -- so events are recorded as "+
				"unverified. Generate an Ed25519 key "+
				"(allem.GenerateKeypair(\"allem-agent.key\")), register the "+
				"public half, and set %s.",
			SigningSecretEnvVar, SigningKeyPathEnvVar)
		return NewHMACSigner(secret), nil
	}
	return nil, nil
}

// Endpoint is the base URL this client talks to.
func (c *Client) Endpoint() string { return c.endpoint }

// Spool is the durable write-ahead log. Exposed so a caller can report its
// depth -- see the counts on Spool, and read their doc comments before printing
// one, because three of them answer different questions.
func (c *Client) Spool() *Spool { return c.spool }

// Gates is the hard-gate cache. Exposed for a caller that wants to warm it at
// startup rather than on the first check.
func (c *Client) Gates() *HardGateCache { return c.gates }

// sequenceFor returns one SequenceGenerator (one run id) per agent per process.
func (c *Client) sequenceFor(agentID string) (*SequenceGenerator, error) {
	c.generatorsMu.Lock()
	defer c.generatorsMu.Unlock()
	if gen, ok := c.generators[agentID]; ok {
		return gen, nil
	}
	gen, err := NewSequenceGenerator(agentID, c.signer)
	if err != nil {
		return nil, err
	}
	c.generators[agentID] = gen
	return gen, nil
}

// signPayload signs the completed payload in place, binding position AND
// content.
//
// Must be called AFTER the payload is fully built: the v2 signature covers a
// digest of the body, so it cannot exist until the body does. Safe to call with
// the unsigned sequence block already in the payload -- the digest excludes the
// `sequence` key precisely so this ordering works.
//
// **A signing failure must not lose the event.** The record is the thing that
// matters (fail-open on enforcement, fail-safe on evidence), and an unsigned
// event is a supported state the server records as `signature_verified: null`.
// So this logs and leaves the block unsigned rather than failing the caller's
// action.
func (c *Client) signPayload(payload map[string]any, agentID string, block SequenceBlock) {
	if c.signer == nil {
		return
	}
	gen, err := c.sequenceFor(agentID)
	if err != nil {
		c.logf(LevelError, "could not sign event %v (%v). Sending it unsigned; "+
			"it will be recorded as unverified, not lost.", payload["external_event_id"], err)
		return
	}
	signed, err := gen.Sign(block, payload)
	if err != nil {
		c.logf(LevelError, "could not sign event %v (%v). Sending it unsigned; "+
			"it will be recorded as unverified, not lost.", payload["external_event_id"], err)
		return
	}
	payload["sequence"] = signed.wire()
}

// deliver posts one spooled event to /events.
//
// Returns an error on failure so the sender records it and retries. The server
// dedupes on (run_id, client_seq) and external_event_id, so replays are safe.
//
// Every attempt updates Reachability, because this is the one place the
// connector learns whether the platform is answering at all. A refusal is an
// ANSWER -- PlatformRefused records the platform as reachable and still returns
// an error, so the row stays pending and the sender retries it. Only
// PlatformDidNotAnswer means offline.
func (c *Client) deliver(payload []byte) error {
	// The sender's own deadline. Its goroutine is not on anybody's latency path,
	// but a request with no bound at all is how a drain loop stops draining.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := deliverEvent(ctx, c.http, c.apiKey, c.endpoint, payload, EventsPath)
	switch {
	case err == nil:
		c.Reachability.recordAnswered("delivered")
		return nil
	default:
		if silent, ok := asDidNotAnswer(err); ok {
			c.Reachability.recordDidNotAnswer(silent.Error())
			return err
		}
		if refused, ok := asRefused(err); ok {
			c.Reachability.recordAnswered(refused.Error())
			return err
		}
		return err
	}
}

// PendingCount is how many events are written durably and not yet delivered.
//
// A local SQLite count, no network. It is a queue depth and nothing else: it
// says nothing about whether the platform is reachable. That question has one
// answer and it is on Reachability.
func (c *Client) PendingCount() (int, error) { return c.spool.PendingCount() }

// Flush blocks up to timeout while the spool drains.
//
// Returns the number of events still pending (0 = fully delivered). Useful
// before process exit and in tests; the agent never needs it.
func (c *Client) Flush(timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		remaining, err := c.spool.PendingCount()
		if err != nil {
			return 0, err
		}
		if remaining == 0 {
			return 0, nil
		}
		c.sender.Wake()
		time.Sleep(20 * time.Millisecond)
	}
	return c.spool.PendingCount()
}

// --------------------------------------------------------------------------- //
// The two operations
// --------------------------------------------------------------------------- //

// buildPayload assembles one event, reserving a sequence number.
//
// The cause is validated FIRST, before Next() consumes a client_seq: a failure
// afterwards burns a sequence number on an event that is never sent, and a burnt
// client_seq is a permanent gap in the completeness record manufactured out of a
// caller's typo.
func (c *Client) buildPayload(agentID string, action Action, eventType string) (map[string]any, SequenceBlock, error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, SequenceBlock{}, errors.New("allem: an agent id is required")
	}

	causeSection, err := causeBlock(action.Cause)
	if err != nil {
		return nil, SequenceBlock{}, err
	}

	gen, err := c.sequenceFor(agentID)
	if err != nil {
		return nil, SequenceBlock{}, err
	}
	block := gen.Next()

	parameters := action.Parameters
	if parameters == nil {
		parameters = map[string]any{}
	}
	actionSection := map[string]any{"type": action.Type, "parameters": parameters}
	if action.Description != "" {
		actionSection["description"] = action.Description
	}
	if action.ToolCalled != "" {
		actionSection["tool_called"] = action.ToolCalled
	}

	payload := map[string]any{
		// The backend treats `agent_external_id` as the canonical field; the
		// friendly public name is sent too, exactly as the Python SDK sends it,
		// so the two produce the same row.
		"agent_id":          agentID,
		"agent_external_id": agentID,
		"action":            actionSection,
		"sequence":          block.wire(),
		// Deterministic id: a retry of this exact event dedupes on the server's
		// external_event_id check before touching the chain.
		"external_event_id": block.RunID + ":" + strconv.FormatInt(block.ClientSeq, 10),
	}
	if eventType != "" {
		payload["event_type"] = eventType
	}
	if action.SessionID != "" {
		payload["context"] = map[string]any{"session_id": action.SessionID}
	}

	impact := map[string]any{}
	if action.MonetaryValue != nil {
		impact["monetary_value"] = *action.MonetaryValue
	}
	if action.AffectsExternal != nil {
		impact["affects_external"] = *action.AffectsExternal
	}
	if action.Reversible != nil {
		impact["reversible"] = *action.Reversible
	}
	if len(impact) > 0 {
		payload["impact"] = impact
	}

	// Only when the caller passed one. Nothing here fills it in.
	if causeSection != nil {
		payload["cause"] = causeSection
	}

	if identity := c.identity.block(agentID, c.logf); identity != nil {
		payload["identity"] = identity
	}

	return payload, block, nil
}

// Check asks Allem whether agentID may perform this action.
//
// On any transport failure this returns an ALLOWING verdict (fail-open), with
// the condition named in Explanation so calling code can log it -- unless the
// action is on this agent's cached hard-gate list, in which case it is denied
// locally. That denial carries no event id, on purpose.
//
// Every error path also returns an allowing verdict. See the file comment.
func (c *Client) Check(ctx context.Context, agentID string, action Action) (Verdict, error) {
	payload, block, err := c.buildPayload(agentID, action, "")
	if err != nil {
		return allowedWithoutVerdict(fmt.Sprintf(
			"Allem could not build this event (%v), so no verdict was obtained. "+
				"Allowed by default (fail-open).", err)), err
	}

	// Sign before spooling, so the bytes on disk are the bytes we send. A
	// signature added after the spool write would not survive a crash between
	// the two, and the replayed event would verify as unsigned.
	c.signPayload(payload, agentID, block)

	body, err := marshalPayload(payload)
	if err != nil {
		return allowedWithoutVerdict(fmt.Sprintf(
			"Allem could not encode this event (%v). Allowed by default "+
				"(fail-open).", err)), err
	}

	// DURABLE FIRST: the record exists on disk before anything can fail. Check
	// still waits for the verdict (that is the point of a pre-flight check) --
	// fail-open on the verdict, fail-safe on the record.
	spoolID, err := c.spool.Write(block.RunID, block.ClientSeq, body, true)
	if err != nil {
		// The evidence could not be written down. The action is still allowed
		// -- refusing it would be this package deciding an enforcement outcome
		// from its own disk -- and the caller is told, loudly, because an
		// unrecorded action is the thing they bought this to prevent.
		c.logf(LevelError,
			"could not write %q to the spool (%v). The action is ALLOWED "+
				"(fail-open) and this event may not reach Allem.", action.Type, err)
		return allowedWithoutVerdict(fmt.Sprintf(
			"Allem could not record this event locally (%v). Allowed by default "+
				"(fail-open).", err)), err
	}

	resp, err := post(ctx, c.http, c.apiKey, c.endpoint+CheckPath, body)
	if err != nil {
		if silent, ok := asDidNotAnswer(err); ok {
			// Allem did not answer. This is the ONLY path on which the local
			// hard gate can produce a denial -- and the only thing in this
			// client that means *offline*. The line is drawn in `post`, which
			// the spool's delivery path also comes through, so the check path
			// and the post path cannot end up with two meanings for one word
			// again.
			c.Reachability.recordDidNotAnswer(silent.Error())
			return c.verdictWhenUnreachable(agentID, action.Type, silent, spoolID, payload), nil
		}
		_ = c.spool.MarkFailed(spoolID, err.Error())
		c.sender.Wake()
		return allowedWithoutVerdict(fmt.Sprintf(
			"Allem could not be asked (%v). Allowed by default (fail-open).", err)), err
	}
	defer drainAndClose(resp)

	// --- The platform ANSWERED. ------------------------------------------- //
	// Recorded before we look at the body: a 401, a 500 and an unreadable
	// response are all answers. Whether they carry a verdict is a separate
	// question, decided below, and it never touches reachability.
	c.Reachability.recordAnswered(fmt.Sprintf("check returned %d", resp.StatusCode))

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || data == nil {
		reason := "an unexpected body shape"
		if err != nil {
			reason = fmt.Sprintf("a body this client could not read (%v)", err)
		}
		_ = c.spool.MarkFailed(spoolID, "check body unreadable: "+reason)
		c.sender.Wake()
		return allowedWithoutVerdict(fmt.Sprintf(
			"Allem returned HTTP %d with %s. Allowed by default (fail-open).",
			resp.StatusCode, reason)), nil
	}

	// Did Allem actually return a VERDICT, or merely a response? A 200 or a 403
	// carrying `allowed` is a verdict -- including the 403 that denies by rule,
	// which the platform chains as evidence. A 401, a 404, a 5xx, or a 403
	// refusing the CREDENTIAL carries no `allowed` key and is not a verdict
	// about the action at all.
	//
	// The distinction has to be made on the BODY, not the status. Reading
	// `data["allowed"]` off any response turned every auth failure and every 500
	// into allowed=false -- a denial manufactured from an outage, which is the
	// invariant this package exists to hold: only a verdict Allem returned, or
	// the local gate, may deny.
	_, carriesAllowed := data["allowed"]
	hasVerdict := (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden) && carriesAllowed
	if !hasVerdict {
		// Not recorded by the platform either, so the spooled record stays
		// pending and replays through /events. Marking it sent here would lose
		// the evidence for exactly the responses we understand least.
		_ = c.spool.MarkFailed(spoolID, fmt.Sprintf("check returned %d with no verdict", resp.StatusCode))
		c.sender.Wake()
		detail, _ := data["detail"].(string)
		if detail == "" {
			detail = "no detail"
		}
		if len(detail) > 200 {
			detail = detail[:200]
		}
		return allowedWithoutVerdict(fmt.Sprintf(
			"Allem returned HTTP %d without a verdict (%s). Allowed by default "+
				"(fail-open).", resp.StatusCode, detail)), nil
	}

	// The server chained the event as part of evaluating it -- delivered.
	_ = c.spool.MarkSent(spoolID)
	// A successful check is the moment to refresh the hard-gate list, per the
	// ruling. Off the latency path: this returns immediately, and a refresh that
	// mattered to THIS check would already be too late. The TTL decides whether
	// it actually reaches the network.
	c.gates.MaybeRefresh(agentID)

	return verdictFromBody(data), nil
}

func verdictFromBody(data map[string]any) Verdict {
	allowed, _ := data["allowed"].(bool)
	eventID, _ := data["event_id"].(string)
	freeze, _ := data["freeze"].(map[string]any)

	verdict := Verdict{
		Allowed:           allowed,
		EventID:           eventID,
		Severity:          "NONE",
		RecommendedAction: "NONE",
		Freeze:            freeze,
	}
	if inner, ok := data["verdict"].(map[string]any); ok {
		if v, ok := inner["explanation"].(string); ok {
			verdict.Explanation = v
		}
		if v, ok := inner["severity"].(string); ok {
			verdict.Severity = v
		}
		if v, ok := inner["recommended_action"].(string); ok {
			verdict.RecommendedAction = v
		}
	}
	return verdict
}

// verdictWhenUnreachable decides locally, from the cached gate list.
//
// Four outcomes, and only one of them denies:
//
//   - no list ever fetched  -> allow, and say so LOUDLY on every check
//   - list held, not gated  -> allow (the platform rule, unchanged)
//   - list held, gated      -> DENY locally
//   - list stale, gated     -> DENY locally anyway
//
// The last row is the one people get wrong. A stale cache does not relax the
// gate: age makes the list less COMPLETE (a rule added during the outage is
// unknown to us) but no less binding on what it already holds. The alternative
// *"silently converts the hard gate back into fail-open after an outage of any
// length."*
func (c *Client) verdictWhenUnreachable(
	agentID, actionType string, cause error, spoolID int64, payload map[string]any,
) Verdict {
	gates := c.gates.GatesFor(agentID)

	if !gates.Available {
		// The honest limit of this design. We cannot enforce a list we have
		// never fetched, and blocking everything would be absurd -- so this
		// fails open. It must be loud, and loud EVERY time: a connector that
		// quietly stops enforcing is the exact failure this package exists to
		// avoid.
		c.logf(LevelWarning,
			"Allem is unreachable (%v) and no hard-gate list has ever been "+
				"fetched for agent %q from GET %s/api/v1/agents/{agent_id}/"+
				"scopes/hard-gates. Allowing %q by default (fail-open). Hard "+
				"gates are NOT enforced locally until that list has been fetched "+
				"at least once.", cause, agentID, c.endpoint, actionType)
		_ = c.spool.MarkFailed(spoolID, cause.Error())
		c.sender.Wake()
		return allowedWithoutVerdict(fmt.Sprintf(
			"Allem unreachable (%v) and no hard-gate list has ever been fetched, "+
				"so no action can be gated locally. Allowed by default "+
				"(fail-open).", cause))
	}

	if !gates.Blocks(actionType) {
		// Not gated. The standing platform rule applies and the record catches
		// up when connectivity returns.
		_ = c.spool.MarkFailed(spoolID, cause.Error())
		c.sender.Wake()
		return allowedWithoutVerdict(fmt.Sprintf(
			"Allem unreachable (%v). Allowed by default (fail-open).", cause))
	}

	// Hard-gated, and the platform cannot be asked. Deny.
	record := c.gates.DenialRecordFor(gates)

	// Fail-open on enforcement, fail-safe on evidence: a locally-denied action
	// still reaches the chain, and it says how it was decided. "Blocked" alone
	// cannot distinguish a gate that worked from a gate that guessed.
	metadata, _ := payload["metadata"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
		payload["metadata"] = metadata
	}
	metadata["allem_local_gate"] = record.asMap()
	if amended, err := marshalPayload(payload); err == nil {
		_ = c.spool.Amend(spoolID, amended)
	} else {
		// The denial still stands. What is lost is the record of HOW it was
		// decided, which is exactly the thing this build refuses to lose
		// quietly.
		c.logf(LevelError,
			"denied %q locally and could not attach the gate record to the "+
				"spooled event (%v). The denial is correct; its provenance is "+
				"not on the row.", actionType, err)
	}
	_ = c.spool.MarkFailed(spoolID, fmt.Sprintf("blocked by local hard gate; %v", cause))
	c.sender.Wake()

	staleness := ""
	if record.CacheStale {
		staleness = fmt.Sprintf(", cache %.0fs old (bound %.0fs)",
			record.CacheAgeS, record.StalenessBoundS)
	}
	c.logf(LevelWarning,
		"Allem is unreachable (%v). %q is hard-gated for agent %q, so it was "+
			"DENIED locally (scope version %s%s). The attempt is spooled and will "+
			"reach the chain when connectivity returns.",
		cause, actionType, agentID, formatScopeVersion(record.ScopeVersion), staleness)

	return Verdict{
		Allowed: false,
		// No event id, on purpose and load-bearing. The platform issues one when
		// IT records a denial; this denial was decided here. Tier 2's
		// `is_real_deny` requires that id, so a Tier 2 consumer reading this
		// verdict still proceeds -- which is exactly the ratified
		// tier-dependent behaviour (docs/divergences.md, 2026-08-05), enforced
		// by the data rather than by both packages remembering to agree.
		EventID: "",
		Explanation: fmt.Sprintf(
			"Allem unreachable (%v). '%s' is a hard gate for this agent (scope "+
				"version %s), so it was denied locally%s.",
			cause, actionType, formatScopeVersion(record.ScopeVersion), staleness),
		Severity:          "HIGH",
		RecommendedAction: "REQUEST_APPROVAL",
		Freeze:            nil,
	}
}

// Log records an action that already happened.
//
// Never blocks on the network: the event is written durably to the local spool
// (a fast local disk write), then delivered by the background worker -- retried
// for as long as it takes. Nothing is ever silently lost.
//
// The returned error is about THIS process's ability to record, never about
// delivery. A spooled event whose delivery has not yet succeeded is not an
// error; it is the design.
//
// ctx is accepted for symmetry and cancellation of the local write. Nothing here
// waits on the network, so a cancelled context does not lose the event.
func (c *Client) Log(ctx context.Context, agentID string, action Action) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, block, err := c.buildPayload(agentID, action, "")
	if err != nil {
		return err
	}
	c.signPayload(payload, agentID, block) // bind position + content
	body, err := marshalPayload(payload)
	if err != nil {
		return err
	}
	if _, err := c.spool.Write(block.RunID, block.ClientSeq, body, true); err != nil { // DURABLE, before anything can fail
		c.logf(LevelError,
			"could not write %q to the spool (%v). This event may not reach Allem.",
			action.Type, err)
		return err
	}
	c.sender.Wake() // background send, non-blocking
	return nil
}

// --------------------------------------------------------------------------- //
// Run lifecycle
// --------------------------------------------------------------------------- //

// emitLifecycle emits one lifecycle event.
//
// The same path as Log in every respect that matters: it consumes a client_seq,
// is signed, and is spooled before any network attempt.
//
// Consuming a sequence number is the point -- it makes a **missing heartbeat
// itself a detectable gap**, so the machinery that finds lost actions finds lost
// heartbeats too.
func (c *Client) emitLifecycle(agentID, eventType string) error {
	payload, block, err := c.buildPayload(agentID, Action{Type: eventType}, eventType)
	if err != nil {
		return err
	}
	c.signPayload(payload, agentID, block)
	body, err := marshalPayload(payload)
	if err != nil {
		return err
	}
	if _, err := c.spool.Write(block.RunID, block.ClientSeq, body, true); err != nil {
		return err
	}
	c.sender.Wake()
	return nil
}

// StartRun begins a run for agentID: emits RUN_START, then beats every interval.
//
// **Call this before the agent's first action.** RUN_START must take
// client_seq = 1, and any Log/Check for this agent would consume that number
// first. This is an explicit call rather than something that happens lazily on
// first use precisely so that ordering is visible in your code instead of
// depending on it.
//
// interval <= 0 means HeartbeatInterval.
//
// **RUN_END is NOT emitted automatically.** Go has no `atexit` and this package
// installs no signal handler -- see heartbeat.go. Call Close, or EndRun, or the
// run reports as unclosed.
//
// Idempotent per agent: a second call returns the existing run rather than
// starting a second beat goroutine or burning another RUN_START.
func (c *Client) StartRun(agentID string, interval time.Duration) (*RunLifecycle, error) {
	c.runsMu.Lock()
	defer c.runsMu.Unlock()
	if existing, ok := c.runs[agentID]; ok {
		return existing, nil
	}
	run, err := newRunLifecycle(c.emitLifecycle, agentID, interval, c.logf)
	if err != nil {
		return nil, err
	}
	c.runs[agentID] = run
	return run, nil
}

// EndRun ends a run started with StartRun. Safe if none is running.
func (c *Client) EndRun(agentID string) {
	c.runsMu.Lock()
	run := c.runs[agentID]
	delete(c.runs, agentID)
	c.runsMu.Unlock()
	if run != nil {
		run.End()
	}
}

// Close stops the background sender (briefly draining the spool) and releases
// the spool handle.
//
// Anything still unsent stays durably in the spool and is replayed by the next
// process. Safe to call more than once.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		// RUN_END first, so the closing events are spooled before the sender is
		// asked to drain. Reversing this would leave every clean shutdown
		// reporting as an unclosed run.
		c.runsMu.Lock()
		runs := make([]*RunLifecycle, 0, len(c.runs))
		for _, run := range c.runs {
			runs = append(runs, run)
		}
		c.runs = map[string]*RunLifecycle{}
		c.runsMu.Unlock()
		for _, run := range runs {
			run.End()
		}

		c.gates.Close()
		c.sender.Stop(2 * time.Second)
		err = c.spool.Close()
	})
	return err
}
