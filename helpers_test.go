package allem

// Shared scaffolding.
//
// Every test here sets ALLEM_HOME and ALLEM_SPOOL_DIR to a temporary directory.
// That is not tidiness: this package's defaults are `~/.allem/state` and
// `~/.allem/spool.db`, and a test run that wrote a hard-gate cache or a spooled
// event into a developer's real Allem directory would put a fabricated row into
// a live chain's delivery queue.

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// isolate points this package's on-disk state at a temporary directory.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(HomeEnvVar, dir)
	t.Setenv(SpoolDirEnvVar, dir)
	// Both signing variables cleared: a developer running the suite with
	// ALLEM_SIGNING_KEY_PATH set in their shell would otherwise get a different
	// payload shape than CI does, and the difference is a signature block.
	t.Setenv(SigningKeyPathEnvVar, "")
	t.Setenv(SigningSecretEnvVar, "")
	t.Setenv(TTLEnvVar, "")
	return dir
}

// capturedLog collects what the SDK said, so a test can assert that a
// degradation was announced rather than merely survived.
type capturedLog struct {
	mu    sync.Mutex
	lines []string
	level []Level
}

func (c *capturedLog) logf(level Level, format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.level = append(c.level, level)
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func (c *capturedLog) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.lines))
	copy(out, c.lines)
	return out
}

func (c *capturedLog) contains(substr string) bool {
	for _, line := range c.all() {
		if containsFold(line, substr) {
			return true
		}
	}
	return false
}

// fakePlatform is an httptest server standing in for Allem.
type fakePlatform struct {
	t      *testing.T
	server *httptest.Server

	mu       sync.Mutex
	received []map[string]any
	paths    []string

	// Knobs a test turns.
	checkStatus  int
	checkBody    any
	eventsStatus int
	hardGates    []string
	scopeVersion *int64
	armed        bool
	agentID      string
	meStatus     int
	requestCount int
}

func newFakePlatform(t *testing.T) *fakePlatform {
	t.Helper()
	p := &fakePlatform{
		t:            t,
		checkStatus:  http.StatusOK,
		eventsStatus: http.StatusAccepted,
		armed:        true,
		agentID:      "0123456789abcdef01234567",
		meStatus:     http.StatusOK,
	}
	p.server = httptest.NewServer(http.HandlerFunc(p.handle))
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakePlatform) URL() string { return p.server.URL }

func (p *fakePlatform) handle(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.requestCount++
	p.paths = append(p.paths, r.Method+" "+r.URL.Path)
	p.mu.Unlock()

	switch {
	case r.URL.Path == CheckPath:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		p.mu.Lock()
		p.received = append(p.received, body)
		status, response := p.checkStatus, p.checkBody
		p.mu.Unlock()

		if response == nil {
			response = map[string]any{
				"allowed":  true,
				"event_id": "evt-from-the-platform",
				"verdict": map[string]any{
					"explanation":        "allowed by the platform",
					"severity":           "NONE",
					"recommended_action": "NONE",
				},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(response)

	case r.URL.Path == EventsPath:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		p.mu.Lock()
		p.received = append(p.received, body)
		status := p.eventsStatus
		p.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))

	case r.URL.Path == "/api/v1/agents/me":
		p.mu.Lock()
		status, agentID := p.meStatus, p.agentID
		p.mu.Unlock()
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id": agentID, "agent_external_id": "test-agent",
				"org_id": "org-1", "observation_mode": false,
			})
		}

	case hasSuffix(r.URL.Path, "/scopes/hard-gates"):
		p.mu.Lock()
		actions, version, armed := p.hardGates, p.scopeVersion, p.armed
		p.mu.Unlock()
		if actions == nil {
			actions = []string{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_id": p.agentID, "agent_external_id": "test-agent",
			"scope_version": version, "hard_gate_actions": actions, "armed": armed,
		})

	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"not found"}`))
	}
}

func (p *fakePlatform) bodies() []map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]map[string]any, len(p.received))
	copy(out, p.received)
	return out
}

func (p *fakePlatform) setHardGates(actions []string, scopeVersion int64, armed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hardGates = actions
	p.scopeVersion = &scopeVersion
	p.armed = armed
}

func (p *fakePlatform) setCheck(status int, body any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checkStatus = status
	p.checkBody = body
}

// deadEndpoint is a URL nothing listens on, so every request there is a genuine
// PlatformDidNotAnswer -- a refused connection, not a status code. It is
// obtained by starting a server and closing it, which is the only way to be
// sure the port is not in use by something else on the machine.
func deadEndpoint(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()
	return url
}

// eventually polls until cond is true or the deadline passes.
func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for: %s", within, what)
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func containsFold(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if equalFold(haystack[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// switchableDoer is how these tests unplug the network WITHOUT changing the
// endpoint.
//
// The endpoint matters: the hard-gate cache file is keyed on
// SHA-256("{endpoint}|{external_id}"), so a test that simulated an outage by
// pointing the client at a dead URL would also point it at a different cache
// file -- and would then pass through the in-memory copy while proving nothing
// about the file on disk. `TestTheCacheSurvivesAColdStart` is what caught that:
// it was the only test where the memory copy was not there to cover for it.
//
// So: one real server, one real URL, and a transport that stops answering. Every
// request while offline returns a transport error, which is what `post` turns
// into PlatformDidNotAnswer -- the same path a refused connection takes.
type switchableDoer struct {
	inner   *http.Client
	mu      sync.Mutex
	offline bool
}

func newSwitchableDoer() *switchableDoer {
	return &switchableDoer{inner: &http.Client{Timeout: 5 * time.Second}}
}

func (d *switchableDoer) Do(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	offline := d.offline
	d.mu.Unlock()
	if offline {
		// The shape a refused connection takes: no response object at all.
		return nil, &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: errConnectionRefused,
		}
	}
	return d.inner.Do(req)
}

func (d *switchableDoer) goOffline() {
	d.mu.Lock()
	d.offline = true
	d.mu.Unlock()
}

func (d *switchableDoer) goOnline() {
	d.mu.Lock()
	d.offline = false
	d.mu.Unlock()
}

var errConnectionRefused = errors.New("connection refused")

// readPackageSource concatenates every non-test .go file in this package, for
// the handful of properties that are about the ABSENCE of something and cannot
// be observed from inside a running process.
func readPackageSource(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var builder strings.Builder
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		builder.Write(raw)
		files++
	}
	if files == 0 {
		t.Fatal("no source files were read, so every assertion over the source " +
			"would pass vacuously")
	}
	return builder.String()
}

// packageImports is the set of packages this package's non-test files import.
//
// Parsed rather than grepped. A guard that matches a string matches its own
// explanatory comment, which is this repository's own finding about its own
// guards -- `docs/deploy-path-report.md`: *"a guard that matches only the shape
// a defect took the first time is a guard that certifies the next one."*
func packageImports(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	packages, err := parser.ParseDir(fset, ".", func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing this package: %v", err)
	}
	found := map[string]bool{}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			for _, spec := range file.Imports {
				found[strings.Trim(spec.Path.Value, `"`)] = true
			}
		}
	}
	return found
}
