package allem

// The Go canonical encoder, checked against the Python package it must match.
//
// `canonicaljson.go` is a reimplementation of `canonicaljson.encode_canonical_json`.
// The Python SDK deliberately refuses to reimplement it, for a reason that
// applies here with more force rather than less:
//
//	A hand-rolled encoder that agreed with the server on every payload anyone
//	tested and disagreed on one customer's unicode key would surface as
//	intermittent `signature_verified: false` on a live agent, which is the
//	most expensive possible place to discover an encoder bug.
//
// Go has no such package, so the encoder had to be written. This file is what
// makes the claim "it agrees" mean something: it runs the actual Python package
// over a corpus and compares bytes. The corpus is built around the places a
// reimplementation plausibly goes wrong -- key ordering across the astral
// plane, control characters, the characters Go escapes and Python does not, and
// the float exponent thresholds -- plus a seeded pseudo-random sweep, because a
// hand-picked corpus only ever contains the mistakes its author thought of.
//
// **It does not silently skip.** `the-red-gate` established that a skipped
// check and a passing check are indistinguishable in the place people read
// them. With `ALLEM_REQUIRE_PYTHON_PARITY=1` -- which CI sets and
// `run-go-sdk.sh` sets -- a missing Python or a missing package is a FAILURE
// that names itself. Without it the test skips, because a customer running
// `go test ./...` on a machine with no Allem checkout has no Python to run and
// no way to obtain one.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type pyCase struct {
	ID   string `json:"id"`
	Expr string `json:"expr,omitempty"`
	F64  string `json:"f64,omitempty"`

	// Not sent to Python.
	value any    `json:"-"`
	repr  string `json:"-"`
}

type pyResult struct {
	ID    string `json:"id"`
	Hex   string `json:"hex"`
	Repr  string `json:"repr"`
	Error string `json:"error"`
}

// pythonInterpreter finds an interpreter that can import `canonicaljson`.
//
// Ordered from most deliberate to least: an operator's explicit choice, then
// the backend's virtualenv (which has the package because the server signs with
// it), then the SDK's own, then whatever `python3` is. A mismatch between the
// package the server uses and the package this test uses would make the whole
// comparison vacuous, so the backend's venv is preferred over a system install.
func pythonInterpreter(t *testing.T) string {
	t.Helper()
	repo := repoRoot(t)
	candidates := []string{
		os.Getenv("ALLEM_PYTHON"),
		filepath.Join(repo, "backend", ".venv", "bin", "python"),
		filepath.Join(repo, "sdk", "allem-python", ".venv", "bin", "python"),
		"python3",
	}
	var tried []string
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		path, err := exec.LookPath(candidate)
		if err != nil {
			tried = append(tried, fmt.Sprintf("%s (not found)", candidate))
			continue
		}
		cmd := exec.Command(path, "-c", "import canonicaljson")
		if out, err := cmd.CombinedOutput(); err != nil {
			tried = append(tried, fmt.Sprintf("%s (no canonicaljson: %s)", candidate, firstLine(string(out))))
			continue
		}
		return path
	}

	message := "no Python interpreter with `canonicaljson` was found, so the Go " +
		"canonical encoder was NOT compared against the package it must match.\n" +
		"  tried: " + strings.Join(tried, "\n         ") + "\n" +
		"  fix:   ALLEM_PYTHON=/path/to/python go test ./...  (or `cd backend && uv sync`)"
	if os.Getenv("ALLEM_REQUIRE_PYTHON_PARITY") == "1" {
		t.Fatalf("%s\n  ALLEM_REQUIRE_PYTHON_PARITY=1 is set, so this is a failure "+
			"rather than a skip: a check that quietly stops running reads as a "+
			"check that passed.", message)
	}
	t.Skipf("%s\n  (set ALLEM_REQUIRE_PYTHON_PARITY=1 to make this a failure)", message)
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// sdk/allem-go -> sdk -> repo root
	return filepath.Dir(filepath.Dir(dir))
}

// runPython hands the corpus to the comparison script and reads the answers.
func runPython(t *testing.T, cases []pyCase) map[string]pyResult {
	t.Helper()
	python := pythonInterpreter(t)

	var stdin bytes.Buffer
	for _, c := range cases {
		line, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshalling case %s: %v", c.ID, err)
		}
		stdin.Write(line)
		stdin.WriteByte('\n')
	}

	cmd := exec.Command(python, filepath.Join("testdata", "canonical_compare.py"))
	cmd.Stdin = &stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("the comparison script failed (%v)\nstderr:\n%s", err, stderr.String())
	}

	results := make(map[string]pyResult, len(cases))
	scanner := bufio.NewScanner(&stdout)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for scanner.Scan() {
		var r pyResult
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			t.Fatalf("unreadable line from the comparison script: %v", err)
		}
		results[r.ID] = r
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading the comparison script: %v", err)
	}
	if len(results) != len(cases) {
		t.Fatalf("sent %d cases and got %d answers back -- the corpus and the "+
			"comparison are not the same population", len(cases), len(results))
	}
	return results
}

// --------------------------------------------------------------------------- //
// The corpus
// --------------------------------------------------------------------------- //
// Every entry is here because a reimplementation could plausibly get it wrong,
// and the comment says which way.
func handPickedCases() []pyCase {
	return []pyCase{
		// -- shape --------------------------------------------------------- //
		{ID: "empty-object", Expr: `{}`, value: map[string]any{}},
		{ID: "empty-array", Expr: `[]`, value: []any{}},
		{ID: "null", Expr: `None`, value: nil},
		{ID: "true", Expr: `True`, value: true},
		{ID: "false", Expr: `False`, value: false},
		{ID: "no-whitespace", Expr: `{"a": 1, "b": [1, 2]}`,
			value: map[string]any{"a": 1, "b": []any{1, 2}}},
		{ID: "nested", Expr: `{"a": {"b": {"c": [1, {"d": None}]}}}`,
			value: map[string]any{"a": map[string]any{"b": map[string]any{"c": []any{1, map[string]any{"d": nil}}}}},
		},

		// -- key ordering -------------------------------------------------- //
		// Sorted by Unicode code point. Go's byte-wise string comparison over
		// UTF-8 is the same order; this is what proves it rather than assuming it.
		{ID: "keys-ascii", Expr: `{"b": 1, "a": 2, "C": 3, "_": 4}`,
			value: map[string]any{"b": 1, "a": 2, "C": 3, "_": 4}},
		// THE astral-plane case. RFC 8785 sorts by UTF-16 code unit and would
		// put U+10000 first; Matrix Canonical JSON sorts by code point and puts
		// U+FFFF first. `backend/app/services/canonical.py` names exactly this
		// pair as the measured difference.
		{ID: "keys-astral", Expr: `{"￿": 1, "\U00010000": 2}`,
			value: map[string]any{"￿": 1, "\U00010000": 2}},
		{ID: "keys-mixed-scripts", Expr: `{"z": 1, "é": 2, "a": 3, "中": 4}`,
			value: map[string]any{"z": 1, "é": 2, "a": 3, "中": 4}},
		{ID: "keys-empty-string", Expr: `{"": 1, "a": 2}`,
			value: map[string]any{"": 1, "a": 2}},
		{ID: "keys-prefix", Expr: `{"ab": 1, "a": 2, "abc": 3}`,
			value: map[string]any{"ab": 1, "a": 2, "abc": 3}},

		// -- string escaping ------------------------------------------------ //
		{ID: "escape-quote-backslash", Expr: `{"k": "a\"b\\c"}`,
			value: map[string]any{"k": `a"b\c`}},
		{ID: "escape-two-char", Expr: `{"k": "\b\f\n\r\t"}`,
			value: map[string]any{"k": "\b\f\n\r\t"}},
		// Lowercase hex in `\u00xx`. CPython indexes `Py_hexdigits`, which is
		// "0123456789abcdef"; an implementation reaching for %X gets this wrong
		// only for the four controls above 0x09 that have no short form.
		{ID: "escape-controls", Expr: `{"k": "\x00\x01\x0b\x0e\x1f"}`,
			value: map[string]any{"k": "\x00\x01\x0b\x0e\x1f"}},
		// NOT escaped by Python. Go's encoding/json escapes all three by
		// default (SetEscapeHTML), which is why this encoder does not use it.
		{ID: "no-html-escape", Expr: `{"k": "<&>"}`,
			value: map[string]any{"k": "<&>"}},
		// NOT escaped by Python. Go's encoding/json escapes both
		// unconditionally -- SetEscapeHTML(false) does not turn it off.
		{ID: "no-line-separator-escape", Expr: `{"k": "  "}`,
			value: map[string]any{"k": "  "}},
		{ID: "no-solidus-escape", Expr: `{"k": "a/b"}`,
			value: map[string]any{"k": "a/b"}},
		{ID: "delete-char-literal", Expr: `{"k": "\x7f"}`,
			value: map[string]any{"k": "\x7f"}},
		// `ensure_ascii=False`: written through as UTF-8, not as \uXXXX.
		{ID: "non-ascii-literal", Expr: `{"k": "é中\U0001f600"}`,
			value: map[string]any{"k": "é中😀"}},

		// -- integers -------------------------------------------------------- //
		{ID: "int-zero", Expr: `{"k": 0}`, value: map[string]any{"k": 0}},
		{ID: "int-negative", Expr: `{"k": -42}`, value: map[string]any{"k": -42}},
		{ID: "int-int64-max", Expr: `{"k": 9223372036854775807}`,
			value: map[string]any{"k": int64(math.MaxInt64)}},
		{ID: "int-int64-min", Expr: `{"k": -9223372036854775808}`,
			value: map[string]any{"k": int64(math.MinInt64)}},
		{ID: "int-uint64-max", Expr: `{"k": 18446744073709551615}`,
			value: map[string]any{"k": uint64(math.MaxUint64)}},
		// The integer RFC 8785 cannot represent and Matrix Canonical JSON can.
		// Only reachable in Go through json.Number, which is why that path exists.
		{ID: "int-beyond-float64", Expr: `{"k": 9007199254740993}`,
			value: map[string]any{"k": json.Number("9007199254740993")}},
		{ID: "int-huge", Expr: `{"k": 123456789012345678901234567890}`,
			value: map[string]any{"k": json.Number("123456789012345678901234567890")}},

		// -- floats: the exponent thresholds -------------------------------- //
		// CPython: exponent form when decpt <= -4 or decpt > 16. Go's shortest
		// %g switches at 6, so everything from here to "float-1e15" is a place
		// the obvious Go implementation disagrees.
		{ID: "float-1.0", Expr: `{"k": 1.0}`, value: map[string]any{"k": 1.0}},
		{ID: "float-neg-zero", Expr: `{"k": -0.0}`, value: map[string]any{"k": math.Copysign(0, -1)}},
		{ID: "float-1234567", Expr: `{"k": 1234567.0}`, value: map[string]any{"k": 1234567.0}},
		{ID: "float-1e15", Expr: `{"k": 1e15}`, value: map[string]any{"k": 1e15}},
		{ID: "float-1e16", Expr: `{"k": 1e16}`, value: map[string]any{"k": 1e16}},
		{ID: "float-1e17", Expr: `{"k": 1e17}`, value: map[string]any{"k": 1e17}},
		{ID: "float-0.0001", Expr: `{"k": 0.0001}`, value: map[string]any{"k": 0.0001}},
		{ID: "float-1e-5", Expr: `{"k": 1e-5}`, value: map[string]any{"k": 1e-5}},
		{ID: "float-1e-7", Expr: `{"k": 1e-7}`, value: map[string]any{"k": 1e-7}},
		{ID: "float-1e-100", Expr: `{"k": 1e-100}`, value: map[string]any{"k": 1e-100}},
		{ID: "float-1e100", Expr: `{"k": 1e100}`, value: map[string]any{"k": 1e100}},
		{ID: "float-0.1", Expr: `{"k": 0.1}`, value: map[string]any{"k": 0.1}},
		{ID: "float-third", Expr: `{"k": 0.3333333333333333}`, value: map[string]any{"k": 1.0 / 3.0}},
		{ID: "float-money", Expr: `{"k": 4200.5}`, value: map[string]any{"k": 4200.5}},
		{ID: "float-max", Expr: `{"k": 1.7976931348623157e308}`, value: map[string]any{"k": math.MaxFloat64}},
		{ID: "float-smallest-normal", Expr: `{"k": 2.2250738585072014e-308}`,
			value: map[string]any{"k": 2.2250738585072014e-308}},
		{ID: "float-smallest-subnormal", Expr: `{"k": 5e-324}`,
			value: map[string]any{"k": math.SmallestNonzeroFloat64}},

		// -- a real Allem payload ------------------------------------------- //
		{
			ID: "allem-body",
			Expr: `{"agent_id": "billing-bot", "agent_external_id": "billing-bot",` +
				` "action": {"type": "refund.issue", "parameters": {"amount": 4200}},` +
				` "external_event_id": "run-1:7"}`,
			value: map[string]any{
				"agent_id":          "billing-bot",
				"agent_external_id": "billing-bot",
				"action": map[string]any{
					"type":       "refund.issue",
					"parameters": map[string]any{"amount": 4200},
				},
				"external_event_id": "run-1:7",
			},
		},
	}
}

func TestCanonicalJSONMatchesPython(t *testing.T) {
	cases := handPickedCases()
	results := runPython(t, cases)

	for _, c := range cases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			want, ok := results[c.ID]
			if !ok {
				t.Fatalf("no Python answer for %s", c.ID)
			}
			if want.Error != "" {
				t.Fatalf("Python refused this corpus entry (%s); the corpus is "+
					"supposed to hold values both sides can encode", want.Error)
			}
			got, err := CanonicalJSON(c.value)
			if err != nil {
				t.Fatalf("Go refused a value Python encoded: %v", err)
			}
			wantBytes, err := hex.DecodeString(want.Hex)
			if err != nil {
				t.Fatalf("unreadable Python output: %v", err)
			}
			if !bytes.Equal(got, wantBytes) {
				t.Fatalf("canonical bytes differ.\n  go:     %s\n  python: %s",
					strconv0(got), strconv0(wantBytes))
			}
		})
	}
}

func strconv0(b []byte) string {
	return fmt.Sprintf("%q", string(b))
}

// TestPythonFloatReprMatchesPython is the sweep the hand-picked corpus cannot be.
//
// Float formatting is the half of this encoder most likely to be subtly wrong,
// because Go and CPython each compute "the shortest decimal that round-trips"
// with a different algorithm (Ryu against David Gay's dtoa) and then FORMAT it
// under different rules. The hand-picked cases cover the thresholds somebody
// thought of. This covers the ones nobody did.
//
// Seeded, so a failure is reproducible and a passing run is not a different
// experiment each time.
func TestPythonFloatReprMatchesPython(t *testing.T) {
	const count = 20000
	rng := rand.New(rand.NewSource(20260917))

	values := make([]float64, 0, count)
	// Uniformly random bit patterns: the only generator that reaches the
	// subnormals, the huge exponents and the 17-significant-digit values that a
	// generator over "plausible numbers" never produces.
	for len(values) < count/2 {
		f := math.Float64frombits(rng.Uint64())
		if math.IsNaN(f) || math.IsInf(f, 0) {
			continue
		}
		values = append(values, f)
	}
	// And numbers of the shape a payload actually carries, because the
	// bit-pattern sweep almost never lands on one: money, durations, ratios,
	// and the decade boundaries around the exponent thresholds.
	for len(values) < count {
		switch rng.Intn(5) {
		case 0:
			values = append(values, float64(rng.Intn(1_000_000_000))/100.0)
		case 1:
			values = append(values, rng.Float64())
		case 2:
			values = append(values, rng.Float64()*math.Pow(10, float64(rng.Intn(40)-20)))
		case 3:
			values = append(values, float64(rng.Intn(2_000_000_000)))
		default:
			values = append(values, math.Pow(10, float64(rng.Intn(45)-22))*float64(rng.Intn(10)+1))
		}
	}

	cases := make([]pyCase, 0, len(values))
	for i, f := range values {
		cases = append(cases, pyCase{
			ID:    fmt.Sprintf("f%05d", i),
			F64:   fmt.Sprintf("%016x", math.Float64bits(f)),
			value: f,
		})
	}

	results := runPython(t, cases)

	mismatches := 0
	for i, c := range cases {
		want := results[c.ID]
		got, err := pythonFloatRepr(values[i])
		if err != nil {
			t.Fatalf("%s: Go refused %v: %v", c.ID, values[i], err)
		}
		if got != want.Repr {
			mismatches++
			if mismatches <= 20 {
				t.Errorf("%s: bits=%s\n  go:     %s\n  python: %s",
					c.ID, c.F64, got, want.Repr)
			}
		}
	}
	if mismatches > 0 {
		t.Fatalf("%d of %d floats formatted differently from CPython's repr()",
			mismatches, len(cases))
	}
	t.Logf("%d floats, all byte-identical to CPython repr()", len(cases))
}

// TestTheDifferentialCorpusIsNotVacuous proves the comparison can fail.
//
// A differential test that passes because both sides are being handed nothing
// is the shape of check this repository keeps finding. So: encode a value with
// a deliberately broken rule and require the comparison to notice.
func TestTheDifferentialCorpusIsNotVacuous(t *testing.T) {
	results := runPython(t, []pyCase{{ID: "probe", Expr: `{"k": 1234567.0}`}})
	want, err := hex.DecodeString(results["probe"].Hex)
	if err != nil {
		t.Fatalf("unreadable Python output: %v", err)
	}
	// What Go's own `%g` would have produced -- the mistake this encoder exists
	// to avoid. If this matched, the whole float half of the file would be
	// testing nothing.
	naive := []byte(`{"k":` + fmt.Sprintf("%g", 1234567.0) + `}`)
	if bytes.Equal(naive, want) {
		t.Fatalf("Go's default float formatting agrees with CPython on 1234567.0, "+
			"so the reason `pythonFloatRepr` exists is not demonstrated by this "+
			"corpus.\n  naive: %s\n  python: %s", naive, want)
	}
	good, err := CanonicalJSON(map[string]any{"k": 1234567.0})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(good, want) {
		t.Fatalf("and the real encoder does not agree either:\n  go: %s\n  python: %s", good, want)
	}
}
