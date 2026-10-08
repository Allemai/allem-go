package allem

// Canonical JSON, byte-identical to the encoder the Allem server verifies
// against.
//
// The Python SDK does not implement this rule — it imports `canonicaljson`,
// the Matrix Canonical JSON package, and the module docstring says why:
//
//	A hand-rolled encoder that agreed with the server on every payload
//	anyone tested and disagreed on one customer's unicode key would surface
//	as intermittent `signature_verified: false` on a live agent, which is
//	the most expensive possible place to discover an encoder bug.
//
// There is no such package for Go, so this file is the hand-rolled encoder
// that warning is about. Two things are done instead of importing:
//
//  1. The rule is implemented from the SOURCE of the thing it must match --
//     `canonicaljson.encode_canonical_json` is exactly
//     `json.JSONEncoder(ensure_ascii=False, allow_nan=False,
//     separators=(",", ":"), sort_keys=True).encode(data).encode("utf-8")`,
//     and every behaviour below is traced to a line of CPython rather than to
//     a reading of a specification.
//
//  2. It is DIFFERENTIALLY TESTED against the real thing. `TestCanonicalJSONMatchesPython`
//     generates payloads -- including the astral-plane keys, the control
//     characters and the float exponent boundaries this encoder could
//     plausibly get wrong -- hands them to the actual Python package, and
//     compares bytes. A claim that two encoders agree is worth exactly as
//     much as the corpus it was checked on, so the corpus is in the repository
//     and the generator is seeded.
//
// **It is NOT RFC 8785**, and the differences are load-bearing rather than
// academic (`backend/app/services/canonical.py`):
//
//   - Keys sort by Unicode code point, not UTF-16 code unit. They disagree for
//     astral-plane keys. Go string comparison is byte-wise over UTF-8, which
//     IS code-point order, so this falls out for free -- but only for valid
//     UTF-8, which is why invalid UTF-8 is an error here rather than being
//     replaced.
//   - Numbers are Python `repr()`: `1e-07` not `1e-7`, `1.0` not `1`, and
//     integers exact at any width. `pythonFloatRepr` below is CPython's
//     `format_float_short` in mode 'r', not Go's `%g`, because the two pick
//     different exponent thresholds and would disagree on `1234567.0`.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrNotCanonicalizable is returned for a value the Python encoder would
// refuse. It is returned, never worked around: a value silently coerced into
// something encodable produces a digest over bytes the server will never see.
var ErrNotCanonicalizable = errors.New("allem: value cannot be canonically encoded")

// CanonicalJSON returns the canonical UTF-8 encoding of v.
//
// The same bytes `canonicaljson.encode_canonical_json(v)` produces in Python,
// for every value both languages can hold.
func CanonicalJSON(v any) ([]byte, error) {
	var b strings.Builder
	if err := encodeCanonical(&b, reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func encodeCanonical(b *strings.Builder, v reflect.Value) error {
	if !v.IsValid() {
		b.WriteString("null")
		return nil
	}
	// Unwrap interfaces and pointers first. A nil pointer and a nil interface
	// are both Python's None.
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			b.WriteString("null")
			return nil
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Bool:
		if v.Bool() {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
		return nil

	case reflect.String:
		// json.Number is a string kind carrying a literal. Python would have
		// had an int or a float here, so it is emitted as a number -- but only
		// after being checked, because an unparseable json.Number written
		// through unvalidated would put a non-JSON token in the digest.
		if v.Type() == numberType {
			return encodeJSONNumber(b, v.String())
		}
		return encodeCanonicalString(b, v.String())

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		b.WriteString(strconv.FormatInt(v.Int(), 10))
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		b.WriteString(strconv.FormatUint(v.Uint(), 10))
		return nil

	case reflect.Float32, reflect.Float64:
		// float32 is widened first: Python has one float type and the digest
		// is over its repr, so a float32 must be encoded as the float64 the
		// server will parse. Widening through the shortest float32 text rather
		// than through the raw bit pattern, because float64(float32(0.1)) is
		// 0.10000000149011612 and the customer wrote 0.1.
		f := v.Float()
		if v.Kind() == reflect.Float32 {
			var err error
			f, err = strconv.ParseFloat(strconv.FormatFloat(f, 'g', -1, 32), 64)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrNotCanonicalizable, err)
			}
		}
		s, err := pythonFloatRepr(f)
		if err != nil {
			return err
		}
		b.WriteString(s)
		return nil

	case reflect.Map:
		return encodeCanonicalMap(b, v)

	case reflect.Slice:
		if v.IsNil() {
			// Python has no nil slice; a caller who meant "no items" wrote an
			// empty list and a caller who meant "absent" wrote nil. Encoding
			// nil as `null` is what `encoding/json` does and what a Python
			// caller passing None would get.
			b.WriteString("null")
			return nil
		}
		return encodeCanonicalArray(b, v)

	case reflect.Array:
		return encodeCanonicalArray(b, v)

	case reflect.Struct:
		return fmt.Errorf(
			"%w: %s is a struct. Build the payload as map[string]any, or pass "+
				"it through allem.Params first -- a struct encoded through its "+
				"Go field tags is a conversion, and a conversion this package "+
				"made on its own would move the bytes the signature covers",
			ErrNotCanonicalizable, v.Type(),
		)
	}

	return fmt.Errorf("%w: %s", ErrNotCanonicalizable, v.Type())
}

// A `json.Number` reaching here came from a decoder configured with
// `UseNumber()`, which is how a Go caller keeps a large integer intact through
// a round trip. Python would have had an int or a float in that slot, so the
// literal is emitted as a number rather than as the string Go stores it in.
var numberType = reflect.TypeOf(json.Number(""))

func encodeJSONNumber(b *strings.Builder, s string) error {
	// An integer literal is emitted verbatim -- Python's int is arbitrary
	// precision and 9007199254740993 must survive, which it would not if this
	// went through a float64.
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		b.WriteString(s)
		return nil
	}
	if isBigIntegerLiteral(s) {
		b.WriteString(s)
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("%w: %q is not a JSON number", ErrNotCanonicalizable, s)
	}
	out, err := pythonFloatRepr(f)
	if err != nil {
		return err
	}
	b.WriteString(out)
	return nil
}

func isBigIntegerLiteral(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' {
		i = 1
	}
	if i == len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func encodeCanonicalArray(b *strings.Builder, v reflect.Value) error {
	b.WriteByte('[')
	for i := 0; i < v.Len(); i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := encodeCanonical(b, v.Index(i)); err != nil {
			return err
		}
	}
	b.WriteByte(']')
	return nil
}

func encodeCanonicalMap(b *strings.Builder, v reflect.Value) error {
	if v.IsNil() {
		b.WriteString("null")
		return nil
	}
	if v.Type().Key().Kind() != reflect.String {
		return fmt.Errorf(
			"%w: map keys must be strings (got %s). Python would raise here "+
				"too -- sort_keys cannot order a mixed-type key set",
			ErrNotCanonicalizable, v.Type().Key(),
		)
	}

	keys := make([]string, 0, v.Len())
	iter := v.MapRange()
	for iter.Next() {
		keys = append(keys, iter.Key().String())
	}
	// Byte-wise, which for valid UTF-8 is Unicode code point order -- the rule
	// Matrix Canonical JSON states and the one place it and RFC 8785 disagree.
	// Invalid UTF-8 is rejected below, before it can reach this comparison and
	// sort into a position no Python program would produce.
	sort.Strings(keys)

	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := encodeCanonicalString(b, k); err != nil {
			return err
		}
		b.WriteByte(':')
		if err := encodeCanonical(b, v.MapIndex(reflect.ValueOf(k).Convert(v.Type().Key()))); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

// encodeCanonicalString writes one JSON string exactly as CPython's
// `_json.c:escape_unicode` does with `ensure_ascii=False`.
//
// What is escaped: `"`, `\`, and the C0 controls. `\b \f \n \r \t` take their
// two-character forms; every other code point at or below U+001F takes
// `\u00xx` with LOWERCASE hex, because CPython indexes `Py_hexdigits`, which is
// "0123456789abcdef".
//
// What is NOT escaped, and each of these is a place `encoding/json` would
// disagree: `/`, `<`, `>`, `&` (Go HTML-escapes those by default), U+2028 and
// U+2029 (Go escapes those unconditionally, with no option to stop it), and
// every other non-ASCII character, which is written through as UTF-8.
func encodeCanonicalString(b *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		// Python would raise UnicodeEncodeError on a surrogate and could not
		// hold these bytes at all. Go's own encoder substitutes U+FFFD, which
		// is the dangerous answer: it produces a digest over bytes that differ
		// from what the caller passed AND from what any Python client would
		// send, silently.
		return fmt.Errorf(
			"%w: string is not valid UTF-8, so no Python client could send it "+
				"and the server could not reproduce this digest",
			ErrNotCanonicalizable,
		)
	}
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c <= 0x1f:
			b.WriteString(`\u00`)
			const hexdigits = "0123456789abcdef"
			b.WriteByte(hexdigits[(c>>4)&0xf])
			b.WriteByte(hexdigits[c&0xf])
		default:
			// Includes every byte of a multi-byte UTF-8 sequence. Validity was
			// established above, so copying bytes through is copying whole
			// characters through.
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return nil
}

// pythonFloatRepr returns what `repr(f)` returns in CPython.
//
// Not `strconv.FormatFloat(f, 'g', -1, 64)`, and the difference is not an edge
// case: Go's shortest-'g' switches to exponent notation at an exponent of 6, so
// it renders 1234567.0 as "1.234567e+06" where Python renders "1234567.0". A
// digest computed over the first is rejected by a server that computed the
// second, on any payload carrying a seven-figure number -- a monetary value, a
// row count, a millisecond timestamp.
//
// CPython's rule (`Python/pystrtod.c`, `format_float_short`, mode 'r'):
//
//	digits, decpt = shortest round-trip digits, and the position of the
//	                decimal point within them
//	use_exp       = decpt <= -4 || decpt > 16
//
// plus `Py_DTSF_ADD_DOT_0`, which appends ".0" to anything that would otherwise
// read as an integer.
func pythonFloatRepr(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		// `allow_nan=False`. Python raises ValueError rather than emitting the
		// JavaScript-isms `NaN` and `Infinity`, which are not JSON, and the
		// canonicalization spec shipped in every evidence export says so:
		// "NaN and Infinity are rejected, not encoded."
		return "", fmt.Errorf(
			"%w: %v has no canonical JSON form (NaN and Infinity are rejected, "+
				"not encoded)", ErrNotCanonicalizable, f,
		)
	}

	// Shortest round-trip digits, via the exponent form so the digits and the
	// decimal exponent can be read off separately. Go and CPython both produce
	// the shortest decimal that round-trips; `TestPythonFloatReprMatchesPython`
	// is what establishes they pick the same one, over a seeded corpus,
	// rather than this comment asserting it.
	e := strconv.FormatFloat(f, 'e', -1, 64)

	neg := false
	if e[0] == '-' {
		neg = true
		e = e[1:]
	}

	mantissa, expPart, ok := strings.Cut(e, "e")
	if !ok {
		return "", fmt.Errorf("%w: unexpected float form %q", ErrNotCanonicalizable, e)
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	exp, err := strconv.Atoi(expPart)
	if err != nil {
		return "", fmt.Errorf("%w: unexpected float exponent %q", ErrNotCanonicalizable, expPart)
	}
	// dtoa's convention: the value is 0.<digits> x 10^decpt.
	decpt := exp + 1

	var out string
	if decpt <= -4 || decpt > 16 {
		out = pythonExponentForm(digits, decpt)
	} else {
		out = pythonFixedForm(digits, decpt)
	}
	if neg {
		out = "-" + out
	}
	return out, nil
}

func pythonFixedForm(digits string, decpt int) string {
	switch {
	case decpt <= 0:
		// 0.0001 -> digits "1", decpt -3 -> "0." + "000" + "1"
		return "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		// ADD_DOT_0: 1e15 -> digits "1", decpt 16 -> "1" + 15 zeros + ".0"
		return digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		return digits[:decpt] + "." + digits[decpt:]
	}
}

func pythonExponentForm(digits string, decpt int) string {
	mantissa := digits[:1]
	if len(digits) > 1 {
		mantissa += "." + digits[1:]
	}
	exp := decpt - 1
	sign := "+"
	if exp < 0 {
		sign = "-"
		exp = -exp
	}
	// At least two exponent digits: CPython writes 1e-05, never 1e-5. This is
	// one of the two places Matrix Canonical JSON and RFC 8785 disagree on
	// numbers, and the export's own spec block names it.
	return fmt.Sprintf("%se%s%02d", mantissa, sign, exp)
}

// Params normalizes any JSON-encodable Go value into the map form this SDK
// puts on the wire.
//
// `Action.Parameters` is `map[string]any` and CanonicalJSON refuses a struct on
// purpose -- see the error it returns. This is the escape hatch for a Go caller
// who has a struct and wants to send it, and it is explicit about what it costs:
//
//	Params round-trips through `encoding/json`, which means the value is
//	encoded with your field tags (so `omitempty` applies, and an unexported
//	field is dropped) and decoded with `UseNumber`, so an integer of any
//	width survives exactly. A whole-valued FLOAT does not survive as a float:
//	`json.Marshal(float64(4200))` emits `4200`, and it comes back an integer.
//	Allem records what arrives, so that event says 4200 and not 4200.0.
//
// If that distinction matters to you -- and on a monetary value it might --
// build the map yourself and put a `float64` in it.
func Params(v any) (map[string]any, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("allem: %T cannot be encoded as JSON: %w", v, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	// Without this, every number becomes a float64 and a large integer loses
	// precision silently -- 9007199254740993 comes back 9007199254740992.
	decoder.UseNumber()

	var out map[string]any
	if err := decoder.Decode(&out); err != nil {
		return nil, fmt.Errorf(
			"allem: %T does not encode to a JSON object, so it cannot be an "+
				"action's parameters: %w", v, err)
	}
	return out, nil
}
