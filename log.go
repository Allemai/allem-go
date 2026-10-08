package allem

// Logging, and why this package logs at all by default.
//
// A Go library that writes to stderr uninvited is bad manners, and this one
// does it anyway, for a reason stated in `sdk/allem-python/allem/client.py`:
//
//	It must be loud, and loud EVERY time: a connector that quietly stops
//	enforcing is the exact failure this package exists to avoid.
//
// Three of this SDK's paths are only safe because somebody finds out about
// them: Allem unreachable with no hard-gate list ever fetched, a spool past its
// size limit, and a hard-gate cache that could not be written to disk. Each is a
// degradation the customer accepted implicitly and would not otherwise see. A
// silent default turns all three into the failure they were written to prevent
// -- `docs/first-line-report.md` is a whole build about a connector that died
// quietly.
//
// So: WARNING and above go to stderr through the standard library's `log`
// package unless the caller says otherwise. `WithLogger` takes any sink,
// `WithLogger(nil)` is how a caller turns it off, and doing so is a decision
// they have made rather than one this package made for them.

import (
	"log"
	"os"
	"strings"
)

// Level is how much a log line matters.
type Level int

// The levels, mapped onto Python's `logging` levels so the two SDKs' output can
// be filtered the same way.
const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarning
	LevelError
	LevelCritical
)

// String is the level's name, uppercase, as it appears in a line.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarning:
		return "WARNING"
	case LevelError:
		return "ERROR"
	case LevelCritical:
		return "CRITICAL"
	default:
		return "LEVEL(" + strings.TrimSpace(string(rune('0'+int(l)))) + ")"
	}
}

// Logf is the sink this package writes to. Implement it to route Allem's output
// into your own logger.
type Logf func(level Level, format string, args ...any)

// discardLogf drops everything. Used when a caller passes WithLogger(nil).
func discardLogf(Level, string, ...any) {}

// defaultLogf writes WARNING and above to stderr.
//
// The threshold is not configurable through this function on purpose: a caller
// who wants DEBUG has a logger of their own and should pass it. What is on the
// line is the level, then the message -- no timestamp, because the standard
// logger already prefixes one and two is worse than none.
func defaultLogf() Logf {
	logger := log.New(os.Stderr, "allem: ", log.LstdFlags)
	return func(level Level, format string, args ...any) {
		if level < LevelWarning {
			return
		}
		logger.Printf(level.String()+" "+format, args...)
	}
}
