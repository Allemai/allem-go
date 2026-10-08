package allem

// The answer shape, matched to the Python SDK's.
//
// `sdk/allem-python/allem/verdict.py` defines six fields and one property that
// matters more than the six: a verdict without an `event_id` was NOT decided by
// Allem. An integrator moving between the two languages must not have to
// relearn what a verdict looks like, so the names are the same and the
// semantics are the same.

// Verdict is the result of an Allem pre-flight check.
//
// Python's Verdict is truthy when the action is allowed, so agent code reads
// `if allem.check_action(...)`. Go has no operator overloading and the
// equivalent is `if v.Allowed`, which is the same sentence with one more word
// in it. Nothing else about the shape changes.
type Verdict struct {
	// Allowed is the answer. May the action proceed?
	Allowed bool

	// EventID is the identifier Allem issued when IT recorded this event.
	//
	// **Empty means Allem did not decide this.** That is load-bearing rather
	// than cosmetic: a local hard-gate denial deliberately carries no id,
	// because the platform issues one when the platform records a denial and
	// this denial was decided in this process. Tier 2 connectors read a verdict
	// without an id as "we never got an answer" rather than as a denial, which
	// is the ratified tier-dependent behaviour (docs/divergences.md,
	// 2026-08-05). Do not fill this in to make the shape tidier.
	EventID string

	// Explanation is why, in a sentence a human can act on. Always set --
	// including on the fail-open paths, where it names the condition so calling
	// code can log it.
	Explanation string

	// Severity and RecommendedAction come from the platform's verdict, or are
	// "NONE" when no verdict was obtained.
	Severity          string
	RecommendedAction string

	// Freeze is the platform's freeze block when one applies, nil otherwise.
	Freeze map[string]any
}

// DecidedByAllem reports whether the platform issued this verdict.
//
// False for every fail-open answer and for a local hard-gate denial. It reads
// the same field Tier 2 reads, so the two cannot drift: the distinction lives
// in the data rather than in two packages remembering to agree.
func (v Verdict) DecidedByAllem() bool { return v.EventID != "" }

// String mirrors Python's `__repr__`, which prints ALLOWED or BLOCKED and the
// explanation, because that is what ends up in a customer's logs.
func (v Verdict) String() string {
	status := "BLOCKED"
	if v.Allowed {
		status = "ALLOWED"
	}
	return "Verdict(" + status + ": " + v.Explanation + ")"
}

// allowedWithoutVerdict is fail-open: no verdict was obtained, and the action
// proceeds. The mirror of `AllemClient._allowed_without_verdict`.
func allowedWithoutVerdict(explanation string) Verdict {
	return Verdict{
		Allowed:           true,
		EventID:           "",
		Explanation:       explanation,
		Severity:          "NONE",
		RecommendedAction: "NONE",
		Freeze:            nil,
	}
}
