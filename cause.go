package allem

// What the agent says provoked an action -- the field the SDK must NEVER fill
// in.
//
// The SDK never invents one. Not from the previous call in this process, not
// from the last event on this run, not from anything the SDK happens to know.
//
// The temptation is real and specific: the Client already holds a run id and a
// monotonic sequence, so "the previous event in this run" is one field away and
// would look right almost all the time. It would also be a guess, and this field
// goes INSIDE the hash recipe -- a guess written into an append-only log, under
// the agent's name, in the one field a reader will treat as the agent's own
// account of itself. An absent cause is a true record; a plausible one is not.
//
// `backend/app/services/declared_cause.py` refuses a rule written against a
// cause field for the same reason: a cause is agent-supplied, so it may never
// determine an enforcement outcome.
//
// So: present only when the caller passes it, dropped entirely when they do not,
// and never defaulted.
//
// `basis` is not settable here and the server refuses it outright (CauseSection
// declares `extra="forbid"`, so a caller-supplied basis is a 422 rather than a
// silent drop): how Allem came to hold a cause is Allem's statement, not the
// caller's. There is no Basis field on the Cause type below, which is the
// strongest form that rule can take in a typed language.

import (
	"fmt"
	"strings"
)

// The six cause kinds. A CLOSED set: Allem refuses an unrecognised kind rather
// than storing it, because an append-only evidence field cannot be tidied up
// later.
const (
	CauseHumanInstruction = "human_instruction"
	CauseSchedule         = "schedule"
	CausePriorEvent       = "prior_event"
	CauseAgentDelegation  = "agent_delegation"
	CauseExternalTrigger  = "external_trigger"
	// CauseUnknown means *no cause was recorded*, never *there was no cause*.
	CauseUnknown = "unknown"
)

// CauseKinds is the closed set, in the order `docs/causation.md` lists it.
var CauseKinds = []string{
	CauseHumanInstruction,
	CauseSchedule,
	CausePriorEvent,
	CauseAgentDelegation,
	CauseExternalTrigger,
	CauseUnknown,
}

// The server's bounds, mirrored.
//
// They have to be here as well as there: a value the server refuses is a 422 the
// CALLER never sees -- the row is already on the spool, the sender retries a
// deterministic refusal forever, and the client_seq it consumed is a permanent
// gap in the completeness record. The most likely over-length value is the
// obvious one: a whole prompt pasted into Note.
const (
	MaxCauseRefLength  = 512
	MaxCauseNoteLength = 2000
)

// Cause is what YOU say provoked an action.
//
// It is optional, it is never inferred, and it changes nothing about a verdict:
// Allem records it and no rule may be written against it. Pass it only when you
// actually know; omitting it is a true record and a guess is not.
type Cause struct {
	// Kind must be one of CauseKinds.
	Kind string
	// Ref points at what provoked the action -- for CausePriorEvent, an event
	// id in THIS organisation's chain.
	Ref string
	// Note is free text. Keep it under MaxCauseNoteLength; a whole prompt does
	// not fit and the server refuses the event rather than truncating it.
	Note string
}

// causeBlock validates a caller-supplied cause locally, or returns nil.
//
// Checked here as well as on the server so a bad value fails at the call site
// rather than as a 422 from a background sender the caller never sees. The
// server's check is the one that counts; this one refuses exactly what the
// server refuses -- the closed kind set and both length bounds -- so the two
// cannot disagree about what is acceptable.
//
// **Called before any sequence number is consumed.** Returning an error after
// Next() would burn a client_seq on an event that is never sent, manufacturing a
// permanent gap in the completeness record out of a caller's typo.
func causeBlock(cause *Cause) (map[string]any, error) {
	if cause == nil {
		return nil, nil
	}
	valid := false
	for _, kind := range CauseKinds {
		if cause.Kind == kind {
			valid = true
			break
		}
	}
	if !valid {
		return nil, fmt.Errorf(
			"allem: Cause.Kind must be one of %v; got %q. The set is closed -- "+
				"Allem refuses an unrecognised kind rather than storing it, "+
				"because an append-only evidence field cannot be tidied up later",
			CauseKinds, cause.Kind)
	}

	block := map[string]any{"kind": cause.Kind}
	for _, field := range []struct {
		key   string
		value string
		limit int
	}{
		{"ref", cause.Ref, MaxCauseRefLength},
		{"note", cause.Note, MaxCauseNoteLength},
	} {
		text := strings.TrimSpace(field.value)
		if text == "" {
			continue
		}
		// Counted in Unicode code points, not bytes. The server's bound is
		// Python's `len()` over a `str`, and an accented note of 400 characters
		// is 400 to the server and up to 800 bytes to Go -- so a byte count
		// would refuse locally what the server accepts, which is the same
		// disagreement in the other direction.
		if length := len([]rune(text)); length > field.limit {
			return nil, fmt.Errorf(
				"allem: Cause.%s is %d characters; Allem refuses more than %d "+
					"and would reject this event. Shorten it, or put the detail "+
					"in the action's parameters",
				strings.ToUpper(field.key[:1])+field.key[1:], length, field.limit)
		}
		block[field.key] = text
	}
	return block, nil
}
