package allem

import "runtime"

// Version is this package's version, matching the Python SDK's `__version__`.
//
// It moves when the module is tagged. Go modules resolve from a tagged Git ref
// through the module proxy, so this constant and the tag have to be changed
// together -- see `docs/go-sdk-report.md`, *Publishing*, which is a decision
// this build records rather than takes.
const Version = "0.1.0"

// userAgent identifies the connector on the wire.
//
// **Nothing on the wire that Allem RECORDS may differ between the two SDKs** --
// a Go-instrumented and a Python-instrumented agent must produce rows an
// auditor cannot tell apart except by `identity.tool_id`. This header is not
// one of those: no code under `backend/app/` reads a User-Agent and no field on
// `AgentEvent` holds one, so it is an operational aid in a proxy log and not
// evidence. `TestTheUserAgentIsNotEvidence` is what keeps that true.
//
// It is NOT the connection tier, and it must never be read as one. The tier is
// read off the authenticated credential at ingestion
// (`backend/app/services/connection_tier.py`); an agent naming its own tier is
// the credential rule inverted.
func userAgent() string {
	return "allem-go/" + Version + " (" + runtime.Version() + "; " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
