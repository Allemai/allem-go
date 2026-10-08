# allem-go

The Allem SDK for Go. Behaviour parity with `sdk/allem-python`; idiomatic Go,
not a transliteration.

```go
verdict, err := client.Check(ctx, "billing-bot", allem.Action{
    Type:       "refund.issue",
    Parameters: map[string]any{"amount": 4200},
})
if verdict.Allowed {
    issueRefund()
}
```

Two operations. `Check` is the pre-flight gate; `Log` is fire-and-forget.

---

## Getting it

```bash
go get github.com/Allemai/allem-go@latest
```

Then import it:

```go
import allem "github.com/Allemai/allem-go"
```

Requires Go 1.22 or newer. The module resolves from `proxy.golang.org` like any
public Go module; no extra configuration is needed.

Those three lines are executed by
`backend/tests/test_go_sdk_parity.py::test_the_readme_install_lines_actually_work`,
against this tree, in a throwaway module. A command shown to a reader is executed
by a test or it is not shown — the rule the console already follows.

**Go 1.22 or newer.** One dependency: `modernc.org/sqlite`, a pure-Go translation
of SQLite. No cgo, so this cross-compiles; it is also a large dependency tree
(~40 MB in the module cache) and that is stated here rather than discovered — see
the report for why the spool is SQLite and not something smaller.

---

## Connecting

```go
package main

import (
    "context"
    "log"
    "os"

    allem "github.com/Allemai/allem-go"
)

func main() {
    client, err := allem.New(os.Getenv("ALLEM_API_KEY"),
        allem.WithEndpoint("https://api.allem.ai"),
        allem.WithSigningKeyPath(os.Getenv("ALLEM_SIGNING_KEY_PATH")),
        allem.WithIdentity(allem.Identity{
            PrincipalID: os.Getenv("ALLEM_PRINCIPAL_ID"),
            ProjectID:   allem.LoadProjectID(""),   // .allem/project.toml
            ToolID:      "my-service",
        }),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    run, err := client.StartRun("billing-bot", 0)
    if err != nil {
        log.Fatal(err)
    }
    defer run.End()

    verdict, err := client.Check(context.Background(), "billing-bot", allem.Action{
        Type:       "refund.issue",
        Parameters: map[string]any{"amount": 4200, "currency": "EUR"},
    })
    if err != nil {
        log.Printf("allem: %v", err)   // the action is still allowed; see below
    }
    if !verdict.Allowed {
        log.Printf("blocked: %s", verdict.Explanation)
        return
    }

    issueRefund()

    _ = client.Log(context.Background(), "billing-bot", allem.Action{
        Type:       "refund.issued",
        Parameters: map[string]any{"amount": 4200},
    })
}

func issueRefund() {}
```

---

## Fail-open, and the one exception

**If Allem is unreachable, `Check` allows.** An Allem outage never breaks your
agent. The action proceeds and the event is delivered when connectivity returns.

**Every error path also allows.** `Check` returns `(Verdict, error)`, and on
every error the verdict permits the action. That is deliberate: only a verdict
Allem returned, or the local hard gate, may deny. A Go zero value (`Verdict{}`,
`Allowed: false`) read by a caller who forgot to check the error would
manufacture a denial out of a typo.

**The exception is a hard gate, and you turn it on yourself.** A scope rule
marked `hard_gate: true` fails **closed**, locally, without asking anyone:

> a gate that only holds while Allem is up is not a gate, it is a gate-shaped
> thing that opens during exactly the incident it was bought for

So the list is fetched and cached on local disk before the incident starts, and
**a stale cache keeps blocking**. Age makes the list less *complete* — a rule
added during an outage is unknown to us — never less binding.

Three things follow, and none of them is negotiable:

- If the SDK has **never** fetched the list, it cannot gate anything and it says
  so loudly, on every check. There is no built-in floor: enforcing rules you did
  not write would be worse than admitting the gap.
- If the cache **directory cannot be written** — a container, a Lambda, a
  read-only root — the list is kept in memory for the process lifetime and
  refetched on every cold start. A check is never failed because a file could
  not be written.
- A local denial carries **no event id**. That is how Tier 2 connectors tell it
  from a denial Allem issued. `verdict.DecidedByAllem()` is the accessor.

---

## The spool

Every event is written to a local SQLite write-ahead log **before** any network
attempt. That is what makes fail-open safe rather than merely convenient: the
agent proceeds, and the evidence is not lost.

- A row is deleted only after it was delivered **and** the retention window
  passed. An unsent row is un-deletable evidence.
- A row the platform permanently refuses three times is **set aside, never
  deleted** — out of the delivery queue so the queue can reach zero, still
  counted by `UnsentCount()`, and `RequeueUndeliverable()` is the way back.
- Three counts answer three questions and are not interchangeable:
  `PendingCount()` (queued), `UndeliverableCount()` (set aside), `UnsentCount()`
  (owed to you, and the one to print).
- Delivery retries 1, 2, 4, 8, 16, 32 seconds and then every 60 seconds,
  indefinitely. A spool that empties itself on failure is worse than no spool.

**v1 is unencrypted, with restrictive permissions** (0700 directory, 0600 file).
The spool holds your action parameters and lives on your machine. Encryption at
rest is revisited for regulated customers.

Where: `$ALLEM_SPOOL_DIR/spool.db`, or `~/.allem/spool.db`. Override with
`allem.WithSpoolPath`.

---

## Signing, and which direction it points

Sign your events and Allem can prove it did not write them:

From a checkout of this repository, in `sdk/allem-go`:

```bash
go run ./cmd/allem-keygen -out ~/.allem/agent.key
```

Once the module is published, from anywhere:

```text
go run github.com/Allemai/allem-go/cmd/allem-keygen -out ~/.allem/agent.key
```

`allem.GenerateKeypair(path)` is the same thing as a library call.

Register the printed public half with
`POST /v1/agents/{agent_id}/signing-keys`, then set
`ALLEM_SIGNING_KEY_PATH=~/.allem/agent.key`.

**You hold the private key and Allem holds only the public one.** That is the
whole point: Allem can verify your completeness claim and cannot produce one, so
"Allem cannot forge your record" is a property of the key material rather than a
promise about our conduct. The registration is itself written into the
append-only chain, which is what makes that checkable.

(The export signature points the *other* way — Allem signs, you verify. Both are
Ed25519. The key registries are separate for exactly that reason.)

`ALLEM_SIGNING_SECRET` still configures HMAC-SHA256 for an existing deployment.
**Allem cannot verify those signatures** — it has never held the secret — so
those events are recorded as unverified. Use Ed25519.

---

## Completeness: runs and heartbeats

`StartRun` emits `run_start` at `client_seq = 1` and beats every 60 seconds.
A heartbeat consumes a sequence number like any other event, which is the trick:
a *missing* heartbeat is itself a detectable gap.

**Go has no `atexit`, and this package installs no signal handler.** A library
that takes over your program's signal disposition without being asked is a
library that gets removed, and Go offers no way to chain onto an existing
handler the way Python does. So:

```go
defer client.Close()   // emits run_end for every run, then drains
```

A program that exits without it reports `UNCLOSED_RUN` — which is accurate,
because nothing observed the shutdown.

---

## Identity

```go
allem.WithIdentity(allem.Identity{
    PrincipalID: os.Getenv("ALLEM_PRINCIPAL_ID"),
    ProjectID:   allem.LoadProjectID(""),
    HostID:      os.Getenv("ALLEM_HOST_ID"),
    ToolID:      "my-service",
})
```

**Nothing is invented and nothing is laundered.** A value that is not known is
omitted, never guessed — a guessed `project_id` attributes one codebase's work to
another, in a log where that cannot be repaired. A value the platform would
refuse is omitted rather than rewritten into one it accepts, because rewriting
`jane.doe@example.com` into `jane.doe-example.com` carries the person straight
through the check that exists to stop exactly that.

`PrincipalID` and `HostID` are **derived by Allem at provisioning**, under a
secret that never leaves Allem. This package cannot recompute them and does not
try. Read them out of your Allem config (`allem init` writes them, and
`LoadIdentityFromEnv()` reads the same variables).

`ProjectID` is **issued by Allem** and lives in a committed
`.allem/project.toml`. `LoadProjectID` reads it. Never mint your own: policy
scoping and freeze bind to project, and the meter counts `governed_projects`.

One consequence worth knowing before you wire it up: a **derived** `principal_id`
(`p-…`) beside an agent id that is *not* derived is treated as two values from
different installs, and the principal is dropped with a warning. That pairing
describes a person on a laptop attached to a server-side service, and attributing
one to the other is a false statement in an append-only log. Provision your agent
(`POST /v1/agents/provision`) and its external id is derived too.

---

## Declared cause

```go
Cause: &allem.Cause{
    Kind: allem.CauseHumanInstruction,
    Ref:  "ticket-4471",
    Note: "the operator asked for it",
}
```

**The SDK never invents one.** Not from the previous call, not from the run, not
from anything it can infer. This field goes inside the hash recipe, under your
agent's name, in the one place a reader treats as the agent's own account of
itself. An absent cause is a true record; a plausible one is not. `unknown` means
*no cause was recorded*, never *there was no cause*.

There is no `Basis` field, and there never will be: how Allem came to hold a
cause is Allem's statement, not yours. The server refuses one outright.

---

## Parameters, and one number that will surprise you

`Action.Parameters` is `map[string]any`. A struct is refused with an error that
names the fix, rather than converted silently — a conversion this package made on
its own would move the bytes your signature covers. `allem.Params` is the
explicit escape hatch:

```go
params, err := allem.Params(myStruct)
```

It round-trips through `encoding/json`, so your field tags apply — and a
**whole-valued float does not survive as a float**: `json.Marshal(float64(4200))`
emits `4200`, and it comes back an integer. Allem records what arrives, so that
event says `4200`, not `4200.0`. If that distinction matters — and on a monetary
value it might — build the map yourself and put a `float64` in it.

(The SDK's own wire encoding does not have this problem. It writes canonical
JSON, so `MonetaryValue: 4200.0` travels as `4200.0` and the server's recomputed
digest matches your signature.)

---

## Logging

This package writes WARNING and above to stderr by default. That is unusual for a
Go library and it is deliberate: three of its paths are degradations that are
only safe because somebody finds out about them — Allem unreachable with no gate
list, a spool past its size limit, a gate cache that could not be written.

```go
allem.WithLogger(func(level allem.Level, format string, args ...any) { … })
allem.WithLogger(nil)   // silence it — your decision, not ours
```

---

## What this SDK does not decide

**The connection tier.** It is read off your authenticated credential at
ingestion. An agent naming its own tier is the credential rule inverted: the
thing being judged saying how trustworthy the judgement is. This SDK sends no
such field and a test asserts it never will. Registering `allem-go` as a
connector is a provisioning change — see the report.

---

## Differences from the Python SDK

Every one of these is recorded, with its reasoning, in
[`docs/go-sdk-report.md`](../../docs/go-sdk-report.md).

| | Python | Go |
|---|---|---|
| `run_end` on exit | `atexit` + SIGTERM | `Close()` only — Go has neither |
| `identity` on events | not sent | sent, when configured |
| Wire encoding | `json.dumps` | canonical JSON (so a whole float stays a float) |
| Gate fetch timeout | constant declared, unused | 3 s, the value the constant names |
| Struct parameters | any dict | refused; use `allem.Params` |

Behaviour parity is asserted by running both SDKs against one server and diffing
the rows Mongo stored: `backend/tests/test_go_sdk_parity.py`.
