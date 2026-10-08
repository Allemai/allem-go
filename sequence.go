package allem

// Client-side sequencing. Proves completeness, not integrity.
//
// The server's hash chain proves stored events were not altered. It cannot
// prove an event is not *missing* -- a dropped write leaves no gap in a
// server-assigned sequence. The client sequence closes that hole: the agent
// numbers its own actions (1, 2, 3, ...) before anything can fail, so a missing
// number on the server is visible evidence of a missing record.
//
// Client sequence and server chain sequence are separate concepts and must
// never be merged (completeness spec, Non-Negotiable Rule 3).
//
// # The direction of the asymmetry
//
// There are two asymmetric-signing problems in this product and they point in
// OPPOSITE directions. Read `backend/app/services/evidence_signing.py` before
// touching this file.
//
// **Here, the agent holds the private key and Allem holds only the public
// half** (`POST /v1/agents/{id}/signing-keys`). That is what makes "Allem
// cannot forge your completeness claim" a property of the key material rather
// than a promise about our conduct -- Allem never holds the means. Registration
// is itself written into the append-only chain, which is what makes the
// sentence checkable rather than merely asserted.
//
// **The export signature is the reverse**: Allem holds the private key and the
// customer verifies with the published public one. Both are Ed25519 now, which
// makes the distinction easier to lose and no less important. The key
// registries are separate for that reason.
//
// # The signed message
//
//	canonical_json({
//	  "agent_id": ..., "run_id": ..., "client_seq": ...,
//	  "content_digest": sha256(canonical_json(body without its "sequence" key)),
//	})
//
// Why "sequence" is excluded from the digest: the signature lives inside that
// block, so a digest covering it could never be computed. Excluding the whole
// block loses nothing, because agent_id, run_id and client_seq are named
// explicitly in the signed message anyway.
//
// This is a THIRD implementation of one specification -- the SDK's Python one,
// the server's (`backend/app/services/sequence_signature.py`), and this. None
// imports another. They are pinned to each other by one golden vector, asserted
// as a literal in all three test suites.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Signature methods as they travel on the wire, in `sequence.signature_method`.
const (
	MethodEd25519 = "ed25519"
	MethodHMAC    = "hmac-sha256"
)

// excludedFromDigest is the top-level body key excluded from the content
// digest. See the package comment: the signature lives inside it.
const excludedFromDigest = "sequence"

// ErrSigningUnavailable is returned when signing was configured and cannot be
// done.
//
// Returned, never swallowed. A client configured to sign that silently sent
// unsigned events would produce exactly the failure mode this whole layer
// exists to remove: a claim that looks stronger than it is.
var ErrSigningUnavailable = errors.New("allem: signing is unavailable")

// Signer is swappable so the signing method can change without touching
// callers.
type Signer interface {
	Sign(message []byte) (string, error)
	Method() string
}

// ContentDigest is the SHA-256 hex of a request body, excluding its `sequence`
// block.
//
// The server computes this over the body **exactly as received, before
// normalization**. Normalization lowercases identifiers and moves fields
// between slots, so a digest taken after it would not match one the client took
// before it.
func ContentDigest(body map[string]any) (string, error) {
	withoutSequence := make(map[string]any, len(body))
	for k, v := range body {
		if k == excludedFromDigest {
			continue
		}
		withoutSequence[k] = v
	}
	encoded, err := CanonicalJSON(withoutSequence)
	if err != nil {
		return "", fmt.Errorf("allem: could not canonicalize the body for signing: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// SigningMessage is the exact bytes signed. One definition, used by signing and
// by the golden-vector test.
func SigningMessage(agentID, runID string, clientSeq int64, digest string) ([]byte, error) {
	return CanonicalJSON(map[string]any{
		"agent_id":       agentID,
		"run_id":         runID,
		"client_seq":     clientSeq,
		"content_digest": digest,
	})
}

// --------------------------------------------------------------------------- //
// Ed25519 -- the current signer
// --------------------------------------------------------------------------- //

// Ed25519Signer signs with a private key this process holds and Allem does not.
//
// The private key never leaves this process: it is not sent to Allem, not
// written to a log, and `String()` is overridden because a private key that
// reaches a formatted log line has already leaked.
type Ed25519Signer struct {
	private ed25519.PrivateKey
}

// NewEd25519Signer wraps a key already in memory.
func NewEd25519Signer(private ed25519.PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{private: private}
}

// GenerateEd25519Signer makes a fresh keypair in memory. Persist it with
// SavePrivateKey.
func GenerateEd25519Signer() (*Ed25519Signer, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningUnavailable, err)
	}
	return &Ed25519Signer{private: private}, nil
}

// LoadEd25519Signer reads a private key from an unencrypted PKCS#8 PEM file --
// the same file the Python SDK writes and reads.
//
// No error returned here quotes the file's contents. A malformed private key is
// still a private key, and an error message is a log line waiting to happen.
func LoadEd25519Signer(path string) (*Ed25519Signer, error) {
	material, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: could not read %s (%v)", ErrSigningUnavailable, path, err)
	}
	block, _ := pem.Decode(material)
	if block == nil {
		return nil, fmt.Errorf(
			"%w: no PEM block in %s. It must be an unencrypted PKCS#8 PEM. "+
				"(Contents withheld: the file holds private key material.)",
			ErrSigningUnavailable, path)
	}
	// An encrypted key needs a password this package deliberately never takes.
	// Named by its PEM type rather than by `x509.IsEncryptedPEMBlock`, which
	// only sees the legacy DEK-Info form and would let a PKCS#8
	// "ENCRYPTED PRIVATE KEY" through to a parse error that says nothing
	// useful.
	if block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["DEK-Info"] != "" {
		return nil, fmt.Errorf(
			"%w: the key in %s is encrypted. It must be an unencrypted PKCS#8 "+
				"PEM -- the same form `python -m allem.sequence --out` writes.",
			ErrSigningUnavailable, path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: could not read an Ed25519 private key from %s (%T). It must be "+
				"an unencrypted PKCS#8 PEM. (Contents withheld: the file holds "+
				"private key material.)",
			ErrSigningUnavailable, path, err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: the key in %s is %T, not Ed25519",
			ErrSigningUnavailable, path, parsed)
	}
	return &Ed25519Signer{private: private}, nil
}

// Method implements Signer.
func (s *Ed25519Signer) Method() string { return MethodEd25519 }

// Sign implements Signer.
func (s *Ed25519Signer) Sign(message []byte) (string, error) {
	if len(s.private) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: the private key is the wrong size", ErrSigningUnavailable)
	}
	return hex.EncodeToString(ed25519.Sign(s.private, message)), nil
}

// PublicKeyPEM returns the PUBLIC half, in the form
// `POST /agents/{id}/signing-keys` takes.
func (s *Ed25519Signer) PublicKeyPEM() (string, error) {
	public, ok := s.private.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("%w: the key has no Ed25519 public half", ErrSigningUnavailable)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSigningUnavailable, err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// String redacts. A private key that reaches a %v has already leaked.
func (s *Ed25519Signer) String() string { return "<Ed25519Signer private_key=REDACTED>" }

// SavePrivateKey writes the private key to path with owner-only permissions.
//
// Permissions are set BEFORE the bytes are written, not after: a chmod after the
// write leaves a window in which the key is world-readable, and that window is
// all anyone sharing the machine needs.
//
// The parent directory is created first, 0700. The Python SDK shipped without
// that and its own published README told a reader to write a key into a
// directory that does not exist on the machine the command is for.
func (s *Ed25519Signer) SavePrivateKey(path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(s.private)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSigningUnavailable, err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if parent := filepath.Dir(path); parent != "" {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return fmt.Errorf("allem: could not create %s: %w", parent, err)
		}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("allem: could not open %s for writing: %w", path, err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return fmt.Errorf("allem: could not write %s: %w", path, err)
	}
	return file.Close()
}

// GenerateKeypair generates a keypair, writes the private half to
// privateKeyPath (0600), and returns the PUBLIC half as PEM for registration
// with Allem.
//
// The private key is written to the path given and is otherwise not retained,
// printed, or transmitted by this function.
func GenerateKeypair(privateKeyPath string) (string, error) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		return "", err
	}
	if err := signer.SavePrivateKey(privateKeyPath); err != nil {
		return "", err
	}
	return signer.PublicKeyPEM()
}

// --------------------------------------------------------------------------- //
// HMAC -- v1, retained, and NOT what the server verifies
// --------------------------------------------------------------------------- //

// HMACSigner is the v1 signer. It is retained so an existing deployment that
// sets ALLEM_SIGNING_SECRET keeps working unchanged rather than crashing, and so
// the Signer interface has its second implementation.
//
// It is symmetric, so verifying requires the same secret used to sign -- which
// means either Allem holds every agent's secret (the property Ed25519 exists to
// remove) or nobody can verify at all. Today it is the latter: **the server has
// no HMAC secret registry and records these events as unverified.**
//
// Do not describe an HMAC-signed sequence as verifiable. Use Ed25519Signer.
type HMACSigner struct {
	secret []byte
}

// NewHMACSigner wraps a shared secret.
func NewHMACSigner(secret string) *HMACSigner {
	return &HMACSigner{secret: []byte(secret)}
}

// Method implements Signer.
func (s *HMACSigner) Method() string { return MethodHMAC }

// Sign implements Signer.
func (s *HMACSigner) Sign(message []byte) (string, error) {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// String redacts, for the same reason Ed25519Signer's does.
func (s *HMACSigner) String() string { return "<HMACSigner secret=REDACTED>" }

// --------------------------------------------------------------------------- //
// The generator
// --------------------------------------------------------------------------- //

// SequenceBlock is one reserved position in a run.
type SequenceBlock struct {
	AgentID   string
	RunID     string
	ClientSeq int64

	// Filled in by Sign. Empty when no signer is configured -- unsigned is a
	// supported state (the server records `signature_verified: null`) and it
	// must not be confused with a signature that failed to verify.
	Signature       string
	SignatureMethod string
}

// wire returns the keys of the sequence block that travel on the wire.
//
// agent_id is already in the event envelope, so it is not repeated inside the
// sequence section -- the same four keys the Python SDK sends.
func (b SequenceBlock) wire() map[string]any {
	block := map[string]any{
		"run_id":     b.RunID,
		"client_seq": b.ClientSeq,
	}
	if b.Signature != "" {
		block["signature"] = b.Signature
		block["signature_method"] = b.SignatureMethod
	}
	return block
}

// SequenceGenerator hands out strictly increasing sequence numbers for one
// agent in one process.
//
// Generates a run_id at construction. Safe for concurrent use: agents are
// frequently concurrent, and a duplicated sequence number would look like
// tampering.
//
// NEVER reuse a sequence number. NEVER roll back the counter. If a send fails
// after a number was reserved, that number is burned -- its absence on the
// server is exactly the completeness signal we want.
//
// v1 limitation, carried over from the Python SDK and documented in the README:
// one generator per process means one run per process. Serverless / one-shot
// agents produce many short runs; completeness still holds per run, but gap
// detection is nearly vacuous for them. Do not attempt cross-process
// persistence here.
//
// **Reserving and signing are two steps, and the order is forced by the
// design.** Next reserves the number before anything can fail, which is what
// makes a lost event visible. The signature binds the CONTENT, so it cannot
// exist until the body is built -- and the body contains the reserved number.
// Hence Next then Sign. A single call that did both could only ever sign the
// position, which is the v1 defect.
type SequenceGenerator struct {
	agentID string
	runID   string
	signer  Signer

	mu  sync.Mutex
	seq int64
}

// NewSequenceGenerator starts a run for one agent.
func NewSequenceGenerator(agentID string, signer Signer) (*SequenceGenerator, error) {
	runID, err := newUUID4()
	if err != nil {
		return nil, err
	}
	return &SequenceGenerator{agentID: agentID, runID: runID, signer: signer}, nil
}

// RunID is the identifier this generator's events are numbered within.
func (g *SequenceGenerator) RunID() string { return g.runID }

// Next reserves the next sequence number. Call this BEFORE spooling.
func (g *SequenceGenerator) Next() SequenceBlock {
	g.mu.Lock()
	g.seq++
	seq := g.seq
	g.mu.Unlock()
	return SequenceBlock{AgentID: g.agentID, RunID: g.runID, ClientSeq: seq}
}

// Current is how many numbers have been handed out.
func (g *SequenceGenerator) Current() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.seq
}

// Sign attaches a content-binding signature to a reserved block.
//
// Returns the block unchanged when no signer is configured.
func (g *SequenceGenerator) Sign(block SequenceBlock, body map[string]any) (SequenceBlock, error) {
	if g.signer == nil {
		return block, nil
	}
	digest, err := ContentDigest(body)
	if err != nil {
		return block, err
	}
	message, err := SigningMessage(block.AgentID, block.RunID, block.ClientSeq, digest)
	if err != nil {
		return block, err
	}
	signature, err := g.signer.Sign(message)
	if err != nil {
		return block, err
	}
	block.Signature = signature
	block.SignatureMethod = g.signer.Method()
	return block, nil
}

// newUUID4 is a random UUID in the canonical textual form, matching what
// Python's `uuid.uuid4()` produces.
//
// Hand-rolled rather than pulled from a module: this package's dependency
// footprint is a thing a Go shop reads before it reads anything else, and a
// UUID is sixteen random bytes with six bits set.
func newUUID4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("allem: no randomness available for a run id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	hexed := hex.EncodeToString(b[:])
	return hexed[0:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:32], nil
}
