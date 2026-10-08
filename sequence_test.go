package allem

// The signature that points the other way, and the golden vector that pins
// three implementations to each other.

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var goldenBody = map[string]any{
	"agent_id":          "billing-bot",
	"agent_external_id": "billing-bot",
	"action": map[string]any{
		"type":       "refund.issue",
		"parameters": map[string]any{"amount": 4200},
	},
	"external_event_id": "run-1:7",
}

func TestSigningMessageGoldenVector(t *testing.T) {
	// THE cross-implementation contract. The SAME literal is asserted in
	// `sdk/allem-python/tests/test_signing.py` and in
	// `backend/tests/test_sequence_signature.py`. The server must not import the
	// SDK and this package imports neither, so three independent implementations
	// of one wire format are kept honest by this string and nothing else.
	//
	// A wire format is expensive to change once agents are signing with it; this
	// literal is what makes an accidental change loud.
	message, err := SigningMessage("billing-bot", "run-1", 7, string(bytes.Repeat([]byte("a"), 64)))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"agent_id":"billing-bot","client_seq":7,"content_digest":"` +
		string(bytes.Repeat([]byte("a"), 64)) + `","run_id":"run-1"}`)
	if !bytes.Equal(message, want) {
		t.Fatalf("the signed bytes differ from the golden vector.\n  go:     %s\n  golden: %s",
			message, want)
	}
}

func TestContentDigestExcludesTheSequenceBlock(t *testing.T) {
	// The signature lives inside `sequence`, so a digest covering it could never
	// be computed. Excluding the whole block is what makes signing possible at
	// all -- and it loses nothing, because agent_id, run_id and client_seq are
	// named explicitly in the signed message.
	bare, err := ContentDigest(goldenBody)
	if err != nil {
		t.Fatal(err)
	}
	withSequence := map[string]any{}
	for k, v := range goldenBody {
		withSequence[k] = v
	}
	withSequence["sequence"] = map[string]any{"run_id": "run-1", "client_seq": 7}

	withDigest, err := ContentDigest(withSequence)
	if err != nil {
		t.Fatal(err)
	}
	if bare != withDigest {
		t.Fatal("the digest changed when a sequence block was added, so a payload " +
			"could never be signed: the signature goes inside the block it covers")
	}
}

func TestContentDigestChangesWithContent(t *testing.T) {
	// The whole point of v2 over v1: a signature for position 5 could be lifted
	// onto any payload at all.
	other := map[string]any{}
	for k, v := range goldenBody {
		other[k] = v
	}
	other["action"] = map[string]any{
		"type": "refund.issue", "parameters": map[string]any{"amount": 9999},
	}
	a, _ := ContentDigest(goldenBody)
	b, _ := ContentDigest(other)
	if a == b {
		t.Fatal("two different bodies digest the same")
	}
}

func TestASignatureVerifiesAgainstThePublicHalf(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	gen, err := NewSequenceGenerator("billing-bot", signer)
	if err != nil {
		t.Fatal(err)
	}
	block := gen.Next()
	signed, err := gen.Sign(block, goldenBody)
	if err != nil {
		t.Fatal(err)
	}
	if signed.SignatureMethod != MethodEd25519 {
		t.Fatalf("method = %q", signed.SignatureMethod)
	}

	// Verified through the PEM the registration endpoint takes, not through the
	// in-memory key, so the export path is exercised too.
	publicPEM, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	public := parsePublicPEM(t, publicPEM)

	digest, _ := ContentDigest(goldenBody)
	message, _ := SigningMessage("billing-bot", block.RunID, block.ClientSeq, digest)
	raw, err := hex.DecodeString(signed.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, message, raw) {
		t.Fatal("the signature does not verify against its own public half")
	}
}

func TestASignatureDoesNotTransferToAnotherPayloadOrPosition(t *testing.T) {
	signer, _ := GenerateEd25519Signer()
	gen, _ := NewSequenceGenerator("billing-bot", signer)
	block := gen.Next()
	signed, _ := gen.Sign(block, goldenBody)
	public := parsePublicPEM(t, mustPEM(t, signer))
	raw, _ := hex.DecodeString(signed.Signature)

	tampered := map[string]any{}
	for k, v := range goldenBody {
		tampered[k] = v
	}
	tampered["action"] = map[string]any{
		"type": "refund.issue", "parameters": map[string]any{"amount": 999999},
	}
	tamperedDigest, _ := ContentDigest(tampered)
	tamperedMessage, _ := SigningMessage("billing-bot", block.RunID, block.ClientSeq, tamperedDigest)
	if ed25519.Verify(public, tamperedMessage, raw) {
		t.Fatal("a signature lifted onto different CONTENT verified")
	}

	digest, _ := ContentDigest(goldenBody)
	otherPosition, _ := SigningMessage("billing-bot", block.RunID, block.ClientSeq+1, digest)
	if ed25519.Verify(public, otherPosition, raw) {
		t.Fatal("a signature lifted onto a different POSITION verified")
	}
}

func TestSequenceNumbersAreStrictlyIncreasingUnderConcurrency(t *testing.T) {
	// Agents are frequently concurrent, and a duplicated sequence number would
	// look like tampering.
	gen, err := NewSequenceGenerator("billing-bot", nil)
	if err != nil {
		t.Fatal(err)
	}
	const goroutines, each = 16, 100

	var mu sync.Mutex
	seen := map[int64]bool{}
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				block := gen.Next()
				mu.Lock()
				if seen[block.ClientSeq] {
					t.Errorf("client_seq %d was handed out twice", block.ClientSeq)
				}
				seen[block.ClientSeq] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != goroutines*each {
		t.Fatalf("got %d distinct numbers, want %d", len(seen), goroutines*each)
	}
	for i := int64(1); i <= goroutines*each; i++ {
		if !seen[i] {
			t.Fatalf("client_seq %d was never handed out, so the sequence has a "+
				"hole in it that no event caused", i)
		}
	}
}

func TestAnUnsignedBlockIsASupportedStateAndNotAFailure(t *testing.T) {
	// The server records `signature_verified: null` for it, which must not be
	// confused with a signature that failed to verify.
	gen, _ := NewSequenceGenerator("billing-bot", nil)
	block := gen.Next()
	signed, err := gen.Sign(block, goldenBody)
	if err != nil {
		t.Fatalf("signing with no signer returned an error: %v", err)
	}
	if signed.Signature != "" || signed.SignatureMethod != "" {
		t.Fatal("a signature appeared with no signer configured")
	}
	wire := signed.wire()
	if _, ok := wire["signature"]; ok {
		t.Fatal("an empty signature reached the wire. Absent and empty are " +
			"different claims and the server reads them differently.")
	}
}

func TestTheWireBlockCarriesFourKeysAndNotAgentID(t *testing.T) {
	// agent_id is already in the event envelope, so it is not repeated inside
	// the sequence section -- the same four keys the Python SDK sends.
	signer, _ := GenerateEd25519Signer()
	gen, _ := NewSequenceGenerator("billing-bot", signer)
	signed, err := gen.Sign(gen.Next(), goldenBody)
	if err != nil {
		t.Fatal(err)
	}
	wire := signed.wire()
	want := map[string]bool{"run_id": true, "client_seq": true, "signature": true, "signature_method": true}
	for key := range wire {
		if !want[key] {
			t.Errorf("the sequence block carries an unexpected key %q", key)
		}
	}
	for key := range want {
		if _, ok := wire[key]; !ok {
			t.Errorf("the sequence block is missing %q", key)
		}
	}
	if _, ok := wire["agent_id"]; ok {
		t.Error("agent_id is repeated inside the sequence block")
	}
}

func TestAPrivateKeyNeverReachesAFormattedString(t *testing.T) {
	// A private key that reaches a traceback frame has already leaked.
	signer, _ := GenerateEd25519Signer()
	rendered := signer.String()
	if !containsFold(rendered, "REDACTED") {
		t.Fatalf("Ed25519Signer renders as %q", rendered)
	}
	if containsFold(rendered, hex.EncodeToString(signer.private[:8])) {
		t.Fatal("key material appears in the rendered form")
	}

	hmacSigner := NewHMACSigner("super-secret")
	if containsFold(hmacSigner.String(), "super-secret") {
		t.Fatalf("HMACSigner renders its secret: %q", hmacSigner.String())
	}
}

func TestAKeyFileIsWrittenOwnerOnlyAndItsParentIsCreated(t *testing.T) {
	// The Python SDK shipped without creating the parent, and its own published
	// README told a reader to write a key into a directory that does not exist
	// on the machine the command is for.
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "does", "not", "exist", "agent.key")

	publicPEM, err := GenerateKeypair(path)
	if err != nil {
		t.Fatalf("GenerateKeypair into a directory that does not exist: %v", err)
	}
	if publicPEM == "" {
		t.Fatal("no public key was returned, so nothing could be registered")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("private key is mode %o, want 600", mode)
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := parent.Mode().Perm(); mode != 0o700 {
		t.Errorf("the directory holding a private key is mode %o, want 700", mode)
	}

	// And it round-trips through the loader the client uses.
	loaded, err := LoadEd25519Signer(path)
	if err != nil {
		t.Fatalf("the key this package wrote could not be read back: %v", err)
	}
	loadedPEM, _ := loaded.PublicKeyPEM()
	if loadedPEM != publicPEM {
		t.Fatal("the key read back is not the key written")
	}
}

func TestNoErrorFromTheKeyLoaderQuotesTheFile(t *testing.T) {
	// A malformed private key is still a private key, and an error message is a
	// log line waiting to happen.
	dir := t.TempDir()
	secretish := "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINOTAREALKEYBUTSTILLSECRET\n-----END PRIVATE KEY-----\n"
	path := filepath.Join(dir, "broken.key")
	if err := os.WriteFile(path, []byte(secretish), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadEd25519Signer(path)
	if err == nil {
		t.Fatal("a malformed key loaded")
	}
	if containsFold(err.Error(), "MC4CAQAwBQYDK2Vw") || containsFold(err.Error(), "SECRET") {
		t.Fatalf("the error quotes the file's contents: %v", err)
	}
	if !containsFold(err.Error(), "Contents withheld") {
		t.Errorf("the error does not say the contents were withheld: %v", err)
	}
}

func TestAnEncryptedKeyIsRefusedByName(t *testing.T) {
	// Named by its PEM type rather than by `x509.IsEncryptedPEMBlock`, which only
	// sees the legacy DEK-Info form and would let a PKCS#8
	// "ENCRYPTED PRIVATE KEY" through to a parse error that says nothing useful.
	dir := t.TempDir()
	path := filepath.Join(dir, "encrypted.key")
	block := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("nonsense")})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadEd25519Signer(path)
	if err == nil || !containsFold(err.Error(), "encrypted") {
		t.Fatalf("an encrypted key produced %v, want a message naming encryption", err)
	}
}

func TestANonEd25519KeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrong-algorithm.key")
	// An RSA key in a valid PKCS#8 PEM. Generated small on purpose: this is
	// about the type check, not about the key.
	rsaPEM := generateRSAKeyPEM(t)
	if err := os.WriteFile(path, rsaPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadEd25519Signer(path)
	if err == nil || !containsFold(err.Error(), "not Ed25519") {
		t.Fatalf("an RSA key produced %v, want a message naming the algorithm", err)
	}
}

func TestRunIDsAreDistinctAndWellFormed(t *testing.T) {
	// The UUID is hand-rolled rather than pulled from a module -- this package's
	// dependency footprint is a thing a Go shop reads first, and a UUID is
	// sixteen random bytes with six bits set. So the bits are asserted.
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id, err := newUUID4()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("a run id repeated: %s", id)
		}
		seen[id] = true
		if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			t.Fatalf("malformed run id: %s", id)
		}
		if id[14] != '4' {
			t.Fatalf("run id %s is not version 4", id)
		}
		if variant := id[19]; variant != '8' && variant != '9' && variant != 'a' && variant != 'b' {
			t.Fatalf("run id %s has variant nibble %q", id, variant)
		}
	}
}

func TestHMACSignsButIsNotCalledVerifiable(t *testing.T) {
	// Retained so a deployment that sets ALLEM_SIGNING_SECRET keeps working. The
	// server has no HMAC secret registry and records these events as unverified.
	signer := NewHMACSigner("shared")
	if signer.Method() != MethodHMAC {
		t.Fatalf("method = %q", signer.Method())
	}
	sig, err := signer.Sign([]byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("HMAC-SHA256 hex is %d characters, want 64", len(sig))
	}
	again, _ := signer.Sign([]byte("message"))
	if sig != again {
		t.Fatal("HMAC is not deterministic")
	}
}

// -- helpers ---------------------------------------------------------------- //

func parsePublicPEM(t *testing.T, text string) ed25519.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		t.Fatalf("not a PEM block: %q", text)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is %T", parsed)
	}
	return public
}

func mustPEM(t *testing.T, signer *Ed25519Signer) string {
	t.Helper()
	text, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func generateRSAKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
