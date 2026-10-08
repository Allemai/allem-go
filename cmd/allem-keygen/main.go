// Command allem-keygen generates an Ed25519 signing keypair for an Allem agent.
//
//	go run github.com/Allemai/allem-go/cmd/allem-keygen -out ~/.allem/agent.key
//
// The private key is written to the path given, mode 0600, and is otherwise not
// retained, printed, or transmitted. The PUBLIC half goes to stdout, for
// `POST /v1/agents/{agent_id}/signing-keys`.
//
// **You hold the private key and Allem holds only the public one.** That is what
// makes "Allem cannot forge your completeness record" a property of the key
// material rather than a promise about our conduct.
//
// It is also what `backend/tests/test_go_sdk_parity.py` uses, so the parity run
// signs with a key the GO SDK generated and wrote rather than one Python
// produced and Go merely read: `SavePrivateKey` and `LoadEd25519Signer` are both
// on the path a customer takes, and a key one of them could not handle would
// otherwise show up as an unsigned event nobody noticed.
package main

import (
	"flag"
	"fmt"
	"os"

	allem "github.com/Allemai/allem-go"
)

func main() {
	out := flag.String("out", "", "where to write the private key (0600)")
	flag.Parse()

	if *out == "" {
		fmt.Fprintln(os.Stderr,
			"allem-keygen: -out is required, e.g. -out ~/.allem/agent.key")
		os.Exit(2)
	}
	public, err := allem.GenerateKeypair(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "allem-keygen: %v\n", err)
		os.Exit(1)
	}
	// The PUBLIC half, on stdout. The private key is written to the path given
	// and is otherwise not retained, printed, or transmitted.
	fmt.Print(public)
}
