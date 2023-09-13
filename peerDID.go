package main

import (
	"crypto/ed25519"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
)

func main() {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}
	identifier := base58.Encode(publicKey)
	did := PeerDID{DID, DID_METHOD_NAME, TRANSFORMER, 0, identifier}
	fmt.Println(did.getDid())
}

const DID = "did"
const DID_METHOD_NAME = "peer"
const TRANSFORMER rune = 'z'

type PeerDID struct {
	scheme     string
	method     string
	transform  rune
	numAlgo    int8
	identifier string
}

func (peerDid PeerDID) getDid() string {
	return fmt.Sprintf("%s:%s:%d:%s%s", peerDid.scheme, peerDid.method, peerDid.numAlgo, string(peerDid.transform), peerDid.identifier)
}