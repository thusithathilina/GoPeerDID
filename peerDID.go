package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
)

func main() {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}
	did := NewPeerDID(publicKey)
	fmt.Println(did.getDid())

	doc, err := did.getDidDoc()
	if err != nil {
		fmt.Println("Error generating DID doc:", err)
		return
	}
	jsonDDOc, err := json.Marshal(doc)
	fmt.Println(string(jsonDDOc))
}

const DID = "did"
const DID_METHOD_NAME = "peer"
const TRANSFORMER rune = 'z'
const DEFAULT_CONTEXT string = "https://www.w3.org/ns/did/v1"

type PeerDID struct {
	scheme     string
	method     string
	transform  rune
	numAlgo    int8
	identifier string
}

func NewPeerDID(publicKey []byte) *PeerDID {
	identifier := base58.Encode(publicKey)
	return &PeerDID{DID, DID_METHOD_NAME, TRANSFORMER, 0, identifier}
}

func (peerDid PeerDID) getDid() string {
	return fmt.Sprintf("%s:%s:%d%s%s", peerDid.scheme, peerDid.method, peerDid.numAlgo, string(peerDid.transform), peerDid.identifier)
}

type VerificationMethod struct {
	Id                 string
	KeyType            string
	Controller         string
	PublicKeyMultibase string
}

type PeerDIDDoc struct {
	Context               []string
	Id                    string
	VerificationMethods   []VerificationMethod
	Authentications       []string
	AssertionMethods      []string
	CapabilityDelegations []string
	CapabilityInvocations []string
}

func signatureVerificationMethod(did PeerDID, publicKeyFormat string) (*VerificationMethod, error) {
	decodedId := base58.Decode(did.identifier)
	if len(decodedId) != 32 {
		return nil, errors.New("key must be a Ed25519")
	}
	return &VerificationMethod{did.getDid() + "#" + did.identifier, publicKeyFormat, did.getDid(), did.identifier}, nil
}

func (peerDid PeerDID) getDidDoc() (*PeerDIDDoc, error) {

	verificationMethod, err := signatureVerificationMethod(peerDid, "Ed25519VerificationKey2020")
	if err != nil {
		return nil, err
	}
	return &PeerDIDDoc{[]string{DEFAULT_CONTEXT},
		peerDid.getDid(),
		[]VerificationMethod{*verificationMethod},
		[]string{verificationMethod.Id},
		[]string{verificationMethod.Id},
		[]string{verificationMethod.Id},
		[]string{verificationMethod.Id},
	}, nil
}
