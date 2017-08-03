package token

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/square/go-jose"
)

// Verifier verifies the serialized representation of a token
type Verifier interface {
	// Verify the payload and return the Token if the payload is valid.
	Verify(s string) (token *AuthToken, err error)
}

// EcdsaVerifier represents an object that can verify tokens.
type ecdsaVerifier struct {
	publicKey *ecdsa.PublicKey
}

// NewVerifier reads a verification key file, and returns a verifier
// to verify token objects.
func  NewVerifier(basename string) (Verifier, error) {
	buf, err := ioutil.ReadFile(basename + ".pub")
	if err != nil {
		return nil, err
	}
	pubKey, err := jose.LoadPublicKey(buf)
	if err != nil {
		return nil, err
	}
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Expected the public key to use ECDSA, but got a key of type %T", pubKey)
	}
	v := &ecdsaVerifier{
		publicKey: ecdsaPubKey,
	}
	return v, nil
}

// Verify checks that a token's signature is valid, and returns the
// token. Otherwise returns an error.
func (ev *ecdsaVerifier) Verify(s string) (token *AuthToken, err error) {
	jws, err := jose.ParseSigned(s)
	if err != nil {
		return
	}
	payload, err := jws.Verify(ev.publicKey)
	if err != nil {
		return
	}
	token = &AuthToken{}
	err = json.Unmarshal(payload, token)
	if err != nil {
		token = nil
		return
	}
	return
}
