package token

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"gopkg.in/square/go-jose.v2"
	"crypto/rsa"
	"time"
	"errors"
)

// Verifier verifies the serialized representation of a token
type Verifier interface {
	// Verify the payload and return the Token if the payload is valid.
	Verify(s string) (token *AuthToken, err error)
}

// EcdsaVerifier represents an object that can verify tokens.
type rsaVerifier struct {
	publicKey *rsa.PublicKey
}

// NewVerifier reads a verification key file, and returns a verifier
// to verify token objects.
func  NewVerifier(basename string) (Verifier, error) {
	buf, err := ioutil.ReadFile(basename + ".pub")
	if err != nil {
		return nil, err
	}
	pubKey, err := LoadPublicKey(buf)
	if err != nil {
		return nil, err
	}
	rsaPublicKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Expected the public key to use ECDSA, but got a key of type %T", pubKey)
	}
	v := &rsaVerifier{
		publicKey: rsaPublicKey,
	}
	return v, nil
}

// Verify checks that a token's signature is valid, and returns the
// token. Otherwise returns an error.
func (ev *rsaVerifier) Verify(s string) (token *AuthToken, err error) {
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

	// check exp field

	if token.Exp.Before(time.Now()) {
		return nil, errors.New("Token expired")
	}

	return
}
