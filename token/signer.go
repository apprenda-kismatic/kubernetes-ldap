package token

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/square/go-jose"
)

// Signer signs an issued token
type Signer interface {
	// Sign a token and return the serialized cryptographic token.
	Sign(token *AuthToken) (string, error)
}

// ecdsaSigner represents a signer of tokens under a particular public key.
type ecdsaSigner struct {
	ecdsaVerifier
	signer jose.Signer
}

// NewSigner is, for the moment, a thin wrapper around Square's
// go-jose library to issue ECDSA-P256 JWS tokens.
func NewSigner(filename string) (Signer, error) {
	// We use P-256, because Go has a constant-time implementation
	// of it. Go correctly checks that points are on the curve. A
	// version of Go > 1.4 is recommended, because ECDSA signatures
	// in previous versions are unsafe.
	key, err := ioutil.ReadFile(filename + ".priv")
	if err != nil {
		return nil, err
	}

	privateKey, err := jose.LoadPrivateKey(key)
	if err != nil {
		return nil, err
	}
	// TODO(dlg): Once JOSE supports it, make sure that this works for curve25519
	// Check that it's actually an ECDSA key,
	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected an ECDSA private key, but got a key of type %T", privateKey)
	}
	// and that it's on the expected curve.
	if ecdsaKey.Params().Name != curveName {
		return nil, fmt.Errorf("expected the key to use %s, but it's using %s", curveName, ecdsaKey.Params().Name)
	}

	signer, err := jose.NewSigner(curveJose, privateKey)
	if err != nil {
		return nil, err
	}
	ecdsaSigner := &ecdsaSigner{
		signer: signer,
	}
	ecdsaSigner.publicKey = &ecdsaKey.PublicKey
	return ecdsaSigner, nil
}

// Sign an authentcation token and return the serialized JWS
func (es *ecdsaSigner) Sign(token *AuthToken) (string, error) {
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		// panic? what are the conditions under which this can fail?
		return "", err
	}
	jws, err := es.signer.Sign(tokenBytes)
	if err != nil {
		return "", err
	}
	signed, err := jws.CompactSerialize()
	if err != nil {
		return "", err
	}
	return signed, nil
}
