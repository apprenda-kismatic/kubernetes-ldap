package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/kismatic/kubernetes-ldap/token/proto"
	jose "github.com/square/go-jose"
)

const (
	curveName = "P-256"    // curveName is the name of the ECDSA curve
	curveJose = jose.ES256 // curveJose is the name of the JWS algorithm
)

var curveEll = elliptic.P256()

// Signer signs an issued token
type Signer interface {
	// Sign a token and return the serialized cryptographic token.
	Sign(token *pb.Token) (string, error)
}

// Verifier verifies the serialized representation of a token
type Verifier interface {
	// Verify the payload and return the Token if the payload is valid.
	Verify(s string) (token *pb.Token, err error)
}

// EcdsaSigner represents a signer of tokens under a particular public key.
type ecdsaSigner struct {
	ecdsaVerifier
	signer jose.Signer
}

// EcdsaVerifier represents an object that can verify tokens.
type ecdsaVerifier struct {
	publicKey *ecdsa.PublicKey
}

// GenerateKeypair generates a public and private ECDSA key, for
// later user with NewIssuer or NewVerifier.
func GenerateKeypair(filename string) (err error) {
	priv, err := ecdsa.GenerateKey(curveEll, rand.Reader)
	if err != nil {
		return
	}
	keyPEM, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename+".priv", keyPEM, os.FileMode(0600))
	if err != nil {
		return
	}
	pub := priv.Public()
	pubKeyPEM, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("Error marshalling public key: %v", err)
	}
	err = ioutil.WriteFile(filename+".pub", pubKeyPEM, os.FileMode(0644))
	return
	// TODO(dlg): also write out JWK
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

// Issue issues a new, signed token, logging it to iss.LogToken
// if that's non-nil.
func (es *ecdsaSigner) Sign(token *pb.Token) (string, error) {
	tokenBytes, err := proto.Marshal(token)
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

// NewVerifier reads a verification key file, and returns a verifier
// to verify token objects.
func NewVerifier(basename string) (Verifier, error) {
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

// Verify checks that a token's signature is valid, and that the
// protobuf is syntactically valid as a token.
func (ev *ecdsaVerifier) Verify(s string) (token *pb.Token, err error) {
	jws, err := jose.ParseSigned(s)
	if err != nil {
		return
	}
	payload, err := jws.Verify(ev.publicKey)
	if err != nil {
		return
	}
	token = &pb.Token{}
	err = proto.Unmarshal(payload, token)
	if err != nil {
		token = nil
		return
	}
	return
}
