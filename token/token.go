package token

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"crypto/rsa"
)

const (
	curveName = "P-256"    // curveName is the name of the ECDSA curve
)

var curveEll = elliptic.P256()

// AuthToken contains information about the authenticated user
type AuthToken struct {
	Username   string
	Assertions map[string]string
}

// GenerateKeypair generates a public and private RSA key, to be
// used for signing and verifying authentication tokens.
func GenerateKeypair(filename string) (err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}
	keyPEM := x509.MarshalPKCS1PrivateKey(priv)

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
}
