package token

import (
	"k8s.io/client-go/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/api/core/v1"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"crypto/rsa"
	"time"
	"log"
	"k8s.io/client-go/rest"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)



// AuthToken contains information about the authenticated user
type AuthToken struct {
	Exp		   time.Time `json:"exp"`
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
	if err != nil {
		log.Fatal(fmt.Sprintf("Erro occured while creating secret from public and private keys. Stopping now. Err: %s", err.Error()))
	}
	err = writeSigningSecret(keyPEM, pubKeyPEM)
	if err != nil {
		log.Fatal(fmt.Sprintf("Erro occured while creating secret from public and private keys. Stopping now. Err: %s", err.Error()))
	}
	return
}


func writeSigningSecret(privKey, pubKey []byte) error {
	newSecret := v1.Secret{
		Type:v1.SecretTypeOpaque,
		ObjectMeta: metav1.ObjectMeta{Name: getSecretName()},
		Data: map[string][]byte{"signing.priv": privKey, "signing.pub": pubKey},
	}

	_ , err := getK8sClient().CoreV1().Secrets(getNamespace()).Create(&newSecret)

	// only fail if error wasn't due to already existing secret
	if err != nil && !k8serrors.IsAlreadyExists(err){
		return err
	}
	return nil
}

func readSigningSecret() (*v1.Secret, error) {
	secret, err := getK8sClient().CoreV1().Secrets(getNamespace()).Get(getSecretName(), metav1.GetOptions{})
	if err != nil{
		return nil, err
	}
	return secret, nil
}

func getNamespace() string {
	ns := "default"
	if os.Getenv("MY_NAMESPACE") != ""{
		ns = os.Getenv("MY_NAMESPACE")
	}
	return ns
}

func getSecretName() string {
	ns := "ldap-signing-cert-secret"
	if os.Getenv("SIGNING_CERT_SECRET_NAME") != ""{
		ns = os.Getenv("SIGNING_CERT_SECRET_NAME")
	}
	return ns
}

func getK8sClient() *kubernetes.Clientset {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)

	if err != nil {
		log.Fatal(err)
	}
	return clientset
}
