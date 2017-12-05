package kubernetesldapmain

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/golang/glog"
	"github.com/apprenda-kismatic/kubernetes-ldap/auth"
	"github.com/apprenda-kismatic/kubernetes-ldap/ldap"
	"github.com/apprenda-kismatic/kubernetes-ldap/token"

	goflag "flag"

	flag "github.com/spf13/pflag"
	"log"
)

const (
	usage = "kubernetes-ldap <options>"
)

var flLdapAllowInsecure = flag.Bool("ldap-insecure", false, "Disable LDAP TLS")
var flLdapHost = flag.String("ldap-host", "", "Host or IP of the LDAP server")
var flLdapPort = flag.Uint("ldap-port", 389, "LDAP server port")
var flBaseDN = flag.String("ldap-base-dn", "", "LDAP user base DN in the form 'dc=example,dc=com'")
var flUserLoginAttribute = flag.String("ldap-user-attribute", "uid", "LDAP Username attribute for login")
var flSearchUserDN = flag.String("ldap-search-user-dn", "", "Search user DN for this app to find users (e.g.: cn=admin,dc=example,dc=com).")
var flSearchUserPassword = flag.String("ldap-search-user-password", "", "Search user password")
var flSkipLdapTLSVerification = flag.Bool("ldap-skip-tls-verification", false, "Skip LDAP server TLS verification")

var flServerPort = flag.Uint("port", 8080, "Local port this proxy server will run on")
var flAuthNServerPort = flag.Uint("authn-port", 8443, "Local port this server will run on for AuthN endpoint")
var flHostTLS = flag.Bool("host-tls", false, "Set to true if you want to host via HTTPS, --tls-cert-file and --tls-private-key-file will be required then.")
var flTLSCertFile = flag.String("tls-cert-file", "","File containing x509 Certificate for HTTPS.  (CA cert, if any, concatenated after server cert). Requires --host-tls set to true to have an effect!")
var flTLSPrivateKeyFile = flag.String("tls-private-key-file", "", "File containing x509 private key matching --tls-cert-file. Requires --host-tls set to true to have an effect!")

var flAuthNTLSCertFile = flag.String("authn-tls-cert-file", "","File containing x509 Certificate for AuthN in-cluster HTTPS.  (CA cert, if any, concatenated after server cert).")
var flAuthNTLSPrivateKeyFile = flag.String("authn-tls-private-key-file", "", "File containing x509 private key matching --authn-tls-cert-file. ")

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", usage)
		flag.PrintDefaults()
	}
}

func Main() {
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine) // support glog flags
	flag.Parse()

	// validate required flags
	requireFlag("--ldap-host", flLdapHost)
	requireFlag("--ldap-base-dn", flBaseDN)
	requireFlag("--authn-tls-cert-file", flAuthNTLSCertFile)
	requireFlag("--authn-tls-private-key-file", flAuthNTLSPrivateKeyFile)

	if *flHostTLS {
		requireFlag("--tls-cert-file", flTLSCertFile)
		requireFlag("--tls-private-key", flTLSPrivateKeyFile)
	}

	glog.CopyStandardLogTo("INFO")

	keypairFilename := "signing"
	if err := token.GenerateKeypair(keypairFilename); err != nil {
		glog.Errorf("Error generating key pair: %v", err)
	}

	var err error
	tokenSigner, err := token.NewSigner(keypairFilename)
	if err != nil {
		glog.Errorf("Error creating token issuer: %v", err)
	}

	tokenVerifier, err := token.NewVerifier(keypairFilename)
	if err != nil {
		glog.Errorf("Error creating token verifier: %v", err)
	}

	ldapTLSConfig := &tls.Config{
		ServerName:         *flLdapHost,
		InsecureSkipVerify: *flSkipLdapTLSVerification,
	}


	ldapClient := &ldap.Client{
		BaseDN:             *flBaseDN,
		LdapServer:         *flLdapHost,
		LdapPort:           *flLdapPort,
		AllowInsecure:      *flLdapAllowInsecure,
		UserLoginAttribute: *flUserLoginAttribute,
		SearchUserDN:       *flSearchUserDN,
		SearchUserPassword: *flSearchUserPassword,
		TLSConfig:          ldapTLSConfig,
	}

	webhook := auth.NewTokenWebhook(tokenVerifier)

	ldapTokenIssuer := &auth.LDAPTokenIssuer{
		LDAPAuthenticator: ldapClient,
		TokenSigner:       tokenSigner,
	}

	// Endpoint for authenticating with token
	routerForApiServer := http.NewServeMux()
	routerForApiServer.Handle("/authenticate", webhook)


	// Endpoint for token issuance after LDAP auth
	routerPublicTokenEndpoint := http.NewServeMux()
	routerPublicTokenEndpoint.Handle("/ldapAuth", ldapTokenIssuer)

	// Endpoint for liveness probe
	routerPublicTokenEndpoint.HandleFunc("/healthz", healthz)

	glog.Infof("Serving on %s", fmt.Sprintf(":%d", *flServerPort))

	tlsCfg := &tls.Config{
		// Change default from SSLv3 to TLSv1.0 (because of POODLE vulnerability)
		MinVersion: tls.VersionTLS10,
	}

	serverPublicTokenEndpoint := &http.Server{
		Addr: fmt.Sprintf(":%d", *flServerPort),
		Handler: routerPublicTokenEndpoint,
		TLSConfig: tlsCfg,
	}

	serverForApiServer := &http.Server{
		Addr: fmt.Sprintf(":%d", *flAuthNServerPort),
		Handler: routerForApiServer,
		TLSConfig: tlsCfg,
	}


	if *flHostTLS {
		go func(){
			err:= serverPublicTokenEndpoint.ListenAndServeTLS(*flTLSCertFile, *flTLSPrivateKeyFile)
			log.Fatal(err)
		}()
		glog.Fatal(serverForApiServer.ListenAndServeTLS(*flAuthNTLSCertFile, *flAuthNTLSPrivateKeyFile))
	} else {
		go func(){
			err := serverPublicTokenEndpoint.ListenAndServe()
			log.Fatal(err)
		}()
		glog.Fatal(serverForApiServer.ListenAndServeTLS(*flAuthNTLSCertFile, *flAuthNTLSPrivateKeyFile))
	}

}

func healthz(w http.ResponseWriter, r *http.Request){
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func requireFlag(flagName string, flagValue *string) {
	if *flagValue == "" {
		fmt.Fprintf(os.Stderr, "kubernetes-ldap: %s is required. \nUse -h flag for help.\n", flagName)
		os.Exit(1)
	}
}
