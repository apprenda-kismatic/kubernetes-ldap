package auth

import (
	"net/http"

	goldap "github.com/go-ldap/ldap"
	"github.com/golang/glog"
	"github.com/kismatic/kubernetes-ldap/ldap"
	"github.com/kismatic/kubernetes-ldap/token"
	"github.com/kismatic/kubernetes-ldap/token/proto"
)

// LDAPTokenIssuer issues cryptographically secure tokens after authenticating the
// user against a backing LDAP directory.
type LDAPTokenIssuer struct {
	LDAPClient  *ldap.Client
	TokenIssuer *token.Issuer
}

func (lti *LDAPTokenIssuer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	user, password, ok := req.BasicAuth()
	if !ok {
		resp.Header().Add("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Authenticate the user via LDAP
	ldapEntry, err := lti.LDAPClient.Authenticate(user, password)
	if err != nil {
		glog.Errorf("Error authenticating user: %v", err)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Auth was successful, create token
	token := lti.createToken(ldapEntry)

	// Sign token and return
	signedToken, err := lti.TokenIssuer.Issue(token)
	if err != nil {
		glog.Errorf("Error signing token: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.Header().Add("Content-Type", "text/plain")
	resp.Write([]byte(signedToken))
}

func (lti *LDAPTokenIssuer) createToken(ldapEntry *goldap.Entry) *pb.Token {
	return &pb.Token{
		Username: ldapEntry.DN,
		Assertions: &pb.Token_StringAssertions{
			StringAssertions: &pb.StringAssertions{
				Assertions: map[string]string{
					"ldapServer": lti.LDAPClient.LdapServer,
					"userDN":     ldapEntry.DN,
				},
			},
		},
	}
}
