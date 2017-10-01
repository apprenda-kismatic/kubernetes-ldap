package auth

import (
	"net/http"

	"github.com/apprenda-kismatic/kubernetes-ldap/ldap"
	"github.com/apprenda-kismatic/kubernetes-ldap/token"
	goldap "github.com/go-ldap/ldap"
	"github.com/golang/glog"
	"strings"
)

// LDAPTokenIssuer issues cryptographically secure tokens after authenticating the
// user against a backing LDAP directory.
type LDAPTokenIssuer struct {
	LDAPServer        string
	LDAPAuthenticator ldap.Authenticator
	TokenSigner       token.Signer
}

func (lti *LDAPTokenIssuer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	user, password, ok := req.BasicAuth()
	if !ok {
		resp.Header().Add("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Authenticate the user via LDAP
	ldapEntry, err := lti.LDAPAuthenticator.Authenticate(user, password)
	if err != nil {
		glog.Errorf("Error authenticating user: %v", err)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Auth was successful, create token
	token := lti.createToken(ldapEntry)

	// Sign token and return
	signedToken, err := lti.TokenSigner.Sign(token)
	if err != nil {
		glog.Errorf("Error signing token: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.Header().Add("Content-Type", "text/plain")
	resp.Write([]byte(signedToken))
}

func (lti *LDAPTokenIssuer) getGroupsFromMembersOf(membersOf string) []string {
	//memberOf: CN=Group1,CN=Users,DC=lab,DC=proofpoint,DC=com

	var groupsOf []string

	splitted_str := strings.Split(membersOf, ",")
	for _, element := range splitted_str {
		if strings.Contains(element, "CN=") {
			groupsOf = append(groupsOf, strings.Replace(element, "CN=", "", 1))
		}
	}

    return groupsOf
}

func (lti *LDAPTokenIssuer) createToken(ldapEntry *goldap.Entry) *token.AuthToken {
	return &token.AuthToken{
		Username: ldapEntry.GetAttributeValue("mail"),
		Groups: lti.getGroupsFromMembersOf(ldapEntry.GetAttributeValue("memberOf")),
		Assertions: map[string]string{
			"ldapServer": lti.LDAPServer,
			"userDN":     ldapEntry.DN,
		},
	}
}
