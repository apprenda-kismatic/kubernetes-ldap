package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/kismatic/kubernetes-ldap/ldap"
	"net/http"
	"strings"

	log "github.com/golang/glog"
)

type LdapAuth struct {
	baseDN             string
	insecure           bool
	ldapServer         string
	ldapPort           uint
	userLoginAttribute string
	searchUserDN       string
	searchUserPassword string
}

func RequireBasicAuthPrompt(w http.ResponseWriter) {

	w.Header().Set("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
	w.WriteHeader(401)
	w.Write([]byte("401 Unauthorized\n"))

	return
}

// Grab credentials from the request
func ParseCredentials(w http.ResponseWriter, r *http.Request) (username, password string, e error) {

	// username = "spockywocky"
	// password = "test"

	const basicScheme string = "Basic "

	// Confirm the request is sending Basic Authentication credentials.
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, basicScheme) {

		// TODO(bc): make .v(2) level
		log.Infof("Trying auth of: %s\n", username)

		// Get the plain-text username and password from the request
		// The first six characters are skipped - e.g. "Basic ".
		str, err := base64.StdEncoding.DecodeString(auth[len(basicScheme):])
		if err != nil {
			e = errors.New("Could not parse basic authentication credentials from request")
			return
		}

		creds := bytes.SplitN(str, []byte(":"), 2)

		if len(creds) == 2 {
			username = string(creds[0])
			password = string(creds[1])
		}

		if username == "" || password == "" {
			e = errors.New("Username and password missing from request")
			return
		}

	} else if r.Header.Get("LDAPToken") != "" {
		// TODO: test for auth token, parse username

	} else {
		e = errors.New("Authentication missing from request")
	}

	return
}

func (a *LdapAuth) Authenticate(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Test connection to the server
		// var l *Conn
		// var err error
		log.Infof("connecting to: %s\n", fmt.Sprintf("%s:%d", a.ldapServer, a.ldapPort))

		// if a.insecure {
		l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", a.ldapServer, a.ldapPort))
		// } else {
		// 	l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", a.ldapServer, a.ldapPort), nil)
		// }

		if err != nil {
			log.Errorf("ERROR: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal server error\n"))
			return
		}
		defer l.Close()

		// LDAP Auth
		// l.Debug = true

		// Get user's user id and password
		uid, userPassword, err := ParseCredentials(w, r)
		if err != nil {
			log.Warningf("Warning: Missing credentials: %s\n", err.Error())
			RequireBasicAuthPrompt(w)
			return
		}

		// Test search username and password
		err = l.Bind(a.searchUserDN, a.searchUserPassword)
		if err != nil {
			log.Errorf("ERROR: Cannot authenticate search user: %s\n", err.Error())
			RequireBasicAuthPrompt(w)
			return
		}

		// Find username
		// TODO(dlg): this is still unsanitized
		ldapfilter := fmt.Sprintf("(%s=%s)", a.userLoginAttribute, uid)

		search := ldap.NewSearchRequest(
			a.baseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			ldapfilter,
			[]string{"dn"},
			nil)

		sr, err := l.Search(search)
		if err != nil {
			log.Fatalf("ERROR: %s\n", err.Error())
			RequireBasicAuthPrompt(w)
			return
		}

		fmt.Printf("Search: %s -> num of entries = %d\n", search.Filter, len(sr.Entries))
		sr.PrettyPrint(0)

		if len(sr.Entries) == 0 {
			log.Errorf("ERROR: user not found: %s\n", uid)
			RequireBasicAuthPrompt(w)
			return
		}

		if len(sr.Entries) > 1 {
			log.Errorf("ERROR: more than one user found for: %s\n", uid)
			RequireBasicAuthPrompt(w)
			return
		}

		//Bind as user to test password
		userDN := sr.Entries[0].DN
		err = l.Bind(userDN, userPassword)
		if err != nil {
			log.Errorf("ERROR: Cannot authenticate user: %s\n", err.Error())
			RequireBasicAuthPrompt(w)
			return
		}

		next.ServeHTTP(w, r)

	})

}

func NewLdapAuth(ldapServer string, ldapPort uint, insecure bool, baseDN string, userLoginAttribute string, searchUserDN string, searchUserPassword string) *LdapAuth {
	return &LdapAuth{ldapServer: ldapServer, ldapPort: ldapPort, insecure: insecure, baseDN: baseDN, userLoginAttribute: userLoginAttribute, searchUserDN: searchUserDN, searchUserPassword: searchUserPassword}
}
