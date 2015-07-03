package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/kismatic/kubernetes-ldap/ldap"

	log "github.com/golang/glog"
)

// LdapAuth represents a connection, and associated lookup strategy,
// for authentication via an LDAP server.
type LdapAuth struct {
	BaseDN             string
	Insecure           bool
	LdapServer         string
	LdapPort           uint
	UserLoginAttribute string
	SearchUserDN       string
	SearchUserPassword string
}

func requireBasicAuthPrompt(w http.ResponseWriter) {

	w.Header().Set("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
	w.WriteHeader(401)
	w.Write([]byte("401 Unauthorized\n"))

	return
}

// ParseCredentials is middleware that grab basic auth credentials from the request
func ParseCredentials(w http.ResponseWriter, r *http.Request) (username, password string, e error) {

	const basicScheme string = "Basic "

	var ok bool
	if username, password, ok = r.BasicAuth(); ok {

		// TODO(bc): make .v(2) level
		log.Infof("Trying auth of: %s\n", username)

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

// Authenticate returns middleware that tries to bind to an LDAP server
// in order to authenticate a user via credentials provided via basic
// auth.
func (a *LdapAuth) Authenticate(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Test connection to the server
		// var l *Conn
		// var err error
		log.Infof("connecting to: %s\n", fmt.Sprintf("%s:%d", a.LdapServer, a.LdapPort))

		if a.Insecure {
			l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", a.LdapServer, a.LdapPort))
		} else {
			l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", a.LdapServer, a.LdapPort), nil)
		}

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
			requireBasicAuthPrompt(w)
			return
		}

		// Test search username and password
		err = l.Bind(a.SearchUserDN, a.SearchUserPassword)
		if err != nil {
			log.Errorf("ERROR: Cannot authenticate search user: %s\n", err.Error())
			requireBasicAuthPrompt(w)
			return
		}

		// Find username
		// TODO(dlg): this is still unsanitized
		ldapfilter := fmt.Sprintf("(%s=%s)", a.UserLoginAttribute, uid)

		search := ldap.NewSearchRequest(
			a.BaseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			ldapfilter,
			[]string{"dn"},
			nil)

		sr, err := l.Search(search)
		if err != nil {
			log.Fatalf("ERROR: %s\n", err.Error())
			requireBasicAuthPrompt(w)
			return
		}

		fmt.Printf("Search: %s -> num of entries = %d\n", search.Filter, len(sr.Entries))
		sr.PrettyPrint(0)

		if len(sr.Entries) == 0 {
			log.Errorf("ERROR: user not found: %s\n", uid)
			requireBasicAuthPrompt(w)
			return
		}

		if len(sr.Entries) > 1 {
			log.Errorf("ERROR: more than one user found for: %s\n", uid)
			requireBasicAuthPrompt(w)
			return
		}

		//Bind as user to test password
		userDN := sr.Entries[0].DN
		err = l.Bind(userDN, userPassword)
		if err != nil {
			log.Errorf("ERROR: Cannot authenticate user: %s\n", err.Error())
			requireBasicAuthPrompt(w)
			return
		}

		next.ServeHTTP(w, r)

	})

}
