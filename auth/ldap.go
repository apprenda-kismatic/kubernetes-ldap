package auth

import (
	"errors"
	"fmt"

	log "github.com/golang/glog"

	"github.com/kismatic/kubernetes-ldap/ldap"

	"net/http"
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

func RequireBasicAuth(w http.ResponseWriter, r *http.Request) {

}

// Grab credentials from the request
func ParseCredentials(w http.ResponseWriter, r *http.Request) (username, password string, err error) {

	// username = "kirkj"
	username = "spockywocky"
	password = "test"

	if username == "" || password == "" {
		err = errors.New("Username and password missing from request")

		w.Header().Set("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
		w.WriteHeader(401)
		w.Write([]byte("401 Unauthorized\n"))
		return
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
			log.Errorf("ERROR: Cannot bind: %s\n", err.Error())
			return
		}

		// Test search username and password
		err = l.Bind(a.searchUserDN, a.searchUserPassword)
		if err != nil {
			log.Errorf("ERROR: Cannot bind: %s\n", err.Error())
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
			return
		}
		// TODO(bc): Check num results

		fmt.Printf("Search: %s -> num of entries = %d\n", search.Filter, len(sr.Entries))
		sr.PrettyPrint(0)

		//Bind as user to test password
		userDN := sr.Entries[0].DN
		err = l.Bind(userDN, userPassword)
		if err != nil {
			log.Errorf("ERROR: Cannot bind user: %s\n", err.Error())
			return
		}

		next.ServeHTTP(w, r)

	})

}

func NewLdapAuth(ldapServer string, ldapPort uint, insecure bool, baseDN string, userLoginAttribute string, searchUserDN string, searchUserPassword string) *LdapAuth {
	return &LdapAuth{ldapServer: ldapServer, ldapPort: ldapPort, insecure: insecure, baseDN: baseDN, userLoginAttribute: userLoginAttribute, searchUserDN: searchUserDN, searchUserPassword: searchUserPassword}
}
