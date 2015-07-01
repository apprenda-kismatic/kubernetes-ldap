package auth

import (
	"fmt"

	log "github.com/golang/glog"

	"github.com/kismatic/kubernetes-ldap/ldap"

	"net/http"
)

type LdapAuth struct {
	ldapServer string
	ldapPort   uint
	username   string
	insecure   bool
}

func RequireBasicAuth(w http.ResponseWriter, r *http.Request) {

}

// Grab credentials from the request
func ParseCredentials(r *http.Request) (username, password string) {

	username = "admin"
	password = "passw0rd"

	return
}

func (a *LdapAuth) Authenticate(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// var l *Conn
		// var err error

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
		l.Debug = true

		user, passwd := ParseCredentials(r)

		err = l.Bind(user, passwd)
		if err != nil {
			log.Errorf("ERROR: Cannot bind: %s\n", err.Error())

			w.Header().Set("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
			w.WriteHeader(401)
			w.Write([]byte("401 Unauthorized\n"))
			return
		}

		next.ServeHTTP(w, r)

	})

}

func NewLdapAuth(ldapServer string, ldapPort uint, insecure bool) *LdapAuth {
	return &LdapAuth{ldapServer: ldapServer, ldapPort: ldapPort, insecure: insecure}
}
