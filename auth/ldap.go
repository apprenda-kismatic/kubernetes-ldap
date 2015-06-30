package auth

import (
	// "crypto/sha1"
	// "crypto/tls"
	// "encoding/base64"
	// "errors"
	"fmt"
	"github.com/kismatic/kubernetes-ldap/ldap"
	"log"
	// "net"
	"net/http"
	// "strings"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"strings"
)

type LdapAuth struct {
	ldapServer string
	ldapPort   uint
	username   string
	insecure   bool
}

func RequireBasicAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
	w.WriteHeader(401)
	w.Write([]byte("401 Unauthorized\n"))
}

// Grab credentials from the request
func ParseCredentials(r *http.Request) (username, password string) {

	username = "admin"    //pair[0]
	password = "passw0rd" //pair[1]

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
			log.Fatalf("ERROR: %s\n", err.Error())
		}
		defer l.Close()

		// LDAP Auth
		l.Debug = true

		user, passwd := ParseCredentials(r)

		err = l.Bind(user, passwd)
		if err != nil {
			log.Printf("ERROR: Cannot bind: %s\n", err.Error())

			RequireBasicAuth(w, r)
			return
		}

		next.ServeHTTP(w, r)

	})

}

func NewLdapAuth(ldapServer string, ldapPort uint, insecure bool) *LdapAuth {
	return &LdapAuth{ldapServer: ldapServer, ldapPort: ldapPort, insecure: insecure}
}
