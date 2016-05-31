package auth

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/go-ldap/ldap"
	"github.com/kismatic/kubernetes-ldap/token"
	"github.com/kismatic/kubernetes-ldap/token/proto"

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

	HeaderName string
	CookieName string

	TLSConfig *tls.Config
	issuer    *token.Issuer
}

func NewLdapAuth(ldapServer string, ldapPort uint, insecure bool, baseDN string, userLoginAttribute string, searchUserDN string, searchUserPassword string) *LdapAuth {
	return &LdapAuth{
		LdapServer:         ldapServer,
		LdapPort:           ldapPort,
		Insecure:           insecure,
		BaseDN:             baseDN,
		UserLoginAttribute: userLoginAttribute,
		SearchUserDN:       searchUserDN,
		SearchUserPassword: searchUserPassword}
}

func (a *LdapAuth) setAuthToken(w http.ResponseWriter, username, userDN string) {
	// TODO: Handle this error
	token, _ := a.issuer.Issue(&pb.Token{
		Username: username,
		Assertions: &pb.Token_StringAssertions{
			StringAssertions: &pb.StringAssertions{
				Assertions: map[string]string{
					"ldapServer": a.LdapServer,
					"userDN":     userDN,
				},
			},
		},
	})
	cookie := &http.Cookie{
		Name:     "k8s-auth",
		Value:    token,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, cookie)
	return
}

func writeBasicAuthError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
	w.WriteHeader(401)
	w.Write([]byte("401 Unauthorized\n"))

	return
}

// RequireAuthorization is middleware that requires LDAP authentication to
// make a request. It either uses a token provided as a header or a cookie,
// or prompts for basic auth as required.
func (a *LdapAuth) RequireAuthorization(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if username, _, ok := r.BasicAuth(); ok {
			err := a.authenticate(w, r)
			if err != nil {
				log.Errorf("error authenticating user %s: %s", username, err)
				writeBasicAuthError(w)
				return
			}
			// Success, so go on to the next handler.
			next(w, r)
			return
		}

		var token *pb.Token
		var err error
		if header, ok := r.Header[a.HeaderName]; ok && len(header) == 1 {
			token, err = a.issuer.Verify(header[0])
		}
		if cookie, ok := r.Cookie(a.CookieName); token == nil && err == nil && ok == nil && cookie.Value != "" {
			token, err = a.issuer.Verify(cookie.Value)
		}
		if err != nil {
			log.Warningf("error authenticating a purported authorization")
		}
		if token == nil || err != nil {
			writeBasicAuthError(w)
			return
		}

		// TODO(someone): whatever access control middleware is necessary; this probably means that we
		// should pass around an http.Context to handle the token
		log.V(2).Infof("verified authorization bearer token: %s", token)

		next(w, r)
		return
	})
}

// Authenticate returns middleware that tries to bind to an LDAP server
// in order to authenticate a user via credentials provided via basic
// auth.
func (a *LdapAuth) authenticate(w http.ResponseWriter, r *http.Request) error {
	log.Infof("connecting to: %s\n", fmt.Sprintf("%s:%d", a.LdapServer, a.LdapPort))

	var err error
	var l *ldap.Conn
	if a.Insecure && a.TLSConfig == nil {
		l, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", a.LdapServer, a.LdapPort))
	} else {
		l, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", a.LdapServer, a.LdapPort), nil)
	}

	if err != nil {
		log.Errorf("%s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error\n"))
		return err
	}
	defer l.Close()

	username, password, ok := r.BasicAuth()
	if !ok {
		log.Errorf("basic auth was not used; this should be impossible: %s\n", err)
		writeBasicAuthError(w)
		return err
	}
	if username == "" || password == "" {
		log.Warningf("username or password missing from request")
		return fmt.Errorf("username or password missing from request")
	}
	log.V(2).Infof("trying auth of: %s\n", username)

	var userDN string

	if a.SearchUserDN != "" {
		// Test search username and password
		err = l.Bind(a.SearchUserDN, a.SearchUserPassword)
		if err != nil {
			log.Errorf("Cannot authenticate search user: %s\n", err)
			writeBasicAuthError(w)
			return err
		}

		// Find username
		// TODO(dlg): this is still unsanitized
		userFilter := fmt.Sprintf("(%s=%s)", a.UserLoginAttribute, username)
		req := &ldap.SearchRequest{
			BaseDN:       a.BaseDN,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases, // ????
			SizeLimit:    2,
			TimeLimit:    10, // make configurable?
			TypesOnly:    false,
			Filter:       userFilter,
		}
		result, err := l.Search(req)
		if err != nil {
			return err
		}

		switch {
		case len(result.Entries) == 1:
			userDN = result.Entries[0].DN
			err = nil
		case len(result.Entries) == 0:
			err = fmt.Errorf("no result for the query %s", req.Filter)
		case len(result.Entries) > 1:
			err = fmt.Errorf("multiple results for the query %s: %+v", req.Filter, result.Entries)
		}

	} else {
		// TODO(dlg): sanitize!!!
		userDN = fmt.Sprintf("cn=%s,%s", username, a.BaseDN)
	}

	// Bind to verify password is correct
	err = l.Bind(userDN, password)

	if err != nil {
		return err
	}

	a.setAuthToken(w, username, userDN)
	return nil
}
