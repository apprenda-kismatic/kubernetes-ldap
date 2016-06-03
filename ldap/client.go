package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap"
)

// LdapClient represents a connection, and associated lookup strategy,
// for authentication via an LDAP server.
type Client struct {
	BaseDN             string
	LdapServer         string
	LdapPort           uint
	AllowInsecure      bool
	UserLoginAttribute string
	TLSConfig          *tls.Config
}

// Authenticate a user against the LDAP directory. Returns an LDAP entry if password
// is valid, otherwise returns an error.
// TODO(abrand): Currently assumes all users can search. Not sure if this is a reasonable assumption.
func (la *Client) Authenticate(username, password string) (*ldap.Entry, error) {
	conn, err := la.connect()
	if err != nil {
		return nil, fmt.Errorf("Error openning LDAP connection: %v", err)
	}
	defer conn.Close()

	// Bind user to validate credentials
	if err = conn.Bind(username, password); err != nil {
		return nil, fmt.Errorf("Error binding user to LDAP server: %v", err)
	}

	req := la.newUserSearchRequest(username)

	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("Error searching for user: %v", err)
	}

	switch {
	case len(res.Entries) == 0:
		return nil, fmt.Errorf("No result for the search filter '%s'", req.Filter)
	case len(res.Entries) > 1:
		return nil, fmt.Errorf("Multiple entries found for the search filter '%s': %+v", req.Filter, res.Entries)
	}

	// Single user entry found
	return res.Entries[0], nil
}

// Open a connection to the LDAP server
func (la *Client) connect() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", la.LdapServer, la.LdapPort)

	if la.TLSConfig != nil {
		return ldap.DialTLS("tcp", address, la.TLSConfig)
	}

	// This will send passwords in clear text (LDAP doesn't obfuscate password in any way),
	// thus we use a flag to enable this mode
	if la.TLSConfig == nil && la.AllowInsecure {
		return ldap.Dial("tcp", address)
	}

	// TLSConfig was not specified, and insecure flag not set
	return nil, errors.New("The LDAP TLS Configuration was not set.")
}

func (la *Client) newUserSearchRequest(username string) *ldap.SearchRequest {
	// TODO(abrand): sanitize
	userFilter := fmt.Sprintf("(%s=%s)", la.UserLoginAttribute, username)
	return &ldap.SearchRequest{
		BaseDN:       la.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases, // ????
		SizeLimit:    2,
		TimeLimit:    10, // make configurable?
		TypesOnly:    false,
		Filter:       userFilter,
	}
}
