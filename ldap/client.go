package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap"
)

// Authenticator authenticates a user against an LDAP directory
type Authenticator interface {
	Authenticate(username, password string) (*ldap.Entry, error)
}

// Client represents a connection, and associated lookup strategy,
// for authentication via an LDAP server.
type Client struct {
	BaseDN             string
	LdapServer         string
	LdapPort           uint
	AllowInsecure      bool
	StartTLS           bool
	UserLoginAttribute string
	SearchUserDN       string
	SearchUserPassword string
	TLSConfig          *tls.Config
}

// Authenticate a user against the LDAP directory. Returns an LDAP entry if password
// is valid, otherwise returns an error.
func (c *Client) Authenticate(username, password string) (*ldap.Entry, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("Error opening LDAP connection: %v", err)
	}
	defer conn.Close()

	// Bind user to perform the search
	if c.SearchUserDN != "" && c.SearchUserPassword != "" {
		err = conn.Bind(c.SearchUserDN, c.SearchUserPassword)
	} else {
		err = conn.Bind(username, password)
	}
	if err != nil {
		return nil, fmt.Errorf("Error binding user to LDAP server: %v", err)
	}

	req := c.newUserSearchRequest(username)

	// Do a search to ensure the user exists within the BaseDN scope
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("Error searching for user %s: %v", username, err)
	}

	switch {
	case len(res.Entries) == 0:
		return nil, fmt.Errorf("No result for the search filter '%s'", req.Filter)
	case len(res.Entries) > 1:
		return nil, fmt.Errorf("Multiple entries found for the search filter '%s': %+v", req.Filter, res.Entries)
	}

	// Now that we know the user exists within the BaseDN scope
	// let's do user bind to check credentials using the full DN instead of
	// the attribute used for search
	if c.SearchUserDN != "" && c.SearchUserPassword != "" {
		err = conn.Bind(res.Entries[0].DN, password)
		if err != nil {
			return nil, fmt.Errorf("Error binding user %s, invalid credentials: %v", username, err)
		}
	}

	// Single user entry found
	return res.Entries[0], nil
}

// Create a new TCP connection to the LDAP server
func (c *Client) dial() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", c.LdapServer, c.LdapPort)

	// This will send passwords in clear text (LDAP doesn't obfuscate password in any way),
	// thus we use a flag to enable this mode
	if c.AllowInsecure {
		l, err := ldap.Dial("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("Error opening unencrypted connection: %v", err)
		}
		return l, err
	}
	if c.TLSConfig != nil {
		// StartTLS
		if c.StartTLS {
			l, err := ldap.Dial("tcp", address)
			if err != nil {
				return nil, fmt.Errorf("Error beginning with an unencrypted connection (StartTLS): %v", err)
			}

			// Reconnect with TLS
			err = l.StartTLS(c.TLSConfig)
			if err != nil {
				return nil, fmt.Errorf("Error switching to an encrypted connection (StartTLS): %v", err)
			}
			return l, err
		} else {
			// LDAPS
			l, err := ldap.DialTLS("tcp", address, c.TLSConfig)
			if err != nil {
				return nil, fmt.Errorf("Error opening encrypted connection (LDAPS): %v", err)
			}
			return l, err
		}
	}

	// TLSConfig was not specified, and insecure flag not set
	return nil, errors.New("The LDAP TLS Configuration was not set.")
}

func (c *Client) newUserSearchRequest(username string) *ldap.SearchRequest {
	// TODO(abrand): sanitize
	userFilter := fmt.Sprintf("(%s=%s)", c.UserLoginAttribute, username)
	return &ldap.SearchRequest{
		BaseDN:       c.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases, // ????
		SizeLimit:    2,
		TimeLimit:    10, // make configurable?
		TypesOnly:    false,
		Filter:       userFilter,
	}
}
