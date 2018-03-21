package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"

	"gopkg.in/ldap.v2"
	"os"
	"io/ioutil"
	"log"
	"strings"
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
	UserLoginAttribute string
	SearchUserDN       string
	SearchUserPassword string
	TLSConfig          *tls.Config
}

// Authenticate a user against the LDAP directory. Returns an LDAP entry if password
// is valid, otherwise returns an error.
func (c *Client) Authenticate(username, password string) (*ldap.Entry, error) {
	if isUserInBlacklist(username) {
		return nil, fmt.Errorf("This user is blacklisted. If you think this is an error contact an admin!")
	}
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

	if c.SearchUserDN == "" {
		return nil, fmt.Errorf("No UserDN was provided, aborting authentication")
	}

	if c.SearchUserPassword == "" {
		return nil, fmt.Errorf("No password for user %s was provided, aborting authentication", c.SearchUserDN)
	}

	// Now that we know the user exists within the BaseDN scope
	// let's do user bind to check credentials using the full DN instead of
	// the attribute used for search
	if c.SearchUserDN != "" && c.SearchUserPassword != "" {
		err = conn.Bind(res.Entries[0].DN, password)
		if err != nil {
			return nil, fmt.Errorf("Error binding user %s, invalid credentials: %v", username, err)
		}

		// Single user entry found
		return res.Entries[0], nil
	}

	return nil, fmt.Errorf("Something was wrong while authenticating the user. The latest error was %s", err.Error())
}

// Create a new TCP connection to the LDAP server
func (c *Client) dial() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", c.LdapServer, c.LdapPort)

	if c.TLSConfig != nil && !c.AllowInsecure {
		return ldap.DialTLS("tcp", address, c.TLSConfig)
	}

	// This will send passwords in clear text (LDAP doesn't obfuscate password in any way),
	// thus we use a flag to enable this mode
	if c.AllowInsecure {
		return ldap.Dial("tcp", address)
	}

	// TLSConfig was not specified, and insecure flag not set
	return nil, errors.New("The LDAP TLS Configuration was not set.")
}

func (c *Client) newUserSearchRequest(username string) *ldap.SearchRequest {
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

func isUserInBlacklist(username string) bool {
	blacklistFile := getBlacklistFilePath()
	blacklistPresent, err := fileExists(blacklistFile)
	if err != nil {
		log.Printf("An error occurred while tryin to read the blacklist file from file %s. Err: %s", blacklistFile, err)
		return false
	}
	if !blacklistPresent {
		return false
	}

	// actually check blacklist
	file, err := ioutil.ReadFile(blacklistFile)
	if err != nil {
		log.Printf("An error occurred while tryin to read the blacklist file from file %s. Err: %s", blacklistFile, err)
		return false
	}
	blacklistedUsers := strings.Split(string(file), "\n")
	for _, blacklistedUser := range blacklistedUsers {
		if blacklistedUser == username {
			return true
		}
	}
	return false
}

func fileExists(filename string) (bool, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func getBlacklistFilePath() string {
	file := "/etc/blacklist"
	envFile := os.Getenv("BLACKLIST_FILEPATH")
	if envFile != "" {
		file = envFile
	}
	return file
}
