package main

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/kismatic/kubernetes-ldap/auth"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	flag "github.com/spf13/pflag"
)

const usage = "kubernetes-ldap <options>"

var flPort = flag.Uint("port", 4000, "Local port this proxy server will run on")

var flInsecure = flag.Bool("ldap-insecure", true, "Disable LDAP SSL/TLS")
var flLdapHost = flag.String("ldap-host", "localhost", "Host or IP of the LDAP server")
var flLdapPort = flag.Uint("ldap-port", 389, "LDAP server port")
var flBaseDN = flag.String("ldap-base-dn", "", "LDAP user base DN in the form 'dc=example,dc=com'")
var flUserLoginAttribute = flag.String("ldap-user-attribute", "uid", "LDAP Username attribute for login")
var flSearchUser = flag.String("ldap-search-user", "", "Search user DN for this app to find users (e.g.: admin). Must be a part of the baseDN.")
var flSearchUserPassword = flag.String("ldap-search-user-password", "", "Search user password")

// TODO(bc): Change to consistent format (host/port)
var flApiserver = flag.String("apiserver", "http://localhost:8080", "Address of Kubernetes API server")

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", usage)
		flag.PrintDefaults()
	}
}

func NewSingleHostReverseProxy(url *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(url)
	// Rewrite the host
	oldDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		oldDirector(r)
		r.Host = url.Host
		rdump, _ := httputil.DumpRequest(r, true)
		glog.Infof("proxy.Director:\n%s\n", rdump)
	}
	return proxy
}

func main() {
	flag.Parse()

	if *flBaseDN == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --ldap-base-dn arg is required")
	}

	if *flBaseDN == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --ldap-base-dn arg is required")
	}

	if *flBaseDN == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --ldap-base-dn arg is required")
	}

	glog.CopyStandardLogTo("INFO")

	l := auth.NewLdapAuth(*flLdapHost, *flLdapPort, *flInsecure, *flBaseDN, *flUserLoginAttribute, *flSearchUser, *flSearchUserPassword)

	target, err := url.Parse(*flApiserver)

	if err != nil {
		glog.Fatal(err)
	}
	proxy := NewSingleHostReverseProxy(target)

	http.Handle("/", l.Authenticate(proxy))

	glog.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *flPort), nil))

}
