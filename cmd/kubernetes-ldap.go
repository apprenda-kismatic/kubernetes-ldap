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
var flLdapHost = flag.String("ldap-host", "", "Host or IP of the LDAP server")
var flLdapPort = flag.Uint("ldap-port", 389, "LDAP server port")
var flBaseDN = flag.String("ldap-base-dn", "", "LDAP user base DN in the form 'dc=example,dc=com'")
var flUserLoginAttribute = flag.String("ldap-user-attribute", "uid", "LDAP Username attribute for login")
var flSearchUserDN = flag.String("ldap-search-user-dn", "", "Search user DN for this app to find users (e.g.: cn=admin,dc=example,dc=com).")
var flSearchUserPassword = flag.String("ldap-search-user-password", "", "Search user password")

// TODO(bc): Change to consistent format (host/port)
var flApiserver = flag.String("apiserver", "", "Address of Kubernetes API server (e.g.: http://k8smaster.kismatic.com:8080")

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

	if *flLdapHost == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --ldap-host arg is required")
	}

	if *flBaseDN == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --ldap-base-dn arg is required")
	}

	if *flSearchUserDN == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --ldap-search-user-dn arg is required")
	}

	if *flSearchUserPassword == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --ldap-search-user-password arg is required")
	}

	if *flApiserver == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --apiserver arg is required")
	}

	glog.CopyStandardLogTo("INFO")

	l := auth.NewLdapAuth(*flLdapHost, *flLdapPort, *flInsecure, *flBaseDN, *flUserLoginAttribute, *flSearchUserDN, *flSearchUserPassword)

	target, err := url.Parse(*flApiserver)

	if err != nil {
		glog.Fatal(err)
	}
	proxy := NewSingleHostReverseProxy(target)

	http.Handle("/", l.Authenticate(proxy))

	glog.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *flPort), nil))

}
