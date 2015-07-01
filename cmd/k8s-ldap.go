package main

import (
	"flag"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/golang/glog"

	"github.com/kismatic/kubernetes-ldap/auth"
)

// Move these to vars to flags

var insecure = flag.Bool("ldap-insecure", true, "Disable LDAP SSL/TLS")
var ldapHost = flag.String("ldap-host", "localhost", "description")
var ldapPort = flag.Uint("ldap-port", 339, "description")

// Change to consistent format (host/port)
var apiserver = flag.String("apiserver", "http://localhost:8080", "Address of Kubernetes API server")

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
	glog.CopyStandardLogTo("INFO")

	l := auth.NewLdapAuth(*ldapHost, *ldapPort, *insecure)

	target, err := url.Parse(*apiserver)
	// target, err := url.Parse("http://jsonplaceholder.typicode.com:80")
	if err != nil {
		glog.Fatal(err)
	}
	proxy := NewSingleHostReverseProxy(target)

	http.Handle("/", l.Authenticate(proxy))

	glog.Fatal(http.ListenAndServe(":4000", nil))

}
