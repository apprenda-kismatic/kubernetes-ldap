package main

import (
	// "crypto/tls"
	// "errors"
	"flag"
	// "fmt"
	"github.com/kismatic/kubernetes-ldap/auth"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
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
	}
	return proxy
}

func main() {

	flag.Parse()
	// if flag.NArg() != 1 {
	// 	flag.Usage()
	// }

	l := auth.NewLdapAuth(*ldapHost, *ldapPort, *insecure)

	target, err := url.Parse(*apiserver)
	// target, err := url.Parse("http://jsonplaceholder.typicode.com:80")
	if err != nil {
		log.Fatal(err)
	}
	proxy := NewSingleHostReverseProxy(target)

	http.Handle("/", l.Authenticate(proxy))

	log.Fatal(http.ListenAndServe(":4000", nil))

}
