package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/t33m/k8s-secure-proxy/pkg/proxy"
)



func runProxy(listen, apiEndpoint, keyPath, certPath, caCertPath string) error {
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return err
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return err
	}

	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return err
	}

	p, err := proxy.NewProxy(listen, apiEndpoint, caPool, key, cert, proxy.DefaultPathRejectRE)
	if err != nil {
		return err
	}
	defer func(){
		_ = p.Shutdown(context.Background())
	}()

	return p.ListenAndServe()
}

func main() {
	apiEndpoint := flag.String( "api-endpoint", "", "endpoint of k8s api node")
	caCertPath := flag.String( "ca", "", "path to CA certificate for verify k8s api node")
	listen := flag.String( "listen", "127.0.0.1:8443", "proxy listen address")
	keyPath := flag.String( "key", "", "path to key for proxy listener")
	certPath := flag.String( "cert", "", "path to certificate for proxy listener")

	if err := runProxy(*listen, *apiEndpoint, *keyPath, *certPath, *caCertPath); err != nil {
		_ , _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
