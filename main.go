package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/t33m/k8s-secure-proxy/pkg/proxy"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Printf(
			"client-ip: %s, user-agent: %s, host: %s, method: %s, path: %s",
			req.RemoteAddr, req.UserAgent(), req.Host, req.Method, req.URL.Path,
		)
		next.ServeHTTP(w, req)
	})
}


func runProxy(listen, virtualHost, apiEndpoint, caCertPath, keyPath, certPath string) error {
	caPool, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	if caCertPath != "" {
		caCert, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			return err
		}
		caPool.AppendCertsFromPEM(caCert)
	}

	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return err
	}

	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return err
	}

	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return err
	}

	vHosts := proxy.VirtualHosts{}
	if vHosts[virtualHost], err = url.Parse(apiEndpoint); err != nil {
		return err
	}

	filterTransport, err := proxy.NewFilterTransport(
		proxy.DefaultPathRejectRE, proxy.DefaultPathAcceptRE, &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    caPool,
		},
	)
	if err != nil {
		return err
	}

	tr := proxy.NewBackendTransport(filterTransport, vHosts)
	server := &http.Server{
		Addr:     listen,
		Handler:  loggingMiddleware(proxy.NewProxyHandler(tr)),
	}

	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	defer func(){
		_ = server.Shutdown(context.Background())
	}()

	done := make(chan struct{}, 1)
	go func() {
		_ = server.ListenAndServeTLS("", "")
		close(done)
	}()

	log.Printf("listening on %s", listen)

	<-done
	return nil
}

func main() {
	flag.Usage = func() {
		_, _  = fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	var listen, virtualHost, apiEndpoint, caCertPath, keyPath, certPath string

	flag.StringVar(&listen, "listen", "127.0.0.1:8443", "proxy listen address")
	flag.StringVar(&virtualHost, "virtual-host", "127.0.0.1", "virtual host")
	flag.StringVar(&apiEndpoint, "api-endpoint", "", "endpoint of k8s api node")
	flag.StringVar(&caCertPath, "ca", "", "path to CA certificate for verify k8s api node")
	flag.StringVar(&keyPath, "key", "", "path to key for proxy listener")
	flag.StringVar(&certPath, "cert", "", "path to certificate for proxy listener")

	flag.Parse()

	if err := runProxy(listen, virtualHost, apiEndpoint, caCertPath, keyPath, certPath); err != nil {
		_ , _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
