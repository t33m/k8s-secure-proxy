package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"

	"go.uber.org/zap"

	logger "github.com/t33m/k8s-secure-proxy/pkg/logger/zap"
	"github.com/t33m/k8s-secure-proxy/pkg/proxy"
)

func runProxy(listen, apiEndpoint, keyPath, certPath, caCertPath string) error {
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

	target := proxy.TargetMap{}
	if target[listen], err = url.Parse(apiEndpoint); err != nil {
		return err
	}

	zapLogger, err := zap.NewProduction()
	if err != nil {
		return err
	}
	log := logger.New(zapLogger.Sugar())

	filterTransport, err := proxy.NewFilterTransport(
		proxy.DefaultPathRejectRE, proxy.DefaultPathAcceptRE, &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    caPool,
		},
	)
	if err != nil {
		return err
	}

	tr := proxy.NewLoggingTransport(proxy.NewTargetTransport(filterTransport, target), log)

	p, err := proxy.NewWithTLS(
		listen, tr, &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	)
	if err != nil {
		return err
	}
	defer func(){
		_ = p.Shutdown(context.Background())
	}()

	done := make(chan struct{}, 1)
	go func() {
		_ = p.ListenAndServeTLS()
		close(done)
	}()

	log.Info("listening...", "endpoint", "https://"+listen)

	<-done
	return nil
}

func main() {
	flag.Usage = func() {
		_, _  = fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	var apiEndpoint, caCertPath, listen, keyPath, certPath string

	flag.StringVar(&apiEndpoint, "api-endpoint", "", "endpoint of k8s api node")
	flag.StringVar(&caCertPath, "ca", "", "path to CA certificate for verify k8s api node")
	flag.StringVar(&listen, "listen", "127.0.0.1:8443", "proxy listen address")
	flag.StringVar(&keyPath, "key", "", "path to key for proxy listener")
	flag.StringVar(&certPath, "cert", "", "path to certificate for proxy listener")

	flag.Parse()

	if err := runProxy(listen, apiEndpoint, keyPath, certPath, caCertPath); err != nil {
		_ , _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
