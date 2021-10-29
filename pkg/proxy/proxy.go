package proxy

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

const secureProxyHeaderReqID = "x-k8s-secure-proxy-request-id"

var (
	corev1GV    = schema.GroupVersion{Version: "v1"}
	corev1Codec = scheme.Codecs.CodecForVersions(
		scheme.Codecs.LegacyCodec(corev1GV),
		scheme.Codecs.UniversalDecoder(corev1GV), corev1GV, corev1GV,
	)
)

type Proxy struct {
	server *http.Server
}

func New(listen string, tr http.RoundTripper) (*Proxy, error) {
	return &Proxy{
		server: &http.Server{
			Addr:     listen,
			Handler:  NewProxyHandler(tr),
			ErrorLog: log.New(ioutil.Discard, "", 0),
		},
	}, nil
}

func NewProxyHandler(tr http.RoundTripper) http.Handler {
	handler := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.Header.Set(secureProxyHeaderReqID, uuid.New().String())
		},
		Transport: tr,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", requestHandler(handler))

	return mux
}

func NewWithTLS(listen string, filterTransport http.RoundTripper, tlsConfig *tls.Config) (*Proxy, error) {
	proxy, err := New(listen, filterTransport)
	if err != nil {
		return nil, err
	}
	proxy.server.TLSConfig = tlsConfig
	return proxy, nil
}

func (p *Proxy) ListenAndServe() error {
	return p.server.ListenAndServe()
}

func (p *Proxy) ListenAndServeTLS() error {
	return p.server.ListenAndServeTLS("", "")
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	return p.server.Shutdown(ctx)
}

func requestHandler(proxy http.Handler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}
}
