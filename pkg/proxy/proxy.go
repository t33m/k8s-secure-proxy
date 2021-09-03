package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

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

func NewProxy(listen, target string, caPool *x509.CertPool, key, cert []byte, pathRejectRe string) (*Proxy, error) {
	targetAsUrl, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	handler := httputil.NewSingleHostReverseProxy(targetAsUrl)
	handler.Transport, err = NewFilterTransport(caPool, pathRejectRe)
	if err != nil {
		return nil, err
	}
	director := handler.Director
	handler.Director = func(req *http.Request) {
		director(req)
		modifyRequest(req)
	}
	handler.ErrorHandler = errorHandler
	mux := http.NewServeMux()
	mux.HandleFunc("/", requestHandler(handler))
	return &Proxy{
		server: &http.Server{
			Addr: listen,
			Handler: mux,
			TLSConfig: &tls.Config{	Certificates: []tls.Certificate{
				{
					PrivateKey:  key,
					Certificate: [][]byte{cert},
				},
			},
				MinVersion: tls.VersionTLS13,
			},
		},
	}, nil
}

func (p *Proxy) ListenAndServe() error {
	return p.server.ListenAndServeTLS("", "")
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	return p.server.Shutdown(ctx)
}

func modifyRequest(req *http.Request) {
	req.Header.Set("X-K8s-Proxy-Id", uuid.New().String())
}

func errorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	switch err.(type) {
	case *forbiddenPathError:
		w.WriteHeader(http.StatusForbidden)
		st := &metav1.Status{
			TypeMeta: metav1.TypeMeta{},
			ListMeta: metav1.ListMeta{},
			Status:   metav1.StatusFailure,
			Message:  err.Error(),
			Reason:   metav1.StatusReasonMethodNotAllowed,
			Code:     http.StatusForbidden,
		}
		_, _ = w.Write([]byte(runtime.EncodeOrDie(corev1Codec, st)))
	}
}

func requestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}
}
