package proxy

import (
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

func requestHandler(proxy http.Handler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}
}
