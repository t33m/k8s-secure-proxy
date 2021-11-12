package proxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubectl/pkg/proxy"
)

const (
	DefaultPathRejectRE = proxy.DefaultPathRejectRE
	DefaultPathAcceptRE = proxy.DefaultPathAcceptRE
)

type FilterTransport struct{
	rejectPaths     []*regexp.Regexp
	acceptPaths     []*regexp.Regexp
	tlsClientConfig *tls.Config
}

var (
	ErrForbiddenPath = errors.New("given path forbidden by secure proxy")
	ErrNotAllowedPath = errors.New("given path is not allowed by secure proxy")
)

func NewFilterTransport(rejectPaths, acceptPaths string, tlsClientConfig *tls.Config) (*FilterTransport, error) {
	t := &FilterTransport{tlsClientConfig: tlsClientConfig}
	var err error
	if t.rejectPaths, err = proxy.MakeRegexpArray(rejectPaths); err != nil {
		return nil, err
	}
	t.acceptPaths, err = proxy.MakeRegexpArray(acceptPaths)
	return t, err
}

func (t *FilterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.filter(req.URL.Path); err != nil {
		return forbiddenResponse(req, err.Error())
	}
	tr := &http.Transport{
		TLSClientConfig: t.tlsClientConfig,
		TLSNextProto:    make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}
	return tr.RoundTrip(req)
}

func (t *FilterTransport) filter(path string) error {
	if matchesRegexp(path, t.rejectPaths) {
		return ErrForbiddenPath
	}
	if !matchesRegexp(path, t.acceptPaths)  {
		return ErrNotAllowedPath
	}
	return nil
}

func matchesRegexp(str string, regexps []*regexp.Regexp) bool {
	for _, re := range regexps {
		if re.MatchString(str) {
			return true
		}
	}
	return false
}

func forbiddenResponse(req *http.Request, reason string) (*http.Response, error) {
	buf := &bytes.Buffer{}
	st := &metav1.Status{
		TypeMeta: metav1.TypeMeta{},
		ListMeta: metav1.ListMeta{},
		Status:   metav1.StatusFailure,
		Message:  reason,
		Reason:   metav1.StatusReasonForbidden,
		Code:     http.StatusForbidden,
	}
	b, err := runtime.Encode(corev1Codec, st)
	if err != nil {
		return nil, err
	}
	if _, err = buf.Write(b); err != nil {
		return nil, err
	}
	return &http.Response{
		Status:      http.StatusText(http.StatusForbidden),
		StatusCode:  http.StatusForbidden,
		Body:        io.NopCloser(buf),
		Request:     req,
	}, nil
}

type Backend interface {
	Get(string) *url.URL
}

type VirtualHosts map[string]*url.URL

func(h VirtualHosts) Get(host string) *url.URL {
	return h[host]
}

type BackendTransport struct {
	inner   http.RoundTripper
	backend Backend
}

func NewBackendTransport(inner http.RoundTripper, backend Backend) *BackendTransport {
	return &BackendTransport{inner: inner, backend: backend}
}

func (t *BackendTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	splitted := strings.Split(req.Host, ":")
	if len(splitted) == 0 {
		return nil, fmt.Errorf("can't parse HOST header %s", req.Host)
	}
	host := splitted[0]
	backendUrl := t.backend.Get(host)
	if backendUrl == nil {
		return nil, fmt.Errorf("not found backend for %s", host)
	}
	req.URL.Scheme = backendUrl.Scheme
	req.URL.Host = backendUrl.Host
	return t.inner.RoundTrip(req)
}
