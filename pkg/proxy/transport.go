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

	"github.com/t33m/k8s-secure-proxy/pkg/logger"
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

type Target interface {
	Get(string) *url.URL
}

type TargetMap map[string]*url.URL

func(m TargetMap) Get(host string) *url.URL {
	return m[host]
}

type TargetTransport struct {
	inner  http.RoundTripper
	target Target
}

func NewTargetTransport(inner http.RoundTripper, target Target) *TargetTransport {
	return &TargetTransport{inner: inner, target: target}
}

func (t *TargetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	targetUrl := t.target.Get(req.Host)
	if targetUrl == nil {
		return nil, fmt.Errorf("not found target for %s", req.Host)
	}
	req.URL.Scheme = targetUrl.Scheme
	req.URL.Host = targetUrl.Host
	return t.inner.RoundTrip(req)
}

type LoggingTransport struct {
	inner  http.RoundTripper
	logger logger.Logger
}

func NewLoggingTransport(tr http.RoundTripper, logger logger.Logger) *LoggingTransport {
	return &LoggingTransport{inner: tr, logger: logger}
}

func (t *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	args := []interface{}{
		"method", req.Method,
		"path", req.URL.EscapedPath(),
	}
	if reqID := req.Header.Get(secureProxyHeaderReqID); reqID != "" {
		args = append(args, secureProxyHeaderReqID, reqID)
	}
	resp, err := t.inner.RoundTrip(req)
	if resp != nil {
		args = append(args, "status_code", resp.StatusCode)
	}
	if err != nil {
		args = append(args, "err", err)
	}
	t.logger.Info("request", args...)
	return resp, err
}
