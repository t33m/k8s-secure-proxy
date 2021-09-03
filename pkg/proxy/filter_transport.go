package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"regexp"

	"k8s.io/kubectl/pkg/proxy"
)

const DefaultPathRejectRE = proxy.DefaultPathRejectRE

type FilterTransport struct{
	caPool      *x509.CertPool
	rejectPaths []*regexp.Regexp
}

type forbiddenPathError struct {
	s string
}
func (e *forbiddenPathError) Error() string {
	return e.s
}

func NewFilterTransport(caPool *x509.CertPool, rejectPaths string) (*FilterTransport, error) {
	t := &FilterTransport{caPool: caPool}
	var err error
	if t.rejectPaths, err = proxy.MakeRegexpArray(rejectPaths); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *FilterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if matchesRegexp(req.URL.Path, t.rejectPaths) {
		return nil, &forbiddenPathError{"given path forbidden by proxy"}
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    t.caPool,
		},
		TLSNextProto:    make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}
	return tr.RoundTrip(req)
}

func matchesRegexp(str string, regexps []*regexp.Regexp) bool {
	for _, re := range regexps {
		if re.MatchString(str) {
			return true
		}
	}
	return false
}
