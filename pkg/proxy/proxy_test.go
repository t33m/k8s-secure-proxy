package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type backend struct {
	url *url.URL
}

func (b backend) Get(string) *url.URL {
	return b.url
}

func TestProxy(t *testing.T) {
	tr, err := NewFilterTransport(DefaultPathRejectRE, DefaultPathAcceptRE, nil)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		_, _ = fmt.Fprintf(w, "ok\n")
	})
	backendServer := httptest.NewServer(mux)
	b := backend{}
	b.url, err = url.Parse(backendServer.URL)
	require.NoError(t, err)

	proxy := httptest.NewServer(NewProxyHandler(NewBackendTransport(tr, b)))

	tests := []struct{
		name               string
		path               string
		expectedStatusCode int
	}{
		{
			name:               "rejected",
			path:               "/api/v1/namespaces/foo/pods/bar/exec",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "allowed",
			path:               "/api/v1/namespaces/foo/pods",
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Post(proxy.URL+tt.path, "application/json", &bytes.Buffer{})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatusCode, resp.StatusCode)
		})
	}
}
