package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_filter(t *testing.T) {
	tests := []struct{
		name        string
		rejectPaths string
		acceptPaths string
		path        string
		err         error
	}{
		{
			name: "reject",
			rejectPaths: DefaultPathRejectRE,
			acceptPaths: DefaultPathAcceptRE,
			path: "/api/v1/namespaces/foo/pods/bar/exec",
			err:  ErrForbiddenPath,
		},
		{
			name: "allow",
			rejectPaths: DefaultPathRejectRE,
			acceptPaths: DefaultPathAcceptRE,
			path: "/api/v1/namespaces/foo/pods",
		},
		{
			name: "not allowed",
			acceptPaths: "^/api/v1/namespaces/foo/pods$",
			path: "/api/v1/namespaces/foo/pods/bar/exec",
			err:  ErrNotAllowedPath,
		},
		{
			name: "reject all",
			rejectPaths: ".*",
			path: "/api/v1/namespaces/foo/pods/bar/exec",
			err:  ErrForbiddenPath,
		},
		{
			name: "disallow all",
			acceptPaths: "",
			path: "/api/v1/namespaces/foo/pods/bar/exec",
			err:  ErrNotAllowedPath,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := NewFilterTransport(tt.rejectPaths, tt.acceptPaths, nil)
			require.NoError(t, err)
			if tt.err != nil {
				assert.Error(t, tr.filter(tt.path))
			} else {
				assert.NoError(t, tr.filter(tt.path))
			}
		})
	}
}
