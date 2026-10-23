package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/api"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/privops"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// Ghép máy standalone với Console từ Admin UI: POST /cloud/pair.

const goodJoinToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newPairServer(t *testing.T, p api.Pairer) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	auth := fakeAuth{tokAdmin: {authz.ScopeAdmin}, tokReader: {authz.ScopeAppsRead}}
	opts := []api.Option{}
	if p != nil {
		opts = append(opts, api.WithPairer(p))
	}
	srv := httptest.NewServer(api.New(apps.New(st, domains.New(st), apps.Options{}), st, auth, opts...))
	t.Cleanup(srv.Close)
	return srv
}

// Pair là trao quyền điều khiển máy: chỉ admin. Reader nhìn được trạng thái
// pair (GET) nhưng không được đổi nó.
func TestCloudPairNeedsAdmin(t *testing.T) {
	called := false
	srv := newPairServer(t, func(context.Context, string) (string, error) { called = true; return "env-1", nil })
	if code, _ := do(t, srv, http.MethodPost, "/api/v1/cloud/pair", "", map[string]string{"token": goodJoinToken}); code != http.StatusUnauthorized {
		t.Errorf("không token → %d, muốn 401", code)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/v1/cloud/pair", tokReader, map[string]string{"token": goodJoinToken}); code != http.StatusForbidden {
		t.Errorf("reader → %d, muốn 403", code)
	}
	if called {
		t.Fatal("pairer bị gọi khi chưa qua authz")
	}
}

func TestCloudPairSuccess(t *testing.T) {
	var got string
	srv := newPairServer(t, func(_ context.Context, tok string) (string, error) { got = tok; return "env-42", nil })
	code, body := do(t, srv, http.MethodPost, "/api/v1/cloud/pair", tokAdmin, map[string]string{"token": "  " + goodJoinToken + "\n"})
	if code != http.StatusAccepted {
		t.Fatalf("→ %d: %s, muốn 202", code, body)
	}
	if got != goodJoinToken {
		t.Errorf("token tới pairer = %q, muốn đã trim khoảng trắng dán thừa", got)
	}
	var out struct {
		EnvID string `json:"env_id"`
	}
	_ = json.Unmarshal(body, &out)
	if out.EnvID != "env-42" {
		t.Errorf("env_id = %q", out.EnvID)
	}
}

func TestCloudPairErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
		want string
	}{
		{"token sai hình dạng", fmt.Errorf("%w: x", privops.ErrInvalidArg), http.StatusBadRequest, "not a join token"},
		{"box chưa có pair.sh", fmt.Errorf("%w: pair.sh: no such file", privops.ErrUnavailable), http.StatusNotImplemented, "--join"},
		{"cloud từ chối token", errors.New("privops: pair.sh: the Console did not accept this token"), http.StatusBadGateway, "the Console did not accept this token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newPairServer(t, func(context.Context, string) (string, error) { return "", c.err })
			code, body := do(t, srv, http.MethodPost, "/api/v1/cloud/pair", tokAdmin, map[string]string{"token": goodJoinToken})
			if code != c.code || !strings.Contains(string(body), c.want) {
				t.Fatalf("→ %d %s, muốn %d chứa %q", code, body, c.code, c.want)
			}
			if strings.Contains(string(body), "privops:") {
				t.Errorf("lộ tiền tố nội bộ: %s", body)
			}
		})
	}
}

func TestCloudPairNotWired(t *testing.T) {
	srv := newPairServer(t, nil)
	if code, _ := do(t, srv, http.MethodPost, "/api/v1/cloud/pair", tokAdmin, map[string]string{"token": goodJoinToken}); code != http.StatusNotImplemented {
		t.Fatalf("→ %d, muốn 501", code)
	}
}
