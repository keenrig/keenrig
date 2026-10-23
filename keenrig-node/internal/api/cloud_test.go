package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/api"
	"github.com/keenrig/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig/keenrig/keenrig-node/internal/instance"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// AD-12 — Admin UI hiện trạng thái pair THẬT, từ agent qua node API; không viết
// cứng. Đường này lộ URL cloud + env id nên ĐÒI đăng nhập, khác /instance.

type cloudOut struct {
	Paired     bool   `json:"paired"`
	CloudURL   string `json:"cloud_url"`
	EnvID      string `json:"env_id"`
	LastSyncAt string `json:"last_sync_at"`
	State      string `json:"state"`
}

// newCloudServer — như newTestServer nhưng có WithInstance, vì bộ helper chung
// không cắm nó (và test "501 khi chưa cắm" bên dưới cần đúng bộ chung đó).
func newCloudServer(t *testing.T) (*httptest.Server, *instance.Config) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := instance.New(st)
	auth := fakeAuth{tokAdmin: {authz.ScopeAdmin}, tokReader: {authz.ScopeAppsRead}}
	h := api.New(apps.New(st, domains.New(st), apps.Options{}), st, auth, api.WithInstance(cfg))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, cfg
}

func readCloud(t *testing.T, srv *httptest.Server, token string) cloudOut {
	t.Helper()
	code, body := do(t, srv, http.MethodGet, "/api/v1/cloud", token, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /cloud (%s) = %d: %s", token, code, body)
	}
	var out cloudOut
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Không token → 401, kể cả khi máy chưa pair: "chưa pair" cũng là thông tin về
// máy này, và cùng một route không được lúc mở lúc đóng theo dữ liệu.
func TestCloudLinkRequiresAuth(t *testing.T) {
	srv, cfg := newCloudServer(t)
	if code, body := do(t, srv, http.MethodGet, "/api/v1/cloud", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("không token → %d: %s, muốn 401 — URL cloud + env id không phải thứ ai cũng đọc được", code, body)
	}
	if err := cfg.SetCloudLink(context.Background(), "https://keenrig.com", "env-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if code, body := do(t, srv, http.MethodGet, "/api/v1/cloud", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("không token, đã pair → %d: %s, muốn 401", code, body)
	}
}

// Có phiên (reader hoặc admin): box trắng trả standalone với ba trường rỗng;
// sau khi agent báo (qua cùng Config mà nodeapi cắm) trả paired/synced đủ trường.
func TestCloudLinkReportsWhatTheAgentSaid(t *testing.T) {
	srv, cfg := newCloudServer(t)
	for _, tok := range []string{tokReader, tokAdmin} {
		want := cloudOut{State: instance.StateStandalone}
		if out := readCloud(t, srv, tok); out != want {
			t.Fatalf("[%s] box trắng → %+v, muốn %+v", tok, out, want)
		}
	}

	// Mốc "bây giờ" đủ gần: handler dùng time.Now() nên phải báo với mốc thật,
	// không phải mốc cố định — một mốc cố định sẽ thành stale khi test già đi.
	now := time.Now().UTC().Truncate(time.Second)
	if err := cfg.SetCloudLink(context.Background(), "https://keenrig.com", "env_01J8ZK", now); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{tokReader, tokAdmin} {
		out := readCloud(t, srv, tok)
		want := cloudOut{Paired: true, CloudURL: "https://keenrig.com", EnvID: "env_01J8ZK",
			LastSyncAt: now.Format(time.RFC3339), State: instance.StateSynced}
		if out != want {
			t.Errorf("[%s] sau khi agent báo → %+v, muốn %+v", tok, out, want)
		}
	}

	// Agent im quá 5 phút → stale, và ba trường vẫn còn (UI cần để vẽ thẻ +
	// lệnh chẩn đoán).
	old := time.Now().Add(-instance.StaleAfter - time.Minute).UTC().Truncate(time.Second)
	if err := cfg.SetCloudLink(context.Background(), "https://keenrig.com", "env_01J8ZK", old); err != nil {
		t.Fatal(err)
	}
	if out := readCloud(t, srv, tokAdmin); out.State != instance.StateStale || !out.Paired || out.EnvID != "env_01J8ZK" {
		t.Errorf("agent im 6 phút → %+v, muốn stale nhưng vẫn paired đủ trường", out)
	}
}

// Không cắm WithInstance (binary cũ / test server chung) → 501 nói rõ, để UI rơi
// về "pairing state unavailable" thay vì vẽ standalone như thật.
func TestCloudLinkNotWiredIs501(t *testing.T) {
	srv, _ := newTestServer(t)
	code, body := do(t, srv, http.MethodGet, "/api/v1/cloud", tokAdmin, nil)
	if code != http.StatusNotImplemented {
		t.Fatalf("chưa cắm instance → %d: %s, muốn 501", code, body)
	}
}

// Và không có đường GHI: pairing là việc của agent, Admin API không đặt được.
func TestCloudLinkCannotBeSetOverTheAdminAPI(t *testing.T) {
	srv, _ := newCloudServer(t)
	body := map[string]any{"cloud_url": "https://evil.example.com", "env_id": "x", "last_sync_at": "2026-09-19T10:00:00Z"}
	for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete} {
		code, resp := do(t, srv, m, "/api/v1/cloud", tokAdmin, body)
		if code >= 200 && code < 300 {
			t.Errorf("%s /api/v1/cloud = %d (%s) — Admin API không được có đường đặt trạng thái pair", m, code, resp)
		}
	}
	if out := readCloud(t, srv, tokAdmin); out.Paired {
		t.Errorf("đã pair sau các request ghi bị từ chối: %+v", out)
	}
}
