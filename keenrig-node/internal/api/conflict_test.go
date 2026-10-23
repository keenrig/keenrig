package api_test

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/api"
	"github.com/keenrig/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig/keenrig/keenrig-node/internal/catalog"
	"github.com/keenrig/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"

	"net/http/httptest"
)

// 409 KHÔNG chỉ có một nghĩa, và gộp chúng lại là một lỗi có thật.
//
// Ngày 2026-09-06 một người dùng chạm trần "1 app" của bậc starter và nhận
// thông báo *"slug hoặc domain đã được app khác dùng"*. Họ có đúng một app, tên
// không trùng gì cả — nhưng giao diện chỉ có mã trạng thái để đoán, và nó đoán
// sai. Người đọc câu đó sẽ đi đổi tên app, mãi mãi không qua được.
//
// Test này canh việc mỗi nguyên nhân mang một `code` RIÊNG, để giao diện chọn
// đúng câu giải thích thay vì suy diễn.
func TestEachKindOfConflictCarriesItsOwnCode(t *testing.T) {
	srv, _ := newServerWithMaxApps(t, 1)

	// App đầu tiên: qua.
	code, body := do(t, srv, http.MethodPost, "/api/v1/catalog/nginx/install", tokAdmin, nil)
	if code != http.StatusCreated {
		t.Fatalf("app đầu = %d: %s", code, body)
	}

	// App thứ hai, TÊN KHÁC: chạm trần hạn mức, không phải trùng tên.
	code, body = do(t, srv, http.MethodPost, "/api/v1/catalog/nginx/install", tokAdmin,
		map[string]any{"slug": "hoan-toan-khac"})
	if code != http.StatusConflict {
		t.Fatalf("app thứ hai = %d: %s", code, body)
	}
	var out struct{ Error, Code string }
	_ = json.Unmarshal(body, &out)
	if out.Code != "quota" {
		t.Errorf("code = %q, muốn %q — tên hoàn toàn khác, nên đây KHÔNG phải "+
			"xung đột tên; gộp hai thứ lại là dẫn người dùng đi đổi tên vô ích",
			out.Code, "quota")
	}
	if out.Error == "" {
		t.Error("thân phản hồi không mang lý do thật")
	}
}

// Trùng tên THẬT thì mới là `conflict`.
func TestARealNameClashIsCodedAsConflict(t *testing.T) {
	srv, _ := newServerWithMaxApps(t, 10)

	if code, b := do(t, srv, http.MethodPost, "/api/v1/catalog/nginx/install", tokAdmin, nil); code != http.StatusCreated {
		t.Fatalf("app đầu = %d: %s", code, b)
	}
	// CÙNG slug → trùng tên thật.
	code, raw := do(t, srv, http.MethodPost, "/api/v1/catalog/nginx/install", tokAdmin, nil)
	if code != http.StatusConflict {
		t.Fatalf("= %d: %s", code, raw)
	}
	var out struct{ Error, Code string }
	_ = json.Unmarshal(raw, &out)
	if out.Code != "conflict" {
		t.Errorf("code = %q, muốn %q", out.Code, "conflict")
	}
}

// newServerWithMaxApps — như newTestServer nhưng đặt trần số app, để dựng được
// ca chạm hạn mức mà không cần một máy thật hết tài nguyên.
func newServerWithMaxApps(t *testing.T, max int) (*httptest.Server, store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cat, errs := catalog.LoadBuiltin()
	for _, e := range errs {
		t.Fatalf("danh mục nhúng hỏng: %v", e)
	}
	auth := fakeAuth{tokAdmin: {authz.ScopeAdmin}, tokReader: {authz.ScopeAppsRead}}
	svc := apps.New(st, domains.New(st), apps.Options{MaxApps: max})
	srv := httptest.NewServer(api.New(svc, st, auth, api.WithCatalog(cat)))
	t.Cleanup(srv.Close)
	return srv, st
}
