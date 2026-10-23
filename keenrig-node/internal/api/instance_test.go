package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/api"
	"github.com/keenrig/keenrig/keenrig-node/internal/instance"
)

// Admin UI phải biết instance thuộc tên miền nào, để đề xuất `<app>.<parent>`.
//
// Trước 2026-09-06 nó KHÔNG biết: `get.sh --domain` ghi `KEENRIG_DOMAIN` vào
// unit systemd và không dòng mã nào đọc biến đó. Hậu quả không phải một lỗi mà
// là một ô nhập trống — người dùng phải tự gõ cả FQDN cho từng app, gõ thiếu,
// và app ra đời không có tên miền nào.
func TestInstanceReportsTheParentDomain(t *testing.T) {
	srv, st := newTestServer(t)

	// Chưa khai: trả rỗng, KHÔNG phải lỗi. Một box chạy độc lập, vào bằng IP,
	// hợp lệ mà không có tên miền nào.
	code, body := do(t, srv, http.MethodGet, "/api/v1/instance", "", nil)
	if code != http.StatusOK {
		t.Fatalf("= %d: %s", code, body)
	}
	var out struct {
		ParentDomain string `json:"parent_domain"`
	}
	_ = json.Unmarshal(body, &out)
	if out.ParentDomain != "" {
		t.Errorf("parent_domain = %q, muốn rỗng khi chưa khai", out.ParentDomain)
	}

	if err := st.SetSetting(context.Background(), api.SettingParentDomain,
		"demo.acme.keenrig.com"); err != nil {
		t.Fatal(err)
	}
	_, body = do(t, srv, http.MethodGet, "/api/v1/instance", "", nil)
	_ = json.Unmarshal(body, &out)
	if out.ParentDomain != "demo.acme.keenrig.com" {
		t.Errorf("parent_domain = %q", out.ParentDomain)
	}
}

// KHÔNG đòi đăng nhập: màn thiết lập lần đầu chạy khi chưa có tài khoản nào, và
// giá trị này người mở trang đã đọc được từ thanh địa chỉ của họ.
func TestInstanceDoesNotRequireAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	if code, body := do(t, srv, http.MethodGet, "/api/v1/instance", "", nil); code != http.StatusOK {
		t.Errorf("= %d: %s — màn thiết lập lần đầu sẽ không lấy được giá trị này", code, body)
	}
}

type instanceOut struct {
	ParentDomain string `json:"parent_domain"`
	Source       string `json:"parent_domain_source"`
	Mode         string `json:"domain_mode"`
}

// Nguồn của tên miền đi kèm giá trị, và CLOUD THẮNG.
//
// Luật chủ dự án 2026-09-07: tên miền của môi trường do keenrig-cloud quyết
// định, keenrig-admin chỉ nhận. Một box đã nhận tên từ cloud mà restart với
// KEENRIG_DOMAIN cũ trong unit không được đổi tên — người dùng đổi ở Console,
// restart, thấy tên cũ quay về là lỗi không lần ra được từ Admin UI.
func TestInstanceReportsTheSourceAndCloudWins(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	cfg := instance.New(st)
	read := func() instanceOut {
		t.Helper()
		code, body := do(t, srv, http.MethodGet, "/api/v1/instance", "", nil)
		if code != http.StatusOK {
			t.Fatalf("GET /instance = %d: %s", code, body)
		}
		var out instanceOut
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Chưa có gì: ba trường đều rỗng, không phải lỗi.
	if out := read(); out != (instanceOut{}) {
		t.Fatalf("box trắng trả %+v, muốn ba trường rỗng", out)
	}

	// Standalone: --domain lúc khởi động → nguồn local, mode không biết.
	if applied, err := cfg.ApplyLocal(ctx, "Home.Example.com."); err != nil || !applied {
		t.Fatalf("ApplyLocal trên box trắng = (%v, %v), muốn (true, nil)", applied, err)
	}
	if out := read(); out != (instanceOut{ParentDomain: "home.example.com", Source: instance.SourceLocal}) {
		t.Fatalf("sau --domain: %+v", out)
	}

	// Cloud cấp tên → đè local, nguồn cloud, mode đi kèm.
	if err := cfg.SetFromCloud(ctx, "demo.acme.keenrig.com", instance.ModeKeenrig); err != nil {
		t.Fatal(err)
	}
	want := instanceOut{ParentDomain: "demo.acme.keenrig.com", Source: instance.SourceCloud, Mode: "keenrig"}
	if out := read(); out != want {
		t.Fatalf("sau khi cloud cấp: %+v, muốn %+v", out, want)
	}

	// Restart với KEENRIG_DOMAIN cũ: KHÔNG đè — cloud thắng.
	if applied, err := cfg.ApplyLocal(ctx, "home.example.com"); err != nil || applied {
		t.Fatalf("ApplyLocal trên box đã nhận tên từ cloud = (%v, %v), muốn (false, nil)", applied, err)
	}
	if out := read(); out != want {
		t.Fatalf("KEENRIG_DOMAIN đè được tên của cloud: %+v", out)
	}
}

// KHÔNG có đường ghi trên control API: PUT/POST/PATCH/DELETE /api/v1/instance
// đều không tồn tại — kể cả với quyền admin. Đây là cách máy kiểm câu
// "keenrig-admin là nơi nhận thông tin thôi": một route ghi thêm vào đây là
// test này đỏ.
func TestInstanceCannotBeSetOverTheAdminAPI(t *testing.T) {
	srv, _ := newTestServer(t)
	body := map[string]any{"parent_domain": "evil.example.com", "mode": "custom"}
	for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete} {
		code, resp := do(t, srv, m, "/api/v1/instance", tokAdmin, body)
		if code >= 200 && code < 300 {
			t.Errorf("%s /api/v1/instance = %d (%s) — Admin API không được có đường đặt tên miền", m, code, resp)
		}
	}
	// Và giá trị vẫn trống sau mọi cú thử.
	_, raw := do(t, srv, http.MethodGet, "/api/v1/instance", "", nil)
	var out instanceOut
	_ = json.Unmarshal(raw, &out)
	if out.ParentDomain != "" {
		t.Errorf("parent_domain = %q sau các request ghi bị từ chối", out.ParentDomain)
	}
}
