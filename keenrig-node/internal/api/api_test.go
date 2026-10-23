package api_test

// Test T7 — control API end-to-end qua httptest, store SQLite thật.
// Gate: ID-02 (scope enforcement), DELETE trả 202, desired `{}` bị chặn.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/api"
	"github.com/keenrig/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// fakeAuth trả principal theo token, để test scope mà không cần T10.
type fakeAuth map[string][]authz.Scope

func (f fakeAuth) Authenticate(r *http.Request) (authz.Principal, error) {
	tok := authz.BearerToken(r)
	scopes, ok := f[tok]
	if !ok {
		return authz.Principal{}, authz.ErrUnauthenticated
	}
	return authz.Principal{Subject: tok, Scopes: scopes}, nil
}

const (
	tokAdmin  = "tok-admin"
	tokReader = "tok-reader"
)

func newTestServer(t *testing.T) (*httptest.Server, store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	auth := fakeAuth{
		tokAdmin:  {authz.ScopeAdmin},
		tokReader: {authz.ScopeAppsRead},
	}
	h := api.New(apps.New(st, domains.New(st), apps.Options{}), st, auth)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, st
}

func do(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, buf.Bytes()
}

func createOK(t *testing.T, srv *httptest.Server, slug, image string) string {
	t.Helper()
	code, body := do(t, srv, "POST", "/api/v1/apps", tokAdmin, map[string]any{
		"slug":    slug,
		"desired": map[string]any{"image": image},
	})
	if code != http.StatusCreated {
		t.Fatalf("POST /apps = %d: %s", code, body)
	}
	var app store.App
	if err := json.Unmarshal(body, &app); err != nil {
		t.Fatal(err)
	}
	return app.ID
}

// ID-02 — scope được enforce THẬT, và 401 khác 403.
func TestScopeEnforcement(t *testing.T) {
	srv, _ := newTestServer(t)

	// Không token → 401 trên MỌI route, kể cả route chỉ đọc.
	for _, p := range []string{"/api/v1/apps", "/api/v1/events"} {
		if code, body := do(t, srv, "GET", p, "", nil); code != http.StatusUnauthorized {
			t.Errorf("GET %s không token = %d, muốn 401: %s", p, code, body)
		}
	}
	// Token lạ → 401.
	if code, _ := do(t, srv, "GET", "/api/v1/apps", "tok-bịa", nil); code != http.StatusUnauthorized {
		t.Errorf("token lạ = %d, muốn 401", code)
	}

	// Token chỉ có apps:read → đọc được…
	if code, body := do(t, srv, "GET", "/api/v1/apps", tokReader, nil); code != http.StatusOK {
		t.Errorf("GET /apps với apps:read = %d: %s", code, body)
	}
	// …nhưng KHÔNG ghi được, và phải là 403 (không phải 401): 401 sẽ bắt UI
	// quay vòng đăng nhập vô hạn cho một người vốn chỉ thiếu quyền.
	code, body := do(t, srv, "POST", "/api/v1/apps", tokReader, map[string]any{
		"slug": "x", "desired": map[string]any{"image": "nginx:1"},
	})
	if code != http.StatusForbidden {
		t.Errorf("POST /apps với apps:read = %d, muốn 403: %s", code, body)
	}
	// …và cũng không đọc được events (thiếu events:read) — admin mới bao hết.
	if code, _ := do(t, srv, "GET", "/api/v1/events", tokReader, nil); code != http.StatusForbidden {
		t.Errorf("GET /events với apps:read = %d, muốn 403", code)
	}
}

// Desired rỗng `{}` phải bị chặn TẠI ADMISSION — đây chính là lỗ hổng ghi trong
// nợ kỹ thuật vòng 2 (desired `{}` lọt xuống tận Docker).
func TestDesiredValidatedAtAdmission(t *testing.T) {
	srv, st := newTestServer(t)

	bad := []any{
		map[string]any{},                           // thiếu image
		map[string]any{"image": ""},                // image rỗng
		map[string]any{"imagee": "nginx:1"},        // gõ nhầm tên trường
		map[string]any{"image": "nginx:1", "x": 1}, // trường lạ
		map[string]any{"image": "nginx:1", "resources": map[string]any{"replicas": 0}},
	}
	for i, d := range bad {
		code, body := do(t, srv, "POST", "/api/v1/apps", tokAdmin, map[string]any{
			"slug": "app-bad", "desired": d,
		})
		if code != http.StatusBadRequest {
			t.Errorf("desired xấu #%d = %d, muốn 400: %s", i, code, body)
		}
	}
	// Không cái nào được ghi vào store.
	list, err := st.ListApps(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("store có %d app sau khi mọi request đều bị từ chối", len(list))
	}

	// PATCH desired cũng phải qua cùng cửa đó.
	id := createOK(t, srv, "app-ok", "nginx:1")
	if code, body := do(t, srv, "PATCH", "/api/v1/apps/"+id+"/desired", tokAdmin, map[string]any{}); code != http.StatusBadRequest {
		t.Errorf("PATCH desired rỗng = %d, muốn 400: %s", code, body)
	}
	// rev KHÔNG được bump khi bị từ chối.
	app, err := st.GetApp(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if app.DesiredRev != 1 {
		t.Errorf("desired_rev = %d sau PATCH bị từ chối, muốn giữ 1", app.DesiredRev)
	}
}

// DELETE trả 202, không phải 204 — và app biến mất khỏi API ngay lập tức trong
// khi row vẫn còn để reconciler dọn container.
func TestDeleteReturns202AndTwoPhase(t *testing.T) {
	srv, st := newTestServer(t)
	id := createOK(t, srv, "app-del", "nginx:1")

	code, body := do(t, srv, "DELETE", "/api/v1/apps/"+id, tokAdmin, nil)
	if code != http.StatusAccepted {
		t.Fatalf("DELETE = %d, muốn 202: %s", code, body)
	}

	if code, _ := do(t, srv, "GET", "/api/v1/apps/"+id, tokAdmin, nil); code != http.StatusNotFound {
		t.Errorf("GET sau DELETE = %d, muốn 404", code)
	}
	if code, _ := do(t, srv, "DELETE", "/api/v1/apps/"+id, tokAdmin, nil); code != http.StatusNotFound {
		t.Errorf("DELETE lần 2 = %d, muốn 404", code)
	}
	// Row vẫn còn ở pha chờ xoá — nếu không, reconciler không biết mà gỡ container.
	pending, err := st.ListAppsPendingDelete(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != id {
		t.Errorf("pending delete = %+v, muốn đúng app vừa xoá", pending)
	}
}

// Domain: trùng → 409 (kể cả giữa hai app khác nhau), sai cú pháp → 400.
func TestDomainConflictAndValidation(t *testing.T) {
	srv, _ := newTestServer(t)
	a := createOK(t, srv, "app-a", "nginx:1")
	b := createOK(t, srv, "app-b", "nginx:1")

	if code, body := do(t, srv, "POST", "/api/v1/apps/"+a+"/domains", tokAdmin,
		map[string]any{"fqdn": "A.Example.COM.", "is_primary": true}); code != http.StatusCreated {
		t.Fatalf("POST domain = %d: %s", code, body)
	}

	// Chuẩn hoá: cùng tên viết khác kiểu phải bị coi là TRÙNG, không phải tên mới.
	if code, body := do(t, srv, "POST", "/api/v1/apps/"+b+"/domains", tokAdmin,
		map[string]any{"fqdn": "a.example.com"}); code != http.StatusConflict {
		t.Errorf("domain trùng (khác hoa thường) = %d, muốn 409: %s", code, body)
	}

	for _, bad := range []string{"", "khôngcódấuchấm", "-x.example.com", "a..b.com", "a.example.com/path"} {
		if code, body := do(t, srv, "POST", "/api/v1/apps/"+b+"/domains", tokAdmin,
			map[string]any{"fqdn": bad}); code != http.StatusBadRequest {
			t.Errorf("fqdn %q = %d, muốn 400: %s", bad, code, body)
		}
	}

	// List trả về dạng ĐÃ chuẩn hoá.
	code, body := do(t, srv, "GET", "/api/v1/apps/"+a+"/domains", tokAdmin, nil)
	if code != http.StatusOK {
		t.Fatalf("GET domains = %d: %s", code, body)
	}
	var ds []store.Domain
	if err := json.Unmarshal(body, &ds); err != nil {
		t.Fatal(err)
	}
	if len(ds) != 1 || ds[0].FQDN != "a.example.com" || !ds[0].IsPrimary {
		t.Errorf("domains = %+v, muốn a.example.com (primary)", ds)
	}

	if code, _ := do(t, srv, "DELETE", "/api/v1/domains/a.example.com", tokAdmin, nil); code != http.StatusNoContent {
		t.Errorf("DELETE domain = %d, muốn 204", code)
	}
}

// desired.domains là nguồn khai báo: PATCH phải đồng bộ bảng app_domains theo.
func TestDesiredDomainsSynced(t *testing.T) {
	srv, _ := newTestServer(t)
	id := createOK(t, srv, "app-sync", "nginx:1")

	patch := func(doms []string) (int, []byte) {
		return do(t, srv, "PATCH", "/api/v1/apps/"+id+"/desired", tokAdmin,
			map[string]any{"image": "nginx:1", "domains": doms})
	}
	list := func() []store.Domain {
		t.Helper()
		_, body := do(t, srv, "GET", "/api/v1/apps/"+id+"/domains", tokAdmin, nil)
		var ds []store.Domain
		if err := json.Unmarshal(body, &ds); err != nil {
			t.Fatal(err)
		}
		return ds
	}

	if code, body := patch([]string{"one.example.com", "two.example.com"}); code != http.StatusOK {
		t.Fatalf("PATCH = %d: %s", code, body)
	}
	ds := list()
	if len(ds) != 2 || ds[0].FQDN != "one.example.com" || !ds[0].IsPrimary {
		t.Fatalf("sau PATCH #1 = %+v", ds)
	}

	// Bỏ bớt + đổi domain chính: tập phải khớp ĐÚNG, không để lại domain mồ côi.
	if code, body := patch([]string{"two.example.com"}); code != http.StatusOK {
		t.Fatalf("PATCH #2 = %d: %s", code, body)
	}
	ds = list()
	if len(ds) != 1 || ds[0].FQDN != "two.example.com" || !ds[0].IsPrimary {
		t.Fatalf("sau PATCH #2 = %+v, muốn chỉ two.example.com làm primary", ds)
	}

	// Khai mảng RỖNG → gỡ hết.
	if code, body := patch([]string{}); code != http.StatusOK {
		t.Fatalf("PATCH mảng rỗng = %d: %s", code, body)
	}
	if ds := list(); len(ds) != 0 {
		t.Errorf("sau PATCH mảng rỗng vẫn còn %+v", ds)
	}

	// Còn `"domains": null` thì KHÁC: schema khai kiểu array, nên null là sai
	// kiểu chứ không phải "ý là rỗng". Nhận bừa null ở đây sẽ dạy client rằng
	// hai cách viết là một, rồi đúng chỗ đó lộ ra khi thêm ràng buộc khác.
	if code, body := patch(nil); code != http.StatusBadRequest {
		t.Errorf(`PATCH "domains": null = %d, muốn 400: %s`, code, body)
	}
}

// Slug xấu bị chặn — slug đi vào TÊN CONTAINER nên đây là biên an toàn,
// không phải chuyện thẩm mỹ.
func TestSlugValidation(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, bad := range []string{"", "-x", "x-", "Hoa Thường", "a/b", "..", "a_b", "quá-dài-" + string(make([]byte, 60))} {
		code, body := do(t, srv, "POST", "/api/v1/apps", tokAdmin, map[string]any{
			"slug": bad, "desired": map[string]any{"image": "nginx:1"},
		})
		if code != http.StatusBadRequest {
			t.Errorf("slug %q = %d, muốn 400: %s", bad, code, body)
		}
	}
	// Slug trùng → 409.
	createOK(t, srv, "dup", "nginx:1")
	if code, body := do(t, srv, "POST", "/api/v1/apps", tokAdmin, map[string]any{
		"slug": "DUP", "desired": map[string]any{"image": "nginx:1"},
	}); code != http.StatusConflict {
		t.Errorf("slug trùng (khác hoa thường) = %d, muốn 409: %s", code, body)
	}
}

// Danh sách rỗng phải là `[]`, không phải `null` — `null.map()` là lỗi runtime ở UI.
func TestEmptyListsAreArrays(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, p := range []string{"/api/v1/apps", "/api/v1/events"} {
		code, body := do(t, srv, "GET", p, tokAdmin, nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d", p, code)
		}
		if string(bytes.TrimSpace(body)) != "[]" {
			t.Errorf("GET %s trả %s, muốn []", p, body)
		}
	}
}

// Body rác không được thành 500.
func TestMalformedBody(t *testing.T) {
	srv, _ := newTestServer(t)
	req, err := http.NewRequest("POST", srv.URL+"/api/v1/apps", bytes.NewReader([]byte("{không phải json")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokAdmin)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("body rác = %d, muốn 400", resp.StatusCode)
	}
}

// Import compose: bản nháp trả về, KHÔNG tạo app; compose nguy hiểm → 422.
func TestImportCompose(t *testing.T) {
	srv, st := newTestServer(t)

	post := func(token, yaml string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest("POST", srv.URL+"/api/v1/import/compose", bytes.NewReader([]byte(yaml)))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, buf.Bytes()
	}

	// Cần quyền GHI, không phải chỉ đọc.
	if code, _ := post(tokReader, "services:\n  x:\n    image: nginx\n"); code != http.StatusForbidden {
		t.Errorf("import với apps:read = %d, muốn 403", code)
	}

	code, body := post(tokAdmin, "services:\n  web:\n    image: nginx:1.27\n    ports: [\"8080:80\"]\n")
	if code != http.StatusOK {
		t.Fatalf("import = %d: %s", code, body)
	}
	var res struct {
		Apps []struct {
			Slug    string `json:"slug"`
			Desired struct {
				Image    string `json:"image"`
				HTTPPort int    `json:"http_port"`
			} `json:"desired"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Apps) != 1 || res.Apps[0].Slug != "web" ||
		res.Apps[0].Desired.Image != "nginx:1.27" || res.Apps[0].Desired.HTTPPort != 80 {
		t.Fatalf("bản nháp = %+v", res.Apps)
	}

	// Import KHÔNG được tạo app — đó là bước riêng, sau khi người dùng đọc ghi chú.
	apps, err := st.ListApps(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 {
		t.Errorf("import đã tạo %d app — nó phải chỉ trả bản nháp", len(apps))
	}

	// Compose nguy hiểm → 422 kèm mã máy đọc được, không phải 200 kèm cảnh báo.
	code, body = post(tokAdmin, "services:\n  x:\n    image: nginx\n    privileged: true\n")
	if code != http.StatusUnprocessableEntity {
		t.Errorf("compose privileged = %d, muốn 422: %s", code, body)
	}
	if !bytes.Contains(body, []byte("compose_rejected")) {
		t.Errorf("thiếu mã lỗi máy đọc được: %s", body)
	}

	if code, _ := post(tokAdmin, "không: [phải yaml"); code != http.StatusBadRequest {
		t.Errorf("YAML hỏng = %d, muốn 400", code)
	}
	if code, _ := post(tokAdmin, ""); code != http.StatusBadRequest {
		t.Errorf("body rỗng = %d, muốn 400", code)
	}
}
