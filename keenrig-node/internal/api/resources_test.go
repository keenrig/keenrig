package api_test

// RS-20 — hạn mức tài nguyên nhìn từ NGOÀI, qua HTTP thật.
//
// # Vì sao cần tầng này khi apps đã có test admission
//
// Vì `api` là adapter, và một adapter làm sai đúng một việc: dịch lỗi thành mã
// HTTP. `apps.ErrUnsupported` bị map thành 500 thì admission vẫn chạy, test của
// apps vẫn xanh, và client nhận một lỗi máy chủ cho một sai sót của chính họ —
// UI sẽ hiện "lỗi hệ thống" thay vì chỉ vào trường cần sửa.
//
// Test này khẳng định MÃ và THÂN phản hồi, hai thứ duy nhất client thấy.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/api"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// serverOnRuntime dựng API với năng lực hạn mức của một driver runtime thật.
//
// Lưu ý về Luật 9: package `api` KHÔNG được import `internal/runtime`, nên tên
// driver ở đây là chuỗi và năng lực lấy từ `internal/resources` — đúng lý do
// package đó tồn tại tách khỏi `runtime` (xem godoc internal/resources).
func serverOnRuntime(t *testing.T, driver string) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	auth := fakeAuth{tokAdmin: {authz.ScopeAdmin}}
	svc := apps.New(st, domains.New(st), apps.Options{ResourceCaps: resources.ByDriver(driver)})
	srv := httptest.NewServer(api.New(svc, st, auth))
	t.Cleanup(srv.Close)
	return srv
}

const imgDigest = "ghcr.io/acme/web@sha256:" +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestPostAppsHanMucKhongThucThiNoiTra400(t *testing.T) {
	srv := serverOnRuntime(t, "k8s")
	code, body := do(t, srv, http.MethodPost, "/api/v1/apps", tokAdmin, map[string]any{
		"slug": "shop",
		"desired": map[string]any{
			"image":     imgDigest,
			"resources": map[string]any{"memory_mb": 512, "pids_limit": 200},
		},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("POST /apps = %d, muốn 400 (k8s không khai được pids theo app)\n%s", code, body)
	}
	// Thân phản hồi phải nói năng lực nào thiếu — nếu không thì UI chỉ hiện
	// "yêu cầu không hợp lệ" và người dùng đoán trong mười một trường.
	if !strings.Contains(string(body), "pids") {
		t.Errorf("thân 400 không nói năng lực nào thiếu:\n%s", body)
	}
}

func TestPostAppsTruongLaTra400(t *testing.T) {
	srv := serverOnRuntime(t, "docker")
	// `memory_gb` không tồn tại. Không có additionalProperties:false thì trường
	// này bị bỏ qua trong im lặng và app chạy KHÔNG có trần RAM.
	code, body := do(t, srv, http.MethodPost, "/api/v1/apps", tokAdmin, map[string]any{
		"slug": "shop",
		"desired": map[string]any{
			"image":     imgDigest,
			"resources": map[string]any{"memory_gb": 2},
		},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("POST /apps với trường lạ = %d, muốn 400\n%s", code, body)
	}
}

func TestPostAppsHanMucHopLeTra201(t *testing.T) {
	srv := serverOnRuntime(t, "docker")
	code, body := do(t, srv, http.MethodPost, "/api/v1/apps", tokAdmin, map[string]any{
		"slug": "shop",
		"desired": map[string]any{
			"image": imgDigest,
			"resources": map[string]any{
				"memory_mb": 512, "memory_swap_mb": 1024, "cpu": 0.5,
				"cpu_shares": 512, "pids_limit": 200, "shm_size_mb": 256,
				"ulimits":  []any{map[string]any{"name": "nofile", "soft": 1024, "hard": 4096}},
				"replicas": 2,
			},
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("POST /apps với hạn mức docker thực thi được = %d, muốn 201\n%s", code, body)
	}

	// Và desired lưu lại phải giữ NGUYÊN hạn mức: một round-trip làm mất trường
	// nghĩa là reconciler deploy một app không có hạn mức người dùng đã khai.
	var app struct {
		ID      string          `json:"id"`
		Desired json.RawMessage `json:"desired"`
	}
	if err := json.Unmarshal(body, &app); err != nil {
		t.Fatalf("giải mã phản hồi: %v\n%s", err, body)
	}
	for _, want := range []string{"memory_swap_mb", "cpu_shares", "pids_limit", "shm_size_mb", "nofile"} {
		if !strings.Contains(string(app.Desired), want) {
			t.Errorf("desired đã lưu mất %q:\n%s", want, app.Desired)
		}
	}
}

func TestPatchDesiredHanMucKhongThucThiNoiTra400(t *testing.T) {
	srv := serverOnRuntime(t, "swarm")
	code, body := do(t, srv, http.MethodPost, "/api/v1/apps", tokAdmin, map[string]any{
		"slug":    "shop",
		"desired": map[string]any{"image": imgDigest, "resources": map[string]any{"memory_mb": 512}},
	})
	if code != http.StatusCreated {
		t.Fatalf("POST /apps = %d, muốn 201\n%s", code, body)
	}
	var app struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &app); err != nil {
		t.Fatal(err)
	}

	code, body = do(t, srv, http.MethodPatch, "/api/v1/apps/"+app.ID+"/desired", tokAdmin,
		map[string]any{
			"image":     imgDigest,
			"resources": map[string]any{"memory_mb": 512, "io_write_mbps": 20},
		})
	if code != http.StatusBadRequest {
		t.Fatalf("PATCH desired thêm io_write_mbps trên swarm = %d, muốn 400\n%s", code, body)
	}
	if !strings.Contains(string(body), "io_bps") {
		t.Errorf("thân 400 không nói năng lực nào thiếu:\n%s", body)
	}
}
