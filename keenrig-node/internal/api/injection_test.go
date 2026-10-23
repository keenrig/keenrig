package api_test

// SEC-03 — "SAST + injection test trên api (SQLi qua tham số, path traversal)".
// SEC-04 — "Secrets không xuất hiện trong logs/events/metrics/error message".
//
// # Vì sao test này không thừa dù ta dùng câu tham số hoá
//
// Toàn bộ store dùng `?` placeholder, nên SQLi "cổ điển" không xảy ra. Nhưng
// đó là một lập luận về code HIỆN TẠI, và nó hết hiệu lực vào ngày ai đó thêm
// một câu nối chuỗi. Test này biến lập luận ấy thành một hàng rào tự động.
//
// Điều nó THẬT SỰ bắt được, ngay hôm nay: một chuỗi độc hại đi qua API không
// được làm sập tiến trình (500 do panic), không được làm rò cấu trúc nội bộ
// (câu SQL, đường dẫn file) ra thông báo lỗi, và không được thoát khỏi thư mục
// dữ liệu qua tham số đường dẫn.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// payloads — tải trọng đối kháng. Chia nhóm để khi test đỏ, tên nhóm đã nói
// ngay hướng tấn công nào lọt.
var payloads = map[string][]string{
	"sqli": {
		`' OR '1'='1`,
		`'; DROP TABLE apps; --`,
		`" OR 1=1 --`,
		`admin'--`,
		`1' UNION SELECT token_hash FROM sessions --`,
		`'; ATTACH DATABASE '/tmp/evil.db' AS evil; --`,
		`x' AND (SELECT COUNT(*) FROM sqlite_master) > 0 --`,
	},
	"path-traversal": {
		`../../../../etc/passwd`,
		`..\..\..\..\windows\win.ini`,
		`....//....//etc/shadow`,
		`/etc/passwd`,
		`C:\Windows\System32\config\SAM`,
		`%2e%2e%2f%2e%2e%2fetc%2fpasswd`,
		`....\\....\\platform.db`,
	},
	"tiêm-lệnh": {
		"; rm -rf /",
		"$(whoami)",
		"`id`",
		"| cat /etc/passwd",
		"\n\rmalicious: header",
	},
	"ký-tự-điều-khiển": {
		"\x00null-byte",
		"\x1b[31mmàu-ansi",
		strings.Repeat("A", 10000), // quá dài
	},
}

// forbidden — dấu vết KHÔNG được xuất hiện trong bất kỳ phản hồi nào.
//
// Đây là phần SEC-04 gộp vào: một thông báo lỗi lộ câu SQL hoặc đường dẫn tuyệt
// đối là món quà cho bước dò tiếp theo, và nó rò qua đúng con đường mà không ai
// nghĩ tới khi rà soát code.
var forbidden = []string{
	"SELECT ", "INSERT ", "UPDATE ", "DELETE FROM", "sqlite", "SQLITE",
	"master.key", "platform.db",
	"/home/", "C:\\Users", "AppData",
	"goroutine ", "panic:", // dấu vết stack trace
}

// assertCleanResponse — hai khẳng định, và cái thứ hai có một ngoại lệ QUAN
// TRỌNG.
//
// Thông báo lỗi hợp lệ có ECHO lại giá trị sai ("slug %q chứa ký tự không hợp
// lệ") — đó là thứ giúp người dùng sửa được lỗi. Echo lại chuỗi do CHÍNH kẻ
// tấn công gửi thì không lộ gì cả: họ đã biết nó rồi.
//
// Nên phép kiểm phải là: phản hồi không được chứa dấu vết nội bộ mà kẻ tấn
// công KHÔNG cung cấp. Bỏ ngoại lệ này thì test đỏ ở đúng chỗ hệ thống đang
// làm đúng, và cách duy nhất làm nó xanh là bỏ echo — tức là làm thông báo lỗi
// tệ đi để đổi lấy một sự an toàn không có thật.
//
// (Độ dài echo đã bị chặn: kiểm MaxSlugLen/MaxFQDNLen chạy TRƯỚC. Ký tự điều
// khiển đã bị escape: fmt %q. Hai lớp đó là thật, và chúng được kiểm bên dưới.)
func assertCleanResponse(t *testing.T, where string, sent string, code int, body []byte) {
	t.Helper()
	if code >= 500 {
		t.Errorf("%s → %d (lỗi nội bộ) với đầu vào rác: %s", where, code, body)
	}
	s := string(body)
	for _, bad := range forbidden {
		if !strings.Contains(s, bad) {
			continue
		}
		if strings.Contains(sent, bad) {
			continue // chỉ là tiếng vọng của chính đầu vào
		}
		t.Errorf("%s rò %q ra phản hồi (SEC-04): %s", where, bad, s)
	}
	// Phản hồi không được PHÌNH theo đầu vào: một thông báo lỗi dài 10KB là
	// một kênh làm ngập log rẻ tiền.
	if len(body) > 4096 {
		t.Errorf("%s: phản hồi dài %d byte với đầu vào %d byte — thông báo lỗi "+
			"phải bị chặn độ dài", where, len(body), len(sent))
	}
	// Và không được mang ký tự điều khiển thô (ANSI escape đi thẳng vào
	// terminal của người vận hành).
	if strings.ContainsAny(s, "\x00\x1b") {
		t.Errorf("%s: phản hồi chứa ký tự điều khiển THÔ — phải escape (fmt %%q)", where)
	}
}

// SQLi qua tham số đường dẫn: /apps/{id}, /domains/{fqdn}.
func TestInjectionInPathParams(t *testing.T) {
	srv, _ := newTestServer(t)
	createOK(t, srv, "app-that", "nginx:1")

	for group, list := range payloads {
		for _, p := range list {
			enc := url.PathEscape(p)
			for _, path := range []string{
				"/api/v1/apps/" + enc,
				"/api/v1/apps/" + enc + "/domains",
				"/api/v1/domains/" + enc,
			} {
				code, body := do(t, srv, "GET", path, tokAdmin, nil)
				assertCleanResponse(t, group+" "+path, p, code, body)
			}
		}
	}

	// Và quan trọng nhất: app thật vẫn còn. `'; DROP TABLE apps; --` mà chạy
	// được thì kiểm mã trạng thái ở trên chẳng có nghĩa gì.
	code, body := do(t, srv, "GET", "/api/v1/apps", tokAdmin, nil)
	if code != 200 {
		t.Fatalf("GET /apps sau loạt tấn công = %d: %s", code, body)
	}
	if !strings.Contains(string(body), "app-that") {
		t.Fatalf("app thật biến mất sau loạt injection — bảng có thể đã bị đụng: %s", body)
	}
}

// SQLi qua query string: ?limit= của /events.
func TestInjectionInQueryParams(t *testing.T) {
	srv, _ := newTestServer(t)
	for group, list := range payloads {
		for _, p := range list {
			path := "/api/v1/events?limit=" + url.QueryEscape(p)
			code, body := do(t, srv, "GET", path, tokAdmin, nil)
			assertCleanResponse(t, group+" ?limit", p, code, body)
			// limit rác phải rơi về mặc định, không được thành 500 hay treo.
			if code != 200 {
				t.Errorf("%s: limit rác → %d, muốn 200 với giá trị mặc định", group, code)
			}
		}
	}
}

// SQLi qua thân JSON: slug, image, fqdn.
func TestInjectionInBody(t *testing.T) {
	srv, _ := newTestServer(t)
	appID := createOK(t, srv, "app-goc", "nginx:1")

	for group, list := range payloads {
		for _, p := range list {
			code, body := do(t, srv, "POST", "/api/v1/apps", tokAdmin, map[string]any{
				"slug": p, "desired": map[string]any{"image": "nginx:1"},
			})
			assertCleanResponse(t, group+" slug", p, code, body)

			code, body = do(t, srv, "POST", "/api/v1/apps/"+appID+"/domains", tokAdmin,
				map[string]any{"fqdn": p})
			assertCleanResponse(t, group+" fqdn", p, code, body)

			code, body = do(t, srv, "PATCH", "/api/v1/apps/"+appID+"/desired", tokAdmin,
				map[string]any{"image": p})
			assertCleanResponse(t, group+" image", p, code, body)
		}
	}

	// App gốc vẫn sống và vẫn đúng chủ.
	if code, body := do(t, srv, "GET", "/api/v1/apps/"+appID, tokAdmin, nil); code != 200 {
		t.Fatalf("app gốc = %d: %s", code, body)
	}
}

// JSON dị dạng phải trả 400, không phải 500 và không panic.
func TestMalformedJSONIsBadRequest(t *testing.T) {
	srv, _ := newTestServer(t)
	bodies := map[string]string{
		"không phải json":  `không phải json`,
		"cụt":              `{"slug":`,
		"lồng sâu":         strings.Repeat(`{"a":`, 2000) + "1" + strings.Repeat("}", 2000),
		"mảng thay object": `[1,2,3]`,
		"null":             `null`,
		"số":               `12345`,
		"chuỗi":            `"chuỗi"`,
	}
	for name, raw := range bodies {
		t.Run(name, func(t *testing.T) {
			code, body := doRaw(t, srv, "POST", "/api/v1/apps", tokAdmin, raw)
			if code >= 500 {
				t.Errorf("→ %d với JSON dị dạng: %s", code, body)
			}
			assertCleanResponse(t, "json "+name, raw, code, body)
		})
	}
}

// Thông báo lỗi của đường import (đầu vào KHÔNG tin cậy theo thiết kế) cũng
// không được rò đường dẫn nội bộ.
func TestImportErrorsDoNotLeakPaths(t *testing.T) {
	srv, _ := newTestServer(t)
	for group, list := range payloads {
		for _, p := range list {
			code, body := doRaw(t, srv, "POST", "/api/v1/import/compose", tokAdmin, p)
			assertCleanResponse(t, "import "+group, p, code, body)
		}
	}
}

// Header Authorization dị dạng không được làm sập đường xác thực.
func TestMalformedAuthHeader(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, h := range []string{
		"Bearer", "Bearer ", "bearer  ", "Basic YWRtaW46YWRtaW4=",
		"Bearer " + strings.Repeat("A", 100000),
		"Bearer ' OR '1'='1",
		// KHÔNG có ký tự điều khiển ở đây: net/http từ chối gửi header chứa
		// \x00 ngay từ phía CLIENT, nên test sẽ đỏ vì thư viện chặn chứ không
		// vì server xử lý sai. Bảo vệ đó là thật và nằm ở tầng khác — kiểm nó
		// ở đây chỉ chứng minh net/http hoạt động đúng.
	} {
		code, body := doWithHeader(t, srv, "GET", "/api/v1/apps", "Authorization", h)
		if code >= 500 {
			t.Errorf("Authorization %q → %d: %s", truncateForLog(h), code, body)
		}
		assertCleanResponse(t, "auth header", h, code, body)
	}
}

func truncateForLog(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// SEC-04 — event ghi vào audit log KHÔNG được mang secret.
//
// Kiểm ở đây chứ không chỉ ở identity: audit log là thứ được xuất ra ngoài khi
// người vận hành mở ticket hỗ trợ, nên nó là đường rò có thật.
func TestEventsCarryNoSecrets(t *testing.T) {
	srv, _ := newTestServer(t)
	createOK(t, srv, "app-secret", "nginx:1")

	code, body := do(t, srv, "GET", "/api/v1/events", tokAdmin, nil)
	if code != 200 {
		t.Fatalf("GET /events = %d", code)
	}
	var evs []map[string]any
	if err := json.Unmarshal(body, &evs); err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, bad := range append([]string{tokAdmin, tokReader, "password", "token_hash"}, forbidden...) {
		if strings.Contains(s, bad) {
			t.Errorf("audit log chứa %q: %s", bad, s)
		}
	}
}

// --- helper cho test đối kháng ---------------------------------------------------

// doRaw gửi thân THÔ, không qua json.Marshal — đó là điểm của mọi test JSON dị
// dạng: nếu marshal giúp làm sạch đầu vào thì test đang kiểm nhầm thứ.
func doRaw(t *testing.T, srv *httptest.Server, method, path, token, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	return send(t, srv, req)
}

// doWithHeader đặt MỘT header tuỳ ý, kể cả header dị dạng.
func doWithHeader(t *testing.T, srv *httptest.Server, method, path, key, value string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(key, value)
	return send(t, srv, req)
}

func send(t *testing.T, srv *httptest.Server, req *http.Request) (int, []byte) {
	t.Helper()
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}
