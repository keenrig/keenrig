package httpd

// Cửa vé "Mở Admin ↗" (CON-13) nằm ngoài /api/v1 và cạnh SPA ở "/" — hai điều
// đó là đủ để nó bị nuốt mất y như đường OIDC từng bị (xem
// TestOIDCPathsAnswerJSONWhenDisabled). Test này canh đúng chỗ đó.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminSessionPathIsNotSwallowedByTheSPA(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	spa := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><html>Admin UI</html>"))
	})
	handoff := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"ticket"}`))
	})
	s := New(st, ":0", WithUI(spa), WithAdminSession(handoff))
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()

	// CẢ HAI method: gắn riêng "POST" sẽ để GET rơi xuống SPA, và người bấm
	// nhầm một link nhận về index.html kèm mã 200 thay vì lý do.
	for _, method := range []string{"GET", "POST"} {
		req, err := http.NewRequest(method, ts.URL+AdminSessionPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, AdminSessionPath, err)
		}
		res.Body.Close()
		if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
			t.Errorf("%s %s trả %q — SPA đã nuốt đường này", method, AdminSessionPath, ct)
		}
	}
}
