package authz

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminImpliesEverything(t *testing.T) {
	admin := Principal{Subject: "root", Scopes: []Scope{ScopeAdmin}}
	for _, s := range AllScopes() {
		if !admin.Has(s) {
			t.Errorf("admin thiếu %q — ScopeAdmin phải bao hàm mọi scope", s)
		}
	}
	narrow := Principal{Subject: "ro", Scopes: []Scope{ScopeAppsRead}}
	if !narrow.Has(ScopeAppsRead) {
		t.Error("thiếu scope chính nó")
	}
	if narrow.Has(ScopeAppsWrite) || narrow.Has(ScopeAdmin) {
		t.Error("apps:read không được suy ra quyền ghi hay admin")
	}
	// Principal rỗng KHÔNG được có quyền gì — nếu Has trả true cho zero value
	// thì mọi request chưa xác thực sẽ đi lọt.
	var zero Principal
	for _, s := range AllScopes() {
		if zero.Has(s) {
			t.Errorf("Principal rỗng lại có %q", s)
		}
	}
}

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":    "abc",
		"bearer abc":    "abc", // scheme không phân biệt hoa thường (RFC 7235)
		"BEARER  abc  ": "abc",
		"Basic abc":     "",
		"abc":           "",
		"Bearer":        "",
		"Bearer ":       "",
		"":              "",
		"Bearer a b":    "a b", // token có khoảng trắng: trả nguyên văn, để bên so sánh từ chối
	}
	for header, want := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		if got := BearerToken(r); got != want {
			t.Errorf("BearerToken(%q) = %q, muốn %q", header, got, want)
		}
	}
}

func TestGuardRequire(t *testing.T) {
	auth := AuthenticatorFunc(func(r *http.Request) (Principal, error) {
		switch BearerToken(r) {
		case "admin":
			return Principal{Subject: "admin", Scopes: []Scope{ScopeAdmin}}, nil
		case "ro":
			return Principal{Subject: "ro", Scopes: []Scope{ScopeAppsRead}}, nil
		case "boom":
			return Principal{}, errors.New("store hỏng")
		}
		return Principal{}, ErrUnauthenticated
	})
	g := NewGuard(auth, nil)

	var sawSubject string
	h := g.Require(ScopeAppsWrite, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := FromContext(r.Context())
		if !ok {
			t.Error("handler không thấy principal — middleware phải nhét vào ctx")
		}
		sawSubject = p.Subject
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		token string
		want  int
	}{
		{"admin", http.StatusOK},
		{"ro", http.StatusForbidden},             // đã xác thực, thiếu scope
		{"lạ", http.StatusUnauthorized},          // không nhận diện được
		{"", http.StatusUnauthorized},            // không có token
		{"boom", http.StatusInternalServerError}, // lỗi hệ thống ≠ lỗi xác thực
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/", nil)
		if c.token != "" {
			r.Header.Set("Authorization", "Bearer "+c.token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("token %q = %d, muốn %d", c.token, w.Code, c.want)
		}
	}
	if sawSubject != "admin" {
		t.Errorf("subject thấy trong handler = %q, muốn admin", sawSubject)
	}
}

// Handler KHÔNG qua Guard thì FromContext phải trả ok=false — handler dựa vào
// đó để biết mình bị gắn nhầm chỗ, thay vì coi request là khách vãng lai.
func TestFromContextWithoutGuard(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if _, ok := FromContext(r.Context()); ok {
		t.Error("FromContext trả ok=true cho request chưa qua middleware")
	}
}
