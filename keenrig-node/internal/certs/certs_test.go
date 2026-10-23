package certs_test

// Test T9 — Manager với issuer giả. ACMEIssuer thật cần một CA (pebble) nên
// nó thuộc e2e T12; ở đây kiểm phần logic quyết định: khi nào xin, khi nào gia
// hạn, khi nào KHÔNG làm gì, và một domain hỏng có kéo đổ domain khác không.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/certs"
	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

type fakeIssuer struct {
	mu       sync.Mutex
	calls    []string
	failFor  map[string]bool
	validFor time.Duration
	now      func() time.Time
}

func (f *fakeIssuer) Name() string { return "fake" }

func (f *fakeIssuer) Issue(_ context.Context, fqdn string) (certs.Bundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fqdn)
	if f.failFor[fqdn] {
		return certs.Bundle{}, errors.New("DNS chưa trỏ về đây")
	}
	d := f.validFor
	if d == 0 {
		d = 90 * 24 * time.Hour
	}
	return certs.Bundle{
		FQDN:     fqdn,
		CertPEM:  []byte("-----BEGIN CERTIFICATE-----\n" + fqdn + "\n-----END CERTIFICATE-----\n"),
		KeyPEM:   []byte("-----BEGIN EC PRIVATE KEY-----\nkey\n-----END EC PRIVATE KEY-----\n"),
		NotAfter: f.now().Add(d),
		IssuedAt: f.now(),
	}, nil
}

func (f *fakeIssuer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func setup(t *testing.T, issuer certs.Issuer, now func() time.Time) (*certs.Manager, store.Store, paths.Layout) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	layout := paths.New(dir)
	return certs.New(st, layout, issuer, certs.Options{Now: now}), st, layout
}

func TestEnsureIssuesOncePerDomain(t *testing.T) {
	clock := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	iss := &fakeIssuer{now: now}
	m, _, layout := setup(t, iss, now)
	ctx := context.Background()

	refs, err := m.Ensure(ctx, []string{"b.example.com", "a.example.com"})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %v, muốn 2", refs)
	}
	if iss.count() != 2 {
		t.Fatalf("Issue gọi %d lần, muốn 2", iss.count())
	}

	// Cert và khoá phải nằm trên đĩa cho gateway đọc.
	for _, fqdn := range []string{"a.example.com", "b.example.com"} {
		for _, p := range []string{m.CertPath(fqdn), m.KeyPath(fqdn)} {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("thiếu file %s: %v", p, err)
			}
		}
	}
	if _, err := os.Stat(layout.ProxyCerts()); err != nil {
		t.Errorf("thiếu thư mục cert: %v", err)
	}

	// Gọi lại: cert còn hạn → KHÔNG xin thêm. Xin lại mỗi tick sẽ chạm rate
	// limit của CA trong vài phút.
	if _, err := m.Ensure(ctx, []string{"a.example.com", "b.example.com"}); err != nil {
		t.Fatal(err)
	}
	if iss.count() != 2 {
		t.Errorf("Issue gọi thêm sau khi đã có cert còn hạn: %d lần", iss.count())
	}
}

func TestEnsureRenewsBeforeExpiry(t *testing.T) {
	clock := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	// Cert chỉ còn sống 40 ngày → chưa cần gia hạn (ngưỡng 30 ngày).
	iss := &fakeIssuer{now: now, validFor: 40 * 24 * time.Hour}
	m, _, _ := setup(t, iss, now)
	ctx := context.Background()

	if _, err := m.Ensure(ctx, []string{"a.example.com"}); err != nil {
		t.Fatal(err)
	}
	if iss.count() != 1 {
		t.Fatalf("Issue = %d", iss.count())
	}

	// Tua tới lúc còn 20 ngày → phải gia hạn.
	clock = clock.Add(20 * 24 * time.Hour)
	if _, err := m.Ensure(ctx, []string{"a.example.com"}); err != nil {
		t.Fatal(err)
	}
	if iss.count() != 2 {
		t.Errorf("không gia hạn khi cert còn dưới 30 ngày: Issue = %d", iss.count())
	}
}

// Một domain xin hỏng KHÔNG được kéo theo domain khác: với nginx, thiếu một
// file cert làm `nginx -t` từ chối CẢ tập cấu hình.
func TestEnsurePartialFailureIsolated(t *testing.T) {
	clock := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	iss := &fakeIssuer{now: now, failFor: map[string]bool{"xau.example.com": true}}
	m, st, _ := setup(t, iss, now)
	ctx := context.Background()

	refs, err := m.Ensure(ctx, []string{"tot.example.com", "xau.example.com"})
	if err != nil {
		t.Fatalf("Ensure trả lỗi tổng dù chỉ một domain hỏng: %v", err)
	}
	if _, ok := refs["tot.example.com"]; !ok {
		t.Error("domain lành không có trong kết quả")
	}
	if _, ok := refs["xau.example.com"]; ok {
		t.Error("domain hỏng lại có cert_ref — nó phải bị loại khỏi desired")
	}

	// Thất bại phải để lại dấu vết cho người vận hành.
	evs, err := st.ListEvents(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range evs {
		if e.Action == "cert.failed" && e.Subject == "xau.example.com" {
			found = true
		}
	}
	if !found {
		t.Error("thiếu event cert.failed")
	}
}

// Cert còn hạn nhưng file trên đĩa bị mất (gateway cài lại) → phải ghi lại từ
// secrets, KHÔNG đi xin cert mới.
func TestEnsureRewritesFilesWithoutReissue(t *testing.T) {
	clock := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	iss := &fakeIssuer{now: now}
	m, _, _ := setup(t, iss, now)
	ctx := context.Background()

	if _, err := m.Ensure(ctx, []string{"a.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.CertPath("a.example.com")); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Ensure(ctx, []string{"a.example.com"}); err != nil {
		t.Fatal(err)
	}
	if iss.count() != 1 {
		t.Errorf("xin cert mới chỉ vì mất file trên đĩa: Issue = %d", iss.count())
	}
	if _, err := os.Stat(m.CertPath("a.example.com")); err != nil {
		t.Errorf("file cert không được ghi lại: %v", err)
	}
}

// Không có issuer mà lại có domain cần cert → lỗi RÕ, không im lặng chạy không.
func TestEnsureWithoutIssuer(t *testing.T) {
	m, _, _ := setup(t, nil, time.Now)
	ctx := context.Background()

	if _, err := m.Ensure(ctx, nil); err != nil {
		t.Errorf("không domain nào thì không cần issuer: %v", err)
	}
	if _, err := m.Ensure(ctx, []string{"a.example.com"}); !errors.Is(err, certs.ErrNoIssuer) {
		t.Errorf("Ensure = %v, muốn ErrNoIssuer", err)
	}
}

// SecretRef phải TẤT ĐỊNH (chuẩn hoá hoa thường) và phần dùng làm tên file
// phải an toàn — CertPath/KeyPath ghép thẳng nó vào đường dẫn.
func TestSecretRefStableAndSafe(t *testing.T) {
	if certs.SecretRef("A.Example.COM") != certs.SecretRef("a.example.com") {
		t.Error("SecretRef phân biệt hoa thường")
	}
	if certs.SecretRef("a.example.com") == certs.SecretRef("b.example.com") {
		t.Error("hai domain khác nhau cho cùng ref")
	}

	m, _, layout := setup(t, nil, time.Now)
	// Tên miền dài nhất và bẩn nhất vẫn phải cho một tên file nằm TRONG
	// ProxyCerts — đây là biên an toàn, không phải chuyện thẩm mỹ.
	for _, fqdn := range []string{
		"a.example.com",
		"rất-dài." + strings.Repeat("x", 60) + ".example.com",
		"../../etc/passwd",
		`a\b.example.com`,
	} {
		for _, p := range []string{m.CertPath(fqdn), m.KeyPath(fqdn)} {
			if filepath.Dir(p) != filepath.Clean(layout.ProxyCerts()) {
				t.Errorf("fqdn %q cho đường dẫn %q — leo ra ngoài %s", fqdn, p, layout.ProxyCerts())
			}
			if base := filepath.Base(p); strings.ContainsAny(base, `/\ `) || strings.Contains(base, "..") {
				t.Errorf("tên file %q không an toàn", base)
			}
		}
	}
}

func TestBundleNeedsRenew(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		after time.Time
		want  bool
	}{
		{"chưa có hạn", time.Time{}, true},
		{"đã hết hạn", now.Add(-time.Hour), true},
		{"còn 1 ngày", now.Add(24 * time.Hour), true},
		{"còn đúng ngưỡng", now.Add(certs.RenewBefore), true},
		{"còn 31 ngày", now.Add(31 * 24 * time.Hour), false},
	}
	for _, c := range cases {
		if got := (certs.Bundle{NotAfter: c.after}).NeedsRenew(now); got != c.want {
			t.Errorf("%s: NeedsRenew = %v, muốn %v", c.name, got, c.want)
		}
	}
}
