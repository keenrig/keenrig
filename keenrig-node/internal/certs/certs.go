// Package certs — cấp và gia hạn chứng chỉ TLS cho các gateway KHÔNG tự làm
// được việc đó (PX-02, đường thứ hai).
//
// # Vì sao package này gần như luôn rảnh
//
// Gateway mặc định là caddy, và caddy có CapACME: nó tự xin, tự gia hạn, tự
// nạp. Với cấu hình mặc định, Manager ở đây không chạy một dòng nào. Nó tồn tại
// vì nginx/nginx-owasp KHÔNG có ACME, và bỏ trống thì đổi driver gateway đồng
// nghĩa với mất HTTPS — một "tuỳ chọn" mà chọn vào là hỏng.
//
// Ai quyết định đường nào: NĂNG LỰC gateway, không phải cấu hình riêng. Xem
// reconciler.tlsModeFor — có CapACME thì Site đi đường acme_by_gateway, không
// có thì đường cert_upload và Manager này phải cấp cert xuống trước.
//
// # Ranh giới với store
//
// Khoá riêng nằm trong bảng secrets (mã hoá bằng master.key), KHÔNG nằm trong
// app_domains.cert_ref — cột đó chỉ giữ KHOÁ TRA CỨU. Bản sao trên đĩa dưới
// paths.ProxyCerts() là CACHE dẫn xuất cho gateway đọc: xoá đi thì lần Ensure
// sau ghi lại từ secrets, không phải đi xin cert mới.
package certs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

var (
	// ErrNoIssuer — chưa cấu hình nơi xin cert nhưng gateway lại cần được cấp.
	// Trả lỗi rõ thay vì im lặng chạy không: gateway không cert nghĩa là mọi
	// site HTTPS đều hỏng, và đó phải là một thông báo chứ không phải một bí ẩn.
	ErrNoIssuer = errors.New("certs: the gateway needs a certificate but no issuer is configured")
	// ErrNotReady — cert chưa có; caller nên bỏ site đó khỏi desired lần này.
	ErrNotReady = errors.New("certs: the certificate is not ready")
)

const (
	// RenewBefore — gia hạn khi hạn còn dưới ngần này.
	//
	// 30 ngày là quy ước của Let's Encrypt cho cert 90 ngày: đủ để một chuỗi
	// thất bại (rate limit, DNS hỏng, máy tắt) vẫn còn nhiều tuần để tự sửa
	// trước khi người dùng thấy cảnh báo trình duyệt.
	RenewBefore = 30 * 24 * time.Hour
	// secretPrefix — tiền tố ref trong bảng secrets.
	secretPrefix = "certs/"
	certFileMode = 0o600
)

// Bundle — cert + khoá riêng + hạn, dạng lưu trong secrets.
type Bundle struct {
	FQDN      string    `json:"fqdn"`
	CertPEM   []byte    `json:"cert_pem"`
	KeyPEM    []byte    `json:"key_pem"`
	NotAfter  time.Time `json:"not_after"`
	IssuedAt  time.Time `json:"issued_at"`
	IssuerURL string    `json:"issuer_url,omitempty"`
}

// NeedsRenew — hết hạn, hoặc sắp hết hạn trong RenewBefore.
func (b Bundle) NeedsRenew(now time.Time) bool {
	return b.NotAfter.IsZero() || !now.Add(RenewBefore).Before(b.NotAfter)
}

// Issuer — seam sang ACME. Tách interface để test chạy được mà không cần
// pebble, và để đổi sang DNS-01 hay một CA nội bộ mà không đụng Manager.
type Issuer interface {
	// Issue xin cert cho fqdn. BLOCK tới khi xong hoặc ctx hết hạn.
	Issue(ctx context.Context, fqdn string) (Bundle, error)
	// Name để ghi vào event/log.
	Name() string
}

// SecretRef — ref trong bảng secrets cho một FQDN.
//
// Băm FQDN thay vì nối thẳng: ref đi vào cột cert_ref và vào tên file trên
// đĩa, mà FQDN có thể dài 253 ký tự và chứa dấu chấm. Băm cho độ dài cố định
// và một segment đường dẫn an toàn — cùng lý do driver docker băm app.id.
func SecretRef(fqdn string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(fqdn)))
	return secretPrefix + hex.EncodeToString(sum[:8])
}

type Manager struct {
	st     store.Store
	layout paths.Layout
	issuer Issuer
	now    func() time.Time
}

type Options struct {
	// Now để test tua thời gian; nil → time.Now.
	Now func() time.Time
}

func New(st store.Store, layout paths.Layout, issuer Issuer, opts Options) *Manager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Manager{st: st, layout: layout, issuer: issuer, now: opts.Now}
}

// HasIssuer cho biết Manager có làm được việc không.
func (m *Manager) HasIssuer() bool { return m != nil && m.issuer != nil }

// Ensure đảm bảo mỗi FQDN có cert còn hạn, trả map fqdn → cert_ref cho những
// cái ĐÃ SẴN SÀNG.
//
// Trả về map thay vì lỗi tổng: một domain xin cert hỏng KHÔNG được kéo theo các
// domain khác. Caller (reconciler) đưa vào desired của gateway những site có
// mặt trong map và bỏ qua phần còn lại — site thiếu cert lên gateway sẽ làm
// nginx từ chối nạp CẢ tập cấu hình.
func (m *Manager) Ensure(ctx context.Context, fqdns []string) (map[string]string, error) {
	if !m.HasIssuer() {
		if len(fqdns) == 0 {
			return map[string]string{}, nil
		}
		return nil, ErrNoIssuer
	}
	out := make(map[string]string, len(fqdns))
	// Thứ tự ổn định: khi rate limit của CA chặn giữa chừng, ta muốn lần chạy
	// sau tiếp tục theo cùng thứ tự chứ không bốc thăm lại từ đầu.
	sorted := append([]string(nil), fqdns...)
	sort.Strings(sorted)

	for _, fqdn := range sorted {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		ref, err := m.ensureOne(ctx, fqdn)
		if err != nil {
			m.event(ctx, "cert.failed", fqdn, map[string]any{"error": err.Error()})
			continue
		}
		out[fqdn] = ref
	}
	return out, nil
}

func (m *Manager) ensureOne(ctx context.Context, fqdn string) (string, error) {
	ref := SecretRef(fqdn)
	b, err := m.load(ctx, ref)
	switch {
	case err == nil && !b.NeedsRenew(m.now()):
		// Cert còn tốt. Vẫn ghi file: gateway có thể vừa được cài lại và mất
		// thư mục cert, còn secrets thì không mất.
		return ref, m.writeFiles(fqdn, b)
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return "", err
	}

	fresh, err := m.issuer.Issue(ctx, fqdn)
	if err != nil {
		return "", fmt.Errorf("xin cert %s qua %s: %w", fqdn, m.issuer.Name(), err)
	}
	fresh.FQDN = fqdn
	if fresh.IssuedAt.IsZero() {
		fresh.IssuedAt = m.now()
	}
	if err := m.save(ctx, ref, fresh); err != nil {
		return "", err
	}
	if err := m.writeFiles(fqdn, fresh); err != nil {
		return "", err
	}
	if err := m.st.SetDomainCertRef(ctx, fqdn, ref); err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	m.event(ctx, "cert.issued", fqdn, map[string]any{
		"issuer": m.issuer.Name(), "not_after": fresh.NotAfter,
	})
	return ref, nil
}

func (m *Manager) load(ctx context.Context, ref string) (Bundle, error) {
	var b Bundle
	raw, err := m.st.GetSecret(ctx, ref)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		// Bundle hỏng coi như CHƯA CÓ: xin lại rẻ hơn nhiều so với để một
		// instance kẹt vĩnh viễn vì một byte lỗi.
		return Bundle{}, store.ErrNotFound
	}
	return b, nil
}

func (m *Manager) save(ctx context.Context, ref string, b Bundle) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return m.st.PutSecret(ctx, ref, raw)
}

// writeFiles ghi cert/key xuống paths.ProxyCerts() cho gateway đọc.
//
// Ghi tạm rồi rename: gateway có thể đang đọc đúng lúc ta ghi, và một file cert
// đọc dở là cert không parse được — nginx sẽ từ chối reload và giữ cấu hình cũ,
// nhưng thông báo lỗi thì chẳng liên quan gì tới nguyên nhân thật.
func (m *Manager) writeFiles(fqdn string, b Bundle) error {
	dir := m.layout.ProxyCerts()
	if err := os.MkdirAll(dir, paths.DirPerm); err != nil {
		return err
	}
	base := SecretRef(fqdn)[len(secretPrefix):]
	for _, f := range []struct {
		name string
		data []byte
	}{
		{base + ".crt", b.CertPEM},
		{base + ".key", b.KeyPEM},
	} {
		if err := writeAtomic(filepath.Join(dir, f.name), f.data); err != nil {
			return err
		}
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, certFileMode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// CertPath / KeyPath — đường dẫn gateway đọc.
func (m *Manager) CertPath(fqdn string) string {
	return filepath.Join(m.layout.ProxyCerts(), SecretRef(fqdn)[len(secretPrefix):]+".crt")
}

func (m *Manager) KeyPath(fqdn string) string {
	return filepath.Join(m.layout.ProxyCerts(), SecretRef(fqdn)[len(secretPrefix):]+".key")
}

func (m *Manager) event(ctx context.Context, action, subject string, data map[string]any) {
	raw, _ := json.Marshal(data)
	_ = m.st.AppendEvent(ctx, action, "certs", subject, raw)
}
