// Package domains — tầng service cho bảng app_domains.
//
// Trách nhiệm gọn: CHUẨN HOÁ FQDN rồi giao việc chống trùng cho ràng buộc
// UNIQUE ở tầng DB (migration 0004). Package này cố tình KHÔNG tự kiểm trùng
// bằng SELECT-rồi-INSERT: hai request cùng lúc xin một tên miền đều đọc thấy
// "chưa ai dùng" và cả hai cùng ghi. Chỉ có DB mới quyết được ai thắng.
//
// Chuẩn hoá là điều kiện để UNIQUE có nghĩa: SQLite so sánh chuỗi phân biệt
// hoa thường, nên "App.Example.com." và "app.example.com" sẽ lọt qua UNIQUE
// như hai tên khác nhau rồi cùng được đẩy sang gateway.
//
// Bảng app_domains là NGUỒN SỰ THẬT của routing. node/proxy/sites/ chỉ
// là cache dẫn xuất: xoá đi thì tick sau dựng lại từ bảng này (FILESYSTEM.md,
// bất biến 3). Hai vai đó không bao giờ được đảo.
package domains

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// ErrInvalidFQDN — tên miền không dùng được. Trả về ngay ở tầng service để API
// map sang 400 (khác hẳn 409 của "đã có chủ").
var ErrInvalidFQDN = errors.New("domains: invalid fqdn")

// MaxFQDNLen / MaxLabelLen — giới hạn RFC 1035.
const (
	MaxFQDNLen  = 253
	MaxLabelLen = 63
)

// Normalize đưa FQDN về dạng chuẩn: bỏ khoảng trắng, bỏ dấu chấm cuối, hạ về
// chữ thường; rồi kiểm cú pháp.
//
// KHÔNG chấp nhận wildcard (*.example.com) ở đây: một site wildcard trên
// gateway trùm lên mọi subdomain, nên "ai sở hữu tên nào" không còn là quan hệ
// 1-1 mà UNIQUE(fqdn) giả định. Muốn hỗ trợ thì phải thiết kế riêng, không
// phải nới lỏng validate.
func Normalize(fqdn string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(fqdn))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidFQDN)
	}
	if len(s) > MaxFQDNLen {
		return "", fmt.Errorf("%w: %d characters long, the maximum is %d", ErrInvalidFQDN, len(s), MaxFQDNLen)
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: %q has no parent domain", ErrInvalidFQDN, s)
	}
	for _, l := range labels {
		if err := checkLabel(l); err != nil {
			return "", fmt.Errorf("%w: %q — %s", ErrInvalidFQDN, s, err)
		}
	}
	return s, nil
}

func checkLabel(l string) error {
	switch {
	case l == "":
		return errors.New("contains an empty label (consecutive dots)")
	case len(l) > MaxLabelLen:
		return fmt.Errorf("label %q is longer than %d characters", l, MaxLabelLen)
	case l[0] == '-' || l[len(l)-1] == '-':
		return fmt.Errorf("label %q starts or ends with a hyphen", l)
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		isAlnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !isAlnum && c != '-' {
			return fmt.Errorf("label %q contains the invalid character %q", l, string(c))
		}
	}
	return nil
}

type Service struct{ st store.Store }

func New(st store.Store) *Service { return &Service{st: st} }

// Add gắn FQDN vào app. Trả ErrInvalidFQDN (400), store.ErrConflict (409 — đã
// có chủ hoặc app đã có domain chính khác), store.ErrNotFound (404 — app lạ).
func (s *Service) Add(ctx context.Context, appID, fqdn string, primary bool) (*store.Domain, error) {
	norm, err := Normalize(fqdn)
	if err != nil {
		return nil, err
	}
	d := &store.Domain{AppID: appID, FQDN: norm, IsPrimary: primary}
	if err := s.st.AddDomain(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Service) List(ctx context.Context, appID string) ([]*store.Domain, error) {
	return s.st.ListDomains(ctx, appID)
}

func (s *Service) ListAll(ctx context.Context) ([]*store.Domain, error) {
	return s.st.ListAllDomains(ctx)
}

// Remove gỡ FQDN. Chuẩn hoá trước khi xoá — người gọi gõ hoa thường tuỳ ý
// nhưng trong DB chỉ có một dạng.
func (s *Service) Remove(ctx context.Context, fqdn string) error {
	norm, err := Normalize(fqdn)
	if err != nil {
		return err
	}
	return s.st.DeleteDomain(ctx, norm)
}

// Sync đưa tập domain của app về ĐÚNG want (level-triggered, giống proxy.Apply).
//
// Vì sao level-triggered: desired.domains là thứ người dùng khai, và PATCH
// desired gửi cả tập chứ không gửi delta. Nhận delta ở đây sẽ buộc API phải
// tính hiệu giữa hai lần khai — đúng chỗ dễ sinh domain mồ côi khi request lỗi
// giữa chừng.
//
// Phần tử ĐẦU TIÊN của want là domain chính. Trả lỗi thì KHÔNG rollback phần
// đã làm: caller (apps.Service) chạy trong cùng luồng với UpdateDesired và sẽ
// trả lỗi lên API; lần PATCH sau vẫn hội tụ vì hàm này idempotent.
func (s *Service) Sync(ctx context.Context, appID string, want []string) error {
	norm := make([]string, 0, len(want))
	seen := map[string]bool{}
	for _, w := range want {
		n, err := Normalize(w)
		if err != nil {
			return err
		}
		if seen[n] {
			return fmt.Errorf("%w: %q declared twice", ErrInvalidFQDN, n)
		}
		seen[n] = true
		norm = append(norm, n)
	}

	have, err := s.st.ListDomains(ctx, appID)
	if err != nil {
		return err
	}
	haveSet := make(map[string]*store.Domain, len(have))
	for _, d := range have {
		haveSet[d.FQDN] = d
	}

	// Xoá TRƯỚC khi thêm: đổi domain chính từ a → b mà thêm trước sẽ đụng
	// partial unique index "một primary mỗi app" và hỏng ở giữa.
	for _, d := range have {
		if !seen[d.FQDN] {
			if err := s.st.DeleteDomain(ctx, d.FQDN); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			delete(haveSet, d.FQDN)
		}
	}
	// Domain giữ lại nhưng đổi vai (chính ↔ phụ) phải dựng lại row, vì cờ
	// primary nằm dưới một partial unique index. Giữ lại cert_ref khi dựng lại:
	// mất nó sẽ khiến module certs tưởng domain chưa có chứng chỉ và đi xin
	// lại từ đầu — tốn một lượt ACME cho một thay đổi thuần sổ sách.
	keepCert := map[string]string{}
	for i, n := range norm {
		d, ok := haveSet[n]
		if !ok || d.IsPrimary == (i == 0) {
			continue
		}
		keepCert[n] = d.CertRef
		if err := s.st.DeleteDomain(ctx, n); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		delete(haveSet, n)
	}
	for i, n := range norm {
		if _, ok := haveSet[n]; ok {
			continue
		}
		d := &store.Domain{AppID: appID, FQDN: n, IsPrimary: i == 0, CertRef: keepCert[n]}
		if err := s.st.AddDomain(ctx, d); err != nil {
			return err
		}
	}
	return nil
}
