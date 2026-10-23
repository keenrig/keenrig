package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// RebaseDomains dời mọi tên của app đang nằm dưới tên miền gốc CŨ sang tên miền
// gốc MỚI: `shop.<old>` → `shop.<new>`, `<old>` → `<new>`.
//
// Dùng khi cloud đổi tên miền gốc của môi trường — release v0.3.8: app chạy
// ngay trên địa chỉ tạm `*.keenrig.com`, và khi tên miền riêng sẵn sàng thì
// Keenrig tự chuyển app sang. Tên miền khác (khách tự gắn) không bị đụng tới.
//
// Idempotent: app đã dời không còn tên nào dưới `old`, nên gọi lại là không làm
// gì. Đó là điều kiện để instance.Config gọi hàm này TRƯỚC khi ghi tên mới: hỏng
// giữa chừng thì lần sync sau gọi lại và làm tiếp phần còn lại.
func (s *Service) RebaseDomains(ctx context.Context, oldParent, newParent string) error {
	oldP, err := domains.Normalize(oldParent)
	if err != nil {
		return err
	}
	newP, err := domains.Normalize(newParent)
	if err != nil {
		return err
	}
	if oldP == newP {
		return nil
	}
	list, err := s.st.ListApps(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, a := range list {
		raw, changed, err := rebaseDesired(a.Desired, oldP, newP)
		if err != nil {
			errs = append(errs, fmt.Errorf("app %s: %w", a.Slug, err))
			continue
		}
		if !changed {
			continue
		}
		if _, err := s.UpdateDesired(ctx, a.ID, raw); err != nil {
			errs = append(errs, fmt.Errorf("app %s: %w", a.Slug, err))
			continue
		}
		s.event(ctx, "app.domains_rebased", a.ID, map[string]any{"from": oldP, "to": newP})
	}

	// Tên gắn NGOÀI desired (màn Domains của Admin) không đi qua UpdateDesired:
	// dời thẳng trong bảng, giữ vai chính/phụ.
	all, err := s.st.ListAllDomains(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, d := range all {
		to, ok := rebaseName(d.FQDN, oldP, newP)
		if !ok {
			continue
		}
		if err := s.st.DeleteDomain(ctx, d.FQDN); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, err)
			continue
		}
		if err := s.st.AddDomain(ctx, &store.Domain{AppID: d.AppID, FQDN: to, IsPrimary: d.IsPrimary}); err != nil {
			errs = append(errs, fmt.Errorf("moving %s to %s: %w", d.FQDN, to, err))
		}
	}
	return errors.Join(errs...)
}

// rebaseName — tên dưới `old` thì trả tên tương ứng dưới `new`.
func rebaseName(fqdn, oldP, newP string) (string, bool) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	if n == oldP {
		return newP, true
	}
	if strings.HasSuffix(n, "."+oldP) {
		return strings.TrimSuffix(n, oldP) + newP, true
	}
	return "", false
}

// rebaseDesired viết lại `domains` trong desired; mọi trường khác giữ NGUYÊN
// từng byte (json.RawMessage), vì desired là thứ người dùng khai.
func rebaseDesired(desired json.RawMessage, oldP, newP string) (json.RawMessage, bool, error) {
	if len(desired) == 0 {
		return nil, false, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(desired, &m); err != nil {
		return nil, false, err
	}
	rawDoms, ok := m["domains"]
	if !ok {
		return nil, false, nil
	}
	var doms []string
	if err := json.Unmarshal(rawDoms, &doms); err != nil {
		return nil, false, err
	}
	changed := false
	for i, d := range doms {
		if to, ok := rebaseName(d, oldP, newP); ok {
			doms[i], changed = to, true
		}
	}
	if !changed {
		return nil, false, nil
	}
	b, err := json.Marshal(doms)
	if err != nil {
		return nil, false, err
	}
	m["domains"] = b
	out, err := json.Marshal(m)
	return out, true, err
}
