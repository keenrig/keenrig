package catalog_test

import (
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/catalog"
)

// Mọi mục trong danh mục đi kèm binary phải có mô tả ở CẢ HAI ngôn ngữ của sản
// phẩm: `description` (tiếng Anh, mặc định) và `description_vi`.
//
// Có vì lỗi đã lên tới trang bán hàng: trước 2026-10-07 mỗi manifest viết một
// ngôn ngữ tuỳ người viết, nên ảnh động Admin tiếng Anh quay ra thẻ Nginx mô tả
// bằng tiếng Việt. Câu kiểm "trông giống tiếng Việt" bắt luôn trường hợp dán
// nhầm bản vi vào ô en.
func TestEveryBuiltinManifestIsBilingual(t *testing.T) {
	cat, errs := catalog.LoadBuiltin()
	if len(errs) > 0 {
		t.Fatalf("danh mục nhúng có lỗi: %v", errs)
	}
	const viMarks = "ăâđêôơưáàảãạấầẩẫậắằẳẵặéèẻẽẹếềểễệíìỉĩịóòỏõọốồổỗộớờởỡợúùủũụứừửữựýỳỷỹỵ"
	for _, m := range cat.List() {
		if strings.TrimSpace(m.Description) == "" || strings.TrimSpace(m.DescriptionVI) == "" {
			t.Errorf("%s: thiếu description hoặc description_vi", m.ID)
			continue
		}
		if strings.ContainsAny(strings.ToLower(m.Title), viMarks) {
			t.Errorf("%s: title (bản tiếng Anh) chứa chữ tiếng Việt: %q — đặt bản vi vào title_vi", m.ID, m.Title)
		}
		if strings.ContainsAny(strings.ToLower(m.Description), viMarks) {
			t.Errorf("%s: description (bản tiếng Anh) chứa chữ tiếng Việt: %.60q", m.ID, m.Description)
		}
		if !strings.ContainsAny(strings.ToLower(m.DescriptionVI), viMarks) {
			t.Errorf("%s: description_vi không có dấu tiếng Việt nào — có phải dán nhầm bản en? %.60q", m.ID, m.DescriptionVI)
		}
	}
}
