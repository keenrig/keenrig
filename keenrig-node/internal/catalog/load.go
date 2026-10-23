package catalog

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	keenrigcatalog "github.com/keenrig-platform/keenrig/keenrig-catalog"
)

// LoadFS nạp mọi *.json trong fsys.
//
// # Một manifest hỏng KHÔNG được làm chết cả danh mục
//
// Trả về (catalog, danh sách lỗi) chứ không phải (nil, err): một file lỗi
// trong danh mục cộng đồng mà làm rỗng toàn bộ danh mục thì một người đóng góp
// gõ nhầm dấu phẩy sẽ làm mọi người khác không cài được gì.
//
// Nhưng lỗi cũng KHÔNG được im lặng — chúng được trả ra để caller ghi log.
// "Bỏ qua file hỏng" mà không nói gì là cách một app biến mất khỏi danh mục và
// không ai biết vì sao.
func LoadFS(fsys fs.FS) (*Catalog, []error) {
	c := New()
	var errs []error

	names, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return c, []error{err}
	}
	// Thứ tự ổn định: Glob không cam kết thứ tự trên mọi filesystem, và với
	// hai id trùng nhau thì "cái nào báo lỗi" sẽ đổi theo từng lần chạy.
	sort.Strings(names)

	for _, name := range names {
		f, err := fsys.Open(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		m, err := Parse(f)
		f.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		// Tên file phải khớp id. Không bắt buộc về mặt kỹ thuật, nhưng lệch
		// nhau nghĩa là `grep -r "id-nào-đó"` không tìm ra file, và đó là thao
		// tác đầu tiên của bất kỳ ai đi sửa một entry.
		if base := strings.TrimSuffix(filepath.Base(name), ".json"); base != m.ID {
			errs = append(errs, fmt.Errorf("%s: the file name does not match id %q", name, m.ID))
			continue
		}
		if err := c.Add(m); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return c, errs
}

// LoadBuiltin nạp danh mục NHÚNG TRONG BINARY.
//
// Không có lời gọi mạng nào (UI-11): một instance mất mạng vẫn cài được app từ
// danh mục này, và máy chủ danh mục không phải là điểm chết của mọi instance.
func LoadBuiltin() (*Catalog, []error) {
	return LoadFS(keenrigcatalog.Manifests())
}

// Load nạp danh mục nhúng, rồi CHỒNG THÊM thư mục ngoài nếu có.
//
// Thứ tự có chủ đích: nhúng trước, ngoài sau, và id trùng thì bản NGOÀI thắng.
// Người vận hành phải ghi đè được một entry họ không tin — nếu bản nhúng luôn
// thắng thì cách duy nhất để sửa một entry là dựng lại binary.
//
// dir rỗng hoặc không tồn tại → chỉ có bản nhúng, KHÔNG phải lỗi: phần lớn
// instance không có danh mục riêng.
func Load(dir string) (*Catalog, []error) {
	c, errs := LoadBuiltin()
	if strings.TrimSpace(dir) == "" {
		return c, errs
	}
	ext, extErrs := LoadFS(os.DirFS(dir))
	if len(extErrs) > 0 {
		// Thư mục không tồn tại là chuyện bình thường, không phải lỗi cần báo.
		for _, e := range extErrs {
			if !errors.Is(e, fs.ErrNotExist) {
				errs = append(errs, e)
			}
		}
	}
	for _, m := range ext.List() {
		c.byID[m.ID] = m // ghi đè có chủ đích
	}
	return c, errs
}

// MustLoad nạp và GHI LOG mọi manifest hỏng, trả danh mục dùng được.
//
// Tên có "Must" nhưng KHÔNG panic: một manifest hỏng không phải lý do để box
// không khởi động được. Cái "must" ở đây là "phải nói ra", không phải "phải chết".
func MustLoad(dir string) *Catalog {
	c, errs := Load(dir)
	for _, err := range errs {
		log.Printf("catalog: skipping malformed manifest: %v", err)
	}
	if c.Len() == 0 {
		log.Printf("catalog: catalog is EMPTY — the install screen will have nothing to offer")
	}
	return c
}

// Icons trả filesystem chứa icon của danh mục NHÚNG.
//
// Đặt ở đây chứ không để tầng api import thẳng keenrig-catalog: khi danh mục
// ngoài (Load(dir)) biết mang theo icon riêng, chỗ chồng hai filesystem lên
// nhau là hàm này — tầng api không phải biết là có mấy nguồn.
//
// Có thể RỖNG. Icon là trang trí; thiếu nó không được làm hỏng việc cài app.
func (c *Catalog) Icons() fs.FS { return keenrigcatalog.Icons() }
