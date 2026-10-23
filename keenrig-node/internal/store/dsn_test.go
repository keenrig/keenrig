package store

// Đường dẫn có ký tự đặc biệt của URI phải mở ĐÚNG file đó.
//
// DSN của SQLite là URI (`file:…?_pragma=…`), nên `#` mở fragment và `?` mở query.
// Nối đường dẫn thô vào làm SQLite mở — và TẠO — một database ở chỗ khác, không
// lỗi, không cảnh báo. Test này bắt đúng cái đó, và nó bắt bằng cách duy nhất
// đáng tin: ghi rồi mở lại ở CÙNG đường dẫn, và kiểm thư mục cha không sinh rác.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenPathWithURISpecialChars(t *testing.T) {
	// `?` và `*` không phải tên thư mục hợp lệ trên Windows, nên chỉ thử `#` và
	// `%` — hai ký tự vừa hợp lệ ở cả hai HĐH, vừa có nghĩa trong URI.
	for _, name := range []string{"co#thang", "co%phantram", "ca#va%hai"} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, name)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			dbPath := filepath.Join(dir, "platform.db")

			st, err := Open(dbPath, filepath.Join(dir, "master.key"))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			ctx := context.Background()
			if err := st.CreateApp(ctx, &App{
				ID: "app-1", Slug: "hop-le", Desired: json.RawMessage(`{}`),
			}); err != nil {
				st.Close()
				t.Fatalf("CreateApp: %v", err)
			}
			st.Close()

			// 1. File phải nằm ĐÚNG chỗ ta yêu cầu.
			if _, err := os.Stat(dbPath); err != nil {
				t.Fatalf("không có database ở đường dẫn đã yêu cầu: %v", err)
			}

			// 2. Và thư mục CHA không được sinh file nào. Đây là khẳng định bắt
			// được lỗi cắt URI: đường dẫn bị cắt tại `#` tạo một file mang tên
			// phần đầu, nằm ở thư mục cha.
			ents, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				if e.Name() != name {
					t.Errorf("sinh rác ở thư mục cha: %q — đường dẫn DSN bị cắt", e.Name())
				}
			}

			// 3. Mở lại phải THẤY dữ liệu vừa ghi. Không có bước này thì test vẫn
			// xanh khi mỗi lần Open trỏ vào một file mới toanh.
			st2, err := Open(dbPath, filepath.Join(dir, "master.key"))
			if err != nil {
				t.Fatalf("mở lại: %v", err)
			}
			defer st2.Close()
			got, err := st2.GetApp(ctx, "app-1")
			if err != nil {
				t.Fatalf("mở lại nhưng không thấy app đã ghi: %v", err)
			}
			if got.Slug != "hop-le" {
				t.Errorf("slug = %q", got.Slug)
			}
		})
	}
}

func TestEscapeDSNPath(t *testing.T) {
	cases := map[string]string{
		"C:/x/y.db":       "C:/x/y.db",
		"C:/a#1/y.db":     "C:/a%231/y.db",
		"C:/a?b/y.db":     "C:/a%3Fb/y.db",
		"C:/100%/y.db":    "C:/100%25/y.db",
		"C:/a%23b/y.db":   "C:/a%2523b/y.db", // `%` phải được escape TRƯỚC
		"/var/lib/sp.db":  "/var/lib/sp.db",
		"/v/a#b?c%d/x.db": "/v/a%23b%3Fc%25d/x.db",
	}
	for in, want := range cases {
		if got := escapeDSNPath(in); got != want {
			t.Errorf("escapeDSNPath(%q) = %q, muốn %q", in, got, want)
		}
	}
}
