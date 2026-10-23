package catalog_test

import (
	"testing"

	"encoding/json"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/catalog"
)

// MỌI app trong danh mục phải CÀI ĐƯỢC bằng đúng giá trị mặc định của nó.
//
// # Vì sao test này tồn tại
//
// Ngày 2026-09-06 một người dùng bấm cài `whoami` và nhận:
//
//	apps: invalid desired state: at '/resources/memory_mb': minimum: got 32, want 64
//
// Manifest khai `min_memory_mb: 32`, còn `desired.schema.json` đặt hạn dưới 64
// (dưới mức đó không image nào khởi động nổi). Hai con số mâu thuẫn nhau, và
// KHÔNG có gì so chúng — nên một app không cài được vẫn nằm trong danh mục,
// hiện lên giao diện, mời người ta bấm.
//
// Đây là dạng hỏng đắt nhất của một danh mục: nó không hỏng lúc build, không
// hỏng lúc khởi động, chỉ hỏng đúng lúc người dùng thử — và thông báo thì nói
// về JSON Schema chứ không nói "app này khai sai".
//
// # Vì sao kiểm qua ToDesired chứ không so hai con số
//
// So `min_memory_mb >= 64` sẽ bắt được đúng lần này rồi mù với mọi trường khác.
// Dựng nguyên trạng thái mong muốn rồi thả qua chính bộ xác thực mà API dùng thì
// mọi ràng buộc — hiện tại và tương lai — đều được canh, kể cả những ràng buộc
// chưa ai nghĩ ra lúc viết test này.
func TestEveryCatalogAppInstallsWithItsOwnDefaults(t *testing.T) {
	cat, errs := catalog.LoadBuiltin()
	for _, e := range errs {
		t.Fatalf("danh mục nhúng hỏng: %v", e)
	}
	apps := cat.List()
	if len(apps) == 0 {
		t.Fatal("danh mục rỗng — test này sẽ xanh mà không kiểm gì")
	}

	for _, m := range apps {
		t.Run(m.ID, func(t *testing.T) {
			d, err := m.ToDesired(catalog.InstallOptions{})
			if err != nil {
				t.Fatalf("ToDesired: %v", err)
			}
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if err := contracts.ValidateDesired(raw); err != nil {
				t.Errorf("app này nằm trong danh mục nhưng KHÔNG cài được bằng giá trị "+
					"mặc định của chính nó: %v", err)
			}
		})
	}
}
