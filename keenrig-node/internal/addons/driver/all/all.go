// Package all — import mọi driver addon để chúng tự Register.
//
// Cùng mô hình runtime/driver/all và proxy/driver/all: main import package này
// bằng `_`, và không có chỗ nào trong core biết tên driver cụ thể. Thêm addon
// thứ ba là thêm MỘT dòng ở đây, không sửa gì khác.
package all

import (
	_ "github.com/keenrig/keenrig/keenrig-node/internal/addons/driver/postgres"
	_ "github.com/keenrig/keenrig/keenrig-node/internal/addons/driver/redis"
)
