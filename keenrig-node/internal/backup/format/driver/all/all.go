// Package all — import mọi driver format để chúng tự Register.
//
// Cùng mô hình backup/target/driver/all, runtime/driver/all, proxy/driver/all và
// addons/driver/all: main import package này bằng `_`, và không chỗ nào trong core
// biết tên driver cụ thể. Thêm format thứ hai (restic) là thêm MỘT dòng ở đây.
package all

import (
	_ "github.com/keenrig/keenrig/keenrig-node/internal/backup/format/driver/tgz"
)
