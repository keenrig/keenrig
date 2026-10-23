// Package all — import mọi driver target để chúng tự Register.
//
// Cùng mô hình runtime/driver/all, proxy/driver/all và addons/driver/all: main
// import package này bằng `_`, và không chỗ nào trong core biết tên driver cụ thể.
// Thêm target thứ ba (SFTP, cloud-managed) là thêm MỘT dòng ở đây.
package all

import (
	_ "github.com/keenrig-platform/keenrig/keenrig-node/internal/backup/target/driver/dir"
	_ "github.com/keenrig-platform/keenrig/keenrig-node/internal/backup/target/driver/s3"
)
