// Package all import mọi driver proxy để chúng tự đăng ký vào registry.
//
// MỘT chỗ duy nhất liệt kê driver được biên dịch vào binary. Import mù (blank
// import) rải rác trong cmd/ sẽ khiến câu hỏi "bản build này hỗ trợ gateway
// nào?" phải trả lời bằng cách grep cả cây nguồn.
//
// Thêm driver mới = thêm đúng một dòng ở đây và một package dưới driver/.
// Không file nào khác phải sửa: không có switch-case tên driver, không có
// danh sách hằng số song song, không có struct config phải mọc thêm trường.
//
// Dùng: `import _ ".../internal/proxy/driver/all"` trong cmd, rồi gọi
// proxy.OpenFromEnv.
package all

import (
	_ "github.com/keenrig/keenrig/keenrig-node/internal/proxy/driver/caddy"
	_ "github.com/keenrig/keenrig/keenrig-node/internal/proxy/driver/nginx"
)
