// Package all — import trắng mọi driver runtime để chúng tự đăng ký.
//
// Tồn tại vì cùng lý do với proxy/driver/all: main chỉ nên biết TÊN driver
// (đọc từ env), không nên biết package nào hiện thực nó. Thêm driver thứ tư =
// thêm một dòng ở đây, không sửa main.
//
// Driver docker là mã AGPL và luôn có mặt. swarm/k8s nằm dưới proprietary/
// (licence thương mại) và được nạp ở all_proprietary.go — build với
// `-tags oss` để ra binary chỉ gồm mã AGPL.
package all

import (
	_ "github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime/driver/docker"
)
