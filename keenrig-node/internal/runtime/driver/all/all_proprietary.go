//go:build !oss

// Driver swarm (bậc Pro) và k8s (bậc Enterprise) — mã dưới proprietary/,
// licence thương mại, xem proprietary/LICENSE. Bỏ file này khỏi build bằng
// `-tags oss`: box vẫn chạy đủ ở runtime docker, chỉ không có hai driver này.
package all

import (
	_ "github.com/keenrig/keenrig/keenrig-node/proprietary/runtime/k8s"
	_ "github.com/keenrig/keenrig/keenrig-node/proprietary/runtime/swarm"
)
