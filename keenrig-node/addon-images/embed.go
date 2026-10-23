// Package addonimages — bộ image hạ tầng ĐÃ PIN DIGEST, nhúng vào binary.
//
// # Vì sao là một package Go thay vì một file dữ liệu
//
// `go:embed` KHÔNG vượt ra ngoài thư mục của package, nên `cmd/keenrig-box`
// không nhúng được `../../addon-images/infra.json`. Ba đường ra, hai đường sai:
//
//	sai   Chép infra.json sang cmd/ → hai bản, và chúng sẽ trôi khỏi nhau.
//	sai   Đọc từ đĩa lúc chạy → một lần OTA thay binary mà quên thay file sẽ
//	      chạy code mới với image cũ, và INFRA_VERSION nói sai sự thật.
//	đúng  addon-images là package, nhúng file của chính nó.
//
// Cùng lý lẽ đã dẫn tới việc `keenrig-catalog` thành module riêng ở T15.
//
// Tên package không có gạch ngang (Go cấm), tên thư mục thì có — đó là hợp lệ và
// là chuyện thường trong Go.
package addonimages

import _ "embed"

// InfraJSON — nội dung infra.json, khớp contracts/jsonschema/infra.schema.json.
//
//go:embed infra.json
var InfraJSON []byte
