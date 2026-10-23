// Package buildinfo — version của bản build, MỘT chỗ cho cả ba binary.
//
// # Vì sao là biến, nạp lúc build
//
// Trước đây keenrig-box, keenrig-agent và keenrig-ota mỗi binary viết cứng
// "0.0.1-m0" của riêng mình. OTA so version trong
// manifest.json với version box báo qua /version và SyncRequest — ba hằng số
// tự gõ tay thì ngay lần phát hành đầu đã có một cái quên đổi, và ota sẽ thấy
// "chưa lên bản mới" trên một box đã lên rồi, rồi rollback nó.
//
// Nạp bằng MỘT cờ cho cả ba (build-release.sh):
//
//	go build -ldflags "-X github.com/keenrig/keenrig/keenrig-node/internal/buildinfo.Version=0.2.0"
//
// Phải là `var`: `-X` không ghi được vào `const`, và sẽ IM LẶNG bỏ qua.
package buildinfo

// Version — semver của bản build. Mặc định "0.0.0-dev": bản build tay không
// bao giờ được trông giống một bản phát hành, và mọi bản phát hành đều lớn hơn
// nó nên ota luôn chịu nâng một box chạy bản dev.
var Version = "0.0.0-dev"

// LDFlag — đường dẫn cho `-X`, để script build và test dùng chung một chuỗi.
const LDFlag = "github.com/keenrig/keenrig/keenrig-node/internal/buildinfo.Version"
