// Command keenrig-ota — tiến trình #4 phía instance (V2-DELTA §2.1).
//
// TRÁCH NHIỆM, đúng thứ tự: verify chữ ký Ed25519 của bản phát hành → gọi
// `POST /node/v1/drain` để box ngừng nhận việc mới → thay `bin/` → health check →
// rollback về `bin-previous` nếu đỏ. State máy ở `node/update/state.json`;
// nó chỉ được ghi `node/update/` và `bin/`, đọc `VERSION`, KHÔNG mở `platform.db`
// (Luật 5, FILESYSTEM.md).
//
// Vì sao là tiến trình riêng: một tiến trình không thể thay thế đáng tin cậy chính binary
// nó đang chạy. Hệ quả ngược lại (câu hỏi mở §10.4): ota không tự update được chính nó —
// nên nó phải NHỎ và ít thay đổi; đừng nhét thêm việc vào đây.
//
// Chữ ký là bắt buộc, không phải tuỳ chọn: checksum chống file hỏng, KHÔNG chống server
// phát hành bị chiếm — kẻ kiểm soát server cũng đặt được sha256 tuỳ ý. Bản thiếu
// `signature`/`key_id` hoặc chữ ký sai phải bị TỪ CHỐI kể cả khi sha256 khớp (V2-DELTA §4.3,
// OT-01). `min_upgradable_from` thấp hơn bản hiện tại thì phải đi qua bản trung gian (OT-06).
//
// `drain` trả 503 (hết timeout mà còn việc chạy) → HUỶ update, gọi `resume`, KHÔNG thay
// `bin/` (OT-02). `bin-previous/` cố ý nằm cùng filesystem với `bin/` vì rollback là
// `rename`, mà `rename` chỉ nguyên tử khi cùng filesystem (FILESYSTEM.md).
//
// Luật 7: `/healthz` + `/readyz` + `/metrics` trên MỌI tiến trình.
// Gate liên quan: OT-01 (từ chối bản không ký), OT-02 (huỷ khi drain 503), OT-03 (app
// không downtime xuyên suốt update — gateway là tiến trình riêng nên box restart không
// đụng kết nối khách), OT-04 (health đỏ → rollback + báo cloud), OT-05 (rollback sau
// migration expand–contract), OT-06 (min_upgradable_from), OT-07 (kill giữa lúc rename
// `bin` → khởi động lại tự nhận trạng thái dở và hoàn tất/hoàn tác), LS-04 (cửa sổ OTA
// không sinh Apply đôi — dựa vào lease của box, không phải vào timing).
//
// Trạng thái: phần XÁC MINH đã có (UP-01) ở `internal/release` và dùng được
// qua lệnh con `verify`. Phần drain → thay `bin/` → rollback vẫn thuộc M5.
package main

import (
	"github.com/keenrig/keenrig/keenrig-node/internal/buildinfo"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keenrig/keenrig/keenrig-node/internal/metrics"
	"github.com/keenrig/keenrig/keenrig-node/internal/nodeapi"
	"github.com/keenrig/keenrig/keenrig-node/internal/release"
)

// trustedKeys — khoá công khai được TIN, nhúng lúc build.
//
// Rỗng ở đây là CÓ CHỦ ĐÍCH cho tới khi hạ tầng phát hành tồn tại: keyring rỗng
// nghĩa là không tin ai, và `verify` từ chối mọi bản. Đó là trạng thái đúng —
// một khoá giữ chỗ sẽ biến "chưa cấu hình" thành "tin nhầm", và không ai phát
// hiện ra cho tới khi có người khai thác nó.
//
// Cách nạp lúc build:
//
//	go build -ldflags "-X main.releaseKeyB64=<base64> -X main.releaseKeyID=<id>"
var (
	releaseKeyID  string
	releaseKeyB64 string
)

func keyring() (release.Keyring, error) {
	ring := release.Keyring{}
	if releaseKeyID == "" || releaseKeyB64 == "" {
		return ring, nil // rỗng = không tin ai
	}
	return ring, ring.Add(releaseKeyID, releaseKeyB64)
}

// version phải TRÙNG chuỗi của keenrig-box và keenrig-agent (V2-DELTA §6) — cả ba đọc
// internal/buildinfo, nạp lúc build.
var version = buildinfo.Version

const process = "keenrig-ota"

func main() {
	var httpAddr string

	root := &cobra.Command{
		Use:           "keenrig-ota",
		Short:         "Keenrig instance updater — verifies signatures, drains, replaces bin/, rolls back",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serve(httpAddr)
		},
	}
	root.Flags().StringVar(&httpAddr, "http", "127.0.0.1:8082", "address serving healthz/readyz/metrics")
	root.Version = version
	root.SetVersionTemplate("keenrig-ota " + version + "\n")
	root.AddCommand(verifyCmd())

	if err := root.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func serve(addr string) error {
	// Dùng CHUNG nodeapi + metrics với box: ba binary phải cùng một quy ước
	// tên metric và cùng hình dạng /healthz, /readyz, /version. Ba bản tự viết
	// sẽ trôi khỏi nhau ngay lần sửa đầu tiên, và lúc đó dashboard nào cũng chỉ
	// đúng cho một tiến trình.
	//
	// Store = nil: tiến trình này KHÔNG mở platform.db (Luật 5, ND-05).
	// Lifecycle = nil: chỉ box mới có vòng lặp để drain.
	// metrics.Default, KHÔNG phải registry mới — xem ghi chú cùng chỗ ở
	// cmd/keenrig-box: một registry riêng làm /metrics phơi ra thứ mà code thật
	// không ghi vào, và không có gì đỏ để lần ra.
	reg := metrics.Default
	reg.SetProcessInfo(process, version)
	h := nodeapi.New(nodeapi.Options{
		Version: nodeapi.Version{Process: process, Version: version},
		Metrics: reg,
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("%s %s: http=%s (M5 scaffold — update not implemented yet)", process, version, addr)
	return srv.ListenAndServe()
}
