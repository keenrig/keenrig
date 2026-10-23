// Command keenrig-agent — tiến trình #3 phía instance (V2-DELTA §2.1).
//
// TRÁCH NHIỆM: thu metric/log của instance rồi đẩy lên cloud qua `/agent/v1/sync`
// (outbound-only, jitter + backoff cap 5 phút, tôn trọng `next_poll_ms`/429,
// `Idempotency-Key` cho mọi lần ghi — điều kiện §7.6). State riêng nằm ở
// `node/agent/`, đây là thư mục DUY NHẤT nó được ghi (FILESYSTEM.md).
//
// TUYỆT ĐỐI KHÔNG: mở `platform.db`, không đọc file trong `node/logs/` (Luật 5).
// Mọi dữ liệu app/log lấy qua node API của box tại `node/run/box.sock`
// (`contracts/openapi/node.yaml`), vì node API không trả đường dẫn file — trả path là khoá
// cứng agent vào cùng máy với box vĩnh viễn (Luật 6).
//
// Tách ra tiến trình riêng để backpressure không lan: log shipper nghẽn không được làm
// đứng vòng reconcile của box. Đồ thị gọi là DAG — không ai gọi ngược xuống agent, nên
// khởi động theo thứ tự bất kỳ, box chưa lên thì tự retry (ND-06).
//
// Luật 7: `/healthz` + `/readyz` + `/metrics` trên MỌI tiến trình, không riêng box.
// Gate liên quan: ND-01 (shape `app_statuses` khớp `sync.schema.json#/$defs/AppStatus`),
// ND-02 (log qua HTTP stream), ND-03 (Idempotency-Key trùng → 409), ND-04 (quyền socket),
// ND-05 (agent không giữ file lock nào trên DB), ND-06 (khởi động thứ tự bất kỳ).
//
// Vòng poll đã có (M3): `internal/agent`. Nó CHỈ chạy khi người vận hành khai
// địa chỉ cloud + khoá — không khai thì tiến trình vẫn phục vụ health/metrics và
// không gọi ra ngoài dòng nào. Đó là hình dạng `UI-11` đòi: self-host không cần
// tài khoản cloud, và "không cần" phải đúng nghĩa là KHÔNG CÓ lời gọi nào.
package main

import (
	"context"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/buildinfo"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/agent"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/metrics"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/nodeapi"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/sysmetrics"
)

// version phải TRÙNG chuỗi của keenrig-box và keenrig-ota: sync protocol là hợp đồng chung,
// ba binary cùng repo cùng artifact thì cùng version string (V2-DELTA §6) — nên cả ba
// đọc internal/buildinfo, nạp lúc build.
var version = buildinfo.Version

const process = "keenrig-agent"

// Biến môi trường, KHÔNG phải cờ dòng lệnh.
//
// Khoá API đi qua cờ sẽ nằm trong `ps aux` cho mọi người dùng trên máy đọc, và
// nằm lại trong lịch sử shell. systemd đọc chúng từ EnvironmentFile 0600.
const (
	envCloudURL = "KEENRIG_CLOUD_URL"
	envAPIKey   = "KEENRIG_AGENT_KEY"
	envEnvID    = "KEENRIG_ENV_ID"
	// envDataDir — mount point mà số đo ĐĨA trong metrics_summary phản ánh
	// (OB-05): đo nơi platform.db + volume của app sống, không phải "/" chung
	// chung — hai thứ này khác partition trên mọi VPS gắn block storage.
	envDataDir = "KEENRIG_DATA_DIR"
	// envBoxAddr — địa chỉ node API của box, khi nó KHÔNG nằm ở đường mặc
	// định `<data dir>/node/run/box.sock`.
	//
	// Nhận cả `host:port` và URL đầy đủ, vì trên Windows box rơi về TCP
	// loopback với cổng ngẫu nhiên (đường dev-only) và không có cách nào đoán
	// ra cổng đó từ đây.
	envBoxAddr = "KEENRIG_BOX_ADDR"
)

func main() {
	var httpAddr string

	root := &cobra.Command{
		Use:           "keenrig-agent",
		Short:         "Keenrig instance agent — collects metrics/logs, pushes /agent/v1/sync",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serve(httpAddr)
		},
	}
	root.Flags().StringVar(&httpAddr, "http", "127.0.0.1:8081", "address serving healthz/readyz/metrics")
	root.Version = version
	root.SetVersionTemplate("keenrig-agent " + version + "\n")

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
	reg := metrics.Default
	reg.SetProcessInfo(process, version)
	h := nodeapi.New(nodeapi.Options{
		Version: nodeapi.Version{Process: process, Version: version},
		Metrics: reg,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Vòng poll chạy NỀN, và lỗi của nó KHÔNG được làm tiến trình chết.
	//
	// `AG-08`: cắt cloud bảy ngày thì mọi thứ local nguyên vẹn. Nếu vòng poll
	// kéo cả tiến trình xuống thì `/healthz` cũng mất, và người vận hành mất
	// luôn đường nhìn vào chính cái máy đang có sự cố.
	if base := os.Getenv(envCloudURL); base != "" {
		key := os.Getenv(envAPIKey)
		if key == "" {
			log.Printf("%s: %s is set but %s is missing - skipping the poll loop",
				process, envCloudURL, envAPIKey)
		} else {
			dataDir := os.Getenv(envDataDir)
			if dataDir == "" {
				dataDir = "/var/lib/keenrig"
			}
			// Executor: lệnh từ cloud biến thành lời gọi node API trên box.
			//
			// Cắm LUÔN, không chờ kiểm box có sống hay không: box khởi động
			// sau agent là ca hợp lệ (ND-06), và một executor cắm theo điều
			// kiện sẽ biến thứ tự khởi động thành một trò may rủi. Box chưa
			// lên thì lệnh đầu tiên thất bại kèm lý do đọc được, và lệnh sau
			// chạy bình thường.
			boxAddr := os.Getenv(envBoxAddr)
			if boxAddr == "" {
				boxAddr = paths.New(dataDir).BoxSocket()
			}
			node := agent.NewNodeClient(boxAddr, 0)
			loop := agent.NewLoop(agent.NewClient(base, key, 0), agent.Options{
				EnvID:   os.Getenv(envEnvID),
				Version: version,
				// ND-01: app_statuses lấy NGUYÊN VĂN từ node API và đi cùng
				// heartbeat. Trước đây trường này bị bỏ trống — heartbeat vẫn
				// đi nhưng Console không bao giờ thấy app nào của env.
				Node: node,
				Exec: agent.NewExec(node),
				// OB-05: số đo đi cùng heartbeat. Collector tự nil-hoá từng
				// trường khi không đo được — kể cả toàn bộ — nên nhánh này
				// không có đường làm hỏng vòng poll.
				Metrics: sysmetrics.New(dataDir).Collect,
				// M5: kéo license từ cloud theo nhịp và giao cho box qua node
				// API — agent KHÔNG ghi file license (thư mục ghi duy nhất của
				// nó là node/agent/); box verify rồi tự ghi.
				License: node,
				// Tên miền gốc do cloud chọn đi xuống box qua node API — box
				// chỉ nhận và hiển thị, không API nào trên box đặt được nó.
				Domain: node,
				// Trạng thái pair (AD-12): agent là tiến trình duy nhất biết
				// nó đã pair; báo cho box sau mỗi sync thành công để Admin UI
				// hiện sự thật thay vì "chưa pair" viết cứng.
				CloudLink: node,
				CloudURL:  base,
			})
			go func() {
				if err := loop.Run(ctx); err != nil && ctx.Err() == nil {
					log.Printf("%s: the poll loop stopped: %v", process, err)
				}
			}()
			log.Printf("%s: polling %s every ~%s (box node API: %s)",
				process, base, agent.DefaultInterval, boxAddr)
		}
	} else {
		// Nói ra thay vì im lặng: "agent chạy mà cloud không thấy gì" là triệu
		// chứng khó lần, và nguyên nhân thường chỉ là một biến chưa đặt.
		log.Printf("%s: %s is not configured - running health/metrics only, NO outbound calls",
			process, envCloudURL)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	log.Printf("%s %s: http=%s", process, version, addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
