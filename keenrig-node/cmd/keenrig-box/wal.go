package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/addons"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/backup/target"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// BK-03 — hai lệnh đưa WAL ra khỏi máy, và một quyết định về LỊCH.
//
// # Vì sao lịch nằm ngoài binary
//
// `ship` được thiết kế để chạy theo chu kỳ, và chu kỳ đó CHÍNH LÀ RPO của hệ
// thống (xem godoc `addons.PITR.ShipWAL`). Nhưng lịch không nằm trong box: nó là
// một systemd timer hoặc một dòng cron, cùng đường mà `backup` đi.
//
// Lý do là ca hỏng: một vòng lặp trong tiến trình box sẽ CHẾT CÙNG box. Đúng lúc
// box gặp sự cố — lúc người ta cần WAL nhất — thì chặng đẩy cũng dừng, và không
// gì báo. Một timer của hệ điều hành sống độc lập với tiến trình nó gọi, và nó
// ghi lại từng lần chạy thất bại vào journal.
//
//	# /etc/systemd/system/keenrig-wal-ship.timer
//	[Timer]
//	OnUnitActiveSec=60
//
// Với chu kỳ 60 giây, RPO đo được trên máy phát triển là ~55 giây — dưới ngưỡng
// 5 phút của gate với biên rộng.

// walPrefix — nơi WAL nằm trên target.
//
// Cố định, không thành cờ: một tiền tố gõ tay khác nhau giữa hai lần chạy chia
// chuỗi WAL thành hai nửa không nối lại được, và lỗi đó chỉ lộ ra lúc khôi phục.
const walPrefix = "wal/postgres"

func newWALCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wal",
		Short: "Continuous WAL archiving for the shared PostgreSQL addon (point-in-time recovery)",
	}
	cmd.AddCommand(newWALShipCmd(dataDir), newWALStatusCmd(dataDir))
	return cmd
}

func newWALShipCmd(dataDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "ship",
		Short: "Force a WAL segment switch and upload every archived segment to the backup target",
		Long: "Run this on a timer. The interval is the platform's RPO: anything committed " +
			"since the last run is still only on this machine. Requires " +
			target.EnvDriver + " and " + target.EnvConfig + ".",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWALShip(cmd.Context(), *dataDir)
		},
	}
}

func runWALShip(ctx context.Context, dataDir string) error {
	// KHÔNG cần passphrase, và điều đó là có chủ đích.
	//
	// Segment WAL đi lên nguyên dạng: `restore_command` của postgres là một lệnh
	// `cp` chạy TRONG container lúc khôi phục, và nó không biết giải mã. Bọc thêm
	// một lớp mã hoá ở đây nghĩa là phải có một lớp giải mã ở chặng khôi phục —
	// đúng lúc hệ thống đang hỏng và đường giải mã chưa được chứng minh.
	//
	// Cái phải nói thẳng: WAL trên target KHÔNG được mã hoá, khác với snapshot
	// của BK-02. Nó chứa mọi thay đổi dữ liệu của mọi app dùng chung cụm, nên
	// target phải là nơi đã được bảo vệ ở tầng lưu trữ (bucket riêng, SSE bật).
	tg, err := target.OpenFromEnv(ctx, os.LookupEnv)
	if err != nil {
		return backupEnvHint(err)
	}

	p, closeFn, err := walProvisioner(dataDir)
	if err != nil {
		return err
	}
	defer closeFn()

	pitr, err := walPITR(ctx, p)
	if err != nil {
		return err
	}

	start := time.Now()
	got, err := pitr.ShipWAL(ctx, tg, walPrefix)
	if err != nil {
		return walAddonHint(err)
	}
	fmt.Printf("shipped %d segments (%d bytes) to %s in %s; newest is %s\n",
		got.Segments, got.Bytes, tg.Name(), time.Since(start).Round(time.Millisecond), got.Newest)
	return nil
}

func newWALStatusCmd(dataDir *string) *cobra.Command {
	return &cobra.Command{
		Use:          "status",
		Short:        "Show whether continuous archiving is on and whether it is failing",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWALStatus(cmd.Context(), *dataDir)
		},
	}
}

func runWALStatus(ctx context.Context, dataDir string) error {
	p, closeFn, err := walProvisioner(dataDir)
	if err != nil {
		return err
	}
	defer closeFn()

	pitr, err := walPITR(ctx, p)
	if err != nil {
		return err
	}
	st, err := pitr.ArchiveStatus(ctx)
	if err != nil {
		return walAddonHint(err)
	}
	fmt.Printf("archiving:     %v\n", st.Enabled)
	fmt.Printf("switch every:  %s\n", st.Timeout)
	fmt.Printf("last archived: %s\n", orNone(st.LastArchived))
	fmt.Printf("failures:      %d\n", st.FailedCount)

	// Hai câu này là toàn bộ lý do lệnh `status` tồn tại: cả hai trạng thái đều
	// IM LẶNG trên một hệ thống trông khoẻ mạnh, và cả hai đều làm mất dữ liệu.
	if !st.Enabled {
		return fmt.Errorf("continuous archiving is OFF: point-in-time recovery is not possible, " +
			"and every base backup taken in this state is unrestorable past its own timestamp")
	}
	if st.FailedCount > 0 {
		return fmt.Errorf("the archive command has failed %d times: WAL is piling up on the data disk "+
			"and PostgreSQL will stop the cluster when that disk fills", st.FailedCount)
	}
	return nil
}

// walPITR lấy năng lực PITR của postgres, hoặc một lỗi nói được nguyên nhân.
func walPITR(ctx context.Context, p *addons.Provisioner) (addons.PITR, error) {
	pitr, err := p.PITR(ctx, addons.KindPostgres)
	if err != nil {
		return nil, walAddonHint(err)
	}
	if pitr == nil {
		return nil, fmt.Errorf("the postgres addon does not support point-in-time recovery in this build")
	}
	return pitr, nil
}

// walAddonHint dịch lỗi "không có container" thành câu người vận hành hiểu.
//
// Container postgres chỉ được dựng khi app ĐẦU TIÊN xin một database. Trên một
// máy chưa có app nào như thế, lỗi thô là `No such container: su-infra-postgres`
// — đúng về kỹ thuật và vô nghĩa với người đọc, vì nó gợi ý một thứ đã hỏng
// trong khi thật ra chưa có gì để hỏng.
func walAddonHint(err error) error {
	if err == nil || !strings.Contains(err.Error(), "No such container") {
		return err
	}
	return fmt.Errorf("the shared PostgreSQL addon is not running on this machine: "+
		"no app has requested a database yet, so there is no WAL to ship (%w)", err)
}

func orNone(s string) string {
	if s == "" {
		return "(none yet)"
	}
	return s
}

// walProvisioner mở store + provisioner cho một lệnh chạy tay.
//
// Cùng phép kiểm tồn tại như `backup`, và vì cùng lý do: `store.Open` trên một
// thư mục không có instance trả về "out of memory (14)", một thông báo nói sai
// hoàn toàn chuyện đang xảy ra.
func walProvisioner(dataDir string) (*addons.Provisioner, func(), error) {
	layout := paths.New(dataDir)
	if _, err := os.Stat(layout.DB()); err != nil {
		return nil, nil, fmt.Errorf("no instance database at %s — check --data", layout.DB())
	}
	st, err := store.Open(layout.DB(), layout.MasterKey())
	if err != nil {
		return nil, nil, fmt.Errorf("opening the instance database: %w", err)
	}
	p, err := addonProvisioner(layout, st)
	if err != nil {
		_ = st.Close()
		return nil, nil, err
	}
	return p, func() { _ = st.Close() }, nil
}
