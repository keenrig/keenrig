package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/crypt"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/format"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/snapshot"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target"
	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// Ba lệnh sao lưu, và một quyết định chung: chúng là lệnh RIÊNG chứ không phải
// endpoint của API.
//
// `restore` phải chạy được khi box KHÔNG chạy — đó là toàn bộ ca dùng của nó:
// VPS trắng, chưa có platform.db, chưa có gì để phục vụ một request. Một
// endpoint HTTP đòi tiến trình đang sống và đòi đăng nhập, tức là đòi đúng
// những thứ vừa mất.
//
// `backup` thì ngược lại — nó chạy được cả hai đường, và ở đây nó là lệnh vì
// lịch chạy sao lưu chưa có (jobs.Worker sẽ gọi cùng hàm này ở bước sau).

func newBackupCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Take a full snapshot of this instance and upload it to the backup target",
		Long: "Requires " + target.EnvDriver + ", " + target.EnvConfig + " and " +
			crypt.EnvPassphrase + ". The snapshot always contains instance/master.key, " +
			"so it is always encrypted — there is no way to turn that off.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBackup(cmd.Context(), *dataDir)
		},
	}
	return cmd
}

func runBackup(ctx context.Context, dataDir string) error {
	layout := paths.New(dataDir)
	tg, f, pass, err := openBackupStack(ctx)
	if err != nil {
		return err
	}

	// Kiểm sự TỒN TẠI của platform.db trước khi mở.
	//
	// Không phải kiểm thừa: `store.Open` trên một thư mục chưa có `instance/`
	// trả về `unable to open database file: out of memory (14)` — thông báo của
	// SQLite khi nó không tạo được file, và nó nói sai hoàn toàn chuyện đang xảy
	// ra. Người vận hành gõ sai `--data` sẽ đi tìm lỗi bộ nhớ.
	//
	// Và KHÔNG tự tạo thư mục: `backup` mà tạo ra một instance rỗng rồi sao lưu
	// nó là ghi đè một bản sao lưu tốt bằng một bản trống.
	if _, err := os.Stat(layout.DB()); err != nil {
		return fmt.Errorf("no instance database at %s — check --data (nothing was backed up)", layout.DB())
	}

	// Mở store THẬT: `backup` chạy trên một instance đang sống, và VACUUM INTO
	// phải đi qua chính connection đang phục vụ để có ảnh chụp nhất quán.
	st, err := store.Open(layout.DB(), layout.MasterKey())
	if err != nil {
		return fmt.Errorf("opening the instance database: %w", err)
	}
	defer st.Close()

	apps, err := st.ListApps(ctx)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(apps))
	for _, a := range apps {
		ids = append(ids, a.ID)
	}

	// DumpAddons để nil ở đây, CÓ CHỦ ĐÍCH và được nói ra: dump addon cần
	// provisioner + Docker đang chạy, và đường đó gắn vào jobs.Worker chứ không
	// phải một lệnh chạy tay trên máy có thể đã hỏng Docker. Một snapshot thiếu
	// dump addon vẫn khôi phục được app và cấu hình — nó chỉ không mang theo nội
	// dung database của addon.
	log.Printf("backup: addon dumps are not included by this command yet — app data and instance state are")

	man, err := snapshot.Create(ctx, snapshot.CreateOptions{
		Layout:     layout,
		Store:      st,
		Format:     f,
		Target:     tg,
		Passphrase: pass,
		Apps:       ids,
		WorkDir:    layout.BackupInfo(),
		Now:        time.Now(),
		BoxVersion: readVersion(layout),
		Log:        log.Printf,
	})
	if err != nil {
		return err
	}
	fmt.Printf("snapshot %s: %d parts, %d bytes stored on %s\n",
		man.ID, len(man.Parts), man.TotalStored(), tg.Name())
	return nil
}

func newRestoreCmd(dataDir *string) *cobra.Command {
	var from string
	var only []string
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore this instance from a snapshot on the backup target",
		Long: "Refuses to run when the destination already holds data. There is no force flag: " +
			"remove the directory yourself if you really mean to replace a live instance.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRestore(cmd.Context(), *dataDir, from, only)
		},
	}
	// `--from` nhận ID snapshot, không phải đường dẫn: NƠI lưu đã do
	// KEENRIG_BACKUP_TARGET quy định, và trộn hai thứ vào một cờ là cách người
	// ta gõ một đường dẫn cục bộ rồi tưởng đã restore từ S3.
	cmd.Flags().StringVar(&from, "from", "",
		"snapshot id to restore (default: the newest complete snapshot on the target)")
	cmd.Flags().StringSliceVar(&only, "app", nil,
		"restore only these app ids; the instance database is left untouched")
	return cmd
}

func runRestore(ctx context.Context, dataDir, id string, only []string) error {
	layout := paths.New(dataDir)
	tg, f, pass, err := openBackupStack(ctx)
	if err != nil {
		return err
	}
	man, err := snapshot.Restore(ctx, snapshot.RestoreOptions{
		Layout:     layout,
		Target:     tg,
		Format:     f,
		Passphrase: pass,
		ID:         id,
		OnlyApps:   only,
		Log:        log.Printf,
	})
	if err != nil {
		if errors.Is(err, snapshot.ErrInstanceNotEmpty) {
			// Lỗi này dẫn tới một hành động rất cụ thể, nên nói thẳng hành động
			// đó thay vì để người vận hành tự đoán.
			return fmt.Errorf("%w\nnothing was changed. Move %s aside and run the command again",
				err, layout.Base())
		}
		return err
	}
	fmt.Printf("restored snapshot %s (%d parts) into %s\n", man.ID, len(man.Parts), layout.Base())
	fmt.Println("start keenrig-box to let the reconciler bring the apps back up")
	return nil
}

func newBackupListCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "backups",
		Short:        "List complete snapshots on the backup target",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// KHÔNG cần passphrase: manifest để trần chính là để lệnh này chạy
			// được. Xem godoc package snapshot.
			tg, err := target.OpenFromEnv(cmd.Context(), os.LookupEnv)
			if err != nil {
				return backupEnvHint(err)
			}
			all, err := snapshot.List(cmd.Context(), tg)
			if err != nil {
				return err
			}
			if len(all) == 0 {
				fmt.Printf("no complete snapshot on %s\n", tg.Name())
				return nil
			}
			for _, m := range all {
				fmt.Printf("%s  %d parts  %10d bytes  %s\n",
					m.ID, len(m.Parts), m.TotalStored(), m.CreatedAt.Format(time.RFC3339))
			}
			return nil
		},
	}
}

// openBackupStack mở cả ba lớp và gộp phần hướng dẫn cấu hình vào MỘT chỗ.
//
// Ba biến môi trường, ba lỗi khác nhau, và cả ba đều hay bị quên cùng lúc trên
// một máy mới. Nói rõ thiếu cái nào ngay lần chạy đầu rẻ hơn nhiều so với để
// người ta chạy ba lần.
func openBackupStack(ctx context.Context) (target.Target, format.Format, string, error) {
	tg, err := target.OpenFromEnv(ctx, os.LookupEnv)
	if err != nil {
		return nil, nil, "", backupEnvHint(err)
	}
	f, err := format.OpenFromEnv(os.LookupEnv)
	if err != nil {
		return nil, nil, "", err
	}
	pass, err := crypt.PassphraseFromEnv(os.LookupEnv)
	if err != nil {
		return nil, nil, "", backupEnvHint(err)
	}
	return tg, f, pass, nil
}

func backupEnvHint(err error) error {
	switch {
	case errors.Is(err, target.ErrNotConfigured):
		return fmt.Errorf("%w\nset %s=dir|s3 and %s=<dsn> (there is no default: a wrong default would write the backup to the disk that is about to die)",
			err, target.EnvDriver, target.EnvConfig)
	case errors.Is(err, crypt.ErrNoPassphrase):
		return fmt.Errorf("%w\nset %s. The snapshot contains instance/master.key, so it is always encrypted. Losing this passphrase means losing every backup",
			err, crypt.EnvPassphrase)
	default:
		return err
	}
}

// readVersion đọc VERSION để ghi vào manifest. Thiếu file thì bỏ trống — nó là
// thông tin cho người đọc, không phải thứ restore dựa vào.
func readVersion(l paths.Layout) string {
	b, err := os.ReadFile(l.VersionFile())
	if err != nil {
		return ""
	}
	return string(b)
}
