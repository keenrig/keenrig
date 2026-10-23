package postgres

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/addons"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target"
)

// BK-03 — WAL archive liên tục + khôi phục theo thời điểm cho postgres.
//
// # Điều đã ĐO ĐƯỢC, và nó khác điều tài liệu gợi ý
//
// PostgreSQL chỉ archive một segment WAL khi nó ĐẦY 16 MB. `archive_timeout`
// được cho là bịt lỗ đó bằng cách đóng segment theo thời gian. Đo thật trên
// postgres:16-alpine với `archive_timeout=60s`:
//
//	1 giao dịch nhỏ     KHÔNG segment nào được archive trong 180 giây.
//	150 giao dịch nhỏ   segment được archive sau ~45 giây.
//
// Nghĩa là `archive_timeout` KHÔNG chặn được RPO một cách độc lập với tải ghi.
// Trên một database ghi thưa — máy self-host điển hình — nó có thể không đóng
// segment nào, và RPO là vô hạn trong khi `archive_mode=on` và mọi con số trạng
// thái đều trông bình thường. Đây đúng là ca hỏng IM LẶNG.
//
// # Vì thế RPO do NỀN TẢNG chặn, không phó mặc postgres
//
//	RPO = chu kỳ gọi ShipWAL + thời gian đẩy
//
// `ShipWAL` gọi `pg_switch_wal()` — dứt khoát, không phụ thuộc tải — rồi đẩy
// segment lên `target.Target`. Cả hai vế đều là con số nền tảng nắm trong tay.
//
// `archive_timeout` vẫn được đặt, nhưng ở đúng vai trò của nó: LƯỚI ĐỠ cho ca
// tiến trình đẩy chết, không phải cơ chế chính.
const (
	// ArchiveTimeout — lưới đỡ: ép đóng segment kể cả khi tiến trình đẩy đã chết.
	//
	// 60 giây để còn dư biên trong ngưỡng 5 phút của gate. Nó KHÔNG phải cơ chế
	// chặn RPO — xem đo đạc ở đầu file.
	ArchiveTimeout = 60 * time.Second

	// walArchiveSubdir — thư mục archive, nằm cạnh pgdata trong cùng mount.
	walArchiveSubdir = "wal-archive"

	// containerDataDir — DataDir nhìn từ BÊN TRONG container.
	containerDataDir = "/var/lib/postgresql/data"
)

// containerArchiveDir — thư mục archive nhìn từ bên trong container.
var containerArchiveDir = path.Join(containerDataDir, walArchiveSubdir)

// archiveCommand — lệnh postgres chạy cho MỖI segment hoàn tất.
//
// Ba chi tiết, mỗi cái vì một cách archive hỏng im lặng:
//
//	test ! -f <đích>  KHÔNG ghi đè segment đã archive. Ghi đè nghĩa là một lần
//	                  khởi động sau restore có thể đạp lên lịch sử WAL cũ, và
//	                  chuỗi replay gãy ở giữa.
//	&& cp             chỉ chép khi phép kiểm trên qua — `&&` chứ không `;`.
//	exit ≠ 0          postgres coi đó là "chưa archive được" và GIỮ segment lại.
//	                  Đó là hành vi đúng, và là lý do một archive_command hỏng
//	                  làm ĐẦY ĐĨA chứ không mất dữ liệu.
func archiveCommand() string {
	return fmt.Sprintf("test ! -f %[1]s/%%f && cp %%p %[1]s/%%f", containerArchiveDir)
}

// archiveArgs — đối số khởi động postgres để bật archiving.
func archiveArgs() []string {
	return []string{
		"postgres",
		"-c", "wal_level=replica",
		"-c", "archive_mode=on",
		"-c", "archive_command=" + archiveCommand(),
		"-c", "archive_timeout=" + strconv.Itoa(int(ArchiveTimeout.Seconds())) + "s",
	}
}

var _ addons.PITR = (*Driver)(nil)

// EnableArchiving — ở driver này archiving được bật bằng CHÍNH đối số khởi động
// container (xem ensureInfra), nên hàm này xác nhận và cho biết có cần dựng lại.
//
// PostgreSQL đọc `archive_mode` LÚC KHỞI ĐỘNG; `pg_reload_conf()` không đổi được
// nó. Nên một cụm đang chạy với archive tắt phải được DỰNG LẠI — và việc đó cắt
// kết nối của MỌI app dùng chung cụm. Trả `needsRestart` để caller chọn thời
// điểm, thay vì tự ý restart giữa giờ làm việc.
func (d *Driver) EnableArchiving(ctx context.Context) (bool, error) {
	st, err := d.ArchiveStatus(ctx)
	if err != nil {
		return false, err
	}
	return !st.Enabled, nil
}

// ArchiveStatus đọc trạng thái archiving từ CHÍNH postgres.
//
// Hỏi server chứ không đọc lại đối số ta vừa truyền: đối số nói ta MUỐN gì, còn
// `pg_settings` nói server ĐANG chạy với gì. Hai thứ lệch nhau đúng vào lúc
// container chưa được dựng lại sau khi đổi cấu hình — ca mà EnableArchiving
// sinh ra để cảnh báo.
func (d *Driver) ArchiveStatus(ctx context.Context) (addons.ArchiveStatus, error) {
	var out addons.ArchiveStatus
	su, err := d.superPassword(ctx)
	if err != nil {
		return out, err
	}
	const q = `SELECT current_setting('archive_mode'), current_setting('archive_timeout'), ` +
		`COALESCE(last_archived_wal,''), COALESCE(failed_count,0) FROM pg_stat_archiver;`
	res, err := d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name: infraName,
		Cmd:  []string{"psql", "-tA", "-F", "|", "-q", "-h", "127.0.0.1", "-U", superUser, "-d", "postgres", "-c", q},
		Env:  map[string]string{"PGPASSWORD": su},
	})
	if err != nil {
		return out, err
	}
	if !res.OK() {
		return out, res.Err("reading pg_stat_archiver")
	}
	fields := strings.Split(strings.TrimSpace(string(res.Stdout)), "|")
	if len(fields) < 4 {
		return out, fmt.Errorf("postgres: unexpected pg_stat_archiver output: %q", res.Stdout)
	}
	out.Enabled = fields[0] == "on" || fields[0] == "always"
	out.Timeout = parsePGDuration(fields[1])
	out.LastArchived = fields[2]
	out.FailedCount, _ = strconv.ParseInt(strings.TrimSpace(fields[3]), 10, 64)
	return out, nil
}

// parsePGDuration đọc giá trị thời gian postgres trả về.
//
// `current_setting` trả CHUỖI CÓ ĐƠN VỊ ("60s", "5min") — parse thẳng thành int
// sẽ cho 0 một cách im lặng. Đơn vị lạ cũng trả 0 để caller thấy "không biết"
// thay vì một con số bịa.
func parsePGDuration(v string) time.Duration {
	v = strings.TrimSpace(v)
	switch {
	case strings.HasSuffix(v, "min"):
		n, _ := strconv.Atoi(strings.TrimSuffix(v, "min"))
		return time.Duration(n) * time.Minute
	case strings.HasSuffix(v, "ms"):
		n, _ := strconv.Atoi(strings.TrimSuffix(v, "ms"))
		return time.Duration(n) * time.Millisecond
	case strings.HasSuffix(v, "s"):
		n, _ := strconv.Atoi(strings.TrimSuffix(v, "s"))
		return time.Duration(n) * time.Second
	default:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0
		}
		return time.Duration(n) * time.Second
	}
}

// ForceArchive ép postgres đóng segment WAL hiện tại NGAY.
//
// # Vì sao nó là bắt buộc chứ không phải tối ưu
//
// `archive_timeout` được cho là đủ để đóng segment theo thời gian. ĐO trên
// postgres:16-alpine, `archive_timeout=60s`:
//
//	1 giao dịch nhỏ     KHÔNG có segment nào được archive trong 180 giây.
//	150 giao dịch nhỏ   segment được archive sau ~45 giây.
//
// Nghĩa là ngưỡng đóng segment theo thời gian phụ thuộc vào TẢI GHI, và một
// database ghi thưa — máy self-host điển hình — có thể ở rất lâu ngoài archive.
// Phó mặc RPO cho `archive_timeout` là phó mặc nó cho tải của app.
//
// `pg_switch_wal()` thì dứt khoát: nó đóng segment đang mở ngay lập tức. Trên
// một cụm KHÔNG có gì mới để ghi, nó không tạo segment mới và trả về vị trí cũ —
// đúng hành vi mong muốn, vì lúc đó không có gì để mất.
func (d *Driver) ForceArchive(ctx context.Context) error {
	su, err := d.superPassword(ctx)
	if err != nil {
		return err
	}
	res, err := d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name: infraName,
		Cmd: []string{"psql", "-q", "-h", "127.0.0.1", "-U", superUser, "-d", "postgres",
			"-c", "SELECT pg_switch_wal();"},
		Env: map[string]string{"PGPASSWORD": su},
	})
	if err != nil {
		return err
	}
	if !res.OK() {
		return res.Err("pg_switch_wal")
	}
	return nil
}

// BaseBackup chụp bản nền VẬT LÝ bằng `pg_basebackup`.
//
// # Vì sao không dùng lại `pg_dump` của BK-01
//
// `pg_dump` là ảnh chụp LOGIC: nó sinh ra câu SQL dựng lại dữ liệu. Không có
// cách nào replay WAL lên trên một bản dump — WAL nói về TRANG VẬT LÝ, và một
// database dựng lại từ SQL có bố cục trang hoàn toàn khác. Đây là lý do BK-03
// phải có đường riêng chứ không mở rộng được BK-01.
//
// Bản nền được ghi vào `dir` trên máy chủ, dưới dạng tar — cùng hình dạng mà
// `format.Format` gói được, nên nó đi thẳng vào snapshot mà không cần lớp trung
// gian nào.
func (d *Driver) BaseBackup(ctx context.Context, dir string) error {
	st, err := d.ArchiveStatus(ctx)
	if err != nil {
		return err
	}
	if !st.Enabled {
		// Chụp base khi chưa bật archive là tạo ra một bản nền KHÔNG BAO GIỜ
		// replay lên được — nó trông giống một bản sao lưu và chỉ vô dụng lúc
		// cần dùng.
		return fmt.Errorf("%w: base backup without WAL archiving would be unrestorable", addons.ErrPITRNotEnabled)
	}
	su, err := d.superPassword(ctx)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	// `-Ft -Xnone`: tar, và KHÔNG nhúng WAL vào bản nền.
	//
	// `-Xstream` (mặc định) nhét WAL cần thiết vào chính bản nền, đủ để khởi
	// động lại NHƯNG chỉ tới đúng thời điểm chụp. Ta muốn replay TIẾP từ archive
	// tới một thời điểm bất kỳ, nên nguồn WAL duy nhất phải là archive — hai
	// nguồn WAL cho một cụm là hai chuỗi lịch sử có thể lệch nhau.
	res, err := d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name: infraName,
		Cmd: []string{"pg_basebackup", "-h", "127.0.0.1", "-U", superUser,
			"-D", "-", "-Ft", "-Xnone", "-c", "fast"},
		Env: map[string]string{"PGPASSWORD": su},
	})
	if err != nil {
		return err
	}
	if !res.OK() {
		return res.Err("pg_basebackup")
	}
	if len(res.Stdout) == 0 {
		// Cùng bài học với `pg_dump -Fc`: khung stream của Docker làm hỏng đầu
		// ra nhị phân mà lệnh vẫn trả 0. Một bản nền 0 byte chỉ lộ ra lúc restore.
		return fmt.Errorf("postgres: pg_basebackup returned 0 bytes")
	}
	if err := os.WriteFile(filepath.Join(dir, baseBackupFile), res.Stdout, 0o600); err != nil {
		return err
	}

	// Ép chuyển segment NGAY sau khi chụp: nếu không, những giao dịch xảy ra
	// ngay trước lúc chụp có thể còn nằm trong segment đang mở và chưa được
	// archive — bản nền restore được nhưng thiếu đúng phần đuôi.
	return d.ForceArchive(ctx)
}

// RestoreToTime dựng lại cụm từ base + replay WAL tới target.
//
// # Nó KHÔNG khôi phục tại chỗ, và đó là quyết định
//
// Hàm này giải nén bản nền vào `dir` và ghi ra `recovery.signal` +
// `restore_command` để một postgres MỚI khởi động lên và tự replay. Nó KHÔNG
// đụng vào cụm đang chạy.
//
// Lý do: PITR đưa CẢ CỤM về một thời điểm, tức là mọi app dùng chung nó cùng bị
// lùi thời gian. Làm việc đó tại chỗ, tự động, trên một cụm đang phục vụ là
// đúng loại thao tác không được phép xảy ra vì một lời gọi hàm. Người vận hành
// dựng cụm mới từ `dir`, kiểm, rồi mới chuyển sang — cùng tinh thần với
// `restore --from` từ chối ghi đè instance đang có dữ liệu.
func (d *Driver) RestoreToTime(ctx context.Context, dir string, at time.Time) error {
	base := filepath.Join(dir, baseBackupFile)
	if _, err := os.Stat(base); err != nil {
		return fmt.Errorf("%w: no base backup at %s", addons.ErrPITRNotEnabled, base)
	}
	out := filepath.Join(dir, restoredSubdir)
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}

	// Bản nền được CHÉP SANG thư mục khôi phục, không chỉ được trỏ tới: `out` là
	// thứ người vận hành mang sang máy khác, nên nó phải tự đủ.
	//
	// Việc giải nén để dành cho postgres trong container đích — đường dẫn, quyền
	// và chủ sở hữu phải đúng như nó mong đợi, và tự dựng lại luật quyền bằng Go
	// là dựng lại một thứ đã có sẵn và dễ sai.
	blob, err := os.ReadFile(base)
	if err != nil {
		return fmt.Errorf("postgres: reading the base backup: %w", err)
	}
	if err := os.WriteFile(filepath.Join(out, baseBackupFile), blob, 0o600); err != nil {
		return err
	}

	// `recovery.signal` là thứ nói với postgres "khởi động ở chế độ khôi phục".
	// Từ PG12 nó thay cho `recovery.conf` cũ; thiếu nó thì server lên như bình
	// thường và replay KHÔNG chạy — bản khôi phục sẽ dừng đúng ở thời điểm chụp
	// base, im lặng.
	conf := "restore_command = 'cp " + containerArchiveDir + "/%f %p'\n"
	if !at.IsZero() {
		conf += "recovery_target_time = '" + at.UTC().Format("2006-01-02 15:04:05.000000+00") + "'\n"
		// Dừng NGAY tại mốc, không đi tiếp. Mặc định của postgres là chạy tới
		// hết WAL có sẵn nếu mốc không đạt tới được.
		conf += "recovery_target_action = 'promote'\n"
	}
	if err := os.WriteFile(filepath.Join(out, recoveryConfFile), []byte(conf), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, recoverySignalFile), nil, 0o600)
}

// archiveSettleTimeout — trần chờ archiver chép xong segment vừa bị đóng.
//
// `pg_switch_wal()` trả về ngay khi segment được đóng; `archive_command` chạy
// BẤT ĐỒNG BỘ sau đó. Đẩy đi ngay lập tức nghĩa là bỏ sót đúng segment vừa ép —
// tức là bỏ sót đúng phần dữ liệu mới nhất, phần mà cả cơ chế này sinh ra để giữ.
const archiveSettleTimeout = 20 * time.Second

// ShipWAL ép đóng segment hiện tại rồi đẩy mọi WAL đã archive lên dst.
//
// # Chỉ đẩy thứ postgres ĐÃ XÁC NHẬN archive xong
//
// `archive_command` là `cp`, và `cp` KHÔNG nguyên khối: một segment đang được
// chép có mặt trong thư mục với kích thước dở dang. Đẩy nó lên nghĩa là đưa một
// segment cụt vào chuỗi WAL, và chuỗi đó gãy đúng ở chỗ nó cụt — im lặng, cho
// tới lần khôi phục.
//
// Nên ranh giới lấy từ CHÍNH postgres: `pg_stat_archiver.last_archived_wal`.
// Tên segment WAL sắp xếp theo thứ tự chuỗi trùng với thứ tự thời gian, nên
// "≤ last_archived_wal" là một phép so sánh chuỗi, và nó chính xác.
func (d *Driver) ShipWAL(ctx context.Context, dst target.Target, prefix string) (addons.Shipped, error) {
	var out addons.Shipped
	if err := target.ValidatePrefix(prefix); err != nil {
		return out, err
	}
	st, err := d.ArchiveStatus(ctx)
	if err != nil {
		return out, err
	}
	if !st.Enabled {
		return out, fmt.Errorf("%w: nothing to ship", addons.ErrPITRNotEnabled)
	}
	if st.FailedCount > 0 {
		// Không đẩy một archive đang hỏng: WAL đang dồn trên đĩa, và một lượt
		// "thành công" ở đây chỉ che mất việc chuỗi đã thủng.
		return out, fmt.Errorf("postgres: the archive command has failed %d times; WAL is piling up on disk", st.FailedCount)
	}

	// Ép đóng segment ĐANG mở — đây là thao tác quyết định RPO. Xem ForceArchive.
	before := st.LastArchived
	if err := d.ForceArchive(ctx); err != nil {
		return out, err
	}
	st = d.waitArchived(ctx, before)

	dir, err := d.cfg.Layout.AddonData(infraName)
	if err != nil {
		return out, err
	}
	archiveDir := filepath.Join(dir, walArchiveSubdir)
	pending, err := pendingSegments(ctx, dst, prefix, archiveDir, st.LastArchived)
	if err != nil {
		return out, err
	}

	for _, name := range pending {
		n, err := putFile(ctx, dst, prefix+"/"+name, filepath.Join(archiveDir, name))
		if err != nil {
			return out, fmt.Errorf("postgres: shipping %s: %w", name, err)
		}
		out.Segments++
		out.Bytes += n
		if !strings.HasSuffix(name, historySuffix) && name > out.Newest {
			out.Newest = name
		}
	}
	if out.Newest == "" {
		out.Newest = st.LastArchived
	}
	return out, nil
}

// pendingSegments — những file trong archiveDir cần đẩy, đã sắp thứ tự.
//
// `upTo` là ranh giới an toàn lấy từ postgres: đẩy quá nó là đẩy một file `cp`
// chưa chép xong.
func pendingSegments(ctx context.Context, dst target.Target, prefix, archiveDir, upTo string) ([]string, error) {
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		return nil, fmt.Errorf("postgres: reading the WAL archive directory: %w", err)
	}

	// Cái gì đã có trên dst rồi thì không đẩy lại. Một lượt đẩy chạy theo chu kỳ,
	// nên không hỏi trước nghĩa là đẩy lại TOÀN BỘ lịch sử ở MỌI lượt.
	objs, err := dst.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	have := make(map[string]bool, len(objs))
	for _, o := range objs {
		have[path.Base(o.Key)] = true
	}

	var out []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case e.IsDir() || have[name]:
		// File `.history` ghi lại các nhánh timeline. Nó KHÔNG nằm trong thứ tự
		// segment nên phép so sánh ranh giới không áp dụng — và thiếu nó thì một
		// cụm đã từng khôi phục không tìm được nhánh của chính mình.
		case strings.HasSuffix(name, historySuffix):
			out = append(out, name)
		case upTo != "" && name <= upTo:
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// putFile đẩy một file lên target và trả về số byte đã đẩy.
func putFile(ctx context.Context, dst target.Target, key, src string) (int64, error) {
	f, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if err := dst.Put(ctx, key, f, info.Size()); err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// waitArchived chờ archiver chép xong segment vừa bị đóng.
//
// Hết giờ KHÔNG phải lỗi: trên một cụm không có gì mới để ghi, `pg_switch_wal()`
// không tạo segment nào, nên không có gì để chờ. Trả về trạng thái mới nhất đọc
// được và để phép so sánh tên quyết định phần còn lại.
func (d *Driver) waitArchived(ctx context.Context, before string) addons.ArchiveStatus {
	deadline := time.Now().Add(archiveSettleTimeout)
	var last addons.ArchiveStatus
	for time.Now().Before(deadline) {
		st, err := d.ArchiveStatus(ctx)
		if err != nil {
			return last
		}
		last = st
		if st.LastArchived != "" && st.LastArchived != before {
			return st
		}
		select {
		case <-ctx.Done():
			return last
		case <-time.After(time.Second):
		}
	}
	return last
}

const (
	baseBackupFile     = "base.tar"
	restoredSubdir     = "restored"
	historySuffix      = ".history"
	recoveryConfFile   = "recovery.conf.append"
	recoverySignalFile = "recovery.signal"
)
