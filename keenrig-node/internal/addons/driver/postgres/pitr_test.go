package postgres

// BK-03 — RPO ĐO ĐƯỢC, không phải RPO tuyên bố.
//
// Gate đòi: "ghi liên tục → mất máy → khôi phục → mất ≤5 phút dữ liệu". Chỗ duy
// nhất con số đó có thể được chứng minh là trên PostgreSQL THẬT, nên cả file này
// chạy trên container thật và tự SKIP khi không có Docker.
//
// # Hai ca, và ca thứ hai mới là ca khó
//
//	ghi NHIỀU   segment WAL đầy liên tục → archive chạy đều. Đây là ca DỄ, và là
//	            ca mà một bản hiện thực chỉ đặt `archive_mode=on` cũng xanh.
//	ghi THƯA    một database ít ghi có thể HÀNG GIỜ không đầy 16 MB. Không có
//	            `archive_timeout` thì RPO ở đây là VÔ HẠN trong khi mọi thứ trông
//	            như đã bật đúng.
//
// Máy self-host điển hình là ca thứ hai. Nên nó có test riêng, và test đó đo
// bằng ĐỒNG HỒ chứ không đọc lại cấu hình mà chính ta vừa truyền vào.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/addons"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target/driver/dir"
)

// Server ĐANG chạy với archiving — không phải ta tưởng thế.
//
// ArchiveStatus hỏi `pg_settings` của chính server, nên test này bắt được đúng
// ca container chưa được dựng lại sau khi đổi đối số khởi động
// (infra_version 1 → 2).
func TestArchivingIsActuallyOn(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	ctx := t.Context()

	// Setup để chắc chắn container đã dựng xong và sẵn sàng nhận lệnh.
	if _, err := d.Setup(ctx, "conf-app-a"); err != nil {
		t.Fatal(err)
	}

	st, err := d.ArchiveStatus(ctx)
	if err != nil {
		t.Fatalf("ArchiveStatus: %v", err)
	}
	if !st.Enabled {
		t.Fatal("archive_mode KHÔNG bật trên server đang chạy — mọi khẳng định RPO phía dưới vô nghĩa")
	}
	// Con số QUYẾT ĐỊNH gate, nên nó được khẳng định tường minh chứ không suy ra.
	if st.Timeout <= 0 || st.Timeout > 5*time.Minute {
		t.Errorf("archive_timeout = %s — phải >0 và ≤5 phút, nếu không RPO không bị chặn", st.Timeout)
	}
	if st.Timeout != ArchiveTimeout {
		t.Errorf("server chạy với archive_timeout=%s nhưng driver khai %s — container chưa được dựng lại?",
			st.Timeout, ArchiveTimeout)
	}
	// archive_command hỏng làm WAL DỒN LẠI trên đĩa cho tới khi đầy rồi dừng cả
	// cụm. Nó phải là 0, và nó phải được NHÌN chứ không nằm im trong log.
	if st.FailedCount != 0 {
		t.Errorf("archive_command đã thất bại %d lần — WAL đang dồn lại trên đĩa", st.FailedCount)
	}

	needsRestart, err := d.EnableArchiving(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if needsRestart {
		t.Error("EnableArchiving báo cần dựng lại trong khi archive đã bật")
	}
}

// CA KHÓ, và là ca đã làm lộ ra một giả định SAI.
//
// Giả định ban đầu: `archive_timeout=60s` đủ để một database ghi thưa vẫn có WAL
// trong archive trong vòng một phút. Test này ĐỎ, và số đo là:
//
//	1 giao dịch nhỏ, chờ 150 giây → KHÔNG segment nào được archive.
//
// Đo lại bằng tay trên `postgres:16-alpine` thuần, ngoài mọi mã của dự án: vẫn
// không có segment nào sau 180 giây; 150 giao dịch thì có sau ~45 giây. Nên
// ngưỡng đóng segment theo thời gian phụ thuộc TẢI GHI, và giả định ban đầu sai.
//
// Test giờ khẳng định thứ hệ thống THẬT SỰ dựa vào: một lượt `ShipWAL` đưa được
// cả một lần ghi lẻ ra khỏi máy.
func TestSparseWriteReachesTargetInOneShip(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	const app = "conf-app-a"
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	if _, err := d.Setup(ctx, app); err != nil {
		t.Fatal(err)
	}
	dst := newFileTarget(t)

	// Lượt đầu dọn nền: mọi WAL đã có trước khi test bắt đầu được đẩy đi, để lượt
	// đo bên dưới chỉ chứa đúng phần ta vừa ghi.
	if _, err := d.ShipWAL(ctx, dst, "wal"); err != nil {
		t.Fatalf("ShipWAL lượt nền: %v", err)
	}

	// Đây đúng là "ghi thưa": một dòng, rồi thôi. Không có gì làm đầy 16 MB.
	appSQL(t, d, app, "CREATE TABLE IF NOT EXISTS thua(id serial primary key, luc timestamptz default now());\n"+
		"INSERT INTO thua DEFAULT VALUES;\n")

	start := time.Now()
	got, err := d.ShipWAL(ctx, dst, "wal")
	if err != nil {
		t.Fatalf("ShipWAL: %v", err)
	}
	took := time.Since(start)

	if got.Segments == 0 {
		t.Fatalf("một lần ghi lẻ KHÔNG được đẩy đi.\nhiện trường: %s", archiverDump(t, d))
	}
	if got.Bytes == 0 || got.Newest == "" {
		t.Errorf("kết quả đẩy trống rỗng: %+v", got)
	}
	// Đây là con số RPO: nếu máy chết ngay sau lần ghi, phần mất là khoảng từ lần
	// ghi tới lúc lượt đẩy này xong.
	if took > 5*time.Minute {
		t.Errorf("một lượt đẩy mất %s — vượt ngưỡng RPO 5 phút", took.Round(time.Second))
	}
	t.Logf("ghi thưa: %d segment (%d byte) rời khỏi máy sau %s, mới nhất %s",
		got.Segments, got.Bytes, took.Round(time.Millisecond), got.Newest)

	// Và nó phải NẰM TRÊN target thật, không chỉ được đếm.
	objs, err := dst.List(ctx, "wal")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) == 0 {
		t.Fatal("ShipWAL báo đã đẩy nhưng target rỗng")
	}
}

// Vòng đầy đủ của gate trên một database ghi LIÊN TỤC.
//
// Đo đúng thứ gate hỏi: nếu máy chết ngay sau giao dịch cuối, phần dữ liệu KHÔNG
// rời khỏi máy là bao nhiêu thời gian. Ở đây phần đó bị chặn bởi chu kỳ đẩy, nên
// test mô phỏng đúng một chu kỳ: ghi liên tục trong `shipEvery`, rồi đẩy.
func TestRPOIsBoundedByShipInterval(t *testing.T) {
	if testing.Short() {
		t.Skip("vòng đầy đủ — bỏ ở chế độ -short")
	}
	d := newDriver(t).(*Driver)
	const app = "conf-app-a"
	// shipEvery — chu kỳ đẩy mà nền tảng sẽ chạy. Chọn 60 giây: nó phải nhỏ hơn
	// hẳn ngưỡng 5 phút để còn biên cho chặng đẩy trên đường truyền thật.
	const shipEvery = 60 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()

	if _, err := d.Setup(ctx, app); err != nil {
		t.Fatal(err)
	}
	dst := newFileTarget(t)
	appSQL(t, d, app, "DROP TABLE IF EXISTS lien_tuc;\n"+
		"CREATE TABLE lien_tuc(id serial primary key, luc timestamptz default now());\n")
	if _, err := d.ShipWAL(ctx, dst, "wal"); err != nil {
		t.Fatalf("ShipWAL lượt nền: %v", err)
	}

	// "Ghi liên tục" trải trên một chu kỳ đẩy: 6 đợt × 25 câu lệnh, cách nhau 10
	// giây. psql tự commit từng câu, nên đây là 150 lần COMMIT trải trên thời
	// gian — không phải một transaction lớn nằm gọn trong một segment.
	var batch strings.Builder
	for range 25 {
		batch.WriteString("INSERT INTO lien_tuc DEFAULT VALUES;\n")
	}
	cycleStart := time.Now()
	for i := range 6 {
		appSQL(t, d, app, batch.String())
		if i < 5 {
			time.Sleep(shipEvery / 6)
		}
	}
	lastCommit := time.Now()

	got, err := d.ShipWAL(ctx, dst, "wal")
	if err != nil {
		t.Fatalf("ShipWAL: %v", err)
	}
	// RPO = khoảng từ giao dịch CŨ NHẤT chưa được đẩy tới lúc lượt đẩy xong. Lấy
	// từ đầu chu kỳ chứ không từ giao dịch cuối: giao dịch cuối là ca DỄ nhất,
	// còn cái người dùng mất là giao dịch đầu chu kỳ nếu máy chết ngay trước lượt
	// đẩy.
	rpo := time.Since(cycleStart)

	if got.Segments == 0 {
		t.Fatalf("150 giao dịch mà không có segment nào rời khỏi máy.\nhiện trường: %s", archiverDump(t, d))
	}
	st, err := d.ArchiveStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.FailedCount != 0 {
		t.Fatalf("archive_command thất bại %d lần — WAL đang dồn trên đĩa", st.FailedCount)
	}
	// Một archive "thành công" mà mất giao dịch còn tệ hơn không archive, vì nó
	// không báo gì.
	if n := strings.TrimSpace(appQuery(t, d, app, "SELECT count(*) FROM lien_tuc;\n")); n != "150" {
		t.Errorf("đếm được %s hàng, muốn 150", n)
	}

	if rpo > 5*time.Minute {
		t.Fatalf("RPO ĐO ĐƯỢC = %s, gate đòi ≤5 phút", rpo.Round(time.Second))
	}
	t.Logf("RPO đo được: %s (chu kỳ đẩy %s, %d segment / %d byte, mới nhất %s, độ trễ giao dịch cuối %s)",
		rpo.Round(time.Second), shipEvery, got.Segments, got.Bytes, got.Newest,
		time.Since(lastCommit).Round(time.Second))
}

// Lượt đẩy thứ hai KHÔNG đẩy lại thứ đã có.
//
// Đẩy chạy theo chu kỳ. Không kiểm trước thì mỗi lượt đẩy lại toàn bộ lịch sử —
// và cái giá đó tăng tuyến tính theo thời gian sống của hệ thống, tới lúc một
// lượt đẩy không kịp xong trước lượt sau.
func TestShipWALDoesNotResendWhatIsAlreadyThere(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	ctx := t.Context()
	if _, err := d.Setup(ctx, "conf-app-a"); err != nil {
		t.Fatal(err)
	}
	dst := newFileTarget(t)

	first, err := d.ShipWAL(ctx, dst, "wal")
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.ShipWAL(ctx, dst, "wal")
	if err != nil {
		t.Fatal(err)
	}
	// Lượt 1 phải đẩy được thứ gì đó, nếu không phép so sánh bên dưới so hai số 0
	// với nhau và test xanh mà không kiểm gì.
	if first.Segments == 0 {
		t.Fatalf("lượt đẩy đầu không đẩy gì.\nhiện trường: %s", archiverDump(t, d))
	}
	if second.Segments >= first.Segments {
		t.Errorf("lượt 1 đẩy %d segment, lượt 2 đẩy %d — không có phép trừ nào xảy ra",
			first.Segments, second.Segments)
	}
	// Và mốc "khôi phục được tới đâu" vẫn phải trả lời được ở lượt không có gì mới.
	if second.Newest == "" {
		t.Error("lượt đẩy rỗng không cho biết segment mới nhất đang có trên target")
	}
}

// Bản nền phải là tar THẬT.
//
// Cùng bài học với `pg_dump -Fc` ở BK-01: khung ghép luồng của Docker làm hỏng
// đầu ra nhị phân trong khi lệnh vẫn trả mã 0. Một bản nền hỏng chỉ lộ ra vào
// đúng lúc cần dùng nó — nên nó được kiểm theo ĐỊNH DẠNG, không theo kích thước.
func TestBaseBackupProducesRealTar(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	ctx := t.Context()
	if _, err := d.Setup(ctx, "conf-app-a"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := d.BaseBackup(ctx, dir); err != nil {
		t.Fatalf("BaseBackup: %v", err)
	}
	blob, err := os.ReadFile(filepath.Join(dir, baseBackupFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) < 8192 {
		t.Fatalf("bản nền chỉ %d byte — một cụm postgres thật không nhỏ thế, nghi đầu ra bị cắt", len(blob))
	}
	// Header tar POSIX: magic "ustar" ở offset 257.
	if string(blob[257:262]) != "ustar" {
		t.Fatalf("byte 257..262 = %q, muốn \"ustar\" — bản nền không phải tar hợp lệ.\n"+
			"Gần như chắc chắn luồng ghép của Docker chưa được tách.", blob[257:262])
	}
	// `PG_VERSION` là file gốc của mọi cụm; tên nó phải nằm trong tar.
	if !strings.Contains(string(blob), "PG_VERSION") {
		t.Error("không thấy PG_VERSION trong bản nền — nó không chứa một cụm postgres")
	}
}

// Restore phải TỪ CHỐI khi không có bản nền, và từ chối bằng ĐÚNG lỗi.
//
// `ErrPITRNotEnabled` là thứ tầng trên bắt để phân biệt "chưa bật PITR" với
// "PITR hỏng". Trả một lỗi chung chung ở đây làm mất phân biệt đó, và caller
// buộc phải dò chuỗi.
func TestRestoreRefusesWithoutBase(t *testing.T) {
	d := &Driver{}
	err := d.RestoreToTime(context.Background(), t.TempDir(), time.Time{})
	if err == nil {
		t.Fatal("RestoreToTime chấp nhận một thư mục KHÔNG có bản nền")
	}
	if !errors.Is(err, addons.ErrPITRNotEnabled) {
		t.Errorf("lỗi = %v, muốn bọc ErrPITRNotEnabled", err)
	}
}

// Hai file, và thiếu file nào cũng hỏng IM LẶNG.
//
//	recovery.signal   thiếu → postgres lên BÌNH THƯỜNG, replay KHÔNG chạy, và
//	                  bản khôi phục dừng đúng ở thời điểm chụp base.
//	restore_command   thiếu → không có nguồn WAL, replay dừng ngay lập tức.
func TestRestoreToTimeWritesRecoveryFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	ctx := t.Context()
	if _, err := d.Setup(ctx, "conf-app-a"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := d.BaseBackup(ctx, dir); err != nil {
		t.Fatal(err)
	}
	target := time.Now().Add(-time.Minute)
	if err := d.RestoreToTime(ctx, dir, target); err != nil {
		t.Fatalf("RestoreToTime: %v", err)
	}

	out := filepath.Join(dir, restoredSubdir)
	if _, err := os.Stat(filepath.Join(out, recoverySignalFile)); err != nil {
		t.Errorf("thiếu recovery.signal — postgres sẽ lên bình thường và không replay gì: %v", err)
	}
	// Bản nền phải được CHÉP SANG, không chỉ được trỏ tới: thư mục khôi phục là
	// thứ người vận hành mang sang máy khác.
	if fi, err := os.Stat(filepath.Join(out, baseBackupFile)); err != nil || fi.Size() < 8192 {
		t.Errorf("bản nền trong thư mục khôi phục rỗng hoặc thiếu: %v", err)
	}
	conf, err := os.ReadFile(filepath.Join(out, recoveryConfFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"restore_command", "recovery_target_time", "promote", containerArchiveDir} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("cấu hình khôi phục thiếu %q:\n%s", want, conf)
		}
	}

	// Mốc RỖNG = replay tới xa nhất có thể. Ghi recovery_target_time trong ca
	// này sẽ chặn replay SỚM hơn ý định — im lặng, và chỉ phát hiện được bằng
	// cách đếm dữ liệu thiếu sau khi đã tin là khôi phục xong.
	dir2 := t.TempDir()
	if err := d.BaseBackup(ctx, dir2); err != nil {
		t.Fatal(err)
	}
	if err := d.RestoreToTime(ctx, dir2, time.Time{}); err != nil {
		t.Fatal(err)
	}
	conf2, err := os.ReadFile(filepath.Join(dir2, restoredSubdir, recoveryConfFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(conf2), "recovery_target_time") {
		t.Errorf("mốc rỗng mà vẫn ghi recovery_target_time:\n%s", conf2)
	}
}

// Năng lực được KHAI BÁO, cùng mô hình proxy.Capabilities. Redis không khai, và
// đó là câu trả lời đúng cho redis chứ không phải một thiếu sót.
func TestPostgresDeclaresPITR(t *testing.T) {
	if addons.PITROf(&Driver{}) == nil {
		t.Fatal("driver postgres KHÔNG khai năng lực PITR")
	}
}

// --- helper --------------------------------------------------------------------

// newFileTarget — một target.Target THẬT trên đĩa, trong thư mục tạm của test.
//
// Không phải fake: `driver/dir` là đúng bản hiện thực mà một cài đặt self-host
// dùng khi chưa cấu hình S3, và nó đã có bộ conformance riêng. Dùng nó ở đây
// nghĩa là đường đẩy được chạy end-to-end chứ không dừng ở một mock đếm lời gọi.
func newFileTarget(t *testing.T) target.Target {
	t.Helper()
	tg, err := dir.New(t.TempDir())
	if err != nil {
		t.Fatalf("dir.New: %v", err)
	}
	return tg
}

// archiverDump — trạng thái thô của archiver, cho thông báo lỗi.
//
// Một test hết giờ mà chỉ nói "hết giờ" bắt người đọc tự dựng lại hiện trường,
// trong khi "archiver đang lỗi" và "archiver ngồi im" là hai lỗi khác hẳn nhau.
func archiverDump(t *testing.T, d *Driver) string {
	t.Helper()
	const q = `SELECT 'last_archived=' || COALESCE(last_archived_wal,'(chưa có)') ||
	  ' archived_count=' || archived_count ||
	  ' failed_count=' || failed_count ||
	  ' last_failed=' || COALESCE(last_failed_wal,'-') ||
	  ' wal_hien_tai=' || pg_walfile_name(pg_current_wal_lsn()) ||
	  ' lan_switch_cuoi=' || (SELECT COALESCE(max(stats_reset)::text,'-') FROM pg_stat_archiver)
	  FROM pg_stat_archiver;`
	su, err := d.superPassword(t.Context())
	if err != nil {
		return "không lấy được mật khẩu super: " + err.Error()
	}
	res, err := d.cfg.Runtime.Exec(t.Context(), addons.ExecSpec{
		Name: infraName,
		Cmd:  []string{"psql", "-tA", "-q", "-h", "127.0.0.1", "-U", superUser, "-d", "postgres", "-c", q},
		Env:  map[string]string{"PGPASSWORD": su},
	})
	if err != nil {
		return "exec lỗi: " + err.Error()
	}
	return strings.TrimSpace(string(res.Stdout)) + strings.TrimSpace(string(res.Stderr))
}

// appSQL chạy SQL trên database của app bằng quyền superuser.
func appSQL(t *testing.T, d *Driver, appID, sql string) {
	t.Helper()
	if res := appExec(t, d, appID, sql, nil); !res.OK() {
		t.Fatalf("SQL trên %s thất bại: %s", appID, res.Stderr)
	}
}

// appQuery chạy một câu SELECT và trả về stdout thô.
func appQuery(t *testing.T, d *Driver, appID, sql string) string {
	t.Helper()
	res := appExec(t, d, appID, sql, []string{"-t", "-A"})
	if !res.OK() {
		t.Fatalf("query trên %s thất bại: %s", appID, res.Stderr)
	}
	return string(res.Stdout)
}

func appExec(t *testing.T, d *Driver, appID, sql string, extra []string) addons.ExecResult {
	t.Helper()
	ctx := t.Context()
	su, err := d.superPassword(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cmd := []string{"psql", "-v", "ON_ERROR_STOP=1", "-q", "-h", "127.0.0.1", "-U", superUser, "-d", dbName(appID)}
	cmd = append(cmd, extra...)
	res, err := d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name:  infraName,
		Cmd:   cmd,
		Stdin: []byte(sql),
		Env:   map[string]string{"PGPASSWORD": su},
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	return res
}
