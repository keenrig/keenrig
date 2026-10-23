package snapshot_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/crypt"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/format"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/format/driver/tgz"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/snapshot"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target/driver/dir"
	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// Toàn bộ bộ test này chạy trên FILESYSTEM THẬT và SQLite THẬT — driver `dir`
// làm Target, `tgz` làm Format, `store.Open` làm nguồn platform.db. Không có
// fake nào, đúng nguyên tắc §3: mỗi lần dùng hạ tầng thật đều ra lỗi mà fake
// không ra được.

const pass = "passphrase-du-dai-cho-ban-sao-luu"

type instance struct {
	base   string
	layout paths.Layout
	st     *store.SQLite
	tg     target.Target
	f      format.Format
}

// newInstance dựng một cây instance THẬT: paths.EnsureDirs, store mở thật (tự
// sinh master.key), và vài app có dữ liệu trên đĩa.
func newInstance(t *testing.T, apps ...string) *instance {
	t.Helper()
	base := t.TempDir()
	l := paths.New(base)
	if err := l.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(l.DB(), l.MasterKey())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	for _, id := range apps {
		d, err := l.AppData(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(d, "data"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "data", "noi-dung.txt"),
			[]byte("du lieu cua "+id), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	tg, err := dir.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &instance{base: base, layout: l, st: st, tg: tg, f: tgz.New()}
}

func (in *instance) createOpts(apps ...string) snapshot.CreateOptions {
	return snapshot.CreateOptions{
		Layout:     in.layout,
		Store:      in.st,
		Format:     in.f,
		Target:     in.tg,
		Passphrase: pass,
		Apps:       apps,
		Now:        time.Date(2026, 8, 12, 3, 20, 8, 0, time.UTC),
	}
}

// --- Create ---------------------------------------------------------------------

// Vòng tròn đầy đủ: chụp một instance thật, rồi khôi phục ra một cây trống và
// đối chiếu từng byte.
func TestCreateThenRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t, "app-mot", "app-hai")

	man, err := snapshot.Create(ctx, in.createOpts("app-mot", "app-hai"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if man.ID != "2026-08-12T03-20-08.000Z" {
		t.Errorf("ID = %q", man.ID)
	}
	if len(man.Parts) != 3 {
		t.Fatalf("có %d phần, muốn 3 (instance + 2 app)", len(man.Parts))
	}
	if !man.Encrypted || man.Format != "tgz" {
		t.Errorf("manifest = %+v", man)
	}

	// Khôi phục ra một instance TRỐNG khác.
	dst := paths.New(t.TempDir())
	got, err := snapshot.Restore(ctx, snapshot.RestoreOptions{
		Layout: dst, Target: in.tg, Format: in.f, Passphrase: pass,
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got.ID != man.ID {
		t.Errorf("khôi phục bản %q, muốn %q", got.ID, man.ID)
	}

	// platform.db và master.key phải có mặt.
	for _, p := range []string{dst.DB(), dst.MasterKey()} {
		if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
			t.Errorf("thiếu %s: %v", p, err)
		}
	}
	// Và master.key phải là ĐÚNG khoá cũ — không thì secret trong DB thành rác.
	before, _ := os.ReadFile(in.layout.MasterKey())
	after, _ := os.ReadFile(dst.MasterKey())
	if string(before) != string(after) {
		t.Error("master.key khôi phục KHÁC khoá gốc — mọi secret trong platform.db thành rác")
	}
	// Dữ liệu từng app.
	for _, id := range []string{"app-mot", "app-hai"} {
		d, _ := dst.AppData(id)
		b, err := os.ReadFile(filepath.Join(d, "data", "noi-dung.txt"))
		if err != nil || string(b) != "du lieu cua "+id {
			t.Errorf("%s: %q, %v", id, b, err)
		}
	}
}

// platform.db trong snapshot phải MỞ LẠI ĐƯỢC và mang dữ liệu đúng thời điểm.
//
// Đây là khẳng định nối `store.SnapshotTo` với cả đường ống: gói–mã hoá–đẩy–
// tải–giải mã–giải nén xong thì file kia vẫn phải là một database dùng được.
func TestRestoredDatabaseOpensWithItsOwnMasterKey(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t)

	const ref, plain = "app/shop/db-password", "mat-khau-that"
	if err := in.st.PutSecret(ctx, ref, []byte(plain)); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Create(ctx, in.createOpts()); err != nil {
		t.Fatal(err)
	}

	dst := paths.New(t.TempDir())
	if _, err := snapshot.Restore(ctx, snapshot.RestoreOptions{
		Layout: dst, Target: in.tg, Format: in.f, Passphrase: pass,
	}); err != nil {
		t.Fatal(err)
	}

	restored, err := store.Open(dst.DB(), dst.MasterKey())
	if err != nil {
		t.Fatalf("platform.db khôi phục không mở được: %v", err)
	}
	defer restored.Close()
	got, err := restored.GetSecret(ctx, ref)
	if err != nil || string(got) != plain {
		t.Errorf("secret sau restore = %q, %v — muốn %q", got, err, plain)
	}
}

// Không có passphrase → TỪ CHỐI TẠO, không hạ cấp xuống "sao lưu để trần".
//
// Snapshot chứa master.key. Một bản không mã hoá là trao toàn bộ instance cho
// bất kỳ ai đọc được Target.
func TestCreateRefusesWithoutPassphrase(t *testing.T) {
	in := newInstance(t)
	opts := in.createOpts()
	opts.Passphrase = ""
	if _, err := snapshot.Create(context.Background(), opts); !errors.Is(err, crypt.ErrNoPassphrase) {
		t.Fatalf("= %v, muốn ErrNoPassphrase", err)
	}
	// Và KHÔNG được để lại object nào trên Target.
	objs, _ := in.tg.List(context.Background(), "")
	if len(objs) != 0 {
		t.Errorf("từ chối rồi vẫn đẩy lên %d object", len(objs))
	}
}

// Object trên Target phải THẬT SỰ được mã hoá — kiểm bằng byte, không bằng cờ
// trong manifest.
//
// Một cờ `"encrypted": true` do chính ta ghi ra thì tự nó không chứng minh gì.
func TestStoredPartsAreActuallyEncrypted(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t, "app-mot")
	man, err := snapshot.Create(ctx, in.createOpts("app-mot"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range man.Parts {
		rc, err := in.tg.Get(ctx, p.Key)
		if err != nil {
			t.Fatal(err)
		}
		head := make([]byte, crypt.PrefixLen)
		_, _ = rc.Read(head)
		rc.Close()
		if !crypt.HasMagic(head) {
			t.Errorf("%s KHÔNG mã hoá — magic đầu file là %q", p.Key, head[:14])
		}
	}
	// Manifest thì NGƯỢC LẠI: phải đọc được không cần passphrase.
	if _, err := snapshot.Load(ctx, in.tg, man.ID); err != nil {
		t.Errorf("manifest phải đọc được không cần passphrase: %v", err)
	}
}

// Hai lần sao lưu trong CÙNG MỘT GIÂY phải cho hai snapshot RIÊNG.
//
// Regression, và nó do test chaos CH-02 tìm ra chứ không do đọc code: bản đầu
// sinh ID với độ phân giải GIÂY, nên hai lệnh liên tiếp cho ra cùng một ID và
// im lặng ghi đè lên nhau. Tái hiện bằng tay:
//
//	snapshot 2026-08-12T08-00-07Z: 1 parts, 7015 bytes stored on dir
//	snapshot 2026-08-12T08-00-07Z: 1 parts, 7015 bytes stored on dir   ← cùng ID
//
// Nặng nhất không phải mất một điểm khôi phục: nếu lần trước bị CẮT giữa chừng,
// manifest của lần này trỏ vào những phần đã bị ghi đè — băm không khớp, và
// `backups` vẫn kể tên nó như một bản hoàn chỉnh.
func TestTwoBackupsInTheSameSecondDoNotCollide(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t, "app-mot")

	base := time.Date(2026, 8, 12, 8, 0, 7, 0, time.UTC)
	first := in.createOpts("app-mot")
	first.Now = base
	a, err := snapshot.Create(ctx, first)
	if err != nil {
		t.Fatal(err)
	}

	second := in.createOpts("app-mot")
	second.Now = base.Add(120 * time.Millisecond) // cùng giây, khác mili-giây
	b, err := snapshot.Create(ctx, second)
	if err != nil {
		t.Fatal(err)
	}

	if a.ID == b.ID {
		t.Fatalf("hai snapshot cùng ID %q — bản sau ghi đè bản trước", a.ID)
	}
	// Và thứ tự từ điển phải vẫn trùng thứ tự thời gian: retention chọn bản để
	// XOÁ dựa vào đúng thứ tự này.
	if a.ID >= b.ID {
		t.Errorf("ID không còn sắp theo thời gian: %q rồi %q", a.ID, b.ID)
	}
	all, err := snapshot.List(ctx, in.tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("List thấy %d bản, muốn 2", len(all))
	}
	// Cả hai phải restore được THẬT, không chỉ có tên.
	for _, m := range all {
		dst := paths.New(t.TempDir())
		if _, rerr := snapshot.Restore(ctx, snapshot.RestoreOptions{
			Layout: dst, Target: in.tg, Format: in.f, Passphrase: pass, ID: m.ID,
		}); rerr != nil {
			t.Errorf("bản %s được kể tên nhưng restore hỏng: %v", m.ID, rerr)
		}
	}
}

// Trùng ID hoàn toàn (đồng hồ lùi, hai tiến trình song song) → TỪ CHỐI, và
// KHÔNG đụng vào thứ đã có.
//
// Mili-giây thu hẹp cửa sổ chứ không đóng hẳn. Đây là cửa đóng hẳn.
func TestCreateRefusesToOverwriteExistingSnapshot(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t, "app-mot")

	opts := in.createOpts("app-mot")
	first, err := snapshot.Create(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

	// CÙNG mốc thời gian → cùng ID.
	_, err = snapshot.Create(ctx, opts)
	if !errors.Is(err, snapshot.ErrSnapshotExists) {
		t.Fatalf("= %v, muốn ErrSnapshotExists", err)
	}
	// Bản cũ phải còn nguyên và còn restore được.
	dst := paths.New(t.TempDir())
	if _, rerr := snapshot.Restore(ctx, snapshot.RestoreOptions{
		Layout: dst, Target: in.tg, Format: in.f, Passphrase: pass, ID: first.ID,
	}); rerr != nil {
		t.Errorf("bản cũ hỏng sau một lần Create bị từ chối: %v", rerr)
	}
}

// --- Restore: luật an toàn --------------------------------------------------------

// Đích đã có dữ liệu → TỪ CHỐI, và dữ liệu đang có không bị đụng.
//
// Restore đè lên instance đang chạy là cách mất dữ liệu nhanh nhất trong hệ
// thống này. Không có cờ `--force` — muốn đè thì phải tự xoá, một hành động
// tường minh không thể làm nhầm.
func TestRestoreRefusesNonEmptyInstance(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t, "app-mot")
	if _, err := snapshot.Create(ctx, in.createOpts("app-mot")); err != nil {
		t.Fatal(err)
	}

	// Khôi phục ngược lên CHÍNH instance đang sống.
	_, err := snapshot.Restore(ctx, snapshot.RestoreOptions{
		Layout: in.layout, Target: in.tg, Format: in.f, Passphrase: pass,
	})
	if !errors.Is(err, snapshot.ErrInstanceNotEmpty) {
		t.Fatalf("= %v, muốn ErrInstanceNotEmpty", err)
	}
	if !strings.Contains(err.Error(), "no force flag") {
		t.Errorf("thông báo không nói cho người vận hành phải làm gì: %v", err)
	}
	// platform.db đang chạy phải còn nguyên và còn dùng được.
	if err := in.st.Ping(ctx); err != nil {
		t.Errorf("store đang chạy hỏng sau một lần restore bị từ chối: %v", err)
	}
}

// Sai passphrase phải lộ ra TRƯỚC khi ghi bất cứ thứ gì ra đĩa.
func TestRestoreWrongPassphraseWritesNothing(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t, "app-mot")
	if _, err := snapshot.Create(ctx, in.createOpts("app-mot")); err != nil {
		t.Fatal(err)
	}

	dstBase := t.TempDir()
	dst := paths.New(dstBase)
	_, err := snapshot.Restore(ctx, snapshot.RestoreOptions{
		Layout: dst, Target: in.tg, Format: in.f, Passphrase: "sai-passphrase-nhung-du-dai",
	})
	if !errors.Is(err, crypt.ErrWrongPassphrase) {
		t.Fatalf("= %v, muốn ErrWrongPassphrase", err)
	}
	if ents, _ := os.ReadDir(dstBase); len(ents) != 0 {
		t.Errorf("sai passphrase mà vẫn ghi ra %d entry", len(ents))
	}
}

// Object bị SỬA sau khi ghi → băm không khớp → lỗi.
//
// Lớp crypt đã bắt được mọi sửa đổi rồi, nên băm ở đây canh một loại lỗi khác:
// Target trả về đúng số byte của một object KHÁC — nhầm key, nhầm phiên bản,
// hoặc một bucket bị ghi chéo.
func TestDigestMismatchIsDetected(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t, "app-mot", "app-hai")
	man, err := snapshot.Create(ctx, in.createOpts("app-mot", "app-hai"))
	if err != nil {
		t.Fatal(err)
	}

	// Tráo nội dung của app-hai sang chỗ của app-mot: cả hai đều là archive hợp
	// lệ, mã hoá đúng passphrase, giải nén sạch — chỉ là SAI DỮ LIỆU.
	var one, two string
	for _, p := range man.Parts {
		switch p.AppID {
		case "app-mot":
			one = p.Key
		case "app-hai":
			two = p.Key
		}
	}
	rc, err := in.tg.Get(ctx, two)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := os.CreateTemp(t.TempDir(), "swap-*")
	n, _ := body.ReadFrom(rc)
	rc.Close()
	body.Seek(0, 0)
	if err := in.tg.Put(ctx, one, body, n); err != nil {
		t.Fatal(err)
	}
	body.Close()

	dst := paths.New(t.TempDir())
	_, err = snapshot.Restore(ctx, snapshot.RestoreOptions{
		Layout: dst, Target: in.tg, Format: in.f, Passphrase: pass,
	})
	if !errors.Is(err, snapshot.ErrDigestMismatch) {
		t.Fatalf("= %v, muốn ErrDigestMismatch — tráo object mà không ai phát hiện", err)
	}
}

// Chọn app cụ thể thì KHÔNG được đụng tới phần instance.
//
// Ca thường nhất của restore không phải "mất cả máy" mà là "app này hỏng, lấy
// lại bản hôm qua" — và việc đó không được phép ghi đè platform.db của cả máy.
func TestRestoreOneAppNeverTouchesInstance(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t, "app-mot", "app-hai")
	if _, err := snapshot.Create(ctx, in.createOpts("app-mot", "app-hai")); err != nil {
		t.Fatal(err)
	}

	dst := paths.New(t.TempDir())
	if _, err := snapshot.Restore(ctx, snapshot.RestoreOptions{
		Layout: dst, Target: in.tg, Format: in.f, Passphrase: pass,
		OnlyApps: []string{"app-hai"},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(dst.DB()); err == nil {
		t.Error("khôi phục MỘT app lại ghi cả platform.db")
	}
	if d, _ := dst.AppData("app-mot"); dirExists(d) {
		t.Error("khôi phục app-hai lại đụng cả app-mot")
	}
	d, _ := dst.AppData("app-hai")
	if !dirExists(d) {
		t.Error("app được chọn lại không tới nơi")
	}
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// --- List / Load ------------------------------------------------------------------

// Object mồ côi (một lần chạy bị ngắt, chưa kịp ghi manifest) KHÔNG được kể tên
// như một bản sao lưu.
func TestListIgnoresSnapshotsWithoutManifest(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t)
	full, err := snapshot.Create(ctx, in.createOpts())
	if err != nil {
		t.Fatal(err)
	}
	// Giả lập một lần chạy đứt giữa chừng: có phần instance, không có manifest.
	if err := in.tg.Put(ctx, "snapshots/2026-08-11T00-00-00Z/instance.tgz",
		strings.NewReader("do dang"), 7); err != nil {
		t.Fatal(err)
	}

	all, err := snapshot.List(ctx, in.tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].ID != full.ID {
		ids := make([]string, len(all))
		for i, m := range all {
			ids[i] = m.ID
		}
		t.Errorf("List = %v, muốn đúng %q — bản dở dang bị kể tên", ids, full.ID)
	}
}

// Nhiều snapshot → List trả MỚI NHẤT TRƯỚC, và Restore không nêu ID thì lấy
// bản mới nhất.
func TestListNewestFirstAndRestoreDefaultsToIt(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t, "app-mot")

	opts := in.createOpts("app-mot")
	opts.Now = time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	if _, err := snapshot.Create(ctx, opts); err != nil {
		t.Fatal(err)
	}
	opts.Now = time.Date(2026, 8, 12, 1, 0, 0, 0, time.UTC)
	newest, err := snapshot.Create(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

	all, err := snapshot.List(ctx, in.tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].ID != newest.ID {
		t.Fatalf("List = %v", all)
	}

	dst := paths.New(t.TempDir())
	got, err := snapshot.Restore(ctx, snapshot.RestoreOptions{
		Layout: dst, Target: in.tg, Format: in.f, Passphrase: pass,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != newest.ID {
		t.Errorf("Restore mặc định lấy %q, muốn bản mới nhất %q", got.ID, newest.ID)
	}
}

// Manifest bản lạ → TỪ CHỐI, không đoán.
func TestUnknownManifestVersionRejected(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t)
	if _, err := snapshot.Create(ctx, in.createOpts()); err != nil {
		t.Fatal(err)
	}
	body := `{"version":99,"id":"2026-08-12T03-20-08Z","format":"tgz","parts":[]}`
	if err := in.tg.Put(ctx, snapshot.ManifestKey("2026-08-12T03-20-08Z"),
		strings.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Load(ctx, in.tg, "2026-08-12T03-20-08Z"); err == nil {
		t.Error("manifest version 99 lại được chấp nhận")
	}
}

// --- addon ------------------------------------------------------------------------

// Dump addon đi vào snapshot và quay lại qua AddonRestore.
//
// Dùng một hàm dump THẬT ghi file thật, không mock: seam ở đây là chữ ký hàm,
// còn dữ liệu đi qua vẫn là byte trên đĩa.
func TestAddonDumpRoundTrip(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t, "app-mot")

	opts := in.createOpts("app-mot")
	opts.DumpAddons = func(_ context.Context, appID, dir string) error {
		return os.WriteFile(filepath.Join(dir, "postgres.dump"),
			[]byte("PGDMP gia lap cho "+appID), 0o600)
	}
	man, err := snapshot.Create(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(man.Parts) != 3 {
		t.Fatalf("có %d phần, muốn 3 (instance + app + addon)", len(man.Parts))
	}

	var loaded string
	dst := paths.New(t.TempDir())
	if _, err := snapshot.Restore(ctx, snapshot.RestoreOptions{
		Layout: dst, Target: in.tg, Format: in.f, Passphrase: pass,
		AddonRestore: func(_ context.Context, appID, dir string) error {
			b, rerr := os.ReadFile(filepath.Join(dir, "postgres.dump"))
			loaded = string(b)
			return rerr
		},
	}); err != nil {
		t.Fatal(err)
	}
	if loaded != "PGDMP gia lap cho app-mot" {
		t.Errorf("dump nạp vào addon = %q", loaded)
	}
}

// Addon không ghi gì → KHÔNG tạo part rỗng.
//
// Một object 0 file trong manifest làm người đọc tưởng addon đã được sao lưu.
func TestEmptyAddonDumpMakesNoPart(t *testing.T) {
	ctx := context.Background()
	in := newInstance(t, "app-mot")
	opts := in.createOpts("app-mot")
	opts.DumpAddons = func(context.Context, string, string) error { return nil }

	man, err := snapshot.Create(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range man.Parts {
		if p.Kind == snapshot.KindAddon {
			t.Errorf("tạo part addon rỗng: %+v", p)
		}
	}
}
