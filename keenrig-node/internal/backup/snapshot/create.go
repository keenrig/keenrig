package snapshot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/crypt"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/format"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target"
	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
)

var (
	// ErrNoApps — không truyền app nào VÀ cũng không có instance để chụp.
	ErrNoApps = errors.New("snapshot: nothing to back up")
	// ErrDigestMismatch — băm đọc lại khác băm đã ghi trong manifest.
	ErrDigestMismatch = errors.New("snapshot: content does not match the digest recorded when it was written")
	// ErrSnapshotExists — đã có object nằm dưới ID sắp ghi.
	//
	// Cửa cuối chặn hai lần sao lưu giẫm lên nhau. Mili-giây trong [NewID] làm
	// ca này gần như không xảy ra, nhưng "gần như" không đủ cho một thao tác mà
	// hậu quả là GHI ĐÈ một bản sao lưu tốt — nhất là khi hai tiến trình có thể
	// chạy song song (lệnh chạy tay trong lúc lịch cũng chạy).
	ErrSnapshotExists = errors.New("snapshot: a snapshot with this id already exists on the target")
)

// DBSnapshotter — thứ duy nhất snapshot cần từ store.
//
// Interface hẹp ĐẶT Ở NƠI DÙNG, không phải nơi định nghĩa: package này không
// cần biết store có 40 method khác, và một test không phải dựng cả store thật
// để kiểm phần gói/mã hoá. Đây cũng là lý do nó không nhận `store.Store`.
type DBSnapshotter interface {
	SnapshotTo(ctx context.Context, dst string) error
}

// AddonDumper ghi dump addon của một app ra dir. Khớp `addons.Addon.Backup`.
//
// Là một hàm chứ không phải interface vì caller thường phải gộp nhiều addon của
// cùng một app vào một thư mục — và đó là việc của caller, không phải của đây.
type AddonDumper func(ctx context.Context, appID, dir string) error

// CreateOptions — mọi thứ Create cần. Không đọc biến môi trường, không đọc
// đồng hồ: cả hai được truyền vào, nên test kiểm được hành vi ở một thời điểm
// xác định.
type CreateOptions struct {
	Layout paths.Layout
	Store  DBSnapshotter
	Format format.Format
	Target target.Target

	// Passphrase BẮT BUỘC. Xem godoc Create.
	Passphrase string

	// Apps — app ID sẽ sao lưu. Rỗng thì snapshot chỉ có phần instance.
	Apps []string

	// DumpAddons — nil thì bỏ qua phần addon, và điều đó được GHI VÀO manifest
	// dưới dạng thiếu part, chứ không im lặng.
	DumpAddons AddonDumper

	// WorkDir — nơi đặt file tạm. Rỗng → os.TempDir(). Nên trỏ vào cùng
	// filesystem với dữ liệu để tránh chép chéo đĩa.
	WorkDir string

	// Now — thời điểm dùng để sinh ID.
	Now time.Time

	BoxVersion string

	// Log — nil thì im lặng. Sao lưu chạy theo lịch lúc không ai ngồi xem, nên
	// dòng log là bằng chứng duy nhất còn lại rằng nó đã chạy và làm được gì.
	Log func(format string, args ...any)
}

// Create gom một snapshot đầy đủ rồi đẩy lên Target.
//
// # Mã hoá là BẮT BUỘC, không có cờ tắt
//
// Snapshot chứa `instance/master.key` — khoá bọc mọi secret của mọi app. Một
// snapshot không mã hoá là trao toàn bộ instance cho bất kỳ ai đọc được Target,
// và Target thì thường là một bucket hoặc một share dùng chung.
//
// Không có `--no-encrypt`, có chủ đích: một cờ như thế sẽ được dùng, và nó sẽ
// được dùng bởi đúng những người không nên dùng nó. Không đặt passphrase →
// [crypt.ErrNoPassphrase], và lỗi đó phải làm lệnh dừng lại chứ không hạ cấp
// xuống "sao lưu nhưng để trần".
//
// # Thứ tự: instance TRƯỚC
//
// Nếu đĩa đầy hay mạng đứt giữa chừng, thứ còn lại trên Target phải là thứ đáng
// giá nhất. `instance/` (platform.db + master.key) là phần mà thiếu nó thì mọi
// phần khác vô nghĩa: không có nó, một cây dữ liệu app không nói được nó thuộc
// app nào, cấu hình ra sao, secret là gì.
//
// # Manifest ghi CUỐI CÙNG
//
// Đó là dấu hiệu "snapshot này hoàn chỉnh". Một lần chạy bị ngắt để lại vài
// object mồ côi không có manifest — và `List` bỏ qua chúng thay vì kể tên một
// bản sao lưu không dùng được. Ghi manifest trước rồi mới đẩy dữ liệu là tạo ra
// đúng cái bẫy đó.
func Create(ctx context.Context, opts CreateOptions) (*Manifest, error) {
	if err := validateCreate(&opts); err != nil {
		return nil, err
	}
	logf := opts.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}

	work, err := os.MkdirTemp(opts.WorkDir, "keenrig-snapshot-*")
	if err != nil {
		return nil, fmt.Errorf("snapshot: creating the work directory: %w", err)
	}
	// Dọn ở MỌI đường thoát: file tạm ở đây là bản sao đầy đủ của platform.db,
	// tức là mọi secret ở dạng đã mã hoá cộng master.key ngay cạnh.
	defer os.RemoveAll(work)

	id := NewID(opts.Now)
	// Không giẫm lên một snapshot đã có. Kiểm TRƯỚC khi ghi byte đầu tiên: phát
	// hiện ở giữa chừng nghĩa là đã ghi đè mất một phần của bản cũ rồi.
	if objs, lerr := opts.Target.List(ctx, Prefix+id+"/"); lerr != nil {
		return nil, lerr
	} else if len(objs) > 0 {
		return nil, fmt.Errorf("%w: %s (%d objects) — nothing was overwritten", ErrSnapshotExists, id, len(objs))
	}

	man := &Manifest{
		Version:    ManifestVersion,
		ID:         id,
		CreatedAt:  opts.Now.UTC(),
		Format:     opts.Format.Name(),
		Encrypted:  true,
		BoxVersion: opts.BoxVersion,
	}
	b := &builder{opts: opts, work: work, id: id, logf: logf}

	instance, err := b.stageInstance(ctx)
	if err != nil {
		return nil, err
	}
	part, err := b.upload(ctx, KindInstance, "", instance)
	if err != nil {
		return nil, err
	}
	man.Parts = append(man.Parts, *part)

	// Sắp xếp app ID để hai lần chạy trên cùng dữ liệu cho ra manifest giống
	// nhau — thứ tự map của Go là ngẫu nhiên có chủ đích, và một manifest đổi
	// thứ tự mỗi lần làm mọi phép so sánh bản này với bản kia thành vô dụng.
	apps := append([]string(nil), opts.Apps...)
	sort.Strings(apps)
	for _, appID := range apps {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := b.addApp(ctx, man, appID); err != nil {
			return nil, err
		}
	}

	if err := b.putManifest(ctx, man); err != nil {
		return nil, err
	}
	logf("backup: snapshot %s complete: %d parts, %d bytes stored", id, len(man.Parts), man.TotalStored())
	return man, nil
}

func validateCreate(o *CreateOptions) error {
	switch {
	case o.Format == nil:
		return errors.New("snapshot: no format driver")
	case o.Target == nil:
		return errors.New("snapshot: no backup target")
	case o.Store == nil:
		return errors.New("snapshot: no database snapshotter")
	case strings.TrimSpace(o.Passphrase) == "":
		return crypt.ErrNoPassphrase
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	return nil
}

type builder struct {
	opts CreateOptions
	work string
	id   string
	logf func(string, ...any)
	seq  int
}

// stageInstance dựng một cây `instance/` TẠM chứ không gói thẳng thư mục thật.
//
// Bắt buộc phải thế, vì thư mục thật chứa `platform.db` đang mở kèm `-wal`/
// `-shm`. Gói thẳng nó là chép một database đang sống — bản sao mở lên vẫn chạy
// nhưng thiếu những giao dịch chưa checkpoint. Thay vào đó `VACUUM INTO` cho ra
// một file tự đủ, và ta gói cây tạm gồm file đó + master.key.
func (b *builder) stageInstance(ctx context.Context) (string, error) {
	dir := filepath.Join(b.work, "instance")
	if err := os.MkdirAll(dir, paths.PrivateDirPerm); err != nil {
		return "", err
	}
	if err := b.opts.Store.SnapshotTo(ctx, filepath.Join(dir, "platform.db")); err != nil {
		return "", err
	}
	// master.key đi CÙNG. Đây là quyết định đã chốt (2026-08-12): bản sao lưu
	// phải tự đủ, và cái giá của nó là archive bắt buộc mã hoá.
	src := b.opts.Layout.MasterKey()
	key, err := os.ReadFile(src)
	if err != nil {
		// Không có master.key nghĩa là store chưa từng mở — sao lưu lúc này cho
		// ra một bản không giải mã được secret nào. Dừng, đừng tạo ra nó.
		return "", fmt.Errorf("snapshot: reading the master key at %s: %w", src, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "master.key"), key, paths.SecretFilePerm); err != nil {
		return "", err
	}
	return dir, nil
}

func (b *builder) addApp(ctx context.Context, man *Manifest, appID string) error {
	data, err := b.opts.Layout.AppData(appID)
	if err != nil {
		return err
	}
	if fi, serr := os.Stat(data); serr == nil && fi.IsDir() {
		part, perr := b.upload(ctx, KindApp, appID, data)
		if perr != nil {
			return perr
		}
		man.Parts = append(man.Parts, *part)
	} else {
		// App chưa có thư mục dữ liệu là chuyện bình thường (vừa tạo, chưa chạy).
		// Nói ra, đừng lặng lẽ bỏ.
		b.logf("backup: app %s has no data directory yet — skipping its data part", appID)
	}

	if b.opts.DumpAddons == nil {
		return nil
	}
	dump := filepath.Join(b.work, "addons", appID)
	if err := os.MkdirAll(dump, paths.PrivateDirPerm); err != nil {
		return err
	}
	if err := b.opts.DumpAddons(ctx, appID, dump); err != nil {
		return fmt.Errorf("snapshot: dumping addons for app %s: %w", appID, err)
	}
	// Không addon nào ghi gì → không tạo part rỗng. Một object 0 file trong
	// manifest làm người đọc tưởng addon đã được sao lưu.
	ents, err := os.ReadDir(dump)
	if err != nil {
		return err
	}
	if len(ents) == 0 {
		return nil
	}
	part, err := b.upload(ctx, KindAddon, appID, dump)
	if err != nil {
		return err
	}
	man.Parts = append(man.Parts, *part)
	return nil
}

// upload đóng gói srcDir → mã hoá → file tạm → đẩy lên Target.
//
// Phải qua file tạm chứ không stream thẳng: `target.Put` đòi size CHÍNH XÁC
// (không có Content-Length thì S3 thật từ chối với MissingContentLength), và
// kích thước sau nén + mã hoá chỉ biết được khi đã ghi xong. Cái giá là một
// lượng đĩa bằng archive của MỘT phần — không phải của cả instance, và đó chính
// là lý do snapshot chia thành nhiều phần.
func (b *builder) upload(ctx context.Context, kind, appID, srcDir string) (*Part, error) {
	key := KeyFor(b.id, kind, appID)

	b.seq++
	tmp, err := os.CreateTemp(b.work, fmt.Sprintf("part-%03d-*.bin", b.seq))
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	// Băm PLAINTEXT: nhánh hash đứng TRƯỚC lớp mã hoá, nên nó băm archive chưa
	// mã hoá. Băm ciphertext thì mỗi lần chạy ra một giá trị khác (salt ngẫu
	// nhiên) và không so được hai bản sao lưu với nhau.
	sum := sha256.New()
	enc, err := crypt.Wrap(tmp, b.opts.Passphrase)
	if err != nil {
		return nil, err
	}
	stats, perr := b.opts.Format.Pack(ctx, srcDir, io.MultiWriter(sum, enc))
	if perr != nil {
		return nil, fmt.Errorf("snapshot: packing %s: %w", srcDir, perr)
	}
	// Close của crypt ghi chunk CUỐI — dấu hiệu duy nhất đánh dấu "stream đã
	// hết". Bỏ qua lỗi ở đây là đẩy lên một archive mà chính ta từ chối đọc.
	if err := enc.Close(); err != nil {
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		return nil, err
	}
	fi, err := tmp.Stat()
	if err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err := b.opts.Target.Put(ctx, key, tmp, fi.Size()); err != nil {
		return nil, fmt.Errorf("snapshot: uploading %s: %w", key, err)
	}

	skipped := make([]string, 0, len(stats.Skipped))
	for _, s := range stats.Skipped {
		skipped = append(skipped, s.String())
	}
	b.logf("backup: %s -> %s (%d files, %d bytes stored)", srcDir, key, stats.Files, fi.Size())
	return &Part{
		Kind:        kind,
		AppID:       appID,
		Key:         key,
		PlainSHA256: hex.EncodeToString(sum.Sum(nil)),
		PlainBytes:  stats.Bytes,
		StoredBytes: fi.Size(),
		Files:       stats.Files,
		Dirs:        stats.Dirs,
		Skipped:     skipped,
	}, nil
}

func (b *builder) putManifest(ctx context.Context, man *Manifest) error {
	if err := man.Validate(); err != nil {
		// Tự kiểm trước khi công bố: một manifest sai đẩy lên rồi là một bản sao
		// lưu trông như hoàn chỉnh mà restore không đọc được.
		return err
	}
	body, err := man.encode()
	if err != nil {
		return err
	}
	return b.opts.Target.Put(ctx, ManifestKey(man.ID), bytes.NewReader(body), int64(len(body)))
}
