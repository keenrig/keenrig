// Package paths định nghĩa bố cục thư mục runtime của một instance Keenrig.
//
// # Bốn tiến trình, một bố cục
//
// Instance chạy 4 tiến trình của mình (cộng dockerd và reverse proxy):
//
//	keenrig-box     control plane; SỞ HỮU ĐỘC QUYỀN instance/platform.db
//	keenrig-agent   thu metric/log, đẩy lên cloud; state riêng ở node/agent
//	keenrig-ota     cập nhật bin/; state riêng ở node/update/state.json
//	caddy|nginx     đường dữ liệu; đọc cert ở node/proxy/cert
//
// Bất biến sống còn: SQLite KHÔNG chịu được nhiều tiến trình cùng ghi
// (MaxOpenConns(1) chỉ serialize trong MỘT tiến trình). Vì vậy mỗi tiến trình
// có vùng state riêng, và mọi thứ cần platform.db đều phải đi qua node API của
// box tại RunDir()/box.sock — không tiến trình nào mở trực tiếp file DB.
//
// # Bốn mặt phẳng dữ liệu
//
// Tách code khỏi state, và state theo từng phạm vi, là điều kiện CẦN để update
// và backup an toàn: mỗi mặt phẳng có vòng đời riêng.
//
//	<base>/bin/           CODE — installer thay NGUYÊN KHỐI khi update; không chứa state
//	<base>/instance/      state của CHÍNH instance: platform.db, master.key  (0700)
//	<base>/node/          state của node này: cert, acme, addon, log, backup, run
//	<base>/apps/<id>/     dữ liệu người dùng của từng app
//
// "node" chứ không phải "platform": keenrig-node là tên của tiến trình phía
// máy chủ, và ở M6 khi có nhiều node thì thư mục này là state RIÊNG của mỗi
// node — "platform" sẽ gợi ý sai rằng nó dùng chung.
//
// Bản cài theo tên cũ được đổi tên tự động lúc khởi động; xem migrate.go.
//
// # Hai bất biến rút ra từ bố cục
//
//  1. Update CHỈ được phép xoá/ghi đè <base>/bin. Ba mặt phẳng còn lại sống sót
//     qua mọi lần update — đó là lý do chúng nằm ngoài thư mục code.
//  2. Restore một instance = khôi phục instance + node (chọn lọc) +
//     apps; KHÔNG cần khôi phục bin (installer tự tải lại đúng version).
//
// # Đồng bộ bắt buộc
//
// installer/layout.md và installer/systemd/*.service phải khớp với file này.
// Đường dẫn bị chép ở ba nơi thì sẽ lệch nhau nếu không ai được nhắc — ghi chú
// này là lời nhắc đó.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Quyền thư mục/file. instance chặt hơn phần còn lại vì chứa master.key —
// mất file đó là mất toàn bộ secret của instance.
const (
	DirPerm        os.FileMode = 0o755
	PrivateDirPerm os.FileMode = 0o700
	SecretFilePerm os.FileMode = 0o600
)

// DefaultBase — vị trí cài đặt chuẩn trên Linux. Dev trên máy cá nhân truyền
// base khác (vd "./data") vào New.
const DefaultBase = "/var/lib/keenrig"

// Layout là bố cục đã neo vào một thư mục gốc. Zero value không dùng được —
// luôn tạo bằng New.
type Layout struct{ base string }

// New neo bố cục vào base. base rỗng → DefaultBase.
func New(base string) Layout {
	if base == "" {
		base = DefaultBase
	}
	return Layout{base: filepath.Clean(base)}
}

func (l Layout) Base() string { return l.base }

// --- mặt phẳng 1: CODE -------------------------------------------------------

// Bin — nơi installer đặt binary + asset tĩnh. Update thay nguyên khối thư mục
// này, nên TUYỆT ĐỐI không ghi state vào đây.
func (l Layout) Bin() string { return filepath.Join(l.base, "bin") }

// --- mặt phẳng 2: STATE CỦA KEENRIG-BOX --------------------------------------------

func (l Layout) Instance() string { return filepath.Join(l.base, "instance") }

// DB — SQLite chứa apps/settings/events/jobs/secrets.
func (l Layout) DB() string { return filepath.Join(l.Instance(), "platform.db") }

// MasterKey — khoá AES-256 bọc mọi secret trong DB. Nằm CẠNH chứ không nằm
// TRONG database: có file DB mà không có file này thì không đọc được secret.
func (l Layout) MasterKey() string { return filepath.Join(l.Instance(), "master.key") }

// License — phong bì license Ed25519 đã ký (JSON). Nằm trong instance/ cạnh
// master.key: license cấp cho MỘT instance (payload mang instance_id), nên nó
// thuộc danh tính của instance chứ không phải dữ liệu node. Agent ghi file này
// khi cloud phát bản mới; không có file = bậc miễn phí, không phải lỗi.
func (l Layout) License() string { return filepath.Join(l.Instance(), "license.json") }

// --- mặt phẳng 3: STATE TẦNG NỀN ---------------------------------------------

func (l Layout) NodeData() string { return filepath.Join(l.base, "node") }

// ProxySites — config site sinh ra từ store cho proxy nhúng. Là CACHE dẫn xuất:
// xoá đi thì tick sau dựng lại từ DB, không được coi là nguồn sự thật.
func (l Layout) ProxySites() string { return filepath.Join(l.NodeData(), "proxy", "sites") }

// ProxyCerts — chứng chỉ TLS đang phục vụ (cert + key theo domain).
func (l Layout) ProxyCerts() string { return filepath.Join(l.NodeData(), "proxy", "cert") }

// ACMEChallenges — webroot cho HTTP-01.
func (l Layout) ACMEChallenges() string { return filepath.Join(l.NodeData(), "acme") }

// AddonsData — thư mục cha cho dữ liệu của addon dùng chung (postgres, redis…).
func (l Layout) Addons() string { return filepath.Join(l.NodeData(), "addons") }

// AddonData — data directory của một addon. name phải là định danh addon đã
// đăng ký (postgres, redis…), không phải input từ người dùng.
func (l Layout) AddonData(name string) (string, error) {
	if !isSafeSegment(name) {
		return "", fmt.Errorf("paths: invalid addon name: %q", name)
	}
	return filepath.Join(l.Addons(), name), nil
}

func (l Layout) Logs() string { return filepath.Join(l.NodeData(), "logs") }

// BackupInfo — metadata backup (danh mục snapshot, chữ ký toàn vẹn); KHÔNG
// phải nơi chứa chính archive.
func (l Layout) BackupInfo() string { return filepath.Join(l.NodeData(), "backup") }

// Update — vùng làm việc của updater (tarball tải về, bản bin cũ chờ rollback).
func (l Layout) Update() string { return filepath.Join(l.NodeData(), "update") }

// VersionFile — version của keenrig-box đang chạy; installer/updater ghi.
func (l Layout) VersionFile() string { return filepath.Join(l.NodeData(), "VERSION") }

// InfraVersionFile — version bộ image addon đã pin digest. Bump giá trị này là
// tín hiệu phải dựng lại toàn bộ container addon; nội dung khớp
// contracts/jsonschema/infra.schema.json.
func (l Layout) InfraVersionFile() string { return filepath.Join(l.NodeData(), "INFRA_VERSION") }

// --- mặt phẳng 3b: RANH GIỚI GIỮA CÁC TIẾN TRÌNH ------------------------------

// RunDir chứa unix socket của node API. Đây là toàn bộ bề mặt tiếp xúc giữa
// các tiến trình ở nấc 0.
//
// Lên nấc cao hơn, node API chuyển sang TCP + mTLS và thư mục này bỏ trống —
// hợp đồng (contracts/openapi/node.yaml) KHÔNG đổi, chỉ đổi transport. Đó là
// lý do agent không được đọc thẳng file log hay file DB: làm vậy là buộc nó
// phải ở cùng máy với box vĩnh viễn.
func (l Layout) RunDir() string { return filepath.Join(l.NodeData(), "run") }

// BoxSocket — nơi keenrig-box lắng nghe node API.
func (l Layout) BoxSocket() string { return filepath.Join(l.RunDir(), "box.sock") }

// Socket trả đường dẫn socket của một tiến trình theo tên.
func (l Layout) Socket(process string) (string, error) {
	if !isSafeSegment(process) {
		return "", fmt.Errorf("paths: invalid process name: %q", process)
	}
	return filepath.Join(l.RunDir(), process+".sock"), nil
}

// AgentData — vùng đệm metric/log của keenrig-agent TRƯỚC khi đẩy lên cloud.
// Tách khỏi instance có chủ đích: agent bị backpressure hay đầy đĩa thì
// không được kéo theo control plane, và mất sạch vùng này cũng chỉ mất metric
// chưa gửi — không mất trạng thái app.
func (l Layout) AgentData() string { return filepath.Join(l.NodeData(), "agent") }

// UpdateState — state máy của keenrig-ota (bản đang tải, bản chờ xác nhận,
// mốc rollback). File riêng chứ không phải bảng trong platform.db: ota phải
// hoạt động được cả khi box đang dừng để thay bin.
func (l Layout) UpdateState() string { return filepath.Join(l.Update(), "state.json") }

// BinPrevious — bản bin/ trước đó, giữ lại để rollback khi health check sau
// update thất bại.
//
// Nằm dưới Update() (cùng cây với Base) nên đổi chỗ với Bin() là rename trong
// CÙNG filesystem — thao tác nguyên tử. Đặt nó ở /tmp hay ổ khác sẽ biến
// rollback thành copy nửa chừng được, tức là không rollback được.
func (l Layout) BinPrevious() string { return filepath.Join(l.Update(), "bin-previous") }

// --- mặt phẳng 4: DỮ LIỆU APP ------------------------------------------------

func (l Layout) AppsDir() string { return filepath.Join(l.base, "apps") }

// AppData trả data directory của một app.
//
// Trả lỗi thay vì nối chuỗi mù quáng: đường dẫn này là đối số của thao tác xoá
// đệ quy lúc purge app, nên một appID chứa ".." hoặc dấu phân cách sẽ leo ra
// ngoài apps và xoá nhầm. Dù id hiện luôn do server sinh, ta không dựa vào
// điều đó để giữ an toàn.
func (l Layout) AppData(appID string) (string, error) {
	if !isSafeSegment(appID) {
		return "", fmt.Errorf("paths: app id is not valid as a directory name: %q", appID)
	}
	return filepath.Join(l.AppsDir(), appID), nil
}

// AppVolume trả thư mục trên máy chủ của MỘT volume của app.
//
//	<base>/apps/<appID>/volumes/<name>
//
// # Vì sao có tầng `volumes/` ở giữa
//
// Để phân biệt thứ NỀN TẢNG quản với thứ APP ghi. Không có nó, một volume tên
// `data` sẽ nằm ngay cạnh bất cứ thứ gì nền tảng muốn để trong `apps/<id>/` sau
// này, và hai bên giẫm lên nhau mà không ai thấy trước.
//
// # Lớp kiểm THỨ HAI, có chủ đích
//
// `name` đã bị schema ép về `^[a-z0-9][a-z0-9-]*[a-z0-9]$`. Kiểm lại ở đây
// KHÔNG thừa: `name` trở thành một đoạn đường dẫn thật, và đường đi tới đây có
// nhiều nguồn — desired do người dùng gửi, importer sinh ra, và một ngày nào đó
// là API khác. Cùng mô hình bốn lớp của `appdata.sh` và của `target.ValidateKey`
// + `driver/dir.path`: luật ở tầng trên có thể bị nới ra sau này, lớp này thì
// không đi đâu cả.
//
// Hậu quả nếu để lọt không phải một file đặt sai chỗ: `name = "../../instance"`
// mount thẳng thư mục chứa `master.key` vào container của một image tuỳ ý.
func (l Layout) AppVolume(appID, name string) (string, error) {
	dir, err := l.AppData(appID)
	if err != nil {
		return "", err
	}
	if !isSafeSegment(name) {
		return "", fmt.Errorf("paths: volume name is not valid as a directory name: %q", name)
	}
	return filepath.Join(dir, "volumes", name), nil
}

// AppVolumesDir — thư mục cha của mọi volume của một app.
func (l Layout) AppVolumesDir(appID string) (string, error) {
	dir, err := l.AppData(appID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "volumes"), nil
}

// isSafeSegment nhận đúng một segment đường dẫn "hiền": không rỗng, không phải
// "." / "..", không chứa dấu phân cách (cả '/' lẫn '\' — Windows nhận cả hai)
// và không chứa byte NUL.
func isSafeSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	if strings.ContainsAny(s, `/\`) || strings.ContainsRune(s, 0) {
		return false
	}
	return true
}

// --- khởi tạo ----------------------------------------------------------------

// EnsureDirs tạo bộ khung thư mục (idempotent). KHÔNG tạo apps/<id> —
// thư mục đó thuộc vòng đời của từng app.
func (l Layout) EnsureDirs() error {
	private := []string{l.Instance()}
	public := []string{
		l.Bin(),
		l.NodeData(),
		l.ProxySites(),
		l.ProxyCerts(),
		l.ACMEChallenges(),
		l.Addons(),
		l.Logs(),
		l.BackupInfo(),
		l.Update(),
		l.RunDir(),
		l.AgentData(),
		l.AppsDir(),
	}
	for _, d := range public {
		if err := os.MkdirAll(d, DirPerm); err != nil {
			return fmt.Errorf("paths: creating %s: %w", d, err)
		}
	}
	// Tạo sau và chmod lại: MkdirAll bỏ qua perm nếu thư mục đã tồn tại, mà
	// instance bị nới quyền là lộ master.key.
	for _, d := range private {
		if err := os.MkdirAll(d, PrivateDirPerm); err != nil {
			return fmt.Errorf("paths: creating %s: %w", d, err)
		}
		if err := os.Chmod(d, PrivateDirPerm); err != nil {
			return fmt.Errorf("paths: tightening permissions on %s: %w", d, err)
		}
	}
	return nil
}
