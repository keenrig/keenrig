// Package snapshot — gom một instance thành nhiều phần, đóng gói, mã hoá, đẩy
// lên Target; và làm ngược lại (BK-02).
//
// Đây là chỗ ba lớp dưới gặp nhau, và nó KHÔNG phải seam thứ tư — nó là caller:
//
//	format.Format   cây thư mục ↔ stream
//	crypt           stream ↔ stream đã mã hoá
//	target.Target   key ↔ bytes
//
// # NHIỀU object, không phải một
//
// Một archive khổng lồ cho cả instance là lựa chọn hiển nhiên và sai. Ba lý do,
// mỗi lý do đo được:
//
//	Phải dàn dựng cả cây     Muốn gói `instance/` + `apps/` thành một, ta phải
//	                         chép chúng vào một thư mục tạm trước — tức là cần
//	                         thêm một lượng đĩa bằng đúng dữ liệu đang có, trên
//	                         chính cái máy sắp hết chỗ.
//	Restore một app          Ca THƯỜNG nhất của restore không phải "mất cả máy"
//	                         mà là "app này hỏng, lấy lại bản hôm qua". Với một
//	                         archive duy nhất, việc đó là tải về và giải nén tất
//	                         cả để lấy một phần.
//	Một byte hỏng mất tất cả gzip là stream: hỏng ở giữa thì phần sau không đọc
//	                         được. Chia theo app thì một app hỏng, phần còn lại
//	                         vẫn về.
//
// Nên bố cục trên Target là:
//
//	snapshots/<id>/manifest.json        KHÔNG mã hoá — xem dưới
//	snapshots/<id>/instance.tgz         platform.db (đã VACUUM INTO) + master.key
//	snapshots/<id>/apps/<appID>.tgz     dữ liệu người dùng của từng app
//	snapshots/<id>/addons/<appID>.tgz   dump addon của app đó
//
// # Manifest KHÔNG mã hoá — và cái giá đã cân
//
// Restore phải biết ba thứ TRƯỚC khi giải mã được thứ gì: format nào, có mã hoá
// hay không, và băm mong đợi là bao nhiêu. Mã hoá luôn manifest là tạo ra bài
// toán con-gà-quả-trứng, và làm `backup list` đòi passphrase chỉ để đọc tên.
//
// Cái phải nói thẳng: manifest do đó LỘ danh sách app ID và thời điểm sao lưu
// cho ai đọc được Target. Nó KHÔNG chứa secret, không chứa domain, không chứa
// nội dung. Đây là hệ quả đã chấp nhận tường minh, không phải bỏ sót — ngày nào
// thấy nó quá đắt thì lối ra là mã hoá manifest bằng một khoá dẫn xuất riêng và
// giữ MỘT file chỉ mục nhỏ ở dạng trần.
//
// # Băm là băm của PLAINTEXT
//
// `tgz` cố ý tất định để so hai bản sao lưu bằng một phép băm; salt ngẫu nhiên
// của `crypt` xoá tính chất đó ở tầng ciphertext. Ghi băm của archive TRƯỚC khi
// mã hoá thì giữ lại được — và nó cũng là thứ duy nhất phát hiện được "Target
// trả về đúng số byte nhưng sai nội dung".
package snapshot

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ManifestVersion — bản của định dạng manifest. Restore từ chối bản nó không
// biết, thay vì đoán: đọc nhầm một trường là restore sai dữ liệu.
const ManifestVersion = 1

// Prefix — gốc của mọi key snapshot trên Target. Cố định để `Prune` chạy được
// trên đúng một tiền tố.
const Prefix = "snapshots/"

// ManifestName — tên object manifest trong mỗi snapshot.
const ManifestName = "manifest.json"

// Kind — loại phần trong một snapshot.
const (
	KindInstance = "instance"
	KindApp      = "app"
	KindAddon    = "addon"
)

// Manifest — thứ duy nhất đọc được mà không cần passphrase.
type Manifest struct {
	Version   int       `json:"version"`
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	// Format — tên driver đã đóng gói. Restore mở driver theo trường NÀY, không
	// theo biến môi trường: đổi biến mà làm snapshot cũ mở không được là biến
	// một thay đổi cấu hình thành mất dữ liệu.
	Format string `json:"format"`
	// Encrypted — luôn true ở bản này. Có mặt để một bản sau diễn đạt được lựa
	// chọn khác mà không phải đoán từ byte đầu của file.
	Encrypted bool `json:"encrypted"`
	// BoxVersion — version của keenrig-box lúc chụp. Không dùng để quyết định gì
	// khi restore; nó là thứ người vận hành cần khi một bản sao lưu cũ giải nén
	// ra schema mà bản mới không hiểu.
	BoxVersion string `json:"box_version,omitempty"`
	Parts      []Part `json:"parts"`
}

// Part — một object trong snapshot.
type Part struct {
	Kind  string `json:"kind"`
	AppID string `json:"app_id,omitempty"`
	Key   string `json:"key"`
	// PlainSHA256 — băm của archive TRƯỚC khi mã hoá. Xem godoc package.
	PlainSHA256 string `json:"plain_sha256"`
	PlainBytes  int64  `json:"plain_bytes"`
	// StoredBytes — số byte thật đã đẩy lên Target (sau nén + mã hoá).
	StoredBytes int64 `json:"stored_bytes"`
	Files       int64 `json:"files"`
	Dirs        int64 `json:"dirs"`
	// Skipped — thứ KHÔNG vào được archive, kèm lý do. Bỏ qua im lặng thì người
	// vận hành không bao giờ biết bản sao lưu thiếu gì.
	Skipped []string `json:"skipped,omitempty"`
}

// Validate kiểm manifest đọc từ Target.
//
// Manifest tới từ nơi lưu trữ — có thể là bucket đã rò rỉ credential. Nên nó là
// dữ liệu từ bên ngoài, và mọi trường điều khiển hành vi restore phải được kiểm
// trước khi dùng.
func (m *Manifest) Validate() error {
	switch {
	case m == nil:
		return fmt.Errorf("snapshot: manifest is nil")
	case m.Version != ManifestVersion:
		return fmt.Errorf("snapshot: manifest version %d is not supported by this build (expected %d)",
			m.Version, ManifestVersion)
	case strings.TrimSpace(m.ID) == "":
		return fmt.Errorf("snapshot: manifest has no id")
	case strings.TrimSpace(m.Format) == "":
		return fmt.Errorf("snapshot: manifest does not say which format packed it")
	case len(m.Parts) == 0:
		return fmt.Errorf("snapshot: manifest %s lists no parts", m.ID)
	}
	seen := map[string]bool{}
	for i, p := range m.Parts {
		switch p.Kind {
		case KindInstance, KindApp, KindAddon:
		default:
			return fmt.Errorf("snapshot: part %d has unknown kind %q", i, p.Kind)
		}
		if strings.TrimSpace(p.Key) == "" {
			return fmt.Errorf("snapshot: part %d (%s) has no key", i, p.Kind)
		}
		if seen[p.Key] {
			// Hai phần cùng key nghĩa là phần sau ghi đè phần trước lúc tạo, và
			// lúc restore ta sẽ giải nén cùng một object hai lần vào hai chỗ.
			return fmt.Errorf("snapshot: key %q appears twice", p.Key)
		}
		seen[p.Key] = true
		if (p.Kind == KindApp || p.Kind == KindAddon) && strings.TrimSpace(p.AppID) == "" {
			return fmt.Errorf("snapshot: %s part %q has no app id", p.Kind, p.Key)
		}
		if p.PlainSHA256 == "" {
			return fmt.Errorf("snapshot: part %q has no plaintext digest — nothing could verify it after restore", p.Key)
		}
	}
	return nil
}

// InstancePart trả phần `instance` (platform.db + master.key), hoặc nil.
func (m *Manifest) InstancePart() *Part {
	for i := range m.Parts {
		if m.Parts[i].Kind == KindInstance {
			return &m.Parts[i]
		}
	}
	return nil
}

// TotalStored — tổng số byte đã đẩy lên Target.
func (m *Manifest) TotalStored() int64 {
	var n int64
	for _, p := range m.Parts {
		n += p.StoredBytes
	}
	return n
}

func (m *Manifest) encode() ([]byte, error) {
	// Indent vì đây là file người vận hành sẽ mở bằng mắt khi mọi thứ khác đã
	// hỏng — đó là toàn bộ lý do nó không mã hoá.
	return json.MarshalIndent(m, "", "  ")
}

// NewID sinh ID từ thời điểm, ĐỦ để sắp xếp bằng so sánh chuỗi.
//
// Thứ tự từ điển phải trùng thứ tự thời gian: `target.List` trả về đã sắp theo
// key, và retention chọn bản để XOÁ dựa trên thứ tự đó. Một định dạng ID mà sắp
// chuỗi ra khác sắp thời gian sẽ xoá nhầm bản — im lặng, theo lịch. Định dạng
// rộng cố định giữ được tính chất đó; thêm mili-giây không phá vì nó cũng rộng
// cố định.
//
// # Vì sao có mili-giây, và nó đã sửa một lỗi mất dữ liệu
//
// Bản đầu chỉ có độ phân giải GIÂY. Test chaos CH-02 bắt được: hai lần sao lưu
// trong cùng một giây cho ra CÙNG một ID và im lặng ghi đè lên nhau. Tái hiện
// bằng tay, hai lệnh liên tiếp:
//
//	snapshot 2026-08-12T08-00-07Z: 1 parts, 7015 bytes stored on dir
//	snapshot 2026-08-12T08-00-07Z: 1 parts, 7015 bytes stored on dir   ← cùng ID
//
// Ba hệ quả, cái sau nặng hơn cái trước: (1) tưởng có hai điểm khôi phục, thực
// ra một; (2) retention đếm chúng là một, nên "giữ 30 bản" giữ ít hơn 30; (3)
// nếu lần trước bị CẮT giữa chừng, manifest của lần này trỏ vào những phần đã
// bị lần kia ghi đè — băm không khớp, và `backups` vẫn kể tên nó như một bản
// hoàn chỉnh. Đó chính là ca test chaos bắt được.
//
// Mili-giây thu hẹp cửa sổ chứ không đóng hẳn nó. Chỗ đóng hẳn là
// [ErrSnapshotExists] — xem Create.
//
// Dùng '-' thay ':' vì ':' không hợp lệ trong tên file trên Windows và driver
// `dir` map key thẳng thành đường dẫn. Dấu '.' thì HỢP LỆ, nên mili-giây giữ
// đúng dạng quen thuộc.
func NewID(t time.Time) string {
	// Ghép "Z" bằng tay: trong layout của Go, "Z" mở đầu một mẫu múi giờ
	// ("Z07:00"), không phải một chữ Z nguyên văn.
	return t.UTC().Format("2006-01-02T15-04-05.000") + "Z"
}

// KeyFor dựng key trên Target cho một phần.
func KeyFor(id, kind, appID string) string {
	switch kind {
	case KindInstance:
		return Prefix + id + "/instance.tgz"
	case KindApp:
		return Prefix + id + "/apps/" + appID + ".tgz"
	case KindAddon:
		return Prefix + id + "/addons/" + appID + ".tgz"
	default:
		return Prefix + id + "/" + kind
	}
}

// ManifestKey dựng key của manifest.
func ManifestKey(id string) string { return Prefix + id + "/" + ManifestName }
