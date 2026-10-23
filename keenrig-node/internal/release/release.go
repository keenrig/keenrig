// Package release — xác minh một bản phát hành TRƯỚC khi cài (UP-01, OT-01).
//
// # Vì sao checksum là chưa đủ
//
// get.sh có kiểm sha256, và nó chống được đúng một thứ: file tải về bị hỏng.
// Nó KHÔNG chống được server phát hành bị chiếm — kẻ kiểm soát server đặt luôn
// được cả file .sha256. Chữ ký Ed25519 chống được điều đó vì khoá riêng không
// nằm trên server phát hành.
//
// Hệ quả: bản thiếu chữ ký, sai key_id, hoặc chữ ký không khớp phải bị TỪ CHỐI
// kể cả khi sha256 khớp hoàn hảo.
//
// # Chữ ký RỜI, trên ĐÚNG BYTE — không phải trên JSON dựng lại
//
// Cách làm phổ biến và sai là: bỏ trường `signature` khỏi object, tuần tự hoá
// lại, rồi ký kết quả. Nó biến an toàn của chữ ký thành một bài toán chuẩn hoá
// JSON — thứ tự khoá, khoảng trắng, cách escape unicode, số nguyên lớn. Mọi
// khác biệt giữa bên ký và bên kiểm là một đường để giả mạo.
//
// Ở đây chữ ký nằm trong MỘT FILE RIÊNG và phủ ĐÚNG dãy byte của manifest.json.
// Bên kiểm không bao giờ tuần tự hoá lại gì cả:
//
//	manifest.json       nội dung, ký nguyên văn
//	manifest.json.sig   64 byte Ed25519, mã hoá base64
//
// # Thứ tự kiểm là một phần của thiết kế
//
//  1. Kiểm chữ ký trên byte manifest.
//  2. CHỈ SAU ĐÓ mới đọc nội dung manifest.
//  3. Kiểm kích thước + sha256 của artifact theo số liệu trong manifest.
//
// Đảo bước 1 và 2 nghĩa là tin vào `size` của một manifest chưa xác minh — và
// một `size` do kẻ tấn công đặt là cách làm cạn đĩa của máy nạn nhân.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	// ErrUnsigned — không có chữ ký. Tách khỏi ErrBadSignature vì hai lỗi này
	// nói hai chuyện khác nhau với người vận hành: "server phát hành cấu hình
	// sai" khác hẳn "có kẻ đang sửa gói của bạn".
	ErrUnsigned = errors.New("release: the release has no signature")
	// ErrUnknownKey — key_id không nằm trong keyring nhúng trong binary.
	ErrUnknownKey = errors.New("release: unrecognised key_id")
	// ErrBadSignature — chữ ký không khớp nội dung.
	ErrBadSignature = errors.New("release: signature mismatch")
	// ErrBadManifest — manifest sai cú pháp hoặc thiếu trường bắt buộc.
	ErrBadManifest = errors.New("release: invalid manifest")
	// ErrChecksum — artifact tải về không khớp sha256 trong manifest.
	ErrChecksum = errors.New("release: artifact checksum mismatch")
	// ErrSize — artifact dài/ngắn hơn số ghi trong manifest.
	ErrSize = errors.New("release: artifact has the wrong size")
	// ErrNoArtifact — manifest không có artifact cho os/arch đang chạy.
	ErrNoArtifact = errors.New("release: no build for this platform")
	// ErrTooOld — bản hiện tại thấp hơn min_upgradable_from (OT-06).
	ErrTooOld = errors.New("release: an intermediate version must be installed first")
)

// Artifact — một file nhị phân trong bản phát hành.
type Artifact struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	URL  string `json:"url"`
	// SHA256 dạng hex thường.
	SHA256 string `json:"sha256"`
	// Size tính bằng byte. BẮT BUỘC: nó là trần cho việc tải, và không có trần
	// thì một server bị chiếm làm cạn đĩa bằng một luồng byte vô tận.
	Size int64 `json:"size"`
}

// Manifest — nội dung manifest.json.
type Manifest struct {
	Version string `json:"version"`
	Channel string `json:"channel"`
	// MinUpgradableFrom — bản cũ hơn mức này phải đi qua bản trung gian (OT-06).
	MinUpgradableFrom string     `json:"min_upgradable_from,omitempty"`
	Artifacts         []Artifact `json:"artifacts"`
	// KeyID chọn khoá công khai trong keyring. Nằm TRONG manifest (đã được ký)
	// chứ không phải cạnh chữ ký: để kẻ tấn công không thể chỉ đổi key_id sang
	// một khoá họ kiểm soát.
	KeyID string `json:"key_id"`
	// ReleasedAt để người vận hành thấy tuổi bản phát hành.
	ReleasedAt string `json:"released_at,omitempty"`
}

// Keyring — khoá công khai được TIN, nhúng trong binary lúc build.
//
// Nhiều khoá chứ không phải một: xoay khoá cần một khoảng thời gian mà cả khoá
// cũ lẫn khoá mới đều được chấp nhận. Chỉ có một khoá nghĩa là mọi lần xoay đều
// làm chết mọi instance chưa kịp update — tức là không ai dám xoay.
type Keyring map[string]ed25519.PublicKey

// Add nạp một khoá dạng base64. Trả lỗi khi khoá sai độ dài — ed25519.Verify
// PANIC với khoá sai kích thước, nên phải chặn ở cửa vào chứ không ở lúc kiểm.
func (k Keyring) Add(keyID, b64 string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return fmt.Errorf("release: key %q is not base64: %w", keyID, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("release: key %q is %d bytes, %d are required",
			keyID, len(raw), ed25519.PublicKeySize)
	}
	k[keyID] = ed25519.PublicKey(raw)
	return nil
}

// Verify kiểm chữ ký RỒI mới phân tích manifest. Trả manifest đã xác minh.
//
// manifestBytes phải là ĐÚNG dãy byte đọc từ file, chưa qua bất kỳ bước chuẩn
// hoá nào. sigB64 là nội dung manifest.json.sig.
func Verify(manifestBytes []byte, sigB64 string, ring Keyring) (*Manifest, error) {
	sigB64 = strings.TrimSpace(sigB64)
	if sigB64 == "" {
		return nil, ErrUnsigned
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("%w: the signature is not base64: %v", ErrBadSignature, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: the signature is %d bytes, %d are required",
			ErrBadSignature, len(sig), ed25519.SignatureSize)
	}

	// key_id nằm TRONG vùng được ký, nên phải đọc nó ra để chọn khoá — nhưng
	// KHÔNG được tin gì khác trong manifest trước khi chữ ký khớp. Đọc đúng
	// một trường, bằng một struct chỉ có một trường.
	var probe struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(manifestBytes, &probe); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadManifest, err)
	}
	if probe.KeyID == "" {
		return nil, fmt.Errorf("%w: key_id is missing", ErrBadManifest)
	}
	pub, ok := ring[probe.KeyID]
	if !ok {
		// KHÔNG thử mọi khoá còn lại: "khoá nào cũng được" biến keyring thành
		// một tập hợp OR, và lúc đó việc thu hồi một khoá không có tác dụng gì.
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, probe.KeyID)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: key %q is corrupt in the keyring", ErrUnknownKey, probe.KeyID)
	}

	if !ed25519.Verify(pub, manifestBytes, sig) {
		return nil, ErrBadSignature
	}

	// TỪ ĐÂY nội dung mới đáng tin.
	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadManifest, err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("%w: version is missing", ErrBadManifest)
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("%w: no artifacts", ErrBadManifest)
	}
	for i, a := range m.Artifacts {
		switch {
		case a.OS == "" || a.Arch == "":
			return fmt.Errorf("%w: artifact[%d] is missing os/arch", ErrBadManifest, i)
		case a.URL == "":
			return fmt.Errorf("%w: artifact[%d] is missing url", ErrBadManifest, i)
		case a.Size <= 0:
			// Size là TRẦN cho việc tải, không phải thông tin trang trí.
			return fmt.Errorf("%w: artifact[%d] is missing size", ErrBadManifest, i)
		}
		if _, err := hex.DecodeString(a.SHA256); err != nil || len(a.SHA256) != sha256.Size*2 {
			return fmt.Errorf("%w: artifact[%d] has an invalid sha256", ErrBadManifest, i)
		}
	}
	return nil
}

// ArtifactFor chọn bản dựng cho os/arch. So khớp CHÍNH XÁC, không suy diễn
// tương thích (amd64 chạy được trên máy arm qua giả lập chẳng hạn) — đoán ở đây
// nghĩa là cài một binary chạy chậm gấp mười mà không ai biết vì sao.
func (m *Manifest) ArtifactFor(goos, goarch string) (Artifact, error) {
	for _, a := range m.Artifacts {
		if a.OS == goos && a.Arch == goarch {
			return a, nil
		}
	}
	return Artifact{}, fmt.Errorf("%w: %s/%s", ErrNoArtifact, goos, goarch)
}

// VerifyArtifact đọc r, khẳng định nó khớp a, và ghi ra w nếu w khác nil.
//
// Đọc qua io.LimitReader theo Size+1: đọc được byte thứ Size+1 nghĩa là nguồn
// dài hơn khai báo, và đó là lúc phải dừng chứ không phải lúc đĩa đầy.
//
// Ghi ra w SONG SONG với việc băm, không phải hai lượt: hai lượt cần lưu toàn
// bộ artifact ở đâu đó trước khi biết nó có hợp lệ không, và "ở đâu đó" luôn
// là đĩa của nạn nhân. Đổi lại, caller PHẢI coi nội dung recorded là rác cho tới
// khi hàm này trả nil — và đó là lý do w nên là một file tạm, không phải bin/.
func VerifyArtifact(r io.Reader, a Artifact, w io.Writer) error {
	want, err := hex.DecodeString(a.SHA256)
	if err != nil {
		return fmt.Errorf("%w: the sha256 in the manifest could not be decoded", ErrBadManifest)
	}

	h := sha256.New()
	var dst io.Writer = h
	if w != nil {
		dst = io.MultiWriter(h, w)
	}
	n, err := io.Copy(dst, io.LimitReader(r, a.Size+1))
	if err != nil {
		return err
	}
	if n != a.Size {
		return fmt.Errorf("%w: read %d bytes, the manifest says %d", ErrSize, n, a.Size)
	}
	// bytes.Equal chứ không phải so sánh hằng thời gian: cả hai vế đều là dữ
	// liệu CÔNG KHAI (hash của một file ai cũng tải được), nên không có bí mật
	// nào để rò qua thời gian so sánh.
	if got := h.Sum(nil); !equalBytes(got, want) {
		return fmt.Errorf("%w: sha256 = %x, manifest ghi %s", ErrChecksum, got, a.SHA256)
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// CheckUpgradePath — OT-06. current thấp hơn MinUpgradableFrom → phải qua bản
// trung gian, không được nhảy thẳng.
//
// So sánh bằng semver rút gọn (major.minor.patch, bỏ hậu tố). Bản không phân
// tích được coi là KHÔNG đủ điều kiện: không biết mình đang ở đâu thì không
// được phép nhảy, vì cái giá của nhảy sai là một migration không hoàn tác được.
func (m *Manifest) CheckUpgradePath(current string) error {
	if strings.TrimSpace(m.MinUpgradableFrom) == "" {
		return nil
	}
	cur, okCur := parseVersion(current)
	min, okMin := parseVersion(m.MinUpgradableFrom)
	if !okCur || !okMin {
		return fmt.Errorf("%w: could not compare %q with min_upgradable_from %q",
			ErrTooOld, current, m.MinUpgradableFrom)
	}
	if less(cur, min) {
		return fmt.Errorf("%w: currently on %s, this release requires at least %s",
			ErrTooOld, current, m.MinUpgradableFrom)
	}
	return nil
}

// parseVersion đọc "1.2.3" hoặc "1.2.3-rc1" hoặc "v1.2.3".
func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n := 0
		if p == "" {
			return out, false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return out, false
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out, true
}

func less(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
