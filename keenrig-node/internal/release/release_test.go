package release_test

// Test UP-01 — "Self-update: binary chữ ký sai/bị sửa → TỪ CHỐI cài".
//
// Testcase nói "chữ ký sai HOẶC bị sửa", và đó là hai đường khác nhau: sửa
// manifest phá chữ ký, sửa binary phá checksum. Cả hai phải chặn được, và test
// phải chứng minh riêng từng đường — một test gộp sẽ vẫn xanh khi một trong hai
// hỏng.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/release"
)

const keyID = "keenrig-release-2026"

type signer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	ring release.Keyring
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring := release.Keyring{}
	if err := ring.Add(keyID, base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	return &signer{pub: pub, priv: priv, ring: ring}
}

// sign trả (bytes manifest, chữ ký base64).
func (s *signer) sign(t *testing.T, m release.Manifest) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw, base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, raw))
}

func payload(body []byte) release.Artifact {
	sum := sha256.Sum256(body)
	return release.Artifact{
		OS: runtime.GOOS, Arch: runtime.GOARCH,
		URL: "https://releases.keenrig.com/stable/keenrig.tar.gz",
		// Bản dựng thật của Keenrig; giá trị cụ thể không quan trọng, tính
		// nhất quán giữa sha256/size và body mới quan trọng.
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)),
	}
}

func goodManifest(body []byte) release.Manifest {
	return release.Manifest{
		Version: "1.2.0", Channel: "stable", KeyID: keyID,
		Artifacts: []release.Artifact{payload(body)},
	}
}

func TestVerifyAcceptsGenuineRelease(t *testing.T) {
	s := newSigner(t)
	body := []byte("nhị phân keenrig-box giả lập")
	raw, sig := s.sign(t, goodManifest(body))

	m, err := release.Verify(raw, sig, s.ring)
	if err != nil {
		t.Fatalf("bản hợp lệ bị từ chối: %v", err)
	}
	if m.Version != "1.2.0" {
		t.Errorf("Version = %q", m.Version)
	}
	a, err := m.ArtifactFor(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if err := release.VerifyArtifact(bytes.NewReader(body), a, nil); err != nil {
		t.Errorf("artifact đúng bị từ chối: %v", err)
	}
}

// --- đường 1: MANIFEST bị sửa --------------------------------------------------

// Sửa BẤT KỲ byte nào của manifest cũng phải phá chữ ký. Test này đổi từng
// trường một, vì một cài đặt sai (ký trên JSON dựng lại thay vì trên byte gốc)
// sẽ vẫn chặn được vài trường và để lọt vài trường khác.
func TestTamperedManifestRejected(t *testing.T) {
	s := newSigner(t)
	body := []byte("nhị phân")
	raw, sig := s.sign(t, goodManifest(body))

	// Kích thước tính từ body chứ không viết cứng: "nhị phân" là 11 byte UTF-8,
	// không phải 8 ký tự — viết cứng ở đây làm phép sửa không đổi gì và test
	// lặng lẽ không kiểm gì cả.
	curSize := fmt.Sprintf(`"size":%d`, len(body))

	tampers := map[string]func(string) string{
		"đổi version":  func(j string) string { return strings.Replace(j, `"1.2.0"`, `"9.9.9"`, 1) },
		"đổi url":      func(j string) string { return strings.Replace(j, "releases.keenrig.com", "evil.example", 1) },
		"đổi sha256":   func(j string) string { return strings.Replace(j, hexOf(body)[:8], "deadbeef", 1) },
		"đổi size":     func(j string) string { return strings.Replace(j, curSize, `"size":999999`, 1) },
		"thêm khoảng ": func(j string) string { return j + " " },
		"đổi key_id":   func(j string) string { return strings.Replace(j, keyID, "khoá-của-kẻ-tấn-công", 1) },
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			bad := []byte(tamper(string(raw)))
			if bytes.Equal(bad, raw) {
				t.Fatal("phép sửa không đổi gì — test này đang không kiểm gì cả")
			}
			_, err := release.Verify(bad, sig, s.ring)
			if err == nil {
				t.Fatal("manifest bị sửa vẫn được chấp nhận")
			}
			// Đổi key_id sang khoá lạ phải báo ĐÚNG là không nhận dạng được
			// khoá, chứ không phải "chữ ký sai" — hai lỗi này dẫn người vận
			// hành tới hai kết luận khác nhau.
			if name == "đổi key_id" && !errors.Is(err, release.ErrUnknownKey) {
				t.Errorf("err = %v, muốn ErrUnknownKey", err)
			}
		})
	}
}

func hexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Ký bằng khoá KHÁC (kẻ tấn công tự sinh cặp khoá của mình) phải bị chặn ở
// key_id, hoặc ở chữ ký nếu họ mượn key_id thật.
func TestSignedByAttackerKeyRejected(t *testing.T) {
	good := newSigner(t)
	evil := newSigner(t) // keyring riêng, cùng keyID

	body := []byte("nhị phân đã bị thay")
	raw, sig := evil.sign(t, goodManifest(body))

	// Kiểm bằng keyring THẬT: cùng key_id nhưng khoá công khai khác nhau.
	if _, err := release.Verify(raw, sig, good.ring); !errors.Is(err, release.ErrBadSignature) {
		t.Errorf("err = %v, muốn ErrBadSignature", err)
	}
}

func TestUnsignedRejected(t *testing.T) {
	s := newSigner(t)
	raw, _ := s.sign(t, goodManifest([]byte("x")))

	for name, sig := range map[string]string{
		"rỗng":             "",
		"chỉ khoảng trắng": "   ",
		"không phải b64":   "!!!không-phải-base64!!!",
		"quá ngắn":         base64.StdEncoding.EncodeToString([]byte("ngắn")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := release.Verify(raw, sig, s.ring); err == nil {
				t.Fatal("bản không có chữ ký hợp lệ vẫn được chấp nhận")
			}
		})
	}
	// Rỗng phải là ErrUnsigned, không phải ErrBadSignature: "server phát hành
	// cấu hình sai" khác hẳn "có kẻ đang sửa gói của bạn".
	if _, err := release.Verify(raw, "", s.ring); !errors.Is(err, release.ErrUnsigned) {
		t.Errorf("chữ ký rỗng → %v, muốn ErrUnsigned", err)
	}
}

// Keyring rỗng = không tin ai. Đây là trạng thái của một binary build thiếu
// khoá, và nó phải TỪ CHỐI mọi thứ chứ không phải chấp nhận mọi thứ.
func TestEmptyKeyringTrustsNothing(t *testing.T) {
	s := newSigner(t)
	raw, sig := s.sign(t, goodManifest([]byte("x")))
	if _, err := release.Verify(raw, sig, release.Keyring{}); !errors.Is(err, release.ErrUnknownKey) {
		t.Errorf("keyring rỗng vẫn chấp nhận: %v", err)
	}
}

// --- đường 2: BINARY bị sửa ------------------------------------------------------

// Manifest ký đúng, nhưng file tải về đã bị thay — đây là kịch bản CDN bị
// chiếm mà server manifest thì không.
func TestTamperedBinaryRejected(t *testing.T) {
	s := newSigner(t)
	body := []byte("nhị phân keenrig-box thật")
	raw, sig := s.sign(t, goodManifest(body))
	m, err := release.Verify(raw, sig, s.ring)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := m.ArtifactFor(runtime.GOOS, runtime.GOARCH)

	evil := append([]byte(nil), body...)
	evil[0] ^= 0xff // đổi ĐÚNG MỘT BIT

	var out bytes.Buffer
	err = release.VerifyArtifact(bytes.NewReader(evil), a, &out)
	if !errors.Is(err, release.ErrChecksum) {
		t.Fatalf("binary bị sửa một bit vẫn qua: %v", err)
	}
}

// Nguồn dài hơn khai báo phải bị chặn Ở CHỖ ĐỌC, không phải lúc đĩa đầy.
func TestOversizedArtifactRejected(t *testing.T) {
	s := newSigner(t)
	body := []byte("ngắn")
	raw, sig := s.sign(t, goodManifest(body))
	m, _ := release.Verify(raw, sig, s.ring)
	a, _ := m.ArtifactFor(runtime.GOOS, runtime.GOARCH)

	// Nguồn "vô tận": nếu VerifyArtifact không giới hạn thì test này treo.
	endless := endlessReader{}
	if err := release.VerifyArtifact(endless, a, nil); !errors.Is(err, release.ErrSize) {
		t.Fatalf("nguồn dài vô tận không bị chặn: %v", err)
	}
}

type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

func TestTruncatedArtifactRejected(t *testing.T) {
	s := newSigner(t)
	body := []byte("nhị phân đầy đủ")
	raw, sig := s.sign(t, goodManifest(body))
	m, _ := release.Verify(raw, sig, s.ring)
	a, _ := m.ArtifactFor(runtime.GOOS, runtime.GOARCH)

	if err := release.VerifyArtifact(bytes.NewReader(body[:5]), a, nil); !errors.Is(err, release.ErrSize) {
		t.Errorf("file cụt vẫn qua: %v", err)
	}
}

// --- manifest không hợp lệ -----------------------------------------------------

// Manifest ký ĐÚNG nhưng thiếu trường bắt buộc vẫn phải bị từ chối: chữ ký
// chứng minh nguồn gốc, không chứng minh nội dung có nghĩa.
func TestSignedButInvalidManifestRejected(t *testing.T) {
	s := newSigner(t)
	cases := map[string]release.Manifest{
		"thiếu version": {Channel: "stable", KeyID: keyID,
			Artifacts: []release.Artifact{payload([]byte("x"))}},
		"không artifact": {Version: "1.0.0", KeyID: keyID},
		"thiếu size": {Version: "1.0.0", KeyID: keyID, Artifacts: []release.Artifact{
			{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "u", SHA256: hexOf([]byte("x"))}}},
		"sha256 hỏng": {Version: "1.0.0", KeyID: keyID, Artifacts: []release.Artifact{
			{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "u", SHA256: "không-phải-hex", Size: 1}}},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			raw, sig := s.sign(t, m)
			if _, err := release.Verify(raw, sig, s.ring); !errors.Is(err, release.ErrBadManifest) {
				t.Errorf("err = %v, muốn ErrBadManifest", err)
			}
		})
	}
}

func TestNoArtifactForPlatform(t *testing.T) {
	s := newSigner(t)
	m := goodManifest([]byte("x"))
	m.Artifacts[0].OS = "plan9"
	m.Artifacts[0].Arch = "sparc"
	raw, sig := s.sign(t, m)
	got, err := release.Verify(raw, sig, s.ring)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.ArtifactFor("linux", "amd64"); !errors.Is(err, release.ErrNoArtifact) {
		t.Errorf("err = %v, muốn ErrNoArtifact", err)
	}
}

// --- OT-06 min_upgradable_from -----------------------------------------------------

func TestUpgradePath(t *testing.T) {
	m := &release.Manifest{Version: "3.0.0", MinUpgradableFrom: "2.5.0"}
	cases := map[string]bool{ // version hiện tại → có được nhảy thẳng không
		"2.5.0":    true,
		"2.5.1":    true,
		"2.6.0":    true,
		"3.0.0":    true,
		"10.0.0":   true,
		"2.4.9":    false,
		"1.0.0":    false,
		"0.0.1-m0": false,
		"linh-ta":  false, // không phân tích được → KHÔNG cho nhảy
	}
	for cur, ok := range cases {
		err := m.CheckUpgradePath(cur)
		if ok && err != nil {
			t.Errorf("từ %s: %v (muốn cho qua)", cur, err)
		}
		if !ok && !errors.Is(err, release.ErrTooOld) {
			t.Errorf("từ %s: err = %v, muốn ErrTooOld", cur, err)
		}
	}
	// Không khai min_upgradable_from → mọi bản đều nhảy thẳng được.
	none := &release.Manifest{Version: "3.0.0"}
	if err := none.CheckUpgradePath("linh-tinh"); err != nil {
		t.Errorf("không khai min_upgradable_from mà vẫn chặn: %v", err)
	}
}

// Khoá sai độ dài phải bị chặn Ở CỬA VÀO keyring: ed25519.Verify PANIC với
// khoá sai kích thước, và một panic trong đường update là mất luôn khả năng
// sửa từ xa.
func TestKeyringRejectsMalformedKey(t *testing.T) {
	ring := release.Keyring{}
	for name, k := range map[string]string{
		"quá ngắn":       base64.StdEncoding.EncodeToString([]byte("ngắn")),
		"không phải b64": "!!!",
		"rỗng":           "",
	} {
		if err := ring.Add("k", k); err == nil {
			t.Errorf("keyring nhận khoá %s", name)
		}
	}
	if len(ring) != 0 {
		t.Errorf("keyring có %d khoá sau khi từ chối hết", len(ring))
	}
}
